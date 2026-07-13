// SPDX-License-Identifier: Apache-2.0
// member.mjs: the MEMBER'S PHONE. Reads the keypair and credential that the
// in-person ceremony (seed.mjs) put on the device, fetches a challenge from
// the door, answers it with a fresh ember presence proof, and, if admitted,
// reads the members-only noticeboard.
//
//   node member.mjs             present Ada's valid credential
//   node member.mjs --lapsed    present Rex's expired credential and watch
//                               the door refuse with the renewal prompt
//
// Only ember HOLDER primitives are used here (parseChal, createProof). The
// adapter package is verifier-side and never touches this file.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { b64uDecode, b64uEncode, createProof, parseChal } from '@prefig/ember';

const STATE_PATH = fileURLToPath(new URL('./doorcheck-state.json', import.meta.url));
const BASE = process.env.DOORCHECK_URL ?? 'http://127.0.0.1:8787';
const lapsed = process.argv.includes('--lapsed');

let state;
try {
	state = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
} catch {
	console.error('doorcheck: cannot read doorcheck-state.json. Run `node seed.mjs` first.');
	process.exit(1);
}

const who = lapsed ? state.lapsedMember : state.member;
const identity = { priv: b64uDecode(who.priv), pub: b64uDecode(who.pub) };
const credBytes = b64uDecode(who.cred);

console.log(`doorcheck member: presenting as ${who.name}${lapsed ? ' (credential lapsed an hour ago)' : ''}\n`);

// 1. Scan the QR on the door (here: GET /challenge).
const chalRes = await fetch(`${BASE}/challenge`);
const { encounter, challenge, expiresAt } = await chalRes.json();
console.log(`1. Door shows a challenge (expires ${expiresAt})`);

// 2. Build the presence proof: sign the challenge nonce and audience with
//    the member key, wrapping the credential chain.
const chal = parseChal(b64uDecode(challenge));
const proof = await createProof({
	credBytes,
	nonce: chal.nonce,
	identity,
	aud: chal.aud,
});
console.log(`2. Phone builds a presence proof (${proof.length} bytes) echoing nonce and audience '${chal.aud}'`);

// 3. Present it (here: POST /present; in real life, show a QR back).
const presentRes = await fetch(`${BASE}/present`, {
	method: 'POST',
	headers: { 'content-type': 'application/json' },
	body: JSON.stringify({ encounter, kind: 'ember-proof', proof: b64uEncode(proof) }),
});
const presented = await presentRes.json();

if (!presented.ok) {
	console.log(`3. Door refuses: [${presented.code}] ${presented.message}`);
	if (String(presented.message).includes('lapsed')) {
		console.log('\n   +----------------------------------------------------+');
		console.log('   |  Your membership has lapsed.                       |');
		console.log('   |  Expiry is the only revocation in this scope, and  |');
		console.log('   |  renewal happens in presence: bring this device    |');
		console.log('   |  to a steward and complete the renewal handshake.  |');
		console.log('   +----------------------------------------------------+');
	}
	process.exit(1);
}

const cookie = presentRes.headers.get('set-cookie');
console.log('3. Door admits the proof and sets an opaque session cookie:');
console.log(`   ${cookie}`);

// 4. Read the members-only noticeboard with the session cookie.
const boardRes = await fetch(`${BASE}${presented.board}`, {
	headers: { cookie: cookie.split(';')[0], accept: 'application/json' },
});
const board = await boardRes.json();
if (!board.ok) {
	console.log(`4. Board refused: ${board.message}`);
	process.exit(1);
}

console.log('4. The members-only noticeboard:');
console.log(`   member:    ${board.upactor.display_hint ?? 'anonymous member'}`);
console.log(`   upactor:   ${board.upactor.id}`);
console.log(`   expires:   ${board.upactor.expires_at ?? 'never'}`);
console.log(`   renewal:   ${board.upactor.renewable} (in presence, with a steward)`);
console.log('   notices:');
for (const n of board.notices) console.log(`     - ${n}`);
