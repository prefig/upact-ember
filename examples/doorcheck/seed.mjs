// SPDX-License-Identifier: Apache-2.0
// seed.mjs: plays the OUT-OF-BAND, IN-PERSON ceremony that ember assumes
// happens before any door check. In real life these steps are QR handshakes
// between phones in the same room; here they are function calls on one
// machine, and the resulting bytes are written to doorcheck-state.json so
// member.mjs (the member's phone) and server.mjs (the door) can pick them up.
//
// Ceremony performed:
//   1. Founder creates the scope genesis (the club is born).
//   2. Founder grants Sam a steward credential (Sam may renew others).
//   3. Sam grants Ada a plain member credential, valid for one hour.
//   4. Sam ALSO granted Rex a member credential two hours ago, valid for one
//      hour, so Rex's credential is already lapsed. This seeds the
//      `--lapsed` demo path in member.mjs.
//
// Nothing here talks to the network and nothing secret leaves this machine.

import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
	b64uEncode,
	createGenesis,
	createReq,
	founderCred,
	generateIdentity,
	grantCred,
	now,
	parseGenesis,
	parseReq,
	verifyCred,
} from '@prefig/ember';

const STATE_PATH = fileURLToPath(new URL('./doorcheck-state.json', import.meta.url));

const SCOPE_NAME = 'doorcheck';
const SCOPE_TTL_S = 86400; // scope-wide max grant lifetime: one day
const MEMBER_TTL_S = 3600; // both member grants live one hour
const AUDIENCE = 'doorcheck-demo'; // must match server.mjs

// The full member <-> steward renewal handshake: the subject asks
// (createReq), the steward reads the request (parseReq) and countersigns a
// fresh link onto their own chain (grantCred). In the real app this is two
// QR codes shown across a table.
async function grantInPresence({ granterCredBytes, granter, subject, name, scopeId, at, asSteward, ttl }) {
	const req = await createReq({ scopeId, identity: subject, name });
	const parsed = await parseReq(req.bytes);
	return grantCred({
		granterCredBytes,
		identity: granter,
		req: parsed,
		at,
		ttlOverride: ttl,
		asSteward,
	});
}

const t = now(); // UNIX seconds, the moment of this seeding
const tPast = t - 7200; // two hours ago, when the club (and Rex's grant) happened

console.log('doorcheck seed: running the in-person ember ceremony\n');

const founder = await generateIdentity();
const steward = await generateIdentity();
const member = await generateIdentity();
const lapsedMember = await generateIdentity();

// 1. Genesis: the founder signs the scope into existence (two hours ago, so
//    an already-lapsed grant can exist inside the scope's history).
const genesisBytes = await createGenesis({
	name: SCOPE_NAME,
	ttl: SCOPE_TTL_S,
	maxDepth: 3,
	identity: founder,
	at: tPast,
});
const scopeId = parseGenesis(genesisBytes).scopeId;
const founderCredBytes = founderCred(genesisBytes);
console.log(`1. Founder created scope '${SCOPE_NAME}' (genesis signed, ${genesisBytes.length} bytes)`);

// 2. Founder grants Sam stewardship, full scope ttl, back at scope creation.
const stewardCredBytes = await grantInPresence({
	granterCredBytes: founderCredBytes,
	granter: founder,
	subject: steward,
	name: 'Sam',
	scopeId,
	at: tPast,
	asSteward: true,
	ttl: SCOPE_TTL_S,
});
console.log('2. Founder granted Sam a steward credential (depth 1)');

// 3. Sam grants Ada plain membership NOW, one hour of validity.
const memberCredBytes = await grantInPresence({
	granterCredBytes: stewardCredBytes,
	granter: steward,
	subject: member,
	name: 'Ada',
	scopeId,
	at: t,
	asSteward: false,
	ttl: MEMBER_TTL_S,
});
console.log('3. Sam granted Ada a member credential (depth 2, expires in one hour)');

// 4. Sam granted Rex plain membership TWO HOURS AGO with one hour of
//    validity, so it lapsed an hour ago. Expiry is ember's only revocation.
const lapsedCredBytes = await grantInPresence({
	granterCredBytes: stewardCredBytes,
	granter: steward,
	subject: lapsedMember,
	name: 'Rex',
	scopeId,
	at: tPast,
	asSteward: false,
	ttl: MEMBER_TTL_S,
});
console.log('4. Sam granted Rex a member credential two hours ago; it lapsed an hour ago');

// Sanity: verify both chains offline before writing anything.
const adaCheck = await verifyCred(memberCredBytes, { at: t });
if (!adaCheck.ok) throw new Error(`seed self-check failed for Ada: ${adaCheck.reason}`);
const rexCheck = await verifyCred(lapsedCredBytes, { at: t });
if (rexCheck.ok || rexCheck.lapsed !== true) {
	throw new Error(`seed self-check failed for Rex: expected a lapsed credential, got ${JSON.stringify(rexCheck.reason)}`);
}

const state = {
	comment: 'doorcheck demo state: the output of the in-person ember ceremony. priv fields are demo keypairs, never reuse.',
	createdAt: t,
	audience: AUDIENCE,
	scopeName: SCOPE_NAME,
	genesis: b64uEncode(genesisBytes),
	member: {
		name: 'Ada',
		priv: b64uEncode(member.priv),
		pub: b64uEncode(member.pub),
		cred: b64uEncode(memberCredBytes),
		expiresAt: adaCheck.expiresAt,
	},
	lapsedMember: {
		name: 'Rex',
		priv: b64uEncode(lapsedMember.priv),
		pub: b64uEncode(lapsedMember.pub),
		cred: b64uEncode(lapsedCredBytes),
		expiresAt: rexCheck.expiresAt,
	},
};

await writeFile(STATE_PATH, JSON.stringify(state, null, '\t') + '\n');

console.log(`\nWrote ${STATE_PATH}`);
console.log(`   Ada's membership is valid until ${new Date(adaCheck.expiresAt * 1000).toISOString()}`);
console.log(`   Rex's membership lapsed at     ${new Date(rexCheck.expiresAt * 1000).toISOString()}`);
console.log('\nNext: node server.mjs   (the door)');
console.log('Then: node member.mjs   (the member\'s phone)');
