// SPDX-License-Identifier: Apache-2.0
// server.mjs: the DOOR. A members-only noticeboard gated by
// @prefig/upact-ember. Plain node:http, no framework, no build step.
//
// The adapter is encounter-bound: one adapter instance is one verified
// encounter at the door. So the server mints a fresh adapter per challenge
// (GET /challenge), authenticates the answering proof on that same instance
// (POST /present), and keeps the instance alive behind an opaque cookie so
// GET /board can ask it currentUpactor. The cookie value is a random token;
// no credential bytes, upactor ids, or ember types ever reach the client
// except through the rendered board.
//
// Run seed.mjs first: this server reads doorcheck-state.json for the scope
// genesis, which is the adapter's trust anchor.

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { b64uDecode, b64uEncode } from '@prefig/ember';
import { createEmberAdapter } from '../../dist/index.js';

const STATE_PATH = fileURLToPath(new URL('./doorcheck-state.json', import.meta.url));
const PORT = Number(process.env.PORT ?? 8787);
const AUDIENCE = 'doorcheck-demo';

let state;
try {
	state = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
} catch {
	console.error('doorcheck: cannot read doorcheck-state.json. Run `node seed.mjs` first.');
	process.exit(1);
}
const genesisBytes = b64uDecode(state.genesis);

// encounterId -> adapter (challenge minted, proof not yet presented)
const encounters = new Map();
// cookie token -> { adapter, session } (proof accepted, session live)
const sessions = new Map();

function pruneEncounters() {
	const cutoff = Date.now();
	for (const [id, e] of encounters) {
		if (e.expiresAt.getTime() < cutoff) encounters.delete(id);
	}
}

// Drop sessions whose membership is no longer valid so the Map does not grow
// without bound. This demo keeps it simple: a real deployment would attach a
// last-seen timestamp and an idle sweep. currentUpactor re-evaluates expiry on
// every call, so a lapsed session here is one whose credential has aged out.
async function pruneSessions() {
	for (const [token, { adapter }] of sessions) {
		if ((await adapter.currentUpactor(new Request('http://localhost/'))) === null) {
			sessions.delete(token);
		}
	}
}

const NOTICES = [
	'Thu 19:00, workshop night: bring the kit you never finished.',
	'The espresso machine is fixed. It was the fuse. It is always the fuse.',
	'Renewal evenings are first Monday of the month, stewards on site.',
];

function json(res, status, body, headers = {}) {
	res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
	res.end(JSON.stringify(body, null, 2) + '\n');
}

function html(res, status, body, headers = {}) {
	res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers });
	res.end(body);
}

function wantsJson(req) {
	return (req.headers.accept ?? '').includes('application/json');
}

function cookieToken(req) {
	const header = req.headers.cookie ?? '';
	for (const part of header.split(';')) {
		const [k, ...rest] = part.trim().split('=');
		if (k === 'doorcheck') return rest.join('=');
	}
	return null;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		const chunks = [];
		let size = 0;
		req.on('data', (c) => {
			size += c.length;
			if (size > 65536) {
				reject(new Error('body too large'));
				req.destroy();
				return;
			}
			chunks.push(c);
		});
		req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
		req.on('error', reject);
	});
}

const PAGE = /* html */ `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>doorcheck</title>
<style>
	body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; color: #1a1a1a; background: #fbfaf8; }
	h1 { font-size: 1.4rem; }
	button { font: inherit; padding: .5rem 1rem; border: 1px solid #1a1a1a; background: #ffd166; border-radius: .4rem; cursor: pointer; }
	pre { background: #efece6; padding: .8rem; border-radius: .4rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
	.muted { color: #666; font-size: .9rem; }
	a { color: #0a58a3; }
</style>
<h1>doorcheck: members-only noticeboard</h1>
<p>This page is the <strong>door</strong>. Press the button and the door
mints a single-use challenge. In the real ember flow the door would show it
as a QR code; here you answer it from a terminal with
<code>node member.mjs</code>, which plays the member's phone.</p>
<p><button id="go">Present credential</button></p>
<div id="out"></div>
<p><a href="/board">Go to the noticeboard</a> <span class="muted">(401 until a member has presented)</span></p>
<script>
document.getElementById('go').addEventListener('click', async () => {
	const r = await fetch('/challenge');
	const c = await r.json();
	document.getElementById('out').innerHTML =
		'<p>Challenge minted (single use, expires ' + c.expiresAt + '). ' +
		'This stands in for the QR code on the door:</p>' +
		'<pre>' + c.challenge + '</pre>' +
		'<p class="muted">Answer it: <code>node member.mjs</code> fetches its own challenge and presents a proof.</p>';
});
</script>
`;

function boardPage(upactor) {
	const hint = upactor.display_hint ?? 'anonymous member';
	const expires = upactor.lifecycle?.expires_at
		? upactor.lifecycle.expires_at.toISOString()
		: 'never';
	const items = NOTICES.map((n) => `<li>${n}</li>`).join('\n\t');
	return `<!doctype html>
<meta charset="utf-8">
<title>doorcheck board</title>
<style>
	body { font: 16px/1.5 system-ui, sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; color: #1a1a1a; background: #fbfaf8; }
	.card { background: #efece6; padding: 1rem; border-radius: .4rem; }
	.muted { color: #666; font-size: .9rem; }
	code { word-break: break-all; }
</style>
<h1>Noticeboard</h1>
<div class="card">
	<p>Welcome, <strong>${hint}</strong>.</p>
	<p class="muted">upactor id: <code>${upactor.id}</code><br>
	membership expires: ${expires}<br>
	Renewal happens in presence: find a steward before it lapses.</p>
</div>
<ul>
	${items}
</ul>
`;
}

const server = createServer(async (req, res) => {
	const url = new URL(req.url, `http://localhost:${PORT}`);

	try {
		if (req.method === 'GET' && url.pathname === '/') {
			return html(res, 200, PAGE);
		}

		if (req.method === 'GET' && url.pathname === '/challenge') {
			pruneEncounters();
			await pruneSessions();
			// One adapter per encounter: the challenge, the answering proof and
			// the resulting session all live on this instance.
			const adapter = createEmberAdapter({ genesis: genesisBytes, audience: AUDIENCE });
			const handle = adapter.beginChallenge();
			const encounter = randomUUID();
			encounters.set(encounter, { adapter, expiresAt: handle.expiresAt });
			return json(res, 200, {
				encounter,
				challenge: b64uEncode(handle.challenge),
				expiresAt: handle.expiresAt.toISOString(),
			});
		}

		if (req.method === 'POST' && url.pathname === '/present') {
			let body;
			try {
				body = JSON.parse(await readBody(req));
			} catch {
				return json(res, 400, { ok: false, code: 'bad_request', message: 'body must be JSON' });
			}
			const entry = encounters.get(body.encounter);
			if (entry === undefined) {
				return json(res, 404, { ok: false, code: 'unknown_encounter', message: 'no such pending challenge; fetch /challenge first' });
			}
			encounters.delete(body.encounter); // single use either way
			let credential;
			try {
				credential = body.kind === 'ember-presentation'
					? { kind: 'ember-presentation', presentation: b64uDecode(String(body.presentation)) }
					: { kind: 'ember-proof', proof: b64uDecode(String(body.proof)) };
			} catch {
				return json(res, 400, { ok: false, code: 'bad_request', message: 'proof/presentation must be base64url' });
			}
			const result = await entry.adapter.authenticate(credential);
			if ('code' in result) {
				// AuthError: show the port-level code and message verbatim; that is
				// the whole point of the demo.
				return json(res, 401, { ok: false, code: result.code, message: result.message });
			}
			const token = randomUUID();
			sessions.set(token, { adapter: entry.adapter, session: result });
			// HttpOnly + SameSite only; no Secure flag because this demo serves
			// plain HTTP on 127.0.0.1. Any real deployment is over TLS and MUST
			// add Secure.
			return json(res, 200, { ok: true, board: '/board' }, {
				'set-cookie': `doorcheck=${token}; HttpOnly; Path=/; SameSite=Lax`,
			});
		}

		if (req.method === 'GET' && url.pathname === '/board') {
			const token = cookieToken(req);
			const entry = token === null ? undefined : sessions.get(token);
			const deny = (message) => wantsJson(req)
				? json(res, 401, { ok: false, message })
				: html(res, 401, `<!doctype html><meta charset="utf-8"><title>doorcheck</title><p>${message}</p><p><a href="/">Back to the door</a></p>`);
			if (entry === undefined) {
				return deny('Members only. Present your credential at the door first.');
			}
			// The port signature takes a Request; the adapter ignores it
			// (encounter-bound), but we honour the signature.
			const upactor = await entry.adapter.currentUpactor(new Request(url));
			if (upactor === null) {
				return deny('Your membership is not currently valid. Renewal happens in presence: find a steward.');
			}
			if (wantsJson(req)) {
				return json(res, 200, {
					ok: true,
					upactor: {
						id: upactor.id,
						display_hint: upactor.display_hint ?? null,
						expires_at: upactor.lifecycle?.expires_at?.toISOString() ?? null,
						renewable: upactor.lifecycle?.renewable ?? null,
					},
					notices: NOTICES,
				});
			}
			return html(res, 200, boardPage(upactor));
		}

		return wantsJson(req)
			? json(res, 404, { ok: false, message: 'not found' })
			: html(res, 404, '<!doctype html><p>not found</p>');
	} catch (err) {
		console.error('doorcheck server error:', err);
		return json(res, 500, { ok: false, message: 'internal error' });
	}
});

server.listen(PORT, '127.0.0.1', () => {
	console.log(`doorcheck door is up: http://127.0.0.1:${PORT}/`);
	console.log(`scope '${state.scopeName}', audience '${AUDIENCE}'`);
	console.log('Present a credential: node member.mjs   (or node member.mjs --lapsed)');
});
