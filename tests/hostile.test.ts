// SPDX-License-Identifier: Apache-2.0
/**
 * Adversarial conformance suite (SPEC.md §6, §7; design §9).
 *
 * Each vector drives the adapter with evidence that is well-formed and
 * internally valid at the substrate level, yet MUST be refused because it is
 * not anchored to the configured trust anchor, is stale/replayed, is
 * addressed elsewhere, or would escalate a session. The adapter must return an
 * AuthError (never a Session) on the authenticate path, and `null` (never a
 * mutated identity) on the issueRenewal path.
 */

import { describe, it, expect } from 'vitest';
import {
	VER,
	TYPE,
	createProof,
	founderCred,
	generateIdentity,
	hex,
	parseChal,
	sign,
	type Identity,
} from '@prefig/ember';
import { createEmberAdapter } from '../src/index.js';
import {
	answerChallenge,
	buildCeremony,
	createClock,
	presentPortfolio,
	renewMember,
} from './helpers/ceremony.js';
import type { AuthError, Session } from '@prefig/upact';

const AUDIENCE = 'door:test-verifier';

function u32be(n: number): Uint8Array {
	return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}
function u64be(n: number): Uint8Array {
	const hi = Math.floor(n / 0x100000000);
	return new Uint8Array([...u32be(hi), ...u32be(n >>> 0)]);
}
function concatBytes(...arrs: Uint8Array[]): Uint8Array {
	const len = arrs.reduce((n, a) => n + a.length, 0);
	const out = new Uint8Array(len);
	let off = 0;
	for (const a of arrs) {
		out.set(a, off);
		off += a.length;
	}
	return out;
}

/**
 * Hand-forge a genesis record REUSING a victim scope's 16 public scopeId
 * bytes but signed under the attacker's own founder key. Replicates ember's
 * `createGenesis` byte layout exactly (Writer is not on ember's public
 * exports map). The result is a self-consistent genesis — its signature
 * verifies against the embedded attacker founder key — that ember's own
 * `scopeId` option will happily accept, defeated only by the adapter's
 * byte-for-byte genesis pin.
 */
async function forgeGenesis(opts: {
	scopeId: Uint8Array;
	founder: Identity;
	ttl: number;
	maxDepth: number;
	name: string;
	at: number;
}): Promise<Uint8Array> {
	const nameBytes = new TextEncoder().encode(opts.name).slice(0, 24);
	const body = concatBytes(
		Uint8Array.of(VER, TYPE.GENESIS),
		opts.scopeId,
		opts.founder.pub,
		u64be(opts.at),
		u32be(opts.ttl),
		Uint8Array.of(opts.maxDepth),
		Uint8Array.of(nameBytes.length),
		nameBytes,
	);
	const sig = await sign(body, opts.founder.priv);
	return concatBytes(body, sig);
}

function isAuthError(v: Session | AuthError): v is AuthError {
	return 'code' in (v as object);
}

describe('hostile vectors: the adapter refuses valid-in-itself-but-wrong evidence', () => {
	it('vector 1: forged genesis reusing the scopeId under an attacker founder key is rejected', async () => {
		const clock = createClock();
		const victim = await buildCeremony({ scopeName: 'garden-coop', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: victim.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});

		// Attacker founds a fresh scope that REUSES the victim's public scopeId,
		// under their own founder key, and self-presents the founder credential.
		const attacker = await generateIdentity();
		const forgedGenesis = await forgeGenesis({
			scopeId: victim.scopeId,
			founder: attacker,
			ttl: 3600,
			maxDepth: 3,
			name: 'garden-coop',
			at: t0,
		});
		const forgedCred = founderCred(forgedGenesis);

		const handle = adapter.beginChallenge();
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: forgedCred,
			identity: attacker,
			at: t0,
		});
		const result = await adapter.authenticate({ kind: 'ember-proof', proof });

		expect(isAuthError(result)).toBe(true);
		const err = result as AuthError;
		expect(err.code).toBe('credential_rejected');
		expect(err.message).toContain('not anchored to the configured genesis');
		// And it never leaks the attacker's key material in the message.
		expect(err.message).not.toContain(hex(attacker.pub));
	});

	it('vector 2: replaying a consumed proof (nonce reuse) is rejected', async () => {
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: t0,
		});

		const first = await adapter.authenticate({ kind: 'ember-proof', proof });
		expect(isAuthError(first)).toBe(false); // genuine presence succeeds once

		// Same proof, same nonce, replayed: the nonce was consumed on first use.
		const replay = await adapter.authenticate({ kind: 'ember-proof', proof });
		expect(isAuthError(replay)).toBe(true);
		expect((replay as AuthError).code).toBe('credential_rejected');
		expect((replay as AuthError).message).toContain('no pending challenge');
	});

	it('vector 3: a proof answering another adapter instance\'s challenge is rejected', async () => {
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', clock });
		const t0 = clock.now();
		const cfg = {
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		};
		const adapterA = createEmberAdapter(cfg);
		const adapterB = createEmberAdapter(cfg);

		// Challenge minted by A; proof answers A's nonce.
		const handleA = adapterA.beginChallenge();
		const proof = await answerChallenge({
			challenge: handleA.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: t0,
		});

		// Presented to B, whose registry never minted that nonce.
		const result = await adapterB.authenticate({ kind: 'ember-proof', proof });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_rejected');
		expect((result as AuthError).message).toContain('no pending challenge');
	});

	it('vector 4: a proof addressed to a different audience is rejected', async () => {
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		// Answer the real (registered) nonce, but bind the proof to a DIFFERENT
		// verifier — a relay of a proof made for someone else's door.
		const chal = parseChal(handle.challenge);
		const proof = await createProof({
			credBytes: c.memberCredBytes,
			nonce: chal.nonce,
			identity: c.member,
			aud: 'door:some-other-verifier',
			iat: t0,
		});
		const result = await adapter.authenticate({ kind: 'ember-proof', proof });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_rejected');
		expect((result as AuthError).message).toContain(
			'proof addressed to a different audience',
		);
	});

	it('vector 5: a relayed/stale proof outside the freshness window is rejected', async () => {
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: t0,
		});
		// Advance past the proof freshness window (maxProofAgeS = 120) but still
		// within the nonce TTL (120 + skew 30 = 150), so the nonce is consumed
		// and the refusal is the freshness check, not the pending-nonce check.
		clock.advance(140);
		const result = await adapter.authenticate({ kind: 'ember-proof', proof });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_rejected');
		expect((result as AuthError).message).toContain('stale proof (expired window)');
	});

	it('vector 6: a renewal downgrade (earlier expiry) is refused and leaves standing intact', async () => {
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', ttl: 3600, clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});

		// Establish a session at full ttl (expires t0 + 3600).
		const h1 = adapter.beginChallenge();
		const proof1 = await answerChallenge({
			challenge: h1.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: t0,
		});
		const session = await adapter.authenticate({ kind: 'ember-proof', proof: proof1 });
		expect(isAuthError(session)).toBe(false);
		const before = await adapter.currentUpactor(new Request('https://door/'));
		expect(before).not.toBeNull();

		// A fresh, valid, correctly-keyed credential for the SAME member, but
		// with a shorter lifetime — a downgrade.
		const downgraded = await renewMember({
			granterCredBytes: c.stewardCredBytes,
			granter: c.steward,
			subject: c.member,
			name: 'Ada',
			scopeId: c.scopeId,
			at: t0,
			asSteward: false,
			ttlOverride: 100, // expires t0 + 100, earlier than the held t0 + 3600
		});
		const h2 = adapter.beginChallenge();
		const proof2 = await answerChallenge({
			challenge: h2.challenge,
			credBytes: downgraded,
			identity: c.member,
			at: t0,
		});
		const renewed = await adapter.issueRenewal(before!, {
			kind: 'ember-proof',
			proof: proof2,
		});
		expect(renewed).toBeNull();

		// Standing is unchanged: still the original full-ttl expiry.
		const after = await adapter.currentUpactor(new Request('https://door/'));
		expect(after).not.toBeNull();
		expect(after!.id).toBe(before!.id);
		expect(after!.lifecycle).toEqual({
			expires_at: new Date((t0 + 3600) * 1000),
			renewable: 'represence',
		});
	});

	it('vector 7: a founder-root proof cannot renew a member session (escalation refused)', async () => {
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});

		// Member session established.
		const h1 = adapter.beginChallenge();
		const proof1 = await answerChallenge({
			challenge: h1.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: t0,
		});
		const session = await adapter.authenticate({ kind: 'ember-proof', proof: proof1 });
		expect(isAuthError(session)).toBe(false);
		const memberIdentity = await adapter.currentUpactor(new Request('https://door/'));
		expect(memberIdentity).not.toBeNull();

		// The founder answers a fresh challenge with the (valid, well-anchored)
		// founder credential, then that proof is offered as renewal evidence for
		// the member's identity. Identity-bound renewal must refuse: the founder
		// key is a different subject.
		const h2 = adapter.beginChallenge();
		const founderProof = await answerChallenge({
			challenge: h2.challenge,
			credBytes: c.founderCredBytes,
			identity: c.founder,
			at: t0,
		});
		const renewed = await adapter.issueRenewal(memberIdentity!, {
			kind: 'ember-proof',
			proof: founderProof,
		});
		expect(renewed).toBeNull();

		// The member session is intact and still the member (not the founder).
		const after = await adapter.currentUpactor(new Request('https://door/'));
		expect(after).not.toBeNull();
		expect(after!.id).toBe(memberIdentity!.id);
	});

	it('vector 8: a forged genesis reusing the scopeId, carried inside a PRESENTATION, is rejected', async () => {
		// The proof-path forgery (vector 1) is also reachable through the
		// portfolio-presentation path: selection there is byte-for-byte genesis
		// equality, not the weak 16-byte scopeId, so the forged scope never
		// matches the configured one and the presentation carries no credential
		// for it.
		const clock = createClock();
		const victim = await buildCeremony({ scopeName: 'garden-coop', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: victim.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});

		const attacker = await generateIdentity();
		const forgedGenesis = await forgeGenesis({
			scopeId: victim.scopeId,
			founder: attacker,
			ttl: 3600,
			maxDepth: 3,
			name: 'garden-coop',
			at: t0,
		});
		const forgedCred = founderCred(forgedGenesis);

		const handle = adapter.beginChallenge();
		const presentation = await presentPortfolio({
			challenge: handle.challenge,
			creds: [forgedCred],
			identity: attacker,
			at: t0,
		});
		const result = await adapter.authenticate({ kind: 'ember-presentation', presentation });

		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_rejected');
		expect((result as AuthError).message).toContain(
			'no credential for the configured scope',
		);
		expect((result as AuthError).message).not.toContain(hex(attacker.pub));
	});

	it('vector 9: two authenticate calls racing the same nonce admit exactly one', async () => {
		// Single-use must hold under concurrency, not just sequential replay:
		// the nonce is consumed synchronously before the first await, so of two
		// concurrent authenticate calls answering one challenge, exactly one can
		// succeed.
		const clock = createClock();
		const c = await buildCeremony({ memberName: 'Ada', clock });
		const t0 = clock.now();
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: t0,
		});

		const [a, b] = await Promise.all([
			adapter.authenticate({ kind: 'ember-proof', proof }),
			adapter.authenticate({ kind: 'ember-proof', proof }),
		]);
		const successes = [a, b].filter((r) => !isAuthError(r)).length;
		const rejections = [a, b].filter(
			(r) => isAuthError(r) && (r as AuthError).message.includes('no pending challenge'),
		).length;
		expect(successes).toBe(1);
		expect(rejections).toBe(1);
	});
});
