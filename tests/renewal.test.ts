// SPDX-License-Identifier: Apache-2.0
/**
 * Flagship represence lifecycle suite (upact SPEC.md §4.4, §6.4, §8).
 *
 * Covers: `expires_at` derived from the chain's leaf expiry; the shipped
 * `renewable: 'represence'` lifecycle; `issueRenewal` with fresh presence
 * evidence extending expiry while preserving the SAME id (D3 Option A,
 * identity-bound); the `>=` anti-downgrade rule (equal expiry accepted,
 * shorter refused); Decision 9 null-collapse for every failure; and the
 * lapsed-session represence flow (`currentUpactor` null, `issueRenewal`
 * still possible, standing restored without re-authentication).
 */

import { describe, expect, it } from 'vitest';
import type { AuthError, IdentityPort, Session, Upactor } from '@prefig/upact';
import { createEmberAdapter } from '../src/index.js';
import type { EmberAdapterExtensions, EmberCredential } from '../src/index.js';
import {
	answerChallenge,
	buildCeremony,
	createClock,
	mintForeignChallenge,
	renewMember,
	type Ceremony,
	type CeremonyClock,
} from './helpers/ceremony.js';

const AUDIENCE = 'door:renewal-suite';
const T0 = 1_700_000_000;

type Adapter = IdentityPort & EmberAdapterExtensions;

function isAuthError(value: Session | AuthError): value is AuthError {
	return typeof value === 'object' && value !== null && 'code' in value;
}

function asSession(value: Session | AuthError): Session {
	if (isAuthError(value)) {
		throw new Error(`expected Session, got ${value.code}: ${value.message}`);
	}
	return value;
}

async function mustUpactor(adapter: Adapter): Promise<Upactor> {
	const upactor = await adapter.currentUpactor(
		new Request('https://door.example/'),
	);
	if (upactor === null) throw new Error('expected an Upactor, got null');
	return upactor;
}

/** Answer a fresh adapter challenge with a proof over `credBytes`. */
async function proofEvidence(
	adapter: Adapter,
	ceremony: Ceremony,
	credBytes: Uint8Array,
	at: number,
): Promise<EmberCredential> {
	const handle = adapter.beginChallenge();
	const proof = await answerChallenge({
		challenge: handle.challenge,
		credBytes,
		identity: ceremony.member,
		at,
	});
	return { kind: 'ember-proof', proof };
}

/** Steward re-grants the member out of band (the represence ceremony). */
async function grantFresh(
	ceremony: Ceremony,
	at: number,
	opts: { name?: string; ttl?: number } = {},
): Promise<Uint8Array> {
	return renewMember({
		granterCredBytes: ceremony.stewardCredBytes,
		granter: ceremony.steward,
		subject: ceremony.member,
		name: opts.name ?? 'Ada',
		scopeId: ceremony.scopeId,
		at,
		asSteward: false,
		...(opts.ttl !== undefined ? { ttlOverride: opts.ttl } : {}),
	});
}

interface Fixture {
	clock: CeremonyClock;
	ceremony: Ceremony;
	credBytes: Uint8Array;
	adapter: Adapter;
}

/**
 * Full ceremony + adapter. When `memberTtl` is given, the member's held
 * credential is a shorter steward grant (exp = T0 + memberTtl) so lapse can
 * happen well inside the steward's own validity window.
 */
async function setup(memberTtl?: number): Promise<Fixture> {
	const clock = createClock(T0);
	const ceremony = await buildCeremony({ memberName: 'Ada', clock });
	const credBytes =
		memberTtl === undefined
			? ceremony.memberCredBytes
			: await grantFresh(ceremony, clock.now(), { ttl: memberTtl });
	const adapter = createEmberAdapter({
		genesis: ceremony.genesisBytes,
		audience: AUDIENCE,
		now: () => clock.now(),
	});
	return { clock, ceremony, credBytes, adapter };
}

async function authenticateMember(
	fixture: Fixture,
): Promise<{ session: Session; upactor: Upactor }> {
	const evidence = await proofEvidence(
		fixture.adapter,
		fixture.ceremony,
		fixture.credBytes,
		fixture.clock.now(),
	);
	const session = asSession(await fixture.adapter.authenticate(evidence));
	const upactor = await mustUpactor(fixture.adapter);
	return { session, upactor };
}

describe('lifecycle surface: expiry from the chain', () => {
	it('derives lifecycle.expires_at from the leaf link expiry with renewable represence', async () => {
		const fixture = await setup(600);
		const { upactor } = await authenticateMember(fixture);
		expect(upactor.lifecycle).toEqual({
			expires_at: new Date((T0 + 600) * 1000),
			renewable: 'represence',
		});
	});

	it('re-evaluates expiry at every currentUpactor call, never caching past it', async () => {
		const fixture = await setup(600);
		await authenticateMember(fixture);
		fixture.clock.advance(500); // still inside the window
		const alive = await mustUpactor(fixture.adapter);
		expect(alive.lifecycle).toEqual({
			expires_at: new Date((T0 + 600) * 1000),
			renewable: 'represence',
		});
		fixture.clock.advance(200); // past exp + skew (600 + 30)
		expect(
			await fixture.adapter.currentUpactor(new Request('https://door.example/')),
		).toBeNull();
	});
});

describe('issueRenewal: fresh presence evidence extends expiry', () => {
	it('accepts a renewed credential, extends expiry, and returns the SAME id', async () => {
		const fixture = await setup(600);
		const { upactor } = await authenticateMember(fixture);
		fixture.clock.advance(300);
		const t1 = fixture.clock.now();

		const renewedCred = await grantFresh(fixture.ceremony, t1, {
			name: 'Ada Prime',
		});
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			renewedCred,
			t1,
		);
		const renewed = await fixture.adapter.issueRenewal(upactor, evidence);
		expect(renewed).not.toBeNull();
		if (renewed === null) throw new Error('unreachable');

		// Identity-bound: same id, new expiry, hint follows the new leaf name.
		expect(renewed.id).toBe(upactor.id);
		expect(renewed.lifecycle).toEqual({
			expires_at: new Date((t1 + 3600) * 1000),
			renewable: 'represence',
		});
		expect(renewed.display_hint).toBe('Ada Prime');

		// The held session was swapped in place: currentUpactor agrees.
		const after = await mustUpactor(fixture.adapter);
		expect(after.id).toBe(upactor.id);
		expect(after.lifecycle).toEqual({
			expires_at: new Date((t1 + 3600) * 1000),
			renewable: 'represence',
		});
	});

	it('renews a LAPSED session: currentUpactor is null but issueRenewal restores standing', async () => {
		const fixture = await setup(600);
		const { upactor } = await authenticateMember(fixture);

		fixture.clock.advance(700); // past exp (600) + skew (30): lapsed
		const t1 = fixture.clock.now();
		expect(
			await fixture.adapter.currentUpactor(new Request('https://door.example/')),
		).toBeNull();

		// The session is RETAINED across the lapse: renewal in presence works
		// without a full re-authenticate.
		const renewedCred = await grantFresh(fixture.ceremony, t1);
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			renewedCred,
			t1,
		);
		const renewed = await fixture.adapter.issueRenewal(upactor, evidence);
		expect(renewed).not.toBeNull();
		if (renewed === null) throw new Error('unreachable');
		expect(renewed.id).toBe(upactor.id);
		expect(renewed.lifecycle).toEqual({
			expires_at: new Date((t1 + 3600) * 1000),
			renewable: 'represence',
		});

		const restored = await mustUpactor(fixture.adapter);
		expect(restored.id).toBe(upactor.id);
	});

	it('keeps the id stable across multiple successive renewals', async () => {
		const fixture = await setup(600);
		const { upactor } = await authenticateMember(fixture);
		const ids = new Set<string>([upactor.id]);
		const expiries: number[] = [T0 + 600];

		let identity = upactor;
		for (const delta of [300, 300]) {
			fixture.clock.advance(delta);
			const at = fixture.clock.now();
			const cred = await grantFresh(fixture.ceremony, at);
			const evidence = await proofEvidence(
				fixture.adapter,
				fixture.ceremony,
				cred,
				at,
			);
			const renewed = await fixture.adapter.issueRenewal(identity, evidence);
			expect(renewed).not.toBeNull();
			if (renewed === null) throw new Error('unreachable');
			ids.add(renewed.id);
			expect(renewed.lifecycle?.renewable).toBe('represence');
			const exp = renewed.lifecycle?.expires_at;
			if (!(exp instanceof Date)) throw new Error('expected expires_at');
			expiries.push(exp.getTime() / 1000);
			identity = renewed;
		}

		expect(ids.size).toBe(1); // one member, one id, across all renewals
		expect(expiries).toEqual([T0 + 600, T0 + 300 + 3600, T0 + 600 + 3600]);
	});

	it('keeps the original Session object valid after renewal (in-place swap)', async () => {
		const fixture = await setup(600);
		const { session, upactor } = await authenticateMember(fixture);
		fixture.clock.advance(100);
		const t1 = fixture.clock.now();
		const cred = await grantFresh(fixture.ceremony, t1);
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			cred,
			t1,
		);
		expect(await fixture.adapter.issueRenewal(upactor, evidence)).not.toBeNull();

		// The pre-renewal Session still addresses the (renewed) encounter.
		await fixture.adapter.invalidate(session);
		expect(
			await fixture.adapter.currentUpactor(new Request('https://door.example/')),
		).toBeNull();
	});
});

describe('issueRenewal: >= anti-downgrade', () => {
	it('refuses evidence carrying a credential shorter than the held one', async () => {
		const fixture = await setup(); // held exp = T0 + 3600
		const { upactor } = await authenticateMember(fixture);

		const shorterCred = await grantFresh(fixture.ceremony, fixture.clock.now(), {
			ttl: 600, // exp = T0 + 600 < held T0 + 3600
		});
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			shorterCred,
			fixture.clock.now(),
		);
		expect(await fixture.adapter.issueRenewal(upactor, evidence)).toBeNull();

		// Held state untouched: the longer credential still governs.
		const held = await mustUpactor(fixture.adapter);
		expect(held.lifecycle).toEqual({
			expires_at: new Date((T0 + 3600) * 1000),
			renewable: 'represence',
		});
	});

	it('accepts equal-expiry re-presentation of the held credential (>= not >)', async () => {
		const fixture = await setup();
		const { upactor } = await authenticateMember(fixture);
		fixture.clock.advance(60);

		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			fixture.credBytes, // the very same held credential, freshly proven
			fixture.clock.now(),
		);
		const renewed = await fixture.adapter.issueRenewal(upactor, evidence);
		expect(renewed).not.toBeNull();
		if (renewed === null) throw new Error('unreachable');
		expect(renewed.id).toBe(upactor.id);
		expect(renewed.lifecycle).toEqual({
			expires_at: new Date((T0 + 3600) * 1000),
			renewable: 'represence',
		});
	});
});

describe('issueRenewal: Decision 9 — every failure is null, never a throw', () => {
	it('returns null when no session was ever established, even for valid evidence', async () => {
		const fixture = await setup();
		const ghost = {
			id: '0'.repeat(32),
			capabilities: new Set(),
			provenance: { substrate: 'ember', instance: '00' },
		} as unknown as Upactor;
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			fixture.credBytes,
			fixture.clock.now(),
		);
		expect(await fixture.adapter.issueRenewal(ghost, evidence)).toBeNull();
	});

	it('returns null after invalidate', async () => {
		const fixture = await setup();
		const { session, upactor } = await authenticateMember(fixture);
		await fixture.adapter.invalidate(session);
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			fixture.credBytes,
			fixture.clock.now(),
		);
		expect(await fixture.adapter.issueRenewal(upactor, evidence)).toBeNull();
	});

	it('returns null for evidence failing the shape guard', async () => {
		const fixture = await setup();
		const { upactor } = await authenticateMember(fixture);
		const vectors: unknown[] = [
			null,
			undefined,
			'renew me',
			fixture.credBytes, // bare credential bytes: no possession proof
			{ kind: 'ember-proof', proof: 'not-bytes' },
			{ kind: 'ember-credential', proof: fixture.credBytes },
			{ kind: 'ember-presentation', presentation: [1, 2, 3] },
		];
		for (const evidence of vectors) {
			expect(await fixture.adapter.issueRenewal(upactor, evidence)).toBeNull();
		}
	});

	it('returns null for replayed evidence (nonce single-use)', async () => {
		const fixture = await setup();
		const { upactor } = await authenticateMember(fixture);
		fixture.clock.advance(60);
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			fixture.credBytes,
			fixture.clock.now(),
		);
		expect(await fixture.adapter.issueRenewal(upactor, evidence)).not.toBeNull();
		expect(await fixture.adapter.issueRenewal(upactor, evidence)).toBeNull();
	});

	it('returns null for evidence answering a challenge this adapter never minted', async () => {
		const fixture = await setup();
		const { upactor } = await authenticateMember(fixture);
		const foreign = mintForeignChallenge({
			scopeId: fixture.ceremony.scopeId,
			aud: AUDIENCE,
			at: fixture.clock.now(),
		});
		const proof = await answerChallenge({
			challenge: foreign.bytes,
			credBytes: fixture.credBytes,
			identity: fixture.ceremony.member,
			at: fixture.clock.now(),
		});
		expect(
			await fixture.adapter.issueRenewal(upactor, { kind: 'ember-proof', proof }),
		).toBeNull();
	});

	it('returns null when the evidence proves a DIFFERENT member (identity-bound)', async () => {
		const fixture = await setup();
		const { upactor } = await authenticateMember(fixture);
		// The steward proves their own (valid, longer-lived) credential — a
		// perfectly good authentication, but not a renewal of THIS identity.
		const handle = fixture.adapter.beginChallenge();
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: fixture.ceremony.stewardCredBytes,
			identity: fixture.ceremony.steward,
			at: fixture.clock.now(),
		});
		expect(
			await fixture.adapter.issueRenewal(upactor, { kind: 'ember-proof', proof }),
		).toBeNull();
	});

	it('returns null when the passed identity id does not match the session', async () => {
		const fixture = await setup();
		const { upactor } = await authenticateMember(fixture);
		const spoofed = { ...upactor, id: 'f'.repeat(32) } as Upactor;
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			fixture.credBytes,
			fixture.clock.now(),
		);
		expect(await fixture.adapter.issueRenewal(spoofed, evidence)).toBeNull();
		// The held session is untouched by the refused attempt.
		expect((await mustUpactor(fixture.adapter)).id).toBe(upactor.id);
	});

	it('returns null when the incoming credential is itself lapsed', async () => {
		const fixture = await setup(); // held exp = T0 + 3600
		const { upactor } = await authenticateMember(fixture);
		const shortCred = await grantFresh(fixture.ceremony, fixture.clock.now(), {
			ttl: 600,
		});
		fixture.clock.advance(700); // shortCred lapsed; held cred still valid
		const evidence = await proofEvidence(
			fixture.adapter,
			fixture.ceremony,
			shortCred,
			fixture.clock.now(),
		);
		expect(await fixture.adapter.issueRenewal(upactor, evidence)).toBeNull();
		expect((await mustUpactor(fixture.adapter)).id).toBe(upactor.id);
	});
});
