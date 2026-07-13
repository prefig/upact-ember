// SPDX-License-Identifier: Apache-2.0
/**
 * Port-contract suite (upact SPEC.md §6, §7). Where hostile.test.ts proves
 * the adapter refuses wrong-but-valid-looking evidence, this suite pins the
 * ordinary contract: the four operations' return shapes and null semantics,
 * the Upactor the port hands back (§7.1 minima, capabilities, provenance,
 * lifecycle), and that only codes from the closed §6.5 vocabulary are ever
 * emitted.
 */

import { describe, it, expect } from 'vitest';
import { hex } from '@prefig/ember';
import type { AuthError, Session, Upactor } from '@prefig/upact';
import { createEmberAdapter } from '../src/index.js';
import { answerChallenge, buildCeremony, createClock } from './helpers/ceremony.js';

const AUDIENCE = 'door:test-verifier';
const REQ = new Request('https://door/');

function isAuthError(v: Session | AuthError): v is AuthError {
	return 'code' in (v as object);
}

/** Establish a live session and return the adapter plus the ceremony. */
async function admittedAdapter(options?: { memberName?: string }) {
	const clock = createClock();
	const c = await buildCeremony({
		...(options?.memberName !== undefined ? { memberName: options.memberName } : {}),
		clock,
	});
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
		at: clock.now(),
	});
	const session = await adapter.authenticate({ kind: 'ember-proof', proof });
	expect(isAuthError(session)).toBe(false);
	return { adapter, ceremony: c, session: session as Session, clock };
}

describe('construction validation', () => {
	it('throws when the configured genesis does not parse', () => {
		expect(() =>
			createEmberAdapter({ genesis: new Uint8Array([1, 2, 3]), audience: AUDIENCE }),
		).toThrow();
	});

	it('throws when the audience exceeds the substrate limit', async () => {
		const c = await buildCeremony();
		expect(() =>
			createEmberAdapter({ genesis: c.genesisBytes, audience: 'x'.repeat(200) }),
		).toThrow(/audience exceeds/);
	});
});

describe('authenticate: Session on success, AuthError on failure (SPEC.md §6.1)', () => {
	it('returns an opaque Session on a genuine proof', async () => {
		const { session } = await admittedAdapter();
		// Opaque: no own enumerable substrate keys, and it is not an AuthError.
		expect('code' in (session as object)).toBe(false);
		expect(Object.keys(session as object)).not.toContain('credBytes');
	});

	it('maps a shape-guard failure to credential_invalid', async () => {
		const c = await buildCeremony();
		const adapter = createEmberAdapter({ genesis: c.genesisBytes, audience: AUDIENCE });
		const notEvidence = await adapter.authenticate({ kind: 'nonsense' });
		expect(isAuthError(notEvidence)).toBe(true);
		expect((notEvidence as AuthError).code).toBe('credential_invalid');

		const wrongType = await adapter.authenticate({ kind: 'ember-proof', proof: 'not-bytes' });
		expect((wrongType as AuthError).code).toBe('credential_invalid');
	});

	it('maps structurally unparseable proof bytes to credential_invalid', async () => {
		const c = await buildCeremony();
		const adapter = createEmberAdapter({ genesis: c.genesisBytes, audience: AUDIENCE });
		const garbage = await adapter.authenticate({
			kind: 'ember-proof',
			proof: new Uint8Array([9, 9, 9, 9, 9]),
		});
		expect(isAuthError(garbage)).toBe(true);
		expect((garbage as AuthError).code).toBe('credential_invalid');
	});

	it('maps a proof answering no registered challenge to credential_rejected', async () => {
		const clock = createClock();
		const c = await buildCeremony({ clock });
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		// A proof built against a challenge this adapter never minted.
		const other = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = other.beginChallenge();
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: c.memberCredBytes,
			identity: c.member,
			at: clock.now(),
		});
		const result = await adapter.authenticate({ kind: 'ember-proof', proof });
		expect(isAuthError(result)).toBe(true);
		expect((result as AuthError).code).toBe('credential_rejected');
	});

	it('never emits a code outside the closed vocabulary across a battery of bad inputs', async () => {
		const clock = createClock();
		const c = await buildCeremony({ clock });
		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const badInputs: unknown[] = [
			undefined,
			null,
			42,
			'string',
			{},
			{ kind: 'ember-proof' },
			{ kind: 'ember-proof', proof: new Uint8Array(0) },
			{ kind: 'ember-presentation', presentation: new Uint8Array([1, 2, 3]) },
		];
		const allowed = new Set(['credential_invalid', 'credential_rejected', 'auth_failed']);
		const forbidden = new Set(['substrate_unavailable', 'identity_unavailable', 'rate_limited']);
		for (const input of badInputs) {
			const result = await adapter.authenticate(input);
			expect(isAuthError(result)).toBe(true);
			const { code } = result as AuthError;
			expect(allowed.has(code)).toBe(true);
			expect(forbidden.has(code)).toBe(false);
		}
	});
});

describe('currentUpactor: Upactor | null, request ignored (SPEC.md §6.2, §7.1)', () => {
	it('returns null before any authenticate', async () => {
		const c = await buildCeremony();
		const adapter = createEmberAdapter({ genesis: c.genesisBytes, audience: AUDIENCE });
		expect(await adapter.currentUpactor(REQ)).toBeNull();
	});

	it('returns a Upactor carrying only the five spec fields and no substrate leakage', async () => {
		const { adapter, ceremony } = await admittedAdapter({ memberName: 'Ada' });
		const upactor = await adapter.currentUpactor(REQ);
		expect(upactor).not.toBeNull();
		const u = upactor as Upactor;

		// §7.2 no silent enrichment: only spec-defined keys.
		const allowedKeys = new Set(['id', 'display_hint', 'capabilities', 'lifecycle', 'provenance']);
		for (const key of Object.keys(u)) expect(allowedKeys.has(key)).toBe(true);

		// §7.1 forbidden identifiers absent, and no raw key material anywhere.
		const serialised = JSON.stringify(u, (_k, v) =>
			v instanceof Set ? [...v] : v,
		);
		for (const forbidden of ['email', 'phone', 'first_name', 'last_name', 'ip', 'device']) {
			expect(serialised.toLowerCase()).not.toContain(forbidden);
		}
		expect(serialised).not.toContain(hex(ceremony.member.pub));
		expect(serialised).not.toContain(hex(ceremony.steward.pub));
		expect(serialised).not.toContain(hex(ceremony.founder.pub));

		// id: opaque 32 hex chars, not derivable from the pubkey by inspection.
		expect(u.id).toMatch(/^[0-9a-f]{32}$/);

		// capabilities: empty and frozen (§5: declare nothing).
		expect(u.capabilities.size).toBe(0);
		expect(Object.isFrozen(u.capabilities)).toBe(true);

		// display_hint: the sanitised self-chosen name.
		expect(u.display_hint).toBe('Ada');

		// provenance (§4.5): substrate name and the scope id, nothing more.
		expect(u.provenance).toEqual({ substrate: 'ember', instance: hex(ceremony.scopeId) });

		// lifecycle (§4.4, §8): represence with an absolute expiry.
		expect(u.lifecycle?.renewable).toBe('represence');
		expect(u.lifecycle?.expires_at).toBeInstanceOf(Date);
	});

	it('derives a different id for the same member key in a different scope (per-scope separation)', async () => {
		const clock = createClock();
		const cA = await buildCeremony({ memberName: 'Ada', clock });
		// A second scope granting the SAME member key a credential.
		const cB = await buildCeremony({ memberName: 'Ada', clock });
		const idIn = async (genesis: Uint8Array, credBytes: Uint8Array, member = cA.member) => {
			const adapter = createEmberAdapter({ genesis, audience: AUDIENCE, now: () => clock.now() });
			const h = adapter.beginChallenge();
			const proof = await answerChallenge({ challenge: h.challenge, credBytes, identity: member, at: clock.now() });
			await adapter.authenticate({ kind: 'ember-proof', proof });
			return (await adapter.currentUpactor(REQ))!.id;
		};
		const idA = await idIn(cA.genesisBytes, cA.memberCredBytes, cA.member);
		const idB = await idIn(cB.genesisBytes, cB.memberCredBytes, cB.member);
		expect(idA).not.toBe(idB);
	});

	it('re-evaluates on every call and drops to null once the credential lapses', async () => {
		const { adapter, clock } = await admittedAdapter();
		expect(await adapter.currentUpactor(REQ)).not.toBeNull();
		clock.advance(3600 + 60); // past the one-hour member ttl
		expect(await adapter.currentUpactor(REQ)).toBeNull();
	});
});

describe('invalidate: subsequent currentUpactor is null (SPEC.md §6.3)', () => {
	it('terminates the session and is a no-op for a foreign session', async () => {
		const { adapter, session } = await admittedAdapter();
		await adapter.invalidate(session);
		expect(await adapter.currentUpactor(REQ)).toBeNull();
		// Idempotent, and a foreign/cloned session value is a harmless no-op.
		await adapter.invalidate(session);
		await adapter.invalidate({} as unknown as Session);
		expect(await adapter.currentUpactor(REQ)).toBeNull();
	});
});
