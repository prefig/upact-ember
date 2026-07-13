// SPDX-License-Identifier: Apache-2.0
/**
 * Adapter back-channel reflection test (Decision 11 / SPEC §7.5).
 *
 * After driving the adapter through a complete happy-path authenticate,
 * ember substrate values (the member public key / network-legible handle,
 * the retained social-graph-bearing credential bytes, the id-derivation
 * pepper, and the derived opaque id) MUST NOT be reachable through any common
 * reflection vector applied to the adapter instance OR the Session it
 * returned. The adapter is a five-method object literal with no fields, and
 * the Session rides on `createSession`'s WeakMap opacity — this suite pins
 * both by construction.
 *
 * Mirror of upact-mastodon/tests/back-channel.test.ts, case-for-case (16
 * vectors), retargeted to ember's substrate surface.
 */

import { describe, it, expect } from 'vitest';
import util from 'node:util';
import { hex } from '@prefig/ember';
import { createEmberAdapter } from '../src/index.js';
import { answerChallenge, buildCeremony, createClock } from './helpers/ceremony.js';
import type { Session } from '@prefig/upact';

// A recognisable ASCII pepper so any leak of the id-derivation secret shows
// up verbatim (real keys/creds are random, so we assert on their hex forms).
const PEPPER_STRING = 'SENTINEL_PEPPER_upact_ember_unique_marker';
const PEPPER = new TextEncoder().encode(PEPPER_STRING);

// Substrate-shaped property names that must never surface on the adapter or
// the Session under any reflection vector.
const SUBSTRATE_KEYS = [
	'client',
	'ember',
	'_client',
	'credBytes',
	'subjectPk',
	'subjectPub',
	'pepper',
	'genesis',
	'genesisBytes',
	'nonceRegistry',
	'current',
	'session',
	'audience',
	'id',
	'revoked',
	'expiresAt',
] as const;

interface Driven {
	adapter: ReturnType<typeof createEmberAdapter>;
	session: Session;
	sentinels: string[];
}

async function driveThroughAuth(): Promise<Driven> {
	const clock = createClock();
	const ceremony = await buildCeremony({ memberName: 'Ada', clock });
	const t0 = clock.now();
	const adapter = createEmberAdapter({
		genesis: ceremony.genesisBytes,
		audience: 'door:sentinel-verifier',
		idPepper: PEPPER,
		now: () => clock.now(),
	});
	const handle = adapter.beginChallenge();
	const proof = await answerChallenge({
		challenge: handle.challenge,
		credBytes: ceremony.memberCredBytes,
		identity: ceremony.member,
		at: t0,
	});
	const result = await adapter.authenticate({ kind: 'ember-proof', proof });
	if ('code' in (result as object)) {
		throw new Error(
			`drive setup: authenticate returned error: ${(result as { message: string }).message}`,
		);
	}
	const session = result as Session;
	const upactor = await adapter.currentUpactor(new Request('https://door.example/'));
	if (upactor === null) throw new Error('drive setup: currentUpactor null');
	const sentinels = [
		hex(ceremony.member.pub), // network-legible member key (behind opacity)
		hex(ceremony.memberCredBytes), // retained social-graph-bearing bytes
		PEPPER_STRING, // id-derivation secret (raw)
		hex(PEPPER), // id-derivation secret (hex form)
		upactor.id, // the derived opaque id must not leak from the session
	];
	return { adapter, session, sentinels };
}

function assertNoSentinel(text: string, sentinels: string[]): void {
	for (const s of sentinels) expect(text).not.toContain(s);
}

describe('adapter back-channel: 16-vector reflection conformance', () => {
	it('vector 1: JSON.stringify(adapter) and JSON.stringify(session) leak no sentinel', async () => {
		const { adapter, session, sentinels } = await driveThroughAuth();
		assertNoSentinel(JSON.stringify(adapter), sentinels);
		expect(JSON.stringify(session)).toBe('"[upact:session]"');
		assertNoSentinel(JSON.stringify(session), sentinels);
	});

	it('vector 2: Object.keys returns no substrate-shaped keys', async () => {
		const { adapter, session } = await driveThroughAuth();
		const keys = [...Object.keys(adapter), ...Object.keys(session)];
		for (const name of SUBSTRATE_KEYS) expect(keys).not.toContain(name);
	});

	it('vector 3: Object.getOwnPropertyNames returns no substrate-shaped keys', async () => {
		const { adapter, session } = await driveThroughAuth();
		const names = [
			...Object.getOwnPropertyNames(adapter),
			...Object.getOwnPropertyNames(session),
		];
		for (const name of SUBSTRATE_KEYS) expect(names).not.toContain(name);
	});

	it('vector 4: Reflect.ownKeys returns no substrate-shaped keys', async () => {
		const { adapter, session } = await driveThroughAuth();
		const keys = [
			...Reflect.ownKeys(adapter as object),
			...Reflect.ownKeys(session as object),
		];
		for (const name of SUBSTRATE_KEYS) expect(keys).not.toContain(name);
	});

	it('vector 5: Object.getOwnPropertySymbols returns no symbols', async () => {
		const { adapter, session } = await driveThroughAuth();
		expect(Object.getOwnPropertySymbols(adapter)).toEqual([]);
		expect(Object.getOwnPropertySymbols(session as object)).toEqual([]);
	});

	it('vector 6: for-in iteration does not yield substrate keys', async () => {
		const { adapter, session } = await driveThroughAuth();
		const keys: string[] = [];
		for (const k in adapter) keys.push(k);
		for (const k in session as object) keys.push(k);
		for (const name of SUBSTRATE_KEYS) expect(keys).not.toContain(name);
	});

	it('vector 7: structuredClone refuses to clone (or yields a non-leaking object)', async () => {
		const { adapter, session, sentinels } = await driveThroughAuth();
		for (const target of [adapter, session] as unknown[]) {
			try {
				const cloned = structuredClone(target);
				assertNoSentinel(util.inspect(cloned, { depth: null }), sentinels);
			} catch (e) {
				// Functions are not cloneable — DataCloneError is itself a pass.
				expect(e).toBeInstanceOf(Error);
			}
		}
	});

	it('vector 8: util.inspect leaks no sentinel', async () => {
		const { adapter, session, sentinels } = await driveThroughAuth();
		assertNoSentinel(
			util.inspect(adapter, { depth: null, showHidden: true }),
			sentinels,
		);
		assertNoSentinel(
			util.inspect(session, { depth: null, showHidden: true }),
			sentinels,
		);
	});

	it('vector 9: direct cast access to .client / .ember returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { client?: unknown }).client).toBeUndefined();
		expect((adapter as { ember?: unknown }).ember).toBeUndefined();
	});

	it('vector 10: direct cast access to ._client / .credBytes returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { _client?: unknown })._client).toBeUndefined();
		expect((adapter as { credBytes?: unknown }).credBytes).toBeUndefined();
	});

	it('vector 11: direct cast access to .subjectPk / .genesis returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { subjectPk?: unknown }).subjectPk).toBeUndefined();
		expect((adapter as { genesis?: unknown }).genesis).toBeUndefined();
	});

	it('vector 12: direct cast access to .pepper / .nonceRegistry returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { pepper?: unknown }).pepper).toBeUndefined();
		expect(
			(adapter as { nonceRegistry?: unknown }).nonceRegistry,
		).toBeUndefined();
	});

	it('vector 13: direct cast access to .current / .session returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { current?: unknown }).current).toBeUndefined();
		expect((adapter as { session?: unknown }).session).toBeUndefined();
	});

	it('vector 14: Session exposes no substrate property and no unwrap escape', async () => {
		const { session, sentinels } = await driveThroughAuth();
		const names = Object.getOwnPropertyNames(session as object);
		for (const name of SUBSTRATE_KEYS) expect(names).not.toContain(name);
		// The only own property is the opacity toJSON, which yields the fixed
		// marker string — never the substrate value.
		expect((session as { toJSON?: () => unknown }).toJSON?.()).toBe(
			'[upact:session]',
		);
		for (const cast of ['credBytes', 'subjectPk', 'id']) {
			expect((session as Record<string, unknown>)[cast]).toBeUndefined();
		}
		assertNoSentinel(String((session as { toJSON?: () => unknown }).toJSON?.()), sentinels);
	});

	it('vector 15: object spread yields no substrate-shaped keys', async () => {
		const { adapter, session, sentinels } = await driveThroughAuth();
		const spreadAdapter = { ...adapter };
		const spreadSession = { ...(session as object) };
		for (const name of SUBSTRATE_KEYS) {
			expect(Object.keys(spreadAdapter)).not.toContain(name);
			expect(Object.keys(spreadSession)).not.toContain(name);
		}
		assertNoSentinel(JSON.stringify(spreadAdapter), sentinels);
		assertNoSentinel(JSON.stringify(spreadSession), sentinels);
	});

	it('vector 16: JSON.stringify wrapped in outer object leaks no sentinel', async () => {
		const { adapter, session, sentinels } = await driveThroughAuth();
		const wrapped = { kind: 'adapter-holder', a: adapter, s: session };
		const json = JSON.stringify(wrapped);
		expect(json).toContain('adapter-holder');
		assertNoSentinel(json, sentinels);
	});
});
