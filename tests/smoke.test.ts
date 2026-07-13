// SPDX-License-Identifier: Apache-2.0
/**
 * Smoke test: the full happy path across the port. Real ember ceremony ->
 * createEmberAdapter -> beginChallenge -> authenticate(proof) ->
 * currentUpactor -> invalidate -> null.
 */

import { describe, expect, it } from 'vitest';
import { hex } from '@prefig/ember';
import { createEmberAdapter } from '../src/index.js';
import { answerChallenge, buildCeremony } from './helpers/ceremony.js';

describe('smoke: encounter happy path', () => {
	it('authenticates a member proof and serves the Upactor until invalidated', async () => {
		const ceremony = await buildCeremony({
			scopeName: 'garden-coop',
			memberName: 'Ada',
			ttl: 3600,
			maxDepth: 3,
		});
		const { clock } = ceremony;
		const t0 = clock.now();

		const adapter = createEmberAdapter({
			genesis: ceremony.genesisBytes,
			audience: 'door:test-verifier',
			now: () => clock.now(),
		});

		// The port carries exactly the five methods; no substrate leaks.
		expect(Object.keys(adapter).sort()).toEqual([
			'authenticate',
			'beginChallenge',
			'currentUpactor',
			'invalidate',
			'issueRenewal',
		]);
		expect((adapter as { client?: unknown }).client).toBeUndefined();

		// Verifier mints a challenge; the app relays the wire bytes.
		const handle = adapter.beginChallenge();
		expect(handle.challenge).toBeInstanceOf(Uint8Array);
		expect(handle.expiresAt).toEqual(new Date((t0 + 120) * 1000));

		// Holder answers with a presence proof over the member credential.
		const proof = await answerChallenge({
			challenge: handle.challenge,
			credBytes: ceremony.memberCredBytes,
			identity: ceremony.member,
			at: t0,
		});

		const session = await adapter.authenticate({ kind: 'ember-proof', proof });
		expect(session).not.toHaveProperty('code'); // not an AuthError
		if ('code' in (session as object)) throw new Error('authenticate failed');
		// Session opacity rides on createSession (SPEC.md §7.4).
		expect(JSON.stringify(session)).toBe('"[upact:session]"');

		// currentUpactor: the port's view of "who is this".
		const upactor = await adapter.currentUpactor(
			new Request('https://door.example/'),
		);
		expect(upactor).not.toBeNull();
		if (upactor === null) throw new Error('unreachable');

		// Exactly the five spec fields, nothing substrate-shaped (SPEC.md §7.1).
		expect(Object.keys(upactor).sort()).toEqual([
			'capabilities',
			'display_hint',
			'id',
			'lifecycle',
			'provenance',
		]);
		expect(upactor.id).toMatch(/^[0-9a-f]{32}$/);
		expect(upactor.id).not.toContain(hex(ceremony.member.pub).slice(0, 16));
		expect(upactor.display_hint).toBe('Ada');
		expect(upactor.capabilities.size).toBe(0);
		expect(upactor.lifecycle).toEqual({
			expires_at: new Date((t0 + 3600) * 1000),
			renewable: 'represence',
		});
		expect(upactor.provenance).toEqual({
			substrate: 'ember',
			instance: hex(ceremony.scopeId),
		});

		// Stable across calls within the encounter.
		const again = await adapter.currentUpactor(
			new Request('https://door.example/other'),
		);
		expect(again?.id).toBe(upactor.id);

		// invalidate ends the encounter: every subsequent call sees null.
		await adapter.invalidate(session as never);
		expect(
			await adapter.currentUpactor(new Request('https://door.example/')),
		).toBeNull();
	});
});
