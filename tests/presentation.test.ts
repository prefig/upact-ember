// SPDX-License-Identifier: Apache-2.0
/**
 * Portfolio-presentation path (U3; ember presentation.js). A member may
 * present a multi-scope portfolio; the adapter selects exactly the credential
 * anchored to its CONFIGURED genesis (byte-pinned, not scopeId-compared) and
 * verifies that one. A portfolio that carries no credential for the
 * configured scope is refused with a message that names no foreign scope.
 *
 * Ember's member key is stable across scopes ("one key, many scopes"), so a
 * single member identity can hold credentials in several scopes at once; that
 * is exactly the case a portfolio presentation exists to serve.
 */

import { describe, it, expect } from 'vitest';
import { hex } from '@prefig/ember';
import type { AuthError, Session, Upactor } from '@prefig/upact';
import { createEmberAdapter } from '../src/index.js';
import {
	buildCeremony,
	createClock,
	presentPortfolio,
	renewMember,
} from './helpers/ceremony.js';

const AUDIENCE = 'door:test-verifier';
const REQ = new Request('https://door/');

function isAuthError(v: Session | AuthError): v is AuthError {
	return 'code' in (v as object);
}

describe('presentation: select the configured scope out of a multi-scope portfolio', () => {
	it('authenticates the credential anchored to the configured genesis and ignores the rest', async () => {
		const clock = createClock();
		const cA = await buildCeremony({ scopeName: 'garden-coop', memberName: 'Ada', clock });
		const cB = await buildCeremony({ scopeName: 'other-club', memberName: 'unused', clock });
		const at = clock.now();

		// The SAME member key (cA.member) also holds a credential in scope B.
		const adaCredInB = await renewMember({
			granterCredBytes: cB.stewardCredBytes,
			granter: cB.steward,
			subject: cA.member,
			name: 'Ada-elsewhere',
			scopeId: cB.scopeId,
			at,
			asSteward: false,
		});

		const adapter = createEmberAdapter({
			genesis: cA.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		const presentation = await presentPortfolio({
			challenge: handle.challenge,
			creds: [cA.memberCredBytes, adaCredInB],
			identity: cA.member,
			at,
		});

		const session = await adapter.authenticate({ kind: 'ember-presentation', presentation });
		expect(isAuthError(session)).toBe(false);

		const upactor = (await adapter.currentUpactor(REQ)) as Upactor;
		expect(upactor).not.toBeNull();
		// Identity and provenance are the CONFIGURED scope (A), not B.
		expect(upactor.provenance).toEqual({ substrate: 'ember', instance: hex(cA.scopeId) });
		expect(upactor.display_hint).toBe('Ada'); // the leaf name in scope A
		expect(upactor.lifecycle?.renewable).toBe('represence');
	});

	it('refuses a portfolio that carries no credential for the configured scope, naming no foreign scope', async () => {
		const clock = createClock();
		const cA = await buildCeremony({ scopeName: 'garden-coop', memberName: 'Ada', clock });
		const cB = await buildCeremony({ scopeName: 'other-club', memberName: 'unused', clock });
		const at = clock.now();

		const adaCredInB = await renewMember({
			granterCredBytes: cB.stewardCredBytes,
			granter: cB.steward,
			subject: cA.member,
			name: 'Ada-elsewhere',
			scopeId: cB.scopeId,
			at,
			asSteward: false,
		});

		// Adapter configured for scope A; portfolio carries only the scope-B cred.
		const adapter = createEmberAdapter({
			genesis: cA.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		const presentation = await presentPortfolio({
			challenge: handle.challenge,
			creds: [adaCredInB],
			identity: cA.member,
			at,
		});

		const result = await adapter.authenticate({ kind: 'ember-presentation', presentation });
		expect(isAuthError(result)).toBe(true);
		const err = result as AuthError;
		expect(err.code).toBe('credential_rejected');
		expect(err.message).toContain('no credential for the configured scope');
		// The refusal leaks nothing about the scope the holder actually carries.
		expect(err.message).not.toContain(hex(cB.scopeId));
		expect(err.message).not.toContain('other-club');
	});

	it('widens the founder-root null expiry to lifecycle.renewable never with no expires_at', async () => {
		const clock = createClock();
		const c = await buildCeremony({ scopeName: 'garden-coop', clock });
		const at = clock.now();

		const adapter = createEmberAdapter({
			genesis: c.genesisBytes,
			audience: AUDIENCE,
			now: () => clock.now(),
		});
		const handle = adapter.beginChallenge();
		// The founder presents their own root credential (depth 0, no expiry).
		const presentation = await presentPortfolio({
			challenge: handle.challenge,
			creds: [c.founderCredBytes],
			identity: c.founder,
			at,
		});

		const session = await adapter.authenticate({ kind: 'ember-presentation', presentation });
		expect(isAuthError(session)).toBe(false);

		const upactor = (await adapter.currentUpactor(REQ)) as Upactor;
		expect(upactor.lifecycle).toEqual({ renewable: 'never' });
		expect(upactor.lifecycle?.expires_at).toBeUndefined();
		// A founder root has no leaf link, so no display hint.
		expect(upactor.display_hint).toBeUndefined();
	});
});
