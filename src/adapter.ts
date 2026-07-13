// SPDX-License-Identifier: Apache-2.0
/**
 * `createEmberAdapter`: verifier-side upact `IdentityPort` over
 * `@prefig/ember` presence credentials (upact SPEC.md §6, §7, §8).
 *
 * Role boundary: the adapter is the VERIFIER at an encounter (ember's
 * verifier role). It mints challenges, consumes proof/presentation bytes,
 * and answers "who is this member and are they currently valid." It is NOT
 * the holder keyring (no private key ever enters it) and NOT the renewal
 * ceremony (createReq/grantCred are member-steward, out of band).
 *
 * THE TRUST ANCHOR: ember's `verifyCred` verifies a chain against nothing
 * but the founder key embedded in the credential itself, and `verifyProof`'s
 * `scopeId` option only compares 16 public, attacker-copyable bytes against
 * the credential's OWN embedded genesis. An attacker can mint a fresh
 * genesis reusing a known scopeId under their own founder key, self-grant,
 * and pass every substrate check. The adapter closes this with a REQUIRED
 * configured genesis and a byte-for-byte pin after every successful verify:
 * `bytesEqual(result.genesis.bytes, genesisBytes)`. Mismatch is
 * `credential_rejected`.
 *
 * Binding shape: encounter-bound (SPEC.md F2, process-bound family). One
 * adapter instance = one verified encounter; all state lives in the factory
 * closure and dies with it. `currentUpactor`'s `Request` parameter is
 * accepted for the fixed §6 signature and deliberately ignored (ember has no
 * request concept).
 *
 * `SubstrateUnavailableError` is deliberately never imported or thrown: the
 * substrate is pure in-process code with no reachable "substrate down"
 * state; unexpected internal throws propagate as-is — a bug, not an outage.
 */

import {
	createSession,
	type AuthError,
	type AuthErrorCode,
	type IdentityPort,
	type Session,
	type Upactor,
} from '@prefig/upact';
import { _unwrapSession } from '@prefig/upact/internal';
import {
	AUD_MAX,
	CHAL_TTL_S,
	CLOCK_SKEW_S,
	bytesEqual,
	createChal,
	hex,
	now,
	parseGenesis,
	parsePresentation,
	parseProof,
	verifyCred,
	verifyPresentation,
	verifyProof,
	type PresentedScope,
	type VerifyResult,
} from '@prefig/ember';

import { deriveUpactorId, mapToUpactor } from './claims-mapper.js';
import { createNonceRegistry } from './nonce-registry.js';
import type {
	ChallengeHandle,
	EmberAdapterExtensions,
	EmberConfig,
	EmberCredential,
	EmberSessionState,
} from './types.js';

/**
 * Known upstream d.ts drift (filed upstream): `PresentedScope.expiresAt` is
 * typed `number` but is actually `null` for a presented founder root. Local
 * widening only; never used to skip the uniform `verifyCred` re-check.
 */
type WidenedPresentedScope = Omit<PresentedScope, 'expiresAt'> & {
	expiresAt: number | null;
};

const GENESIS_PIN_MESSAGE = 'credential is not anchored to the configured genesis';
const NO_PENDING_CHALLENGE_MESSAGE =
	'no pending challenge: stale or replayed proof';
const SCOPE_ABSENT_MESSAGE =
	'presentation carries no credential for the configured scope';

/**
 * Exact ember parse-level reason strings: structural invalidity (could never
 * have been parsed) maps to `credential_invalid`. Everything else the
 * substrate says — chain/signature refusals, freshness/binding failures,
 * lapse, and UNRECOGNISED reason strings from a future ember version — is an
 * understood-and-refused `credential_rejected` (SPEC.md §6.5).
 */
const STRUCTURAL_REASONS: ReadonlySet<string> = new Set([
	'not a proof',
	'not a presentation',
	'not a credential',
	'not a genesis',
	'not a link',
	'truncated message',
]);

/**
 * The single AuthError translation point. `message` is always
 * `${context}: ${exact substrate reason}` — it carries only ember reason
 * strings and adapter-fixed prose, never pubkey hex, member names, scope
 * ids/names, or nonce values. The `lapsed` flag is accepted for symmetry
 * with ember's VerifyResult: a lapse is a refusal (`credential_rejected`)
 * whose message preserves the substrate string ('lapsed — renew in
 * presence') so apps can prompt renewal.
 */
export function mapVerifyFailure(
	reason: string | undefined,
	lapsed: boolean,
	context: string,
): AuthError {
	const detail = reason ?? 'substrate refused without a reason';
	const code: AuthErrorCode =
		!lapsed && STRUCTURAL_REASONS.has(detail)
			? 'credential_invalid'
			: 'credential_rejected';
	return { code, message: `${context}: ${detail}` };
}

/** Narrow an unknown credential/evidence value to the EmberCredential union. */
function guardCredentialShape(value: unknown): EmberCredential | undefined {
	if (typeof value !== 'object' || value === null) return undefined;
	const record = value as Record<string, unknown>;
	if (
		record['kind'] === 'ember-proof' &&
		record['proof'] instanceof Uint8Array
	) {
		return { kind: 'ember-proof', proof: record['proof'] };
	}
	if (
		record['kind'] === 'ember-presentation' &&
		record['presentation'] instanceof Uint8Array
	) {
		return { kind: 'ember-presentation', presentation: record['presentation'] };
	}
	return undefined;
}

function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

/** Leaf link name from a verify result; null for founder root / empty name. */
function leafNameOf(result: VerifyResult): string | null {
	const links = result.links ?? [];
	const leaf = links.length > 0 ? links[links.length - 1] : undefined;
	if (leaf === undefined || leaf.name.length === 0) return null;
	return leaf.name;
}

/** Normalise VerifyResult.expiresAt (undefined never occurs on ok results). */
function expiryOf(result: VerifyResult): number | null {
	return result.expiresAt === undefined ? null : result.expiresAt;
}

/**
 * Construct an encounter-bound ember adapter. Factory-only, no class
 * (Decision 11): returns an object literal of exactly five methods (four
 * port ops + `beginChallenge`) — no fields, no `this`.
 *
 * Construction-time validation: `config.genesis` must parse as a genesis
 * record; `config.audience` must be at most AUD_MAX (128) UTF-8 bytes.
 * The genesis signature is not async-checked at construction because
 * verifyCred/verifyProof re-verify it inside every authenticate.
 */
export function createEmberAdapter(
	config: EmberConfig,
): IdentityPort & EmberAdapterExtensions {
	// Defensive copies: the caller owns the input buffers (SPEC.md §7.5
	// ownership hygiene, not a vulnerability fix).
	const genesisBytes: Uint8Array = new Uint8Array(config.genesis);
	const genesis = parseGenesis(genesisBytes); // throws 'not a genesis' / 'truncated message'
	const scopeId: Uint8Array = genesis.scopeId;

	const audienceByteLength = new TextEncoder().encode(config.audience).length;
	if (audienceByteLength > AUD_MAX) {
		throw new Error(
			`upact-ember: config.audience exceeds ${AUD_MAX} bytes (SPEC.md §7: the audience is the verifier identifier bound into every challenge)`,
		);
	}
	const audience: string = config.audience;
	const pepper: Uint8Array =
		config.idPepper === undefined
			? new Uint8Array(0)
			: new Uint8Array(config.idPepper);
	const clock: () => number = config.now ?? now;
	const maxProofAgeS: number = config.maxProofAgeS ?? CHAL_TTL_S;
	const skew: number = config.clockSkewS ?? CLOCK_SKEW_S;

	// Pending challenges: single-use, bounded, TTL-swept (window covers the
	// proof freshness window plus skew grace).
	const nonceRegistry = createNonceRegistry(maxProofAgeS + skew);

	// The instance's one bound session (encounter-bound binding).
	let current: EmberSessionState | null = null;

	function beginChallenge(): ChallengeHandle {
		const at = clock();
		nonceRegistry.prune(at);
		const chal = createChal({ scopeId, aud: audience, at });
		nonceRegistry.register(hex(chal.nonce), chal.iat);
		return {
			challenge: chal.bytes,
			expiresAt: new Date((chal.iat + maxProofAgeS) * 1000),
		};
	}

	interface VerifiedEvidence {
		credBytes: Uint8Array;
		subjectPk: Uint8Array;
		expiresAt: number | null;
		leafName: string | null;
	}

	/**
	 * Shared verification pipeline for authenticate and issueRenewal:
	 * parse framing, consume the pending nonce (single-use, consumed even on
	 * refusal), run the substrate verify with the audience always enforced,
	 * apply the genesis byte pin, and re-check the credential for a uniform
	 * VerifyResult (with subject binding when `expectedSubject` is given).
	 * Returns the verified evidence or an AuthError (issueRenewal collapses
	 * errors to null per SPEC.md §6.4 / Decision 9).
	 */
	async function verifyEvidence(
		shaped: EmberCredential,
		context: string,
		expectedSubject: Uint8Array | null,
	): Promise<VerifiedEvidence | AuthError> {
		const at = clock();
		if (shaped.kind === 'ember-proof') {
			let parsed: ReturnType<typeof parseProof>;
			try {
				parsed = parseProof(shaped.proof);
			} catch (err) {
				return {
					code: 'credential_invalid',
					message: `${context}: ${errorMessage(err)}`,
				};
			}
			if (!nonceRegistry.consume(hex(parsed.nonce), at)) {
				return {
					code: 'credential_rejected',
					message: `${context}: ${NO_PENDING_CHALLENGE_MESSAGE}`,
				};
			}
			const result = await verifyProof(shaped.proof, {
				nonce: parsed.nonce,
				aud: audience, // always enforced — never null/open
				at,
				scopeId,
				maxAgeS: maxProofAgeS,
				skew,
			});
			if (!result.ok) {
				// Only the reason string is forwarded; the result object (which
				// carries genesis/links even on failure) never escapes this frame.
				return mapVerifyFailure(result.reason, result.lapsed === true, context);
			}
			if (result.genesis === undefined) {
				throw new Error('ember verifyProof returned ok without a genesis');
			}
			// TRUST-ANCHOR PIN: byte-for-byte against the configured genesis.
			if (!bytesEqual(result.genesis.bytes, genesisBytes)) {
				return {
					code: 'credential_rejected',
					message: `${context}: ${GENESIS_PIN_MESSAGE}`,
				};
			}
			// verifyProof already ran the full chain verification; the extra
			// credential re-check happens only when a subject binding is
			// required (issueRenewal), so 'credential is for a different key'
			// refuses mechanically.
			const check =
				expectedSubject === null
					? result
					: await verifyCred(parsed.credBytes, { at, expectedSubject, skew });
			if (!check.ok) {
				return mapVerifyFailure(check.reason, check.lapsed === true, context);
			}
			if (check.subjectPk === undefined) {
				throw new Error('ember verifyCred returned ok without a subject');
			}
			return {
				credBytes: new Uint8Array(parsed.credBytes),
				subjectPk: new Uint8Array(check.subjectPk),
				expiresAt: expiryOf(check),
				leafName: leafNameOf(check),
			};
		}

		// Presentation path (U3 multi-scope).
		let parsedPres: ReturnType<typeof parsePresentation>;
		try {
			parsedPres = parsePresentation(shaped.presentation);
		} catch (err) {
			return {
				code: 'credential_invalid',
				message: `${context}: ${errorMessage(err)}`,
			};
		}
		if (!nonceRegistry.consume(hex(parsedPres.nonce), at)) {
			return {
				code: 'credential_rejected',
				message: `${context}: ${NO_PENDING_CHALLENGE_MESSAGE}`,
			};
		}
		const pres = await verifyPresentation(shaped.presentation, {
			nonce: parsedPres.nonce,
			aud: audience,
			at,
			maxAgeS: maxProofAgeS,
			skew,
		});
		if (!pres.ok) {
			return mapVerifyFailure(pres.reason, false, context);
		}
		if (pres.holderPk === undefined) {
			throw new Error('ember verifyPresentation returned ok without a holder key');
		}
		const scopes = (pres.scopes ?? []) as readonly WidenedPresentedScope[];
		// Select the single presented scope anchored to OUR genesis, byte for
		// byte. Absent — including ember's legitimate `ok:true, scopes:[]`
		// silent-drop — is a rejection whose message names no foreign scopes.
		const match = scopes.find((s) => bytesEqual(s.genesis.bytes, genesisBytes));
		if (match === undefined) {
			return {
				code: 'credential_rejected',
				message: `${context}: ${SCOPE_ABSENT_MESSAGE}`,
			};
		}
		const check = await verifyCred(match.credential, {
			at,
			expectedSubject: expectedSubject ?? pres.holderPk,
			skew,
		});
		if (!check.ok) {
			return mapVerifyFailure(check.reason, check.lapsed === true, context);
		}
		if (check.subjectPk === undefined) {
			throw new Error('ember verifyCred returned ok without a subject');
		}
		return {
			credBytes: new Uint8Array(match.credential),
			subjectPk: new Uint8Array(check.subjectPk),
			expiresAt: expiryOf(check),
			leafName: match.displayName,
		};
	}

	async function authenticate(credential: unknown): Promise<Session | AuthError> {
		try {
			const shaped = guardCredentialShape(credential);
			if (shaped === undefined) {
				return {
					code: 'credential_invalid',
					message:
						'authenticate: credential fails the ember evidence shape guard',
				};
			}
			const verified = await verifyEvidence(shaped, 'authenticate', null);
			if ('code' in verified) return verified;
			const state: EmberSessionState = {
				credBytes: verified.credBytes,
				id: await deriveUpactorId(scopeId, verified.subjectPk, pepper),
				subjectPk: verified.subjectPk,
				expiresAt: verified.expiresAt,
				revoked: false,
			};
			current = state;
			return createSession(state);
		} catch (err) {
			return {
				code: 'auth_failed',
				message: `authenticate: unexpected failure: ${errorMessage(err)}`,
			};
		}
	}

	async function currentUpactor(_request: Request): Promise<Upactor | null> {
		if (current === null || current.revoked) return null;
		// Expiry is ember's only revocation: validity is a function of the wall
		// clock and is re-evaluated at every use, never cached past expiry.
		// Unexpected throws propagate as-is — a bug, not an outage.
		const result = await verifyCred(current.credBytes, {
			at: clock(),
			expectedSubject: current.subjectPk,
			skew,
		});
		if (result.ok) {
			if (result.subjectPk === undefined) {
				throw new Error('ember verifyCred returned ok without a subject');
			}
			return mapToUpactor({
				scopeId,
				subjectPk: current.subjectPk,
				pepper,
				leafName: leafNameOf(result),
				expiresAt: expiryOf(result),
			});
		}
		if (result.lapsed === true) {
			// Known but lapsed: null through the port, session RETAINED so a
			// post-lapse identity-bound issueRenewal with fresh presence evidence
			// can restore standing without a full re-authenticate.
			return null;
		}
		// Structurally invalid retained bytes (defensive; should be impossible).
		current = null;
		return null;
	}

	async function invalidate(session: Session): Promise<void> {
		// The ONLY _unwrapSession site in this package (SPEC.md §7.4).
		const state = _unwrapSession<EmberSessionState>(session);
		if (state === undefined) return; // foreign/cloned Session: no-op
		state.revoked = true;
		state.credBytes.fill(0); // wipe the one social-graph-bearing buffer we hold
		if (current === state) current = null;
	}

	async function issueRenewal(
		identity: Upactor,
		evidence: unknown,
	): Promise<Upactor | null> {
		// SPEC.md §6.4 / Decision 9: the only failure channel is null — never a
		// throw. Unlike authenticate (whose auth_failed carries a diagnostic),
		// renewal has no error value to carry one, so a should-be-impossible
		// invariant violation collapses to null here, symmetric with the
		// documented "a bug, not an outage" posture.
		try {
			// A LAPSED current is fine — that is the point of represence.
			if (current === null || current.revoked) return null;
			const shaped = guardCredentialShape(evidence);
			if (shaped === undefined) return null;
			const verified = await verifyEvidence(
				shaped,
				'issueRenewal',
				current.subjectPk,
			);
			if ('code' in verified) return null;
			// Identity-bound acceptance (D3 Option A): the member key never rotates
			// at renewal, so a subject mismatch is always a different member.
			const candidate = await deriveUpactorId(scopeId, verified.subjectPk, pepper);
			if (candidate !== identity.id || candidate !== current.id) return null;
			// Anti-downgrade, mirroring ember portfolio.js upsertCredential
			// verbatim (incomingExp >= leafExpiry): null = never = +infinity;
			// equal-expiry re-presentation is accepted, matching the substrate.
			const incomingExp = verified.expiresAt ?? Infinity;
			const heldExp = current.expiresAt ?? Infinity;
			if (incomingExp < heldExp) return null;
			// Swap in place so the existing Session object stays valid.
			current.credBytes = verified.credBytes;
			current.expiresAt = verified.expiresAt;
			return mapToUpactor({
				scopeId,
				subjectPk: current.subjectPk,
				pepper,
				leafName: verified.leafName,
				expiresAt: verified.expiresAt,
			});
		} catch {
			return null;
		}
	}

	return {
		authenticate,
		currentUpactor,
		invalidate,
		issueRenewal,
		beginChallenge,
	};
}
