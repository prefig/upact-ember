// SPDX-License-Identifier: Apache-2.0
/**
 * Public and internal types for `@prefig/upact-ember`.
 *
 * The public surface uses only `Uint8Array`, `string`, and `Date` — never a
 * substrate-typed value (upact SPEC.md §7.5). `EmberSessionState` is
 * module-internal: it is the substrate session value wrapped by
 * `createSession` and is NEVER exported from the package entry.
 */

/**
 * Configuration for `createEmberAdapter`. See upact SPEC.md §7 for the
 * privacy rationale behind each field.
 */
export interface EmberConfig {
	/**
	 * REQUIRED trust anchor: the scope's genesis record bytes, obtained from
	 * the scope's steward out of band — never from a credential being
	 * verified. Byte-pinned on every verify: ember's own `scopeId` check
	 * compares 16 public, attacker-copyable bytes against the credential's
	 * OWN embedded genesis, so it is not a trust anchor on its own.
	 */
	genesis: Uint8Array;
	/**
	 * REQUIRED verifier identifier bound into challenges and enforced on
	 * proofs/presentations. At most `AUD_MAX` (128) bytes; construction
	 * throws over-limit. No default-open verification.
	 */
	audience: string;
	/**
	 * Optional deployment pepper mixed into id derivation (limits
	 * hash-confirmability to the deployment).
	 */
	idPepper?: Uint8Array;
	/** Injectable clock, UNIX seconds. Default ember `now()`. */
	now?: () => number;
	/** Proof/presentation freshness window, seconds. Default ember `CHAL_TTL_S` = 120. */
	maxProofAgeS?: number;
	/** Clock skew grace, seconds. Default ember `CLOCK_SKEW_S` = 30. */
	clockSkewS?: number;
}

/** A single-scope ember presence proof (wire TYPE.PROOF). */
export type EmberProofCredential = {
	kind: 'ember-proof';
	proof: Uint8Array;
};

/** A multi-scope ember portfolio presentation (wire TYPE.PRES). */
export type EmberPresentationCredential = {
	kind: 'ember-presentation';
	presentation: Uint8Array;
};

/**
 * The credential union accepted by `authenticate`. Wire bytes only — never a
 * substrate-typed object (SPEC.md §7.5).
 */
export type EmberCredential =
	| EmberProofCredential
	| EmberPresentationCredential;

/**
 * Evidence accepted by `issueRenewal`: a FRESH proof or presentation
 * answering a new `beginChallenge`, carrying the credential the member
 * renewed with a steward out of band. Fresh-proof-only at v0.1 — bare
 * credential bytes are deliberately not accepted (no possession proof).
 */
export type EmberRenewalEvidence = EmberCredential;

/**
 * Return value of the out-of-port `beginChallenge` helper: the challenge
 * wire bytes the app relays to the holder (QR/screen/any channel) and the
 * moment the pending nonce expires.
 */
export interface ChallengeHandle {
	challenge: Uint8Array;
	expiresAt: Date;
}

/**
 * Out-of-port extensions on the adapter object (SPEC.md Decision 10 / F4:
 * the port stays one-shot; init helpers live beside it, `buildAuthRedirect`
 * precedent).
 */
export interface EmberAdapterExtensions {
	/**
	 * Mints an ember challenge bound to the configured scope and audience,
	 * registers the nonce as pending (single-use), and returns wire bytes.
	 * Synchronous — ember `createChal` is sync.
	 */
	beginChallenge(): ChallengeHandle;
}

/**
 * INTERNAL — the substrate session value held behind `createSession`'s
 * opacity. Never exported from the package entry; reachable only via
 * `_unwrapSession` inside `invalidate` (SPEC.md §7.4).
 *
 * Privacy minima: this is the minimum state supporting re-verification
 * without a new presence exchange. NOT stored: parsed chain/links, per-link
 * names, issuer pubkeys, depth, nonce, aud.
 */
export interface EmberSessionState {
	/** Retained leaf credential bytes — the substrate session object. */
	credBytes: Uint8Array;
	/** Derived upact id, for identity-bound renewal matching. */
	id: string;
	/** Network-legible handle (F3); stays behind opacity. */
	subjectPk: Uint8Array;
	/** Leaf link exp (UNIX seconds); null = founder root (never expires). */
	expiresAt: number | null;
	revoked: boolean;
}
