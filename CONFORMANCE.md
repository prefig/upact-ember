# Conformance: @prefig/upact-ember

**Spec version:** upact v0.1
**Package version:** 0.1.0
**Date:** 2026-07-12

## Substrate

ember, an offline presence-credential protocol: Ed25519 chains of renewal from a scope's genesis record, verified with no server, no registry, and no network. The adapter is the verifier role; holders keep their own keys and credentials, and grants and renewals happen out of band between member and steward.

Pre-conforming substrate: ember's natural shape (self-chosen names, no contact identifiers, no central directory, expiry as the only revocation) is already aligned with upact's privacy minima, and the adapter is mostly type translation. Two enforcement duties remain with the adapter, because the substrate does not carry them:

1. **The trust anchor.** ember's `verifyCred` anchors a chain to the founder key embedded in the credential itself, and `verifyProof`'s `scopeId` option compares public, attacker-copyable bytes against the credential's own embedded genesis. Neither is a trust anchor on its own. The adapter requires a configured genesis at construction and byte-pins every successful verify against it; a mismatch is `credential_rejected`.
2. **The correlation handle.** ember member keys are deliberately stable across renewals and across scopes ("one key, many scopes"), which makes the raw public key and its fingerprint cross-application correlation handles. The adapter derives `Upactor.id` as a salted per-scope hash (see Identifier derivation) and never exposes the public key, the fingerprint, chain depth, issuer keys, or scope names through the port.

## Threat model

Casual-to-anonymous coordination: door checks, session gates, and meeting entry for groups that renew membership in presence. There is no central directory, no substrate operator to trust, and verification is fully offline, so the substrate-operator trust question of the hosted adapters does not arise. Pseudonymity is the natural state; members are known by self-chosen names and per-scope opaque ids.

What expiry-as-only-revocation gives: a compromised or departed member ages out of the scope without any revocation infrastructure, and a verifier needs no list, no network, and no freshness feed beyond its own clock. What it does not give: revocation before expiry. A stolen member key is valid until the credential lapses, and a steward cannot force a member out mid-window. Deployments choose their exposure with the credential TTL granted at the ceremony, not with adapter configuration.

The configured genesis is the trust anchor. The adapter refuses any credential not anchored byte-for-byte to it, closing the self-granted-scope forgery that the substrate's own checks permit. Obtaining the genuine genesis from the scope's steward out of band is the deployment's responsibility; a deployment configured with an attacker's genesis trusts the attacker's scope, correctly.

Two disclosure caveats. First, the salted id derivation is confirmable: a party who already holds a member's public key, the scope id, and the deployment pepper (or knows no pepper is configured) can recompute the id and confirm that a given `Upactor` is that member. The derivation prevents cross-scope and cross-deployment correlation by parties without those inputs; it does not hide membership from parties who hold them. Second, the member key itself is stable across scopes at the substrate layer. Two verifiers who collude at the wire level (comparing proof bytes, not port output) can correlate a member across scopes regardless of anything this adapter does; the adapter's guarantee is only that the port output does not enable that correlation.

## Capabilities self-declared

`[]` for v0.1.

The ember substrate affords multi-scope portfolio presentation and in-presence renewal. Neither is surfaced as a capability at v0.1: no shipped consumer gates on them. Per the minimum-viable discipline (CONTRIBUTING.md), capabilities land when a concrete consumer surfaces them. Substrate affordances are described in the README instead, following the SimpleX adapter's precedent.

Concrete consumer for the v0.1 cap set: none required, since `[]` is the empty case.

## AuthError mapping table

`message` is always `${context}: ${detail}`, where `detail` is the exact substrate reason string or adapter-fixed prose. It never carries key material, member names, scope identifiers, or nonce values. One narrow exception: a chain or signature refusal forwards ember's `link N: ...` reason verbatim, whose ordinal reveals the failing link's position (a chain-depth signal the port otherwise strips from a valid `Upactor`). This appears only on a refused credential, is a small integer, and carries no key, name, or nonce; reaching it requires evidence with an over-length chain, which the substrate refuses to issue in the first place.

| Substrate failure | `AuthErrorCode` |
|---|---|
| Shape-guard failure (wrong `kind`, field not a `Uint8Array`) | `credential_invalid` |
| Parse throws with a structural reason: `not a proof`, `not a presentation`, `not a credential`, `not a genesis`, `not a link`, `truncated message` | `credential_invalid` |
| Nonce unknown, already consumed, or expired (adapter prose: `no pending challenge: stale or replayed proof`) | `credential_rejected` |
| Chain and signature refusals: `genesis signature invalid`, every `link N: ...` variant, `chain exceeds scope max depth`, `credential is for a different key` | `credential_rejected` |
| Freshness and binding refusals: `stale proof (nonce mismatch)`, `stale proof (expired window)`, `proof is future-dated`, `proof addressed to a different audience`, `different scope`, `holder does not control the member key`, and the presentation analogues | `credential_rejected` |
| Lapsed credential (substrate string `lapsed — renew in presence`, preserved verbatim so applications can prompt renewal) | `credential_rejected` |
| Genesis byte-pin mismatch (adapter prose: `credential is not anchored to the configured genesis`) | `credential_rejected` |
| Presentation verifies but carries no credential for the configured scope (adapter prose: `presentation carries no credential for the configured scope`; names no foreign scopes) | `credential_rejected` |
| Unrecognised reason string from a future ember version (verbatim reason in `message`) | `credential_rejected` |
| Unexpected throw inside `authenticate` | `auth_failed` |

`substrate_unavailable`, `identity_unavailable`, and `rate_limited` are never emitted. The substrate is pure in-process code with no reachable outage state, exposes no identity-existence signal distinct from credential validity, and does not rate-limit.

`issueRenewal` collapses every failure to `null` per SPEC §6.4: absent or revoked session, shape-guard failure, nonce refusal, verify refusal, genesis-pin mismatch, identity-bound subject mismatch, and expiry downgrade (an incoming credential expiring before the held one; equal expiry is accepted, and a never-expiring founder root compares as later than any date).

## Session opacity

This adapter uses `createSession` from `@prefig/upact` for `Session` construction. The opacity guarantee at SPEC.md §7.4 is inherited from the upact runtime kernel. `_unwrapSession` is imported from `@prefig/upact/internal` at exactly one site, inside `invalidate`, which is the marked boundary for substrate-side session access.

## Adapter back-channel closure

This adapter passes the reflection test enumerated canonically in SPEC.md §7.4, at `tests/back-channel.test.ts`: after a full happy-path authenticate, sentinel substrate values (the member's public key, the retained credential bytes, the pepper, and the derived id) are unreachable through every listed vector. `tests/hostile.test.ts` exercises the adversarial verification vectors (foreign genesis with a copied scope id, foreign challenges, replayed and stale proofs, wrong-audience evidence).

## Deviations from SHOULD clauses

None.

In particular, the absence of transparent refresh is not a deviation. `currentUpactor` returns `null` on lapse rather than refreshing the credential, because there is nothing the adapter could refresh with: ember renewal is an in-presence member-steward ceremony, which is the substrate's entire point. `lifecycle.renewable: 'represence'` declares exactly this, and `issueRenewal` accepts only fresh presence evidence minted against a new challenge. The session is retained across a lapse so that renewal restores standing without a full re-authenticate.

## Identifier derivation

`Upactor.id` is the truncated hex form of `SHA-256(utf8('upact-ember/id/v1') || pepper || scopeId || subjectPk)` (the domain tag, then the optional deployment pepper, then the scope id, then the member's Ed25519 public key; the digest is computed via Web Crypto's `crypto.subtle.digest` and truncated to half its hex length).

This is a salted derivation, and it deliberately breaks the unsalted precedent of the other four adapters (Supabase, SimpleX, OIDC, Mastodon), which hash the substrate identifier alone or pass it through directly. Their substrate identifiers are already per-substrate or per-instance: a Supabase UUID, a SimpleX agent id, or a Mastodon actor URL identifies a user within one service. An ember member key is not. It is deliberately stable across scopes, so an unsalted `SHA-256(subjectPk)` would produce the same id in every scope and every deployment, an application-layer correlation handle in exactly the sense SPEC §7.3 forbids. The scope-id salt makes ids per-scope by construction, the optional pepper breaks confirmability across deployments of the same scope, and the domain tag prevents cross-protocol hash reuse. The derivation is deterministic per (pepper, scope, member key), stable across renewals, and not reversible from the application layer.

## Lifecycle

`Upactor.lifecycle = { expires_at: <leaf link expiry>, renewable: 'represence' }` for a member credential. The expiry is the leaf link's absolute expiry, the substrate's only revocation.

`Upactor.lifecycle = { renewable: 'never' }` for a presented founder root, with `expires_at` deliberately omitted: a founder root has no intrinsic TTL, per SPEC §8.

## Provenance

`Upactor.provenance = { substrate: 'ember', instance: <scope id, lowercase hex> }` for every Upactor. The scope id is public wire material carried by every credential in the scope; it identifies the scope, not the member.

## Closure-captured state

- Genesis bytes and parsed scope id: in closure (defensive copies of the caller's buffers)
- Audience string: in closure
- Deployment pepper: in closure (defensive copy; empty when unconfigured)
- Clock, freshness window, skew grace: in closure
- Pending-challenge nonce registry (single-use, bounded, TTL-swept): in closure
- The encounter's one bound session state (retained credential bytes, derived id, member public key, expiry, revoked flag): in closure, wrapped by `createSession`, reachable only via `_unwrapSession` inside `invalidate`

None of these are reachable via reflection on the adapter instance. The adapter is an object literal of the port operations plus `beginChallenge`: no fields, no `this`, no class.

## Out-of-port helpers

`beginChallenge()` is exposed as an adapter extension method (out of `IdentityPort`, following the `buildAuthRedirect` precedent) for the challenge-init phase. It mints an ember challenge bound to the configured scope and audience, registers the nonce as pending (single-use), and returns the challenge wire bytes plus their expiry moment. It is synchronous, because ember's `createChal` is synchronous. There is no logout analogue: `invalidate` marks the session revoked and wipes the retained credential bytes, and the deployment owns post-encounter UX.
