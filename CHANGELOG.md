# Changelog

All notable changes to this package are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This package uses [semantic versioning](https://semver.org/) from v1.0.0 onward; v0.x breaking changes are permitted between minor versions.

---

## [0.1.0]: 2026-07-12

First public release of the ember presence-credential adapter for [upact](https://github.com/prefig/upact).

### Added

- `createEmberAdapter(config)`: factory returning `IdentityPort & EmberAdapterExtensions`. Verifier-side, encounter-bound: one adapter instance is one verified encounter, and all substrate state lives in closure scope per upact SPEC §7.5. Construction validates the configured genesis (the trust anchor) and the audience length.
- `beginChallenge()`: out-of-port adapter extension for the challenge-init phase. Mints an ember challenge bound to the configured scope and audience, registers the nonce as pending (single-use, bounded, TTL-swept), and returns the challenge wire bytes plus their expiry.
- `authenticate({ kind: 'ember-proof' | 'ember-presentation', ... })`: consumes proof or presentation bytes answering a pending challenge. Fully offline verification with the audience always enforced, a byte-for-byte genesis pin against the configured trust anchor on every success, and single-use nonce consumption. Mints an opaque `Session` via `createSession`. Maps substrate refusals to upact `AuthError` per `CONFORMANCE.md`.
- `currentUpactor(request)`: re-verifies the retained credential at the current wall clock on every call (expiry is ember's only revocation; validity is never cached past expiry). Returns `null` on lapse while retaining the session so post-lapse renewal can restore standing. The `Request` parameter is accepted for the standard port signature and deliberately ignored.
- `invalidate(session)`: marks the session revoked and wipes the retained credential bytes. The only `_unwrapSession` site in the package.
- `issueRenewal(identity, evidence)`: the first shipped `renewable: 'represence'` implementation. Accepts a fresh proof or presentation answering a new challenge and carrying the credential renewed with a steward out of band. Identity-bound (same member key, same derived id) and anti-downgrade (an incoming credential expiring earlier than the held one is refused; equal expiry is accepted, matching the substrate's own portfolio rule). Every failure collapses to `null` per upact Decision 9.
- Salted per-scope identifier derivation: `Upactor.id` mixes a protocol domain tag, an optional deployment pepper (`idPepper`), the scope id, and the member key, so the cross-scope-stable ember member key never becomes a cross-application correlation handle. Rationale in `CONFORMANCE.md`.
- Display-hint sanitisation: self-chosen member names are trimmed, stripped of truncation-torn replacement characters, and rejected when email-shaped; the key fingerprint is deliberately never a fallback.
- `CONFORMANCE.md`: filled-in conformance statement against upact v0.1, including the `AuthError` mapping table and the presentation-to-OpenID4VP mapping rationale in the README.
- Reflection test (`tests/back-channel.test.ts`, vectors per upact SPEC §7.4) verifies no sentinel substrate value leaks through the adapter instance; hostile-vector suite (`tests/hostile.test.ts`) covers foreign-genesis forgery, foreign challenges, replay, staleness, and wrong-audience evidence.

### Substrate

ember: offline Ed25519 chains of renewal from a scope's genesis record. No server, no registry, no network; expiry is the only revocation, and renewal is an in-presence member-steward ceremony the adapter never participates in. The adapter is the verifier role only: not the holder keyring (no private key ever enters it) and not the renewal ceremony.
