# @prefig/upact-ember

[upact](https://github.com/prefig/upact) adapter for [ember](https://github.com/prefig/ember) presence credentials. Verifier-side: the adapter mints challenges, consumes proof or presentation bytes, and answers "who is this member and are they currently valid" through the standard `IdentityPort`. Verification is fully offline Ed25519 chain checking; there is no server, no registry, and no network call anywhere in the adapter. This is the first shipped adapter with a `renewable: 'represence'` lifecycle: credentials expire, and the only renewal path is a fresh in-presence ceremony.

## The verifier at an encounter

The adapter is the verifier's side of an encounter (a door check, a session gate, a meeting entry point). One adapter instance corresponds to one verified encounter; all state lives in the factory closure and dies with it.

Members hold their own credentials and answer challenges on their own devices, so no private key ever enters the adapter. Granting and renewing credentials is a member-steward exchange that happens out of band (in ember's demo, a QR handshake between two phones); the adapter only ever sees the resulting proof or presentation bytes.

## Install

```bash
npm install @prefig/upact @prefig/upact-ember @prefig/ember
```

`@prefig/upact` and `@prefig/ember` are peer dependencies. The adapter itself has no runtime dependencies beyond the Web Crypto API. Runs in Node 18 and later, and in any Web-platform runtime.

## Usage

The flow is challenge, relay, authenticate. The application relays the challenge bytes to the holder over any channel it likes (QR code, screen, local link) and relays the answer back.

```ts
import { createEmberAdapter } from '@prefig/upact-ember';

const adapter = createEmberAdapter({
	genesis: genesisBytes, // the scope's genesis record, obtained from the steward out of band
	audience: 'door:main-entrance',
});

// 1. Mint a challenge and show it to the holder (QR, screen, any channel).
const handle = adapter.beginChallenge();
render(handle.challenge); // valid until handle.expiresAt

// 2. The holder's keyring answers the challenge; the app receives the bytes.
const result = await adapter.authenticate({ kind: 'ember-proof', proof: proofBytes });
if ('code' in result) {
	// AuthError: branch on result.code, show result.message detail if useful
	deny(result.code);
} else {
	const upactor = await adapter.currentUpactor(request);
	admit(upactor);
}
```

A multi-scope portfolio presentation is accepted the same way, as `{ kind: 'ember-presentation', presentation: presentationBytes }`. The adapter selects the presented credential anchored to its configured genesis and ignores the rest; a presentation carrying no credential for the configured scope is rejected.

Challenges are single-use and expire after the freshness window. Each successful `authenticate` consumes the pending challenge nonce, so a replayed proof is refused even inside the freshness window.

## Configuration

```ts
interface EmberConfig {
	genesis: Uint8Array;
	audience: string;
	idPepper?: Uint8Array;
	now?: () => number;
	maxProofAgeS?: number;
	clockSkewS?: number;
}
```

| Field | Required | Default | Notes |
|---|---|---|---|
| `genesis` | yes | | **The trust anchor.** The scope's genesis record bytes, obtained from the scope's steward out of band, never from a credential being verified. Every verify is byte-pinned against it: ember's own `scopeId` check compares public, attacker-copyable bytes against the credential's own embedded genesis, so an attacker who mints a fresh genesis reusing a known scope id under their own founder key passes every substrate check. The pin closes that. Parsed and validated at construction. |
| `audience` | yes | | Verifier identifier bound into every challenge and enforced on every proof and presentation. At most 128 UTF-8 bytes (ember `AUD_MAX`); construction throws over-limit. There is no default-open verification. |
| `idPepper` | no | absent | Deployment pepper mixed into the `Upactor.id` derivation. Limits hash confirmability to parties holding the pepper; see the privacy notes below. |
| `now` | no | ember `now()` | Injectable clock, UNIX seconds. For tests and controlled-time deployments. |
| `maxProofAgeS` | no | `120` (ember `CHAL_TTL_S`) | Proof and presentation freshness window in seconds. |
| `clockSkewS` | no | `30` (ember `CLOCK_SKEW_S`) | Clock skew grace in seconds. |

## Sessions and expiry

Expiry is ember's only revocation mechanism: there are no revocation lists, and not renewed means not a member. The adapter treats validity as a function of the wall clock, re-evaluated on every `currentUpactor` call and never cached past expiry.

- `authenticate` mints an opaque `Session` via `createSession` on success.
- `currentUpactor(request)` re-verifies the retained credential at the current time. The `Request` parameter is accepted for the standard port signature and deliberately ignored: the binding is encounter-bound, and ember has no request concept.
- When the credential lapses, `currentUpactor` returns `null` but the session is retained, so a post-lapse `issueRenewal` with fresh presence evidence can restore standing without a full re-authenticate.
- `issueRenewal(identity, evidence)` accepts a fresh proof or presentation answering a new `beginChallenge`, carrying the credential the member renewed with a steward out of band. Bare credential bytes are deliberately not accepted: renewal evidence must prove key possession. Acceptance is identity-bound (the same member key, the same derived id) and anti-downgrade (an incoming credential expiring earlier than the held one is refused; equal expiry is accepted, matching the substrate's own portfolio rule). Every failure collapses to `null` per the port contract.
- `invalidate(session)` marks the session revoked and wipes the retained credential bytes, the one social-graph-bearing buffer the adapter holds.

`Upactor.lifecycle` is `{ expires_at, renewable: 'represence' }` for a member credential, taken from the leaf link's absolute expiry, and `{ renewable: 'never' }` for a presented founder root, which does not expire.

## Presentations and OpenID4VP

ember's presentation wire shape is deliberately shaped like an OpenID4VP exchange, so a future Digital Credentials API adapter stays a mechanical shim rather than a redesign. The mapping:

| ember | field | OpenID4VP analogue |
|---|---|---|
| challenge (request) | `nonce` | `nonce` in the authorization request |
| challenge (request) | `audience` | the verifier's `client_id` / audience binding |
| challenge (request) | `scopes?` | `presentation_definition` (which credentials are requested) |
| presentation (response) | `holder` | the holder binding key declared in the `vp_token` |
| presentation (response) | `credentials[]` | the verifiable credentials carried in the `vp_token` |
| presentation (response) | `proof` | the holder-binding signature over the presentation |

The adapter consumes the response side through `authenticate({ kind: 'ember-presentation', ... })`. The request side is `beginChallenge()`, which mints a challenge bound to the configured scope and audience.

## Display names

`Upactor.display_hint` comes from the member's self-chosen name on the leaf credential link (or the presented display name). It is sanitised before it crosses the port: trimmed, replacement characters stripped (ember byte-truncates names and may split a multibyte character at the tear), email-shaped values rejected, and empty results omitted entirely. The member key fingerprint is deliberately never used as a fallback display hint, because it is a cross-scope-stable correlation handle.

## Capabilities

`Upactor.capabilities` is always `[]` for this adapter at v0.1. Ember's substrate affordances (multi-scope portfolios, in-presence renewal) are not declared as capabilities pre-emptively: per the project's audit discipline, new capabilities land when a concrete consumer surfaces.

## Security posture

- The adapter follows upact SPEC.md §7 (privacy minima) and §7.5 (back-channel closure). The `Upactor` carries only the fields the port contract defines; chain depth, issuer keys, scope names, and the member's public key never cross the port.
- **The configured genesis is the trust anchor.** Ember's chain verification anchors to the founder key embedded in the credential itself, so the adapter byte-pins every successful verify against the configured genesis. A credential anchored to any other genesis, including one reusing the same scope id, is rejected.
- The audience is always enforced. A proof or presentation addressed to a different verifier is refused; there is no configuration that opens verification to any audience.
- Challenge nonces are single-use, bounded in number, and swept on a TTL covering the freshness window plus skew grace. A nonce is consumed on first use even when verification then refuses, so a refused proof cannot be retried.
- Substrate state (genesis bytes, audience, pepper, retained credential bytes, the member's public key) lives in closure scope and is unreachable by reflection on the adapter instance.
- `SubstrateUnavailableError` is never thrown: the substrate is pure in-process code with no reachable outage state. An unexpected internal throw is a bug, not an outage.

## Privacy notes

- `Upactor.id` is a salted per-scope hash of the member's public key, with a protocol domain tag and the optional deployment pepper mixed in. Ember member keys are deliberately stable across scopes ("one key, many scopes"), so an unsalted hash would be a cross-application correlation handle; the scope salt makes ids per-scope by construction. The id is stable across renewals within a scope.
- Without a pepper, a party who already knows a member's public key and the scope id can recompute the id and confirm membership. Configure `idPepper` where that confirmability matters; see `CONFORMANCE.md` for the full derivation.
- `AuthError.message` carries only ember reason strings and adapter-fixed prose, never key material, member names, scope identifiers, or nonce values.
- `provenance` is `{ substrate: 'ember', instance: <scope id, hex> }`. The scope id is public wire material, not a member identifier.

See `CONFORMANCE.md` for the full conformance statement and the `AuthError` mapping table.

## Status

v0.1.0. First public release. Breaking changes between v0.x revisions are permitted; v1.0 marks the first stable version.

## Licence

Apache-2.0. See `LICENSE`.
