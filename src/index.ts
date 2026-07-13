// SPDX-License-Identifier: Apache-2.0
/**
 * Public entry point for `@prefig/upact-ember`.
 *
 * The adapter implements `IdentityPort` (from `@prefig/upact`) as the
 * VERIFIER at an ember encounter: offline Ed25519 chain-of-renewal
 * verification, encounter-bound sessions, and the first shipped
 * 'represence' lifecycle (upact SPEC.md §4.4, §6, §8).
 *
 * Deliberately re-exports NOTHING from `@prefig/ember` — a re-export would
 * be a substrate-typed escape path (SPEC.md §7.5). The public surface uses
 * only `Uint8Array`, `string`, and `Date`. `EmberSessionState` is NEVER
 * exported.
 */

export { createEmberAdapter } from './adapter.js';
export type {
	ChallengeHandle,
	EmberAdapterExtensions,
	EmberConfig,
	EmberCredential,
	EmberPresentationCredential,
	EmberProofCredential,
	EmberRenewalEvidence,
} from './types.js';
