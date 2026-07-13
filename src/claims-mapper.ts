// SPDX-License-Identifier: Apache-2.0
/**
 * Pure claims mapping: from plain primitives (never ember result types) to a
 * port-shaped `Upactor`. The privacy boundary lives here (upact SPEC.md §7).
 *
 * Rules:
 *
 * 1. **`id` is a salted per-scope hash** (SPEC.md §7.3 / F3):
 *    `hex(SHA-256(utf8('upact-ember/id/v1') || pepper || scopeId || subjectPk))[:32]`.
 *    Ember's member key is deliberately stable across renewals AND scopes
 *    ("one key, many scopes"), so an unscoped hash would be a
 *    cross-application correlation handle; the scopeId salt makes ids
 *    per-scope by construction, the optional pepper breaks cross-deployment
 *    confirmability, and the domain tag prevents cross-protocol hash reuse.
 *    Stable across renewals (subjectPk and scopeId both stable).
 * 2. **`display_hint` is sanitised** (SPEC.md §4.2): trimmed, U+FFFD
 *    stripped (ember str8 byte-truncates at NAME_MAX=24 and may split a
 *    multibyte char), email-shaped values rejected, empty omitted.
 *    `fingerprint(pub)` is deliberately NOT a fallback: it is a
 *    cross-scope-stable correlation handle.
 * 3. **`lifecycle`** (SPEC.md §4.4, §8, F6): member credential →
 *    `{ expires_at, renewable: 'represence' }` from the leaf link's absolute
 *    exp; founder root → `{ renewable: 'never' }` with `expires_at`
 *    deliberately omitted.
 *
 * Async is a MUST: `crypto.subtle.digest` forces it.
 */

import type { Capability, Upactor } from '@prefig/upact';

const ID_LENGTH_HEX = 32;
const ID_DOMAIN_TAG = 'upact-ember/id/v1';

const EMPTY_CAPABILITIES: ReadonlySet<Capability> = Object.freeze(
	new Set<Capability>(),
);

/**
 * Derive the opaque per-scope upact id:
 * `hex(SHA-256(utf8('upact-ember/id/v1') || pepper || scopeId || subjectPk))[:32]`.
 *
 * Encoding is unambiguous: fixed domain tag, then variable pepper, then
 * fixed-length scopeId (16) and subjectPk (32) suffix.
 */
export async function deriveUpactorId(
	scopeId: Uint8Array,
	subjectPk: Uint8Array,
	pepper: Uint8Array,
): Promise<string> {
	const tag = new TextEncoder().encode(ID_DOMAIN_TAG);
	const input = new Uint8Array(
		tag.length + pepper.length + scopeId.length + subjectPk.length,
	);
	input.set(tag, 0);
	input.set(pepper, tag.length);
	input.set(scopeId, tag.length + pepper.length);
	input.set(subjectPk, tag.length + pepper.length + scopeId.length);
	const digest = await crypto.subtle.digest('SHA-256', input);
	return bytesToHex(new Uint8Array(digest)).slice(0, ID_LENGTH_HEX);
}

/**
 * Sanitise a self-chosen member name into a display hint, or `undefined`
 * when nothing safe remains. Never returns an empty string, an email-shaped
 * value, or replacement characters from a truncation-torn multibyte name.
 */
export function sanitiseDisplayHint(
	name: string | null | undefined,
): string | undefined {
	if (name === null || name === undefined) return undefined;
	// Strip U+FFFD: ember's str8 byte-truncates at NAME_MAX and may split a
	// multibyte character, decoding to replacement characters at the tear.
	const stripped = name.replace(/�/g, '').trim();
	if (stripped === '') return undefined;
	if (looksEmailShaped(stripped)) return undefined;
	return stripped;
}

/** Inputs to `mapToUpactor` — plain primitives only, no ember result types. */
export interface UpactorMappingInput {
	/** The configured scope's 16-byte id (salt for the derived id). */
	scopeId: Uint8Array;
	/** The member's 32-byte Ed25519 public key. Never crosses the port raw. */
	subjectPk: Uint8Array;
	/** Deployment pepper; may be empty. */
	pepper: Uint8Array;
	/** Leaf link name (proof) or presented display name; null when absent. */
	leafName: string | null;
	/** Leaf link exp (UNIX seconds); null = founder root (never expires). */
	expiresAt: number | null;
}

/**
 * Map verified-credential primitives to the port `Upactor`. Exactly the five
 * spec fields: no depth, no subjectPk, no fingerprint, no scope name, no
 * chain fields (SPEC.md §7.1 strip, §7.2 no silent enrichment).
 */
export async function mapToUpactor(
	input: UpactorMappingInput,
): Promise<Upactor> {
	const id = await deriveUpactorId(
		input.scopeId,
		input.subjectPk,
		input.pepper,
	);
	const displayHint = sanitiseDisplayHint(input.leafName);
	return {
		id,
		...(displayHint !== undefined ? { display_hint: displayHint } : {}),
		capabilities: EMPTY_CAPABILITIES,
		lifecycle:
			input.expiresAt === null
				? { renewable: 'never' }
				: {
						expires_at: new Date(input.expiresAt * 1000),
						renewable: 'represence',
					},
		provenance: {
			substrate: 'ember',
			instance: bytesToHex(input.scopeId),
		},
	};
}

function bytesToHex(bytes: Uint8Array): string {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

function looksEmailShaped(value: string): boolean {
	// SPEC.md §4.2: display_hint MUST NOT be a contact identifier. A narrow
	// shape check (single `@` with non-empty parts and a dotted domain) so
	// <=24-byte unicode/emoji names pass freely — but "a@b.c" fits in 24
	// bytes and is rejected.
	const at = value.indexOf('@');
	if (at <= 0) return false;
	if (at !== value.lastIndexOf('@')) return false;
	const local = value.slice(0, at);
	const domain = value.slice(at + 1);
	return local.length > 0 && domain.length > 0 && domain.includes('.');
}
