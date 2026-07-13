// SPDX-License-Identifier: Apache-2.0
/**
 * Pure-function tests for the claims mapper: salted per-scope id derivation,
 * display-hint sanitisation fixtures, and the Upactor field mapping including
 * the SPEC.md §7.1 forbidden-field strip.
 */

import { describe, expect, it } from 'vitest';
import {
	deriveUpactorId,
	mapToUpactor,
	sanitiseDisplayHint,
} from '../src/claims-mapper.js';

/** Deterministic fixture bytes: `length` bytes starting at `seed`. */
function bytes(length: number, seed: number): Uint8Array {
	const out = new Uint8Array(length);
	for (let i = 0; i < length; i++) out[i] = (seed + i) & 0xff;
	return out;
}

const SCOPE_A = bytes(16, 0x10);
const SCOPE_B = bytes(16, 0x90);
const SUBJECT_PK = bytes(32, 0x40);
const OTHER_PK = bytes(32, 0xc0);
const NO_PEPPER = new Uint8Array(0);
const PEPPER = bytes(16, 0x77);

function hexOf(b: Uint8Array): string {
	let out = '';
	for (const x of b) out += x.toString(16).padStart(2, '0');
	return out;
}

describe('deriveUpactorId', () => {
	it('produces exactly 32 lowercase hex characters', async () => {
		const id = await deriveUpactorId(SCOPE_A, SUBJECT_PK, NO_PEPPER);
		expect(id).toMatch(/^[0-9a-f]{32}$/);
	});

	it('is deterministic for identical inputs (fresh Uint8Array copies)', async () => {
		const first = await deriveUpactorId(SCOPE_A, SUBJECT_PK, PEPPER);
		const second = await deriveUpactorId(
			bytes(16, 0x10),
			bytes(32, 0x40),
			bytes(16, 0x77),
		);
		expect(second).toBe(first);
	});

	it('matches the documented construction: hex(SHA-256(tag || pepper || scopeId || subjectPk))[:32]', async () => {
		const tag = new TextEncoder().encode('upact-ember/id/v1');
		const input = new Uint8Array(
			tag.length + PEPPER.length + SCOPE_A.length + SUBJECT_PK.length,
		);
		input.set(tag, 0);
		input.set(PEPPER, tag.length);
		input.set(SCOPE_A, tag.length + PEPPER.length);
		input.set(SUBJECT_PK, tag.length + PEPPER.length + SCOPE_A.length);
		const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
		const expected = hexOf(digest).slice(0, 32);
		expect(await deriveUpactorId(SCOPE_A, SUBJECT_PK, PEPPER)).toBe(expected);
	});

	it('per-scope separation: the same subjectPk in two scopes yields different ids', async () => {
		const inA = await deriveUpactorId(SCOPE_A, SUBJECT_PK, NO_PEPPER);
		const inB = await deriveUpactorId(SCOPE_B, SUBJECT_PK, NO_PEPPER);
		expect(inA).not.toBe(inB);
	});

	it('different subjects in the same scope yield different ids', async () => {
		const one = await deriveUpactorId(SCOPE_A, SUBJECT_PK, NO_PEPPER);
		const two = await deriveUpactorId(SCOPE_A, OTHER_PK, NO_PEPPER);
		expect(one).not.toBe(two);
	});

	it('a pepper changes the id (breaks cross-deployment confirmability)', async () => {
		const unpeppered = await deriveUpactorId(SCOPE_A, SUBJECT_PK, NO_PEPPER);
		const peppered = await deriveUpactorId(SCOPE_A, SUBJECT_PK, PEPPER);
		const otherPepper = await deriveUpactorId(
			SCOPE_A,
			SUBJECT_PK,
			bytes(16, 0x01),
		);
		expect(peppered).not.toBe(unpeppered);
		expect(otherPepper).not.toBe(peppered);
	});

	it('never embeds the raw subjectPk hex in the id', async () => {
		const id = await deriveUpactorId(SCOPE_A, SUBJECT_PK, NO_PEPPER);
		expect(id).not.toContain(hexOf(SUBJECT_PK).slice(0, 16));
	});
});

describe('sanitiseDisplayHint', () => {
	it('passes a plain name through unchanged', () => {
		expect(sanitiseDisplayHint('Ada')).toBe('Ada');
	});

	it('trims surrounding whitespace and control whitespace', () => {
		expect(sanitiseDisplayHint('  Ada \n\t')).toBe('Ada');
	});

	it('strips U+FFFD replacement chars from a NAME_MAX-torn multibyte name', () => {
		// str8 byte-truncation at NAME_MAX=24 can split a multibyte character,
		// decoding to replacement characters at the tear.
		expect(sanitiseDisplayHint('Ada Lovelace�')).toBe('Ada Lovelace');
		expect(sanitiseDisplayHint('Ada��Lovelace')).toBe('AdaLovelace');
	});

	it('returns undefined when only replacement chars / whitespace remain', () => {
		expect(sanitiseDisplayHint('��')).toBeUndefined();
		expect(sanitiseDisplayHint('  �  ')).toBeUndefined();
	});

	it('maps empty, whitespace-only, null and undefined to undefined', () => {
		expect(sanitiseDisplayHint('')).toBeUndefined();
		expect(sanitiseDisplayHint('   ')).toBeUndefined();
		expect(sanitiseDisplayHint(null)).toBeUndefined();
		expect(sanitiseDisplayHint(undefined)).toBeUndefined();
	});

	it('rejects email-shaped values, including minimal and padded forms', () => {
		expect(sanitiseDisplayHint('ada@example.com')).toBeUndefined();
		expect(sanitiseDisplayHint('a@b.c')).toBeUndefined();
		expect(sanitiseDisplayHint('  ada@example.com  ')).toBeUndefined();
	});

	it('keeps non-email uses of @ (leading @, multiple @, dotless domain)', () => {
		expect(sanitiseDisplayHint('@ada')).toBe('@ada');
		expect(sanitiseDisplayHint('a@b@c.d')).toBe('a@b@c.d');
		expect(sanitiseDisplayHint('ada@home')).toBe('ada@home');
	});

	it('keeps short unicode/emoji names', () => {
		expect(sanitiseDisplayHint('Ada 🌱')).toBe('Ada 🌱');
	});
});

describe('mapToUpactor', () => {
	const baseInput = {
		scopeId: SCOPE_A,
		subjectPk: SUBJECT_PK,
		pepper: NO_PEPPER,
		leafName: 'Ada',
		expiresAt: 1_700_003_600,
	};

	it('maps a member credential to exactly the five spec fields', async () => {
		const upactor = await mapToUpactor(baseInput);
		expect(Object.keys(upactor).sort()).toEqual([
			'capabilities',
			'display_hint',
			'id',
			'lifecycle',
			'provenance',
		]);
		expect(upactor.id).toBe(
			await deriveUpactorId(SCOPE_A, SUBJECT_PK, NO_PEPPER),
		);
		expect(upactor.display_hint).toBe('Ada');
		expect(upactor.capabilities.size).toBe(0);
		expect(upactor.lifecycle).toEqual({
			expires_at: new Date(1_700_003_600 * 1000),
			renewable: 'represence',
		});
		expect(upactor.provenance).toEqual({
			substrate: 'ember',
			instance: hexOf(SCOPE_A),
		});
	});

	it('threads the pepper into the derived id', async () => {
		const upactor = await mapToUpactor({ ...baseInput, pepper: PEPPER });
		expect(upactor.id).toBe(await deriveUpactorId(SCOPE_A, SUBJECT_PK, PEPPER));
	});

	it('founder root (expiresAt null) → { renewable: "never" } with expires_at absent', async () => {
		const upactor = await mapToUpactor({ ...baseInput, expiresAt: null });
		expect(upactor.lifecycle).toEqual({ renewable: 'never' });
		expect('expires_at' in upactor.lifecycle).toBe(false);
	});

	it('omits display_hint entirely when the name is null or unsafe', async () => {
		for (const leafName of [null, '', '�', 'ada@example.com']) {
			const upactor = await mapToUpactor({ ...baseInput, leafName });
			expect('display_hint' in upactor).toBe(false);
			expect(Object.keys(upactor).sort()).toEqual([
				'capabilities',
				'id',
				'lifecycle',
				'provenance',
			]);
		}
	});

	it('§7.1: forbidden substrate fields never appear, and no value leaks the raw key', async () => {
		const upactor = await mapToUpactor(baseInput);
		for (const forbidden of [
			'subjectPk',
			'pub',
			'fingerprint',
			'depth',
			'chain',
			'scopeName',
			'scope_name',
			'steward',
			'cred',
			'proof',
		]) {
			expect(upactor).not.toHaveProperty(forbidden);
		}
		const flat = JSON.stringify(upactor);
		expect(flat).not.toContain(hexOf(SUBJECT_PK).slice(0, 16));
	});
});
