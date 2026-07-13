// SPDX-License-Identifier: Apache-2.0
/**
 * Nonce registry tests: single-use consumption, TTL sweep with an explicit
 * clock, bounded-size eviction, and cross-instance isolation.
 */

import { describe, expect, it } from 'vitest';
import { createNonceRegistry } from '../src/nonce-registry.js';

const T0 = 1_700_000_000;
const TTL = 150; // maxProofAgeS + clockSkewS shape

describe('nonce registry: single use', () => {
	it('consumes a pending nonce exactly once; the second consume fails', () => {
		const registry = createNonceRegistry(TTL);
		registry.register('aa'.repeat(16), T0);
		expect(registry.consume('aa'.repeat(16), T0 + 1)).toBe(true);
		expect(registry.consume('aa'.repeat(16), T0 + 2)).toBe(false);
		expect(registry.size()).toBe(0);
	});

	it('rejects a nonce it never minted', () => {
		const registry = createNonceRegistry(TTL);
		registry.register('aa'.repeat(16), T0);
		expect(registry.consume('bb'.repeat(16), T0 + 1)).toBe(false);
		// The unknown probe must not disturb the genuinely pending nonce.
		expect(registry.consume('aa'.repeat(16), T0 + 2)).toBe(true);
	});

	it('deletes the entry even when the consume fails on expiry (no oracle retry)', () => {
		const registry = createNonceRegistry(TTL);
		registry.register('cc'.repeat(16), T0);
		expect(registry.consume('cc'.repeat(16), T0 + TTL + 1)).toBe(false);
		expect(registry.size()).toBe(0);
		expect(registry.consume('cc'.repeat(16), T0 + TTL + 2)).toBe(false);
	});
});

describe('nonce registry: TTL window', () => {
	it('accepts a consume exactly at the TTL boundary and rejects one past it', () => {
		const atBoundary = createNonceRegistry(TTL);
		atBoundary.register('01'.repeat(16), T0);
		expect(atBoundary.consume('01'.repeat(16), T0 + TTL)).toBe(true);

		const pastBoundary = createNonceRegistry(TTL);
		pastBoundary.register('01'.repeat(16), T0);
		expect(pastBoundary.consume('01'.repeat(16), T0 + TTL + 1)).toBe(false);
	});

	it('prune drops only entries older than the TTL at the given time', () => {
		const registry = createNonceRegistry(TTL);
		registry.register('old0'.padEnd(32, '0'), T0);
		registry.register('old1'.padEnd(32, '0'), T0 + 10);
		registry.register('new0'.padEnd(32, '0'), T0 + 100);
		expect(registry.size()).toBe(3);

		registry.prune(T0 + TTL + 5); // old0 aged out; old1, new0 survive
		expect(registry.size()).toBe(2);
		expect(registry.consume('old0'.padEnd(32, '0'), T0 + TTL + 5)).toBe(false);
		expect(registry.consume('old1'.padEnd(32, '0'), T0 + TTL + 5)).toBe(true);
		expect(registry.consume('new0'.padEnd(32, '0'), T0 + TTL + 5)).toBe(true);
	});

	it('register sweeps expired entries as the clock advances', () => {
		const registry = createNonceRegistry(TTL);
		registry.register('stale'.padEnd(32, '0'), T0);
		// A later register at t > T0 + TTL prunes the stale entry in passing.
		registry.register('fresh'.padEnd(32, '0'), T0 + TTL + 50);
		expect(registry.size()).toBe(1);
		expect(registry.consume('stale'.padEnd(32, '0'), T0 + TTL + 51)).toBe(
			false,
		);
	});
});

describe('nonce registry: bounded size', () => {
	it('never exceeds the cap and evicts the oldest pending entry', () => {
		const registry = createNonceRegistry(TTL, 3);
		registry.register('n0'.padEnd(32, '0'), T0);
		registry.register('n1'.padEnd(32, '0'), T0 + 1);
		registry.register('n2'.padEnd(32, '0'), T0 + 2);
		expect(registry.size()).toBe(3);

		registry.register('n3'.padEnd(32, '0'), T0 + 3);
		expect(registry.size()).toBe(3);

		// Oldest (n0) evicted; the newer three still answerable.
		expect(registry.consume('n0'.padEnd(32, '0'), T0 + 4)).toBe(false);
		expect(registry.consume('n1'.padEnd(32, '0'), T0 + 4)).toBe(true);
		expect(registry.consume('n2'.padEnd(32, '0'), T0 + 4)).toBe(true);
		expect(registry.consume('n3'.padEnd(32, '0'), T0 + 4)).toBe(true);
	});

	it('a flood evicts in insertion order, keeping only the newest cap entries', () => {
		const registry = createNonceRegistry(TTL, 2);
		for (let i = 0; i < 10; i++) {
			registry.register(`f${i}`.padEnd(32, '0'), T0 + i);
		}
		expect(registry.size()).toBe(2);
		expect(registry.consume('f7'.padEnd(32, '0'), T0 + 10)).toBe(false);
		expect(registry.consume('f8'.padEnd(32, '0'), T0 + 10)).toBe(true);
		expect(registry.consume('f9'.padEnd(32, '0'), T0 + 10)).toBe(true);
	});
});

describe('nonce registry: cross-instance isolation', () => {
	it('a nonce registered in one registry is not answerable in another', () => {
		const a = createNonceRegistry(TTL);
		const b = createNonceRegistry(TTL);
		a.register('shared'.padEnd(32, '0'), T0);

		expect(b.size()).toBe(0);
		expect(b.consume('shared'.padEnd(32, '0'), T0 + 1)).toBe(false);
		// The foreign probe must not consume A's pending nonce.
		expect(a.consume('shared'.padEnd(32, '0'), T0 + 2)).toBe(true);
	});
});
