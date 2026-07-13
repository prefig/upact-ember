// SPDX-License-Identifier: Apache-2.0
/**
 * Module-private pending-challenge registry.
 *
 * Ember's protocol.js documents "the verifier must keep the nonce it minted"
 * as a verifier obligation; the adapter owns it rather than delegating replay
 * protection to the app. Nonces are SINGLE-USE: consumed (deleted) on first
 * lookup, success or failure — this kills replay and oracle probing. The
 * registry is bounded (evict oldest) and TTL-swept with an injectable clock.
 *
 * Not exported from the package entry (upact SPEC.md §7.5 back-channel
 * closure): one registry lives per adapter instance, inside the factory
 * closure.
 */

export interface NonceRegistry {
	/** Record a freshly minted nonce as pending. Prunes, then bounds. */
	register(nonceHex: string, mintedAt: number): void;
	/**
	 * Look up AND CONSUME a nonce. Returns true only if it was pending and
	 * within the TTL window; the entry is deleted either way.
	 */
	consume(nonceHex: string, at: number): boolean;
	/** Drop entries older than the TTL window at time `at`. */
	prune(at: number): void;
	/** Number of pending nonces (test observability). */
	size(): number;
}

/**
 * Create a bounded, TTL-swept, single-use nonce registry.
 *
 * @param ttlS  window in seconds a pending nonce stays answerable
 *              (adapter passes `maxProofAgeS + clockSkewS`).
 * @param cap   maximum pending entries; the oldest is evicted past it.
 */
export function createNonceRegistry(
	ttlS: number,
	cap: number = 1024,
): NonceRegistry {
	// Map preserves insertion order, so the first key is the oldest entry.
	const pending = new Map<string, number>();

	function prune(at: number): void {
		for (const [key, mintedAt] of pending) {
			if (at - mintedAt > ttlS) pending.delete(key);
		}
	}

	function register(nonceHex: string, mintedAt: number): void {
		prune(mintedAt);
		if (pending.size >= cap) {
			const oldest = pending.keys().next();
			if (!oldest.done) pending.delete(oldest.value);
		}
		pending.set(nonceHex, mintedAt);
	}

	function consume(nonceHex: string, at: number): boolean {
		prune(at);
		const mintedAt = pending.get(nonceHex);
		pending.delete(nonceHex);
		if (mintedAt === undefined) return false;
		return at - mintedAt <= ttlS;
	}

	return {
		register,
		consume,
		prune,
		size: () => pending.size,
	};
}
