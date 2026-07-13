// SPDX-License-Identifier: Apache-2.0
/**
 * Test-only ceremony builder: drives a REAL `@prefig/ember` ceremony (the
 * substrate is pure, offline, and dependency-free, so unit tests are
 * end-to-end). Produces genesis, founder credential, steward grant, member
 * credential, plus challenge/proof/presentation builders — all against an
 * injectable clock so tests have zero wall-clock dependence.
 *
 * Renewal note for holder-app authors (documented, not enforced by the
 * verifier): the subject-side nonce-echo check — `links[last].nonce` must
 * answer the nonce of the member's own `createReq` — is a holder/steward
 * obligation. The verifier made no request, so the adapter does not check
 * it; `renewMember` below performs the full createReq -> parseReq ->
 * grantCred ceremony, which produces a correctly echoed nonce.
 */

import {
	createChal,
	createGenesis,
	createPresentation,
	createProof,
	createReq,
	founderCred,
	generateIdentity,
	grantCred,
	parseChal,
	parseGenesis,
	parseReq,
	type Identity,
} from '@prefig/ember';

/** Injectable test clock, UNIX seconds. */
export interface CeremonyClock {
	now(): number;
	set(atS: number): void;
	advance(deltaS: number): void;
}

/** Create a settable clock starting at `startS` (default 1_700_000_000). */
export function createClock(startS: number = 1_700_000_000): CeremonyClock {
	let t = startS;
	return {
		now: () => t,
		set: (atS: number) => {
			t = atS;
		},
		advance: (deltaS: number) => {
			t += deltaS;
		},
	};
}

export interface CeremonyOptions {
	/** Scope name in the genesis record. Default 'test-scope'. */
	scopeName?: string;
	/** Steward's self-chosen name on the founder's grant. Default 'Steward'. */
	stewardName?: string;
	/** Member's self-chosen name on the steward's grant. Default 'Member'. */
	memberName?: string;
	/** Scope renewal ttl in seconds. Default 3600. */
	ttl?: number;
	/** Scope max chain depth. Default 3. */
	maxDepth?: number;
	/** Injectable clock; a fresh one is created when omitted. */
	clock?: CeremonyClock;
}

export interface Ceremony {
	founder: Identity;
	steward: Identity;
	member: Identity;
	/** The scope's genesis record bytes — the adapter's trust anchor. */
	genesisBytes: Uint8Array;
	/** The scope's 16-byte id (parsed from the genesis). */
	scopeId: Uint8Array;
	/** Founder's own credential: the bare genesis, no links (depth 0). */
	founderCredBytes: Uint8Array;
	/** Steward's credential: founder grant at depth 1 (steward: true). */
	stewardCredBytes: Uint8Array;
	/** Member's credential: steward grant at depth 2 (steward: false). */
	memberCredBytes: Uint8Array;
	/** The clock every ceremony step was driven by. */
	clock: CeremonyClock;
}

/**
 * Build a full scope ceremony at `clock.now()`: genesis (founder-signed),
 * founder credential, founder-grants-steward, steward-grants-member.
 */
export async function buildCeremony(
	options: CeremonyOptions = {},
): Promise<Ceremony> {
	const clock = options.clock ?? createClock();
	const at = clock.now();
	const founder = await generateIdentity();
	const steward = await generateIdentity();
	const member = await generateIdentity();

	const genesisBytes = await createGenesis({
		name: options.scopeName ?? 'test-scope',
		ttl: options.ttl ?? 3600,
		maxDepth: options.maxDepth ?? 3,
		identity: founder,
		at,
	});
	const scopeId = parseGenesis(genesisBytes).scopeId;
	const founderCredBytes = founderCred(genesisBytes);

	const stewardCredBytes = await renewMember({
		granterCredBytes: founderCredBytes,
		granter: founder,
		subject: steward,
		name: options.stewardName ?? 'Steward',
		scopeId,
		at,
		asSteward: true,
	});
	const memberCredBytes = await renewMember({
		granterCredBytes: stewardCredBytes,
		granter: steward,
		subject: member,
		name: options.memberName ?? 'Member',
		scopeId,
		at,
		asSteward: false,
	});

	return {
		founder,
		steward,
		member,
		genesisBytes,
		scopeId,
		founderCredBytes,
		stewardCredBytes,
		memberCredBytes,
		clock,
	};
}

/**
 * The out-of-band member <-> steward renewal ceremony:
 * createReq -> parseReq -> grantCred. Returns the subject's new credential
 * bytes. Used both to build the initial chain and to renew a lapsed member.
 */
export async function renewMember(opts: {
	granterCredBytes: Uint8Array;
	granter: Identity;
	subject: Identity;
	name: string;
	scopeId: Uint8Array | null;
	at: number;
	asSteward?: boolean;
	ttlOverride?: number;
}): Promise<Uint8Array> {
	const req = await createReq({
		scopeId: opts.scopeId,
		identity: opts.subject,
		name: opts.name,
	});
	const parsed = await parseReq(req.bytes);
	return grantCred({
		granterCredBytes: opts.granterCredBytes,
		identity: opts.granter,
		req: parsed,
		at: opts.at,
		...(opts.ttlOverride !== undefined ? { ttlOverride: opts.ttlOverride } : {}),
		asSteward: opts.asSteward ?? true,
	});
}

/**
 * Holder side: answer a verifier challenge (wire bytes, e.g. from the
 * adapter's `beginChallenge`) with a single-scope presence proof over
 * `credBytes`, echoing the challenge's nonce and audience.
 */
export async function answerChallenge(opts: {
	challenge: Uint8Array;
	credBytes: Uint8Array;
	identity: Identity;
	at: number;
}): Promise<Uint8Array> {
	const chal = parseChal(opts.challenge);
	return createProof({
		credBytes: opts.credBytes,
		nonce: chal.nonce,
		identity: opts.identity,
		aud: chal.aud,
		iat: opts.at,
	});
}

/**
 * Holder side: answer a verifier challenge with a multi-scope portfolio
 * presentation carrying every credential in `creds` that is valid at `at`
 * and belongs to `identity`.
 */
export async function presentPortfolio(opts: {
	challenge: Uint8Array;
	creds: Uint8Array[];
	identity: Identity;
	at: number;
	/** Optional hex scope-id restriction, as ember's createPresentation takes. */
	scopes?: string[] | null;
}): Promise<Uint8Array> {
	const chal = parseChal(opts.challenge);
	return createPresentation({
		creds: opts.creds,
		identity: opts.identity,
		nonce: chal.nonce,
		audience: chal.aud,
		at: opts.at,
		scopes: opts.scopes ?? null,
	});
}

/**
 * Verifier-independent challenge minting for tests that need a nonce the
 * adapter did NOT register (hostile vectors). Mirrors ember `createChal`.
 */
export function mintForeignChallenge(opts: {
	scopeId: Uint8Array | null;
	aud: string;
	at: number;
}): { bytes: Uint8Array; nonce: Uint8Array } {
	const chal = createChal({ scopeId: opts.scopeId, aud: opts.aud, at: opts.at });
	return { bytes: chal.bytes, nonce: chal.nonce };
}
