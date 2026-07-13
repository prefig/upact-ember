# doorcheck

A members-only noticeboard gated by `@prefig/upact-ember`, end to end, on one
machine, offline, with zero dependencies beyond Node and the two packages
already in this repo. Plain `node:http`, ESM `.mjs`, no framework, no build
step for the example itself.

Three programs, three roles:

| file | plays | does |
| --- | --- | --- |
| `seed.mjs` | the in-person ceremony | founder creates the scope, grants a steward, the steward grants a member; writes `doorcheck-state.json` |
| `server.mjs` | the door | mints challenges, verifies proofs through the upact adapter, gates `/board` |
| `member.mjs` | the member's phone | answers a challenge with a presence proof and reads the board |

## Run it

From this directory (the package's `dist/` must exist; run `npm run build`
in the package root if it does not):

```sh
node seed.mjs      # once: the in-person ceremony, writes doorcheck-state.json
node server.mjs    # keep running: the door, http://127.0.0.1:8787/
node member.mjs    # in another terminal: present the valid credential
```

Happy path: `member.mjs` fetches a challenge, signs a proof over it with the
member key, POSTs it, receives an opaque `httpOnly` session cookie, and reads
`/board`, which shows the upactor id, the display hint, the membership
expiry, and a reminder that renewal happens in presence.

Then the lapse path:

```sh
node member.mjs --lapsed
```

This presents a credential that was granted two hours ago with one hour of
validity. The door refuses with the port-level error code
`credential_rejected`; the error message carries the substrate's own lapse
reason verbatim (it says "lapsed" and tells the holder to renew in
presence), and the phone shows what a renewal prompt would look like.
Expiry is ember's only revocation; getting readmitted means finding a
steward in person, not clicking a reset link.

You can also open `http://127.0.0.1:8787/` in a browser: the page is the
door's screen. Pressing "Present credential" mints a challenge and displays
it where the real app would show a QR code. `/board` in the browser answers
401 until a member has presented.

## What maps to what

The real ember flow is phones exchanging QR codes in the same room. Each
piece here stands in for one of those steps:

- `seed.mjs` is the ceremony that happens before any door exists: genesis,
  steward grant, member grant. In the real app each grant is a
  request/response QR handshake (`createReq`, `parseReq`, `grantCred`)
  between two people who can see each other. The state file is "what ended
  up stored on each phone".
- `GET /challenge` is the door displaying a QR. The server calls the
  adapter's `beginChallenge()`; the challenge is single use and expires in
  about two minutes.
- `member.mjs` is the holder side, using only ember holder primitives
  (`parseChal`, `createProof`). The adapter package never appears on the
  member's side of the wire.
- `POST /present` is the member showing the answering QR. The server calls
  `adapter.authenticate(...)` and either sets an opaque session cookie or
  relays the `AuthError` code and message.
- `GET /board` is the capability-gated resource. The server calls
  `adapter.currentUpactor(...)`; `null` means 401 with a friendly message,
  anything else is a member in good standing.

The adapter is encounter-bound: one instance is one verified encounter at
the door. The server therefore creates a fresh adapter per challenge and
keeps it behind the cookie token, which is how the upact spec intends this
substrate to be held.

## What is deliberately faked

- The QR transport. Bytes that would travel by camera travel by localhost
  HTTP instead. Nothing about the verification changes: the proof still
  binds the challenge nonce and the audience string, and replaying it fails.
- Both roles run on one machine, and the member's private key sits in a JSON
  file next to the server. Real holders keep keys on their own device;
  `doorcheck-state.json` is a demo artifact, not a pattern.
- Sessions live in server memory and vanish on restart. Fine for a demo of a
  protocol whose sessions are meant to be encounter-scoped anyway.
- The lapsed credential is seeded with a backdated grant so you do not have
  to wait an hour for a real lapse.

## Cleanup

Stop the server and delete `doorcheck-state.json`. Nothing else is written.
