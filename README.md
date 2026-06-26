# E2E Encrypted Messenger — Phase-Wise Implementation Plan

**Scope decision that solves your frontend problem:** this whole project is two CLI
programs talking to each other through a relay server. No browser, no React, no
HTML. The only "frontend" is a terminal. This means you genuinely don't need any
frontend skills for the core deliverable — it removes that whole problem rather
than asking you to learn it. A GUI is listed as an optional Phase 9 at the very
end, only if you want it later.

"Backend" here is also smaller than the word suggests: one Rust web server with
4–5 endpoints, holding nothing but public keys and encrypted blobs it can't read.
I've added a short primer (Phase 4) before you touch it, since that's the one
genuinely new domain (HTTP, client-server, async).

Assumed starting point: comfortable with basic Rust syntax (structs, traits,
`Result`/`Option`, modules). Not assumed: anything about networking, web
frameworks, or async Rust — those get explained as you reach them.

---

## Phase 0 — Environment & Project Skeleton

**Goal:** a working Rust workspace, before any crypto code exists.

**Tools:**
- `rustup` — installs and manages Rust toolchains
- `cargo` — Rust's build tool/package manager (you'll live in this)
- VS Code + `rust-analyzer` extension (or RustRover) — gives you inline type info and error squiggles, which matters a lot when juggling crypto types
- `git` — even solo, commit after every passing test. You will want to bisect later when the ratchet misbehaves.

**What to set up:**
```
e2e-messenger/            <- cargo workspace
├── Cargo.toml             <- [workspace] members = ["crypto-core", "client", "server"]
├── crypto-core/           <- pure crypto logic, no networking, no I/O
├── client/                <- CLI binary, depends on crypto-core
└── server/                <- relay binary, depends on crypto-core (for types only)
```
Splitting into 3 crates from day one matters: `crypto-core` should compile and
pass tests with zero knowledge of HTTP. That separation is what lets you debug
crypto and networking independently later (this is the "don't fight two fires
at once" principle the whole plan is built around).

**Deliverable:** `cargo build` succeeds across the workspace with empty stub crates. Commit.

---

## Phase 1 — Crypto Primitive Wrappers

**Goal:** thin, tested wrapper functions around each primitive. Boring on purpose — this phase exists so that later, if something breaks, you already know it's not the cipher.

**Crates (add via `cargo add <name>` inside `crypto-core` — this always grabs the current stable version, so you don't need to hunt for version numbers):**
- `x25519-dalek` — X25519 Diffie-Hellman
- `ed25519-dalek` — signing/verification (used for the signed-prekey signature)
- `chacha20poly1305` — authenticated encryption (the actual message cipher)
- `hkdf` — key derivation
- `sha2` — hash function HKDF needs underneath
- `rand_core` + `OsRng` (from `rand`) — secure randomness for key generation
- `zeroize` (optional but recommended) — wipes key material from memory when dropped, instead of leaving it sitting in RAM

**What to write:** one function each for: `dh(private, public) -> SharedSecret`, `hkdf_derive(input, info, len) -> Vec<u8>`, `aead_seal(key, nonce, plaintext, aad) -> ciphertext`, `aead_open(...)`, `sign`/`verify`.

**Validate against:** RFC 7748 (X25519 test vectors), RFC 5869 (HKDF test vectors), RFC 8439 (ChaCha20-Poly1305 test vectors). Paste the vectors straight into unit tests — if your wrapper doesn't reproduce the published output, stop here, don't move on.

**Deliverable:** `cargo test` green, all primitives pinned to spec test vectors.

---

## Phase 2 — X3DH, Fully Offline

**Goal:** Alice and Bob derive the *same* shared secret with no server involved.

**Crates:** nothing new — reuses Phase 1 wrappers. Add `serde` + `serde_json` now (you'll need them repeatedly) to represent the prekey bundle as a struct you can later send over the wire.

**What to build:**
- A `KeyBundle` struct: identity key (IK), signed prekey (SPK) + its signature, one one-time prekey (OPK)
- Alice's side: generate ephemeral key (EK), compute DH1=IK_A·SPK_B, DH2=EK_A·IK_B, DH3=EK_A·SPK_B, DH4=EK_A·OPK_B, then `SK = HKDF(DH1‖DH2‖DH3‖DH4)`
- Bob's side: same four DHs computed from his private keys + Alice's public IK/EK, same HKDF
- One test binary/test function: `assert_eq!(sk_alice, sk_bob)`

**Deliverable:** a single passing assertion. No networking, no server — this is the whole phase.

---

## Phase 3 — Double Ratchet, Fully Offline

**This is the hard phase and where most of your debugging time will go. Budget more time here than it looks like it needs.**

**Crates:** still nothing new beyond Phase 1/2. You'll use plain `std::collections::HashMap` for the skipped-message-key store — no special crate needed.

**What to build, straight from the Signal spec pseudocode:**
- Root chain → sending chain, receiving chain (each a KDF chain via HKDF)
- Per-message key derivation (symmetric ratchet: one-way, key deleted after use)
- DH ratchet step: triggered whenever you see a new public key in an incoming message header
- Skipped-message-key store with a `MAX_SKIP` cap, so a flood of "future" message numbers can't make you cache unbounded keys

**Tests to write (these *are* your correctness proof, treat them as load-bearing):**
- In-order delivery
- Out-of-order delivery (message 7 arrives before 5)
- Dropped message (5 never arrives, 6/7 still decrypt)
- Simultaneous send (both sides message before either reply lands — exercises both ratchets clicking near-concurrently)

**Deliverable:** all four scenarios pass as automated tests, still with zero networking.

---

## Phase 4 — Backend Primer (new ground, slow down here)

**Goal:** understand the concepts before writing the relay, so Phase 5 is implementation, not simultaneous learning + implementation.

**Concepts, plainly:**
- **Client–server model:** the server is just a program that listens on a port and waits. A client (your CLI app) opens a connection, sends a request, gets a response, closes or keeps the connection open.
- **HTTP:** the request format almost the whole internet agrees on. A request has a *method* (`GET` = fetch something, `POST` = create/send something) and a *path* (`/inbox/alice`). A response has a status code (200 = ok, 404 = not found) and a body.
- **REST:** just a convention for mapping your actions onto HTTP methods + paths sensibly (e.g. `POST /bundles` to publish a prekey bundle, `GET /bundles/bob` to fetch one).
- **JSON:** the text format you'll send bodies in. `serde_json` converts your Rust structs to/from JSON automatically if you `#[derive(Serialize, Deserialize)]` on them.
- **async/await + tokio:** a normal Rust function blocks the whole thread while waiting (e.g. for a network reply). `tokio` is a runtime that lets thousands of waiting operations share a few threads efficiently. You mostly just need to know: mark functions `async fn`, run the program inside `#[tokio::main]`, and `.await` anything that talks to the network.

**Tools to install:** `axum` (web framework — defines routes, parses requests), `tokio` (the async runtime axum needs underneath).

**Exercise before touching the real relay:** build a throwaway "hello world" axum server with one route (`GET /ping` → returns `"pong"`), run it, and `curl http://localhost:3000/ping` from a terminal. Seeing the request/response loop work on something trivial first will make the real relay much less confusing. The official axum repo's `examples/` directory has this almost verbatim — read 2–3 of the simplest examples there.

**Deliverable:** you can explain, in your own words, what happens between you running `curl` and seeing `pong` print. That's the whole backend mental model you need for this project.

---

## Phase 5 — The Relay Server

**Goal:** a dumb store-and-forward server that only ever touches public keys and ciphertext.

**Crates:** `axum`, `tokio`, `serde`/`serde_json` (from Phase 4), plus:
- `uuid` — generate client IDs
- In-memory storage first: `std::collections::HashMap` wrapped in `tokio::sync::Mutex` (shared mutable state across concurrent requests — axum will explain in its docs why you need the lock)
- Persistent storage later (optional, only if you want the server itself to survive a restart): `rusqlite` or `sqlx` with SQLite

**Endpoints to build, one at a time, testing each with `curl` before moving to the next:**
1. `POST /register` — client registers a username
2. `POST /bundles/:user` — publish a prekey bundle (IK, SPK+sig, OPKs)
3. `GET /bundles/:user` — fetch one bundle, **consuming and deleting** one OPK from the pool (important: a OPK reused is a security bug, not just a quirk)
4. `POST /inbox/:user` — enqueue an encrypted message for a user
5. `GET /inbox/:user` — drain a user's inbox

**Deliverable:** all 5 endpoints working end-to-end via `curl`, verified manually that the server's stored data is *only* public keys + opaque bytes — never a private key, never plaintext. This property is worth writing down as a one-line comment in the code; if you ever do write this up, a reviewer will check exactly this.

---

## Phase 6 — Wiring the Clients to the Relay

**Goal:** two real CLI programs, exchanging real encrypted messages through the server you just built.

**Crates:**
- `reqwest` — HTTP *client* library (the counterpart to axum, which is the server side)
- `clap` — parses command-line arguments (`./client --name alice send bob "hello"`)
- Plain `std::io::stdin()` for a simple interactive loop if you want a chat-like REPL instead of one-shot commands

**What to build:** the client calls `reqwest` to hit the server's endpoints, feeds the bytes it gets back into your Phase 2/3 crypto-core functions, and prints decrypted plaintext to the terminal. This is the phase where your three crates finally talk to each other.

**Deliverable:** run two terminal windows, `alice` and `bob`, send messages back and forth through a server running in a third terminal, see correct plaintext on both sides.

---

## Phase 7 — Persistence & Session Resume

**Goal:** prove the "stateful networked app" claim — kill a client mid-conversation, restart it, and continue.

**Crates:**
- `serde` + `bincode` (or just `serde_json` for readability while debugging) — serialize the full ratchet state (chain keys, skipped-key store, counters) to a file
- Optionally `sled` (an embedded key-value store, no separate database process needed) if a flat file feels too crude

**Deliverable:** start `alice`, exchange a few messages, kill the process (Ctrl+C), restart it, send/receive again with no broken state. This is the single most convincing demo moment — it's the difference between "I called `encrypt()`" and "I built a stateful protocol."

---

## Phase 8 — Demo Polish & Forward-Secrecy Proof

**Goal:** package this into something a reviewer can watch in 3 minutes and immediately understand.

**What to do:**
- Write a short `README.md`: what it is, how to run the server + two clients, a one-paragraph explanation of X3DH/Double Ratchet for a non-specialist reader
- Forward-secrecy demo: deliberately dump/print one derived message key to the terminal, then show that earlier messages still don't decrypt with it (because each key is one-way derived and discarded) — this is the single most visually convincing thing you can show
- Record it: `asciinema rec` gives you a terminal-recording file that's easy to share (much lighter than screen-recording video, and the text stays copy-pasteable for anyone watching)

**Deliverable:** a recorded demo + README, plus a clean `git log` showing the phases above as a believable build history.

---

## Phase 9 — Optional Stretch: a GUI

Only pursue this if you specifically want a GUI beyond the CLI — it's not needed for the core deliverable, and the CLI demo above already satisfies "demoable, immediately understood by any reviewer."

If you do want one, given zero frontend background: pick **`egui`**, not Tauri/web tech. `egui` is pure Rust — you stay in the same language and mental model the entire project, no HTML/CSS/JS at all. Tauri would technically work too, but it reintroduces exactly the web-frontend learning curve this whole plan was designed to avoid.

---

## Rough pacing (not deadlines — just a sanity check on relative weight)

| Phase | Relative effort |
|---|---|
| 0 — Setup | smallest |
| 1 — Primitives | small |
| 2 — X3DH | small–medium |
| 3 — Double Ratchet | **largest single phase** |
| 4 — Backend primer | small |
| 5 — Relay server | medium |
| 6 — Client wiring | medium |
| 7 — Persistence | small–medium |
| 8 — Demo polish | small |
| 9 — GUI (optional) | skip unless wanted |

Phase 3 deserves roughly as much time as everything else combined — it's where the actual protocol correctness lives, and where subtle bugs (off-by-one in chain indices, mishandled simultaneous-send) hide longest.
