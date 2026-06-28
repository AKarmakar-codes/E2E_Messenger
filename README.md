# E2E Messenger — End-to-End Encrypted Chat in Rust

A from-scratch implementation of the [Signal Protocol](https://signal.org/docs/) in Rust — the same cryptographic foundation used by Signal, WhatsApp, and iMessage. Two users can exchange encrypted messages through an untrusted relay server, and the system provides **forward secrecy** and **break-in recovery** by design.

---

## Quickstart

You need three terminals.

**Terminal 1 — Relay Server**
```bash
cargo run -p server
# Server running on http://127.0.0.1:3000
```

**Terminal 2 — Alice**
```bash
cargo run -p client -- alice
# No state found. Creating new state for alice...
# Registered and published prekey bundle for alice
# Logged in as alice.
# Type /send <recipient> <message> to send a message.
# Type /exit or /quit to quit.
> /send bob Hey Bob, this is end-to-end encrypted!
```

**Terminal 3 — Bob**
```bash
cargo run -p client -- bob
# No state found. Creating new state for bob...
# Registered and published prekey bundle for bob
# Logged in as bob.
> 
# [alice] Hey Bob, this is end-to-end encrypted!
```

**Interactive commands:**
- `/send <recipient> <message>` — Encrypt and send a message.
- `/exit` or `/quit` — Exit the client.

Incoming messages are received automatically via background polling — no manual refresh needed.

---

## How It Works

This project implements two protocols in sequence.

### X3DH — Extended Triple Diffie-Hellman (Phase 2)

X3DH solves the **asynchronous key establishment problem**: how can Alice and Bob agree on a shared secret without Bob being online?

Bob pre-publishes a bundle of public keys to the relay server:
- **IK** — his long-term identity key
- **SPK** — a signed prekey (rotated periodically)
- **OPK** — a one-time prekey (consumed once and never reused)

When Alice wants to message Bob for the first time, she fetches his bundle and computes four Diffie-Hellman operations using her own ephemeral key and Bob's public keys. Bob can compute the same four DH outputs from his private keys. Both sides run the combined output through HKDF to derive an identical 32-byte shared secret `SK` — without ever having exchanged a symmetric key.

### Double Ratchet (Phase 3)

X3DH gives one shared secret. The Double Ratchet uses that secret to derive **a fresh encryption key for every single message**, then immediately discard it.

Two ratchets run simultaneously:
- **Symmetric-key ratchet**: Each message advances a KDF chain, yielding a new one-time message key `mk` and a new chain key `ck`. Once used, `mk` is deleted.
- **Diffie-Hellman ratchet**: Each reply includes a fresh DH public key. Seeing it triggers a root-key update, breaking the chain entirely from the attacker's perspective.

This gives two concrete guarantees:
1. **Forward secrecy** — Compromising today's keys reveals nothing about past messages; their keys are already gone.
2. **Break-in recovery** — After a compromise, the DH ratchet heals the session within two messages.

---

## Forward-Secrecy Proof (Live Demo)

After Bob receives two or more sequential messages from the same sender, the client automatically prints a cryptographic proof to the terminal:

```
[alice] Message 1
[alice] Message 2
┌─ [Forward-Secrecy Proof] ─────────────────────────────┐
│  Current msg key (mk):  0x3a7f2c1d9e4b0f8a...  │
│  Attempting to decrypt PREVIOUS message with this key: │
│  ✓ FAILED as expected: AEAD decryption failed: Error  │
│  Previous message key was discarded — proof complete.  │
└────────────────────────────────────────────────────────┘
```

This proves that message key #2 cannot decrypt message #1. The key for message #1 was derived, used once, and permanently discarded. No amount of future key compromise can retroactively recover it.

---

## Session Persistence (Phase 7)

Client state — including identity keys, Double Ratchet session parameters, chain keys, and message counters — is automatically serialized to `<username>_state.json` after every message. Kill the client at any point and restart it; it will resume the ratchet session exactly where it left off and drain any queued inbox messages.

```bash
# Kill bob (Ctrl+C), then restart:
cargo run -p client -- bob
# Loaded existing session state for bob
# [alice] Messages sent while offline...
```

---

## Architecture

```
E2E/
├── crypto-core/    # All cryptographic primitives and protocols
│   ├── X3DH key derivation (x3dh_alice_derive, x3dh_bob_derive)
│   ├── Double Ratchet state machine (DoubleRatchet)
│   └── Primitives: X25519, Ed25519, ChaCha20-Poly1305, HKDF
│
├── server/         # Dumb relay — never sees plaintext
│   ├── POST /register           — register a username
│   ├── POST /bundles/:user      — publish a prekey bundle
│   ├── GET  /bundles/:user      — fetch a bundle (consumes one OPK)
│   ├── POST /inbox/:user        — enqueue an encrypted message
│   └── GET  /inbox/:user        — drain inbox (returns & clears)
│
└── client/         # Interactive CLI with background polling
    ├── First run: generate keys, register, publish bundle
    ├── Resume:    load state from <username>_state.json
    ├── Background task polls inbox every 1 second
    └── REPL: /send <recipient> <msg>
```

## Crate Dependencies

| Crate | Purpose |
|---|---|
| `x25519-dalek` | X25519 Diffie-Hellman |
| `ed25519-dalek` | Ed25519 signatures (SPK verification) |
| `chacha20poly1305` | AEAD encryption (ChaCha20-Poly1305) |
| `hkdf` + `sha2` | HKDF key derivation |
| `axum` + `tokio` | Async HTTP server |
| `reqwest` | HTTP client |
| `serde` + `serde_json` | Serialization for state and API types |
| `rand` | Cryptographic randomness |

---

## Running the Tests

```bash
cargo test -p crypto-core
```

All 12 unit tests covering RFC test vectors, X3DH, and the full Double Ratchet protocol (in-order, out-of-order, dropped, simultaneous send, serialization resume).
