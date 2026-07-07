

# Cryptographic Architecture Overview

This document outlines the core cryptographic components and the integrated data flow used to achieve private, verifiable message filtering.

---

## 1. Component Breakdown

### Poseidon Hash Function

A hash function takes an arbitrary input and produces a fixed-size fingerprint. It is deterministic (the same input always yields the same output) and one-way (irreversible). While standard hash functions like SHA-256 exist, **Poseidon** is designed specifically to be computationally cheap inside a **zero-knowledge (ZK) circuit**.

* **The Problem with SHA-256:** It relies on bitwise operations (XOR, bit rotations, AND). These are trivial for a standard CPU but brutally expensive to express as arithmetic constraints (additions and multiplications over a large prime field) inside ZK circuits. Every XOR must be decomposed into numerous field operations.
* **The Poseidon Advantage:** It is built entirely from field-native operations from the ground up (additions, multiplications, and a nonlinear step). Consequently, representing it inside a circuit costs a fraction of what SHA-256 would.

> **Key Takeaway:** Poseidon is optimized for being "cheap to prove" rather than for raw hardware speed. Inside your protocol, it computes $h = \text{Poseidon}(m, r)$ directly within the proof circuit to demonstrate: *"I know a message $m$ and blinding factor $r$ that hash to this specific $h$."*

### Associated Data (AD)

Associated Data is a native feature of Authenticated Encryption with Associated Data (AEAD) schemes—the encryption framework underlying Signal-style protocols (like the Double Ratchet).

Standard encryption takes a key and plaintext to output a ciphertext and an authentication tag. AD acts as an optional third input: **extra data that remains unencrypted (travels in the clear) but is cryptographically bound to the ciphertext via the authentication tag.**

```
[Key] + [Plaintext] + [Associated Data (AD)] ---> [Ciphertext] + [Authentication Tag]

```

* **Integrity Enforcement:** If you encrypt message $m$ under key $K$ with $\text{AD} = h$, decryption will *only* succeed if the receiver provides that exact same $h$. Tweaking even a single bit of the AD causes the tag verification to fail, aborting decryption.
* **Protocol Fit:** The Double Ratchet automatically computes an authentication tag over `(ciphertext, AD)`. By assigning $\text{AD} = (h, r)$, the message fingerprint safely accompanies the payload. Any tampering with the fingerprint breaks decryption automatically, without requiring modifications to the ratchet's internal logic.

### Plonky2

Plonky2 is the proving system—the underlying machinery that transforms the statement *"I know secret values satisfying these constraints"* into a compact, easily verifiable proof ($\pi$) without exposing the underlying secrets.

Two properties make it ideal for this use case:

1. **Transparent Setup:** Unlike systems like Groth16, Plonky2 does not require a one-time "trusted setup" ceremony per circuit. If you modify the circuit (e.g., updating the classification model), you do not need to redo any cryptographic setup.
2. **Fast Proving & Native Rust:** It is one of the fastest available provers for circuits of this scale. Because your CLI is built in Rust, it integrates natively without needing awkward language bridges.

> **Circuit Logic:** Inside Plonky2, you define the constraints:
> *Given public values $\theta, b, \tau, h$ and private (secret) witnesses $m, r$, verify that:*
> 
> $$C_\theta(\phi(m)) = 1 \quad \text{AND} \quad \text{Poseidon}(m, r) = h$$
> 
> 

---

## 2. Integrated Data Flow

The following sequence details how the components interact across the sender, server, and receiver during a single message transmission.

### Phase 1: Local Sender Operations

1. **Feature Extraction:** The sender takes plaintext $m$ and generates a random blinding factor $r$. They compute the feature vector $f = \phi(m)$ locally as a plain computation (outside the ZK circuit).
2. **Proof Generation:** The sender feeds $(m, r, f)$ as private witnesses and $(\theta, b, \tau)$ as public inputs into the Plonky2 circuit. The circuit internally:
* Computes $C_\theta(f)$ and verifies it equals $1$ (passing the filter).
* Computes $\text{Poseidon}(m, r)$ and verifies it matches the public output $h$.


3. **Output:** The Plonky2 prover outputs the fingerprint and proof pair: $(h, \pi)$. Neither value leaks the contents of $m$.
4. **Payload Encryption:** The sender invokes the standard Double Ratchet encryption function on $m$, setting $\text{AD} = (h, r)$ to output `(ciphertext, tag)`.
5. **Transmission:** The sender transmits the final bundle to the server:

$$\text{Payload} = (\text{ciphertext}, \text{tag}, h, r, \pi)$$



### Phase 2: Server Verification

1. **Validation:** The server runs the Plonky2 verifier on the public inputs $(\theta, b, \tau, h, \pi)$. This operation is fast, lightweight, and requires no access to the plaintext $m$.
2. **Routing:** * **If valid:** The server forwards $(\text{ciphertext}, \text{tag}, h, r)$ to the receiver.
* **If invalid:** The payload is dropped.
* *Note: The server never decrypts the payload and never sees $m$.*



### Phase 3: Receiver Decryption & Binding Check

1. **AEAD Decryption:** The receiver attempts to decrypt the ciphertext using the provided $\text{AD} = (h, r)$. If $h$ or $r$ were altered during transit, decryption fails immediately. Successful decryption yields the plaintext $m$.
2. **Equivalence Check:** The receiver independently recomputes $\text{Poseidon}(m, r)$ via plain local computation (no ZK circuit required) and verifies that the output matches the transmitted $h$.
* **Match:** The message is verified as the exact payload cleared by the sender's local ZK proof.
* **Mismatch:** The message is rejected, catching a malicious sender who proved validity for one message but transmitted another.
