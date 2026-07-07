Poseidon hash
A hash function takes any input and produces a fixed-size fingerprint — same input always gives the same output, and you can't work backward from the output to the input. You already know hashes like SHA-256. Poseidon does the same job, but it's designed specifically to be cheap inside a zero-knowledge circuit.
Here's why that matters: SHA-256 is built from bitwise operations (XOR, bit rotations, AND) that are cheap for a normal CPU but brutally expensive to express as arithmetic constraints (the language ZK circuits are built in — additions and multiplications over a large prime field). Every XOR needs to be decomposed into many field operations. Poseidon is built entirely out of field-native operations from the start (additions, multiplications, and a nonlinear step), so representing it inside a circuit costs a fraction of what SHA-256 would. That's the entire reason it exists — it's a hash function optimized for "cheap to prove," not for hardware speed.
In your protocol, Poseidon is what computes h = Poseidon(m, r) — and critically, this computation happens inside the proof circuit itself, not just alongside it. The proof needs to demonstrate "I know an m and r that hash to this h" as part of the same proof that shows "and this m passes the classifier."
Associated Data (AD)
This is a feature already built into the AEAD encryption Signal-style protocols use (the encryption at the heart of the Double Ratchet). AEAD encryption normally takes a key and a plaintext, and gives you ciphertext + an authentication tag. AD is an optional third input: extra data that isn't encrypted (it travels in the clear) but is cryptographically tied to that specific ciphertext via the authentication tag.
Concretely: if you encrypt message m under key K with AD = h, then decryption only succeeds if the receiver decrypts with that exact same h as AD. Change even one bit of h, and decryption fails outright — the tag won't verify. So AD isn't secret, but it's bound: you can't swap it out after the fact without breaking the ciphertext's integrity.
That's exactly why it's useful here — the Double Ratchet already computes an authentication tag over (ciphertext, AD). By setting AD = (h, r), you get "the fingerprint travels with the message, and tampering with the fingerprint breaks decryption" for free, without touching the ratchet's internals at all.
Plonky2
This is the actual proving system — the machinery that turns "I know secret values satisfying these constraints" into a small proof that anyone can verify quickly, without seeing the secrets. Two properties matter for your use case:

Transparent setup: some proof systems (like Groth16) need a one-time "trusted setup" ceremony per circuit — if you ever change the circuit (e.g., update the classifier), you need a new ceremony, which is a real operational headache. Plonky2 needs no such ceremony, so updating the model doesn't require redoing any cryptographic setup.
Fast proving, native Rust: it's currently one of the fastest provers for circuits of this size, and since your CLI is already Rust, there's no awkward bridge between languages.

Plonky2 is where you write the actual circuit: "given public values θ, b, τ, h — and private (secret) values m, r — check that Cθ(ϕ(m)) = 1 AND Poseidon(m, r) = h." Running this circuit through Plonky2's prover gives you the proof π. Running it through the verifier (a much cheaper operation) gives a yes/no on whether π is valid, without ever seeing m or r.
How they all integrate — the full data flow

Sender, locally: has plaintext m, picks random r.
Computes f = ϕ(m) (the feature vector) — plain computation, not inside the circuit.
Feeds (m, r, f) as private witnesses and (θ, b, τ) as public inputs into the Plonky2 circuit, which internally:

Computes Cθ(f) and checks it equals 1 (passes the filter).
Computes Poseidon(m, r) and checks it equals a public output h.


Plonky2's prover outputs (h, π) — the fingerprint and the proof. Neither reveals m.
Sender calls the normal Double Ratchet encryption function on m, but sets AD = (h, r). This produces (ciphertext, tag). The tag now cryptographically locks h and r to this specific ciphertext.
Sender transmits (ciphertext, tag, h, r, π) to the server.
Server: runs Plonky2's verifier on (θ, b, τ, h, π) — cheap, fast, doesn't need m. If valid, forwards (ciphertext, tag, h, r) to the receiver. Never decrypts, never sees m.
Receiver: decrypts using AD = (h, r) as given — decryption only succeeds if h, r weren't tampered with (that's AD's job). This recovers m.
Receiver independently recomputes Poseidon(m, r) (plain computation, no circuit needed here) and checks it equals h. If it matches, the message that was proven-clean is provably the message that arrived. If not, they've caught a sender who proved one thing and sent another.