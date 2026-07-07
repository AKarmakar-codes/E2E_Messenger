# Revised Project Implementation Plan: Verifiable Client-Side Content Moderation

## 1. System Architecture & Security Updates

To establish a strict, cryptographically enforceable binding without heavy in-circuit overhead, the protocol utilizes a combination of proactive zero-knowledge gating and reactive cryptographic attribution.

* **Sender:** The client evaluates a public linear classifier $C_{\theta}$ on the plaintext message[cite: 3, 44]. The sender picks a random nonce $r$ and creates a Poseidon hash commitment $h = \text{Poseidon}(m, r)$ (or $h = \text{Poseidon}(\phi(m), r)$). 
* **Transport Binding:** Both $r$ and $h$ are transmitted in the unencrypted, authenticated Associated Data (AD) field of the Double Ratchet ciphertext[cite: 48].
* **Server Gating:** The server acts as a zero-knowledge middlebox, gating delivery of the ciphertext entirely on the validity of the provided proof, without ever seeing the plaintext[cite: 2, 3].
* **Receiver Verification:** Upon decryption, the recipient recomputes the hash using the decrypted message and the $r$ value from the AD field. A mismatch proves cryptographically that the sender maliciously encrypted different content than they evaluated in the proof.

**Revised Security Property:** No message clears the server without a valid proof. Any mismatch between the proved content and the delivered plaintext is cryptographically detectable and attributable by the recipient.

---

## 2. Scope & Feasibility Adjustments

To ensure the project remains achievable for a two-person team within 14 weeks, the following scoping decisions have been finalized:

| Feature / Component | Status | Notes |
| :--- | :--- | :--- |
| **Model Architecture** | **Keep** | Linear classifier using fixed-dimension feature hashing[cite: 44]. |
| **Neural Networks (MLP)** | **Cut** | Small MLPs (hidden layers, quantized ReLUs) are dropped from the scope[cite: 45]. |
| **Proof System** | **Keep** | Plonky2[cite: 54]. |
| **Alternative Systems** | **Cut** | Halo2/KZG and Groth16 benchmarking are moved to discussion/future work[cite: 57, 58]. |
| **Commitment Scheme** | **Keep** | Poseidon hash commitment with newly introduced nonce $r$[cite: 52]. |
| **Benchmarking Hardware** | **Keep** | Desktop-class CPU[cite: 63]. |
| **Mobile Hardware** | **Cut** | Phone/Termux/Raspberry Pi benchmarking is relegated to a stretch goal[cite: 63]. |
| **Adversarial Evaluation** | **Keep** | Synonym substitution, homoglyph insertion, and whitespace insertion[cite: 63]. |
| **Paraphrase Evasion** | **Cut** | Paraphrase-based evasion is difficult to standardize and cut from evaluation[cite: 63]. |
| **Feature Dimension Sweep** | **Keep** | Bound to $d \in \{64, 256, 1024\}$ to establish trends. |
| **Full Dimension Sweep**| **Cut**| Sweeping up to 2048 is unnecessary for baseline scaling trends[cite: 63]. |

---

## 3. Phase-Wise Implementation Plan

### Phase 0: Feasibility Checkpoint (Weeks 1)
*Goal: Validate the zero-knowledge circuit approach before committing to heavy engineering.*
* Manually calculate the circuit constraints required for a linear model where $d=256$, plus one Poseidon hash[cite: 60].
* Compare these constraint counts against documented per-constraint proving times for Plonky2[cite: 60].
* Make a final decision on the binding target: hashing the full message $m$ versus the feature vector $\phi(m)$.
* **Fallback Checkpoint:** If native Plonky2 circuit writing stalls by week 4, the team will pivot to using the EZKL compiler.
* **Deliverable:** A 1-page computational estimate and a formal "go/no-go" decision on the circuit approach.

### Phase 1: Classifier & Data Preparation (Weeks 1–2)
*Goal: Establish a reliable, ZK-free machine learning baseline.*
* Train the linear classifier using a public dataset, such as the Jigsaw Toxic Comment corpus or an SMS spam dataset[cite: 63].
* Lock in the hashed-feature dimension $d$. 
* **Deliverable:** A trained model (weights $\theta$, bias $b$, threshold $\tau$) and logged baseline accuracy, precision, recall, and F1 scores generated *before* any ZK constraints are applied[cite: 63, 65].

### Phase 2: Protocol Finalization (Weeks 2–3)
*Goal: Formalize the updated threat model and cryptographic binding.*
* Update the protocol architecture to reflect the receiver-side nonce check.
* Clearly document the threat model involving the X3DH and Double Ratchet protocols[cite: 29].
* Explicitly define what the system *does not* solve, including client substitution and the governance of the public model[cite: 41, 43].
* **Deliverable:** A 2–3 page design document replacing the original proposal's Sections 3 and 4, featuring a strict list of security guarantees and non-goals.

### Phase 3: Circuit Implementation (Weeks 3–6)
*Goal: Build and test the zero-knowledge proof circuit.*
* Implement the core logic—dot product, threshold comparison, and Poseidon hash—inside Plonky2's circuit builder[cite: 63].
* Leverage Plonky2's native Rust integration and fast recursive arguments[cite: 54].
* Unit-test the circuit outputs against the plaintext model using held-out examples[cite: 63].
* **Deliverable:** A working Plonky2 (or EZKL) circuit, final constraint counts, and successful proving/verification passes on test sets that perfectly match the plaintext model.

### Phase 4: CLI Integration (Weeks 6–8)
*Goal: Connect the circuit to the E2EE transport layer.*
* **Sender Terminal:** Extend the existing Double Ratchet send path to compute the feature vector $f$, generate the proof $\pi$, calculate $h$, and set the AD field to carry $(h, r)$[cite: 63].
* **Server Terminal:** Extend the relay path to parse and verify the proof before forwarding the ciphertext[cite: 63].
* **Receiver Terminal:** Implement the decryption hook that recomputes $H(m, r)$, compares it against $h$, and logs any cryptographic mismatches.
* **Deliverable:** A live 3-terminal demonstration showcasing an honest message passing end-to-end, a failing message being dropped by the server, and a forged mismatch being caught by the recipient.

### Phase 5: Benchmarking (Weeks 8–10)
*Goal: Quantify the systems cost of verifiable moderation.*
* Measure proving time, proof size, and verification time across feature dimensions $d \in \{64, 256, 1024\}$[cite: 63, 66].
* Track end-to-end added latency (median and p95) on the desktop environment[cite: 68].
* Compare the performance against the ~3s proof-generation baseline reported in zero-knowledge middlebox literature[cite: 67].
* **Deliverable:** A comprehensive set of benchmark plots and comparison tables.

### Phase 6: Adversarial Evaluation (Weeks 10–12)
*Goal: Empirically measure the real-world robustness of the public classifier.*
* Calculate the exact evasion rate against the trained model using a fixed perturbation budget (e.g., maximum edit distance)[cite: 69].
* Test specifically against synonym substitution, homoglyph insertion, and whitespace/zero-width-character insertion[cite: 63].
* **Deliverable:** Hard data quantifying the evasion rate for each perturbation class[cite: 70].

### Phase 7: Write-up & Release (Weeks 12–14)
*Goal: Finalize the academic output and open-source artifacts.*
* Assemble the results into a comprehensive paper draft[cite: 63].
* Write an explicit limitations section discussing the unresolved governance problem (who controls the model controls what is censored) and the risk of client substitution[cite: 82, 85].
* Explicitly list all scoped cuts (MLP, Halo2, mobile benchmarks, paraphrase evasion) as areas for future work.
* **Deliverable:** The final paper draft and a public open-source code repository release[cite: 63].