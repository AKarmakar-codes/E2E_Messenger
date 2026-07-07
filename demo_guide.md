

### Step-by-Step Live Demo Guide

To run a full demo of the end-to-end encrypted messenger with forward-secrecy proofs and session persistence, follow these steps using three separate terminal windows:

#### Step 1: Restart the Relay Server (Terminal 1)
Since the server was already running with the old code, you need to restart it so the route fix takes effect:
1. In the terminal running the server, press `Ctrl+C` to terminate the process.
2. Restart it:
   ```bash
   cargo run -p server
   ```
   *Expected Output:*
   ```text
   Server running on http://127.0.0.1:3000
   ```

#### Step 2: Start Alice (Terminal 2)
In a new terminal window, start Alice's client:
```bash
cargo run -p client -- alice
```
*Expected Output:*
```text
No state found. Creating new state for alice...
Registered and published prekey bundle for alice
Logged in as alice.
Type /send <recipient> <message> to send a message.
Type /exit or /quit to quit.
> 
```

#### Step 3: Start Bob (Terminal 3)
In a third terminal window, start Bob's client:
```bash
cargo run -p client -- bob
```
*Expected Output:*
```text
No state found. Creating new state for bob...
Registered and published prekey bundle for bob
Logged in as bob.
> 
```

#### Step 4: Send Messages & Verify Forward Secrecy
1. In **Alice's terminal** (Terminal 2), send a message to Bob:
   ```text
   > /send bob Hello Bob, this is encrypted!
   ```
   *Bob's terminal will automatically print:*
   ```text
   [alice] Hello Bob, this is encrypted!
   ```
2. In **Alice's terminal**, send a second consecutive message:
   ```text
   > /send bob Here is another message.
   ```
   *Bob's terminal will print the message and automatically output the cryptographic **Forward-Secrecy Proof**:*
   ```text
   [alice] Here is another message.
   ┌─ [Forward-Secrecy Proof] ─────────────────────────────┐
   │  Current msg key (mk):  0x6fa1d90c2834eb92...  │
   │  Attempting to decrypt PREVIOUS message with this key: │
   │  ✓ FAILED as expected: AEAD decryption failed: Error  │
   │  Previous message key was discarded — proof complete.  │
   └────────────────────────────────────────────────────────┘
   ```
   This confirms that the key for the first message was

[ignoring loop detection]

The issue you encountered (`Error: "Publishing prekey bundle failed: 404 Not Found"`) was caused by a syntax mismatch in `server/src/main.rs`. The server crate uses `axum = "0.7"`, which expects route parameters to be prefixed with a colon (e.g., `:user`) rather than brackets (e.g., `{user}`). I have corrected this in `server/src/main.rs` to use `:user`.

---

### Step-by-Step Live Demo Guide

To run a full demo of the end-to-end encrypted messenger, follow these steps using three separate terminal windows:

#### Step 1: Restart the Relay Server (Terminal 1)
Since the server was already running, you need to restart it so the route fix takes effect:
1. In the terminal running the server, press `Ctrl+C` to terminate the process.
2. Restart it:
   ```bash
   cargo run -p server
   ```

#### Step 2: Start Alice (Terminal 2)
In a new terminal window, start Alice's client:
```bash
cargo run -p client -- alice
```

#### Step 3: Start Bob (Terminal 3)
In a third terminal window, start Bob's client:
```bash
cargo run -p client -- bob
```

#### Step 4: Send Messages & Verify Forward Secrecy
1. In **Alice's terminal**, send a message to Bob:
   ```text
   > /send bob Hello Bob!
   ```
   *Bob's terminal will automatically print:*
   ```text
   [alice] Hello Bob!
   ```
2. In **Alice's terminal**, send a second consecutive message:
   ```text
   > /send bob Here is another message.
   ```
   *Bob's terminal will print the message and output the cryptographic **Forward-Secrecy Proof** showing that the key for the first message has been deleted and cannot be retroactively decrypted.*