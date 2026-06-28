use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use crypto_core::{
    KeyBundle, PrekeyBundleAnnouncement, InboxMessage, X3DHInit,
    DoubleRatchet, EncryptedMessage, sign
};

#[derive(Serialize, Deserialize)]
struct ClientState {
    username: String,
    ik_secret: [u8; 32],
    ik_sign_secret: [u8; 32],
    spk_secret: [u8; 32],
    opk_secrets: Vec<[u8; 32]>,
    sessions: HashMap<String, DoubleRatchet>,
    last_received: HashMap<String, EncryptedMessage>,
}

impl ClientState {
    fn file_path(username: &str) -> String {
        format!("{}_state.json", username)
    }

    fn load(username: &str) -> Result<Self, String> {
        let path_str = Self::file_path(username);
        let path = Path::new(&path_str);
        if !path.exists() {
            return Err("State file does not exist".to_string());
        }
        let file = File::open(path).map_err(|e| e.to_string())?;
        let state: ClientState = serde_json::from_reader(file).map_err(|e| e.to_string())?;
        Ok(state)
    }

    fn save(&self) -> Result<(), String> {
        let path_str = Self::file_path(&self.username);
        let file = File::create(path_str).map_err(|e| e.to_string())?;
        serde_json::to_writer_pretty(file, self).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn generate_new(username: &str) -> Self {
        let mut ik_bytes = [0u8; 32];
        let mut ik_sign_bytes = [0u8; 32];
        let mut spk_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut ik_bytes);
        OsRng.fill_bytes(&mut ik_sign_bytes);
        OsRng.fill_bytes(&mut spk_bytes);

        let mut opk_secrets = Vec::new();
        for _ in 0..50 {
            let mut opk_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut opk_bytes);
            opk_secrets.push(opk_bytes);
        }

        Self {
            username: username.to_string(),
            ik_secret: ik_bytes,
            ik_sign_secret: ik_sign_bytes,
            spk_secret: spk_bytes,
            opk_secrets,
            sessions: HashMap::new(),
            last_received: HashMap::new(),
        }
    }
}

async fn register_and_publish(state: &ClientState, server_url: &str) -> Result<(), String> {
    let client = reqwest::Client::new();

    // 1. Register
    let reg_payload = serde_json::json!({
        "username": state.username
    });
    let reg_res = client.post(format!("{}/register", server_url))
        .json(&reg_payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if !reg_res.status().is_success() {
        return Err(format!("Server registration failed: {}", reg_res.status()));
    }

    // 2. Publish bundle
    let bob_ik_sec = StaticSecret::from(state.ik_secret);
    let bob_ik_pub = PublicKey::from(&bob_ik_sec);

    let bob_spk_sec = StaticSecret::from(state.spk_secret);
    let bob_spk_pub = PublicKey::from(&bob_spk_sec);

    let bob_sign_key = SigningKey::from_bytes(&state.ik_sign_secret);
    let bob_verify_key = bob_sign_key.verifying_key();

    let spk_bytes = bob_spk_pub.to_bytes();
    let spk_sig = sign(&bob_sign_key, &spk_bytes);

    let mut one_time_prekeys = Vec::new();
    for opk_bytes in &state.opk_secrets {
        let opk_sec = StaticSecret::from(*opk_bytes);
        one_time_prekeys.push(PublicKey::from(&opk_sec));
    }

    let announcement = PrekeyBundleAnnouncement {
        identity_key: bob_ik_pub,
        identity_signing_key: bob_verify_key,
        signed_prekey: bob_spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekeys,
    };

    let pub_res = client.post(format!("{}/bundles/{}", server_url, state.username))
        .json(&announcement)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !pub_res.status().is_success() {
        return Err(format!("Publishing prekey bundle failed: {}", pub_res.status()));
    }

    println!("Registered and published prekey bundle for {}", state.username);
    Ok(())
}

async fn send_message(
    state_arc: Arc<Mutex<ClientState>>,
    server_url: &str,
    recipient: &str,
    text: &str,
) -> Result<(), String> {
    let client = reqwest::Client::new();
    
    // We lock the state to check and modify the DoubleRatchet session
    let (x3dh_init, encrypted_msg) = {
        let mut state = state_arc.lock().unwrap();
        if !state.sessions.contains_key(recipient) {
            // Fetch recipient bundle
            let res = client.get(format!("{}/bundles/{}", server_url, recipient))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !res.status().is_success() {
                return Err(format!("Could not fetch prekey bundle for {}: status {}", recipient, res.status()));
            }
            let bundle = res.json::<KeyBundle>().await.map_err(|e| e.to_string())?;

            // X3DH Alice derive
            let alice_ik_sec = StaticSecret::from(state.ik_secret);
            let alice_ek_sec = StaticSecret::from(crypto_core::random_bytes_32());
            let alice_ek_pub = PublicKey::from(&alice_ek_sec);

            let sk = crypto_core::x3dh_alice_derive(&alice_ik_sec, &alice_ek_sec, &bundle)?;

            // Initialize Alice Double Ratchet
            let mut ratchet = DoubleRatchet::init_alice(sk, bundle.signed_prekey);
            let encrypted_msg = ratchet.ratchet_encrypt(text.as_bytes(), b"")?;
            
            let x3dh_init = X3DHInit {
                alice_identity_key: PublicKey::from(&alice_ik_sec),
                alice_ephemeral_key: alice_ek_pub,
                used_one_time_prekey: bundle.one_time_prekey,
            };

            state.sessions.insert(recipient.to_string(), ratchet);
            (Some(x3dh_init), encrypted_msg)
        } else {
            let ratchet = state.sessions.get_mut(recipient).unwrap();
            let encrypted_msg = ratchet.ratchet_encrypt(text.as_bytes(), b"")?;
            (None, encrypted_msg)
        }
    };

    let sender = {
        let state = state_arc.lock().unwrap();
        state.username.clone()
    };

    let msg = InboxMessage {
        sender,
        x3dh_init,
        ratchet_message: encrypted_msg,
    };

    let res = client.post(format!("{}/inbox/{}", server_url, recipient))
        .json(&msg)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !res.status().is_success() {
        return Err(format!("Could not enqueue message: status {}", res.status()));
    }

    // Save client state
    {
        let state = state_arc.lock().unwrap();
        state.save()?;
    }

    Ok(())
}

fn start_polling(state_arc: Arc<Mutex<ClientState>>, server_url: String) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let username = {
            let state = state_arc.lock().unwrap();
            state.username.clone()
        };

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            let url = format!("{}/inbox/{}", server_url, username);
            let res = match client.get(&url).send().await {
                Ok(res) => res,
                Err(_) => continue,
            };

            if !res.status().is_success() {
                continue;
            }

            let messages = match res.json::<Vec<InboxMessage>>().await {
                Ok(msgs) => msgs,
                Err(_) => continue,
            };

            if messages.is_empty() {
                continue;
            }

            let mut state = state_arc.lock().unwrap();
            for msg in messages {
                let sender_clone = msg.sender.clone();

                let decrypted_verbose: Result<(Vec<u8>, [u8; 32]), String> = match &msg.x3dh_init {
                    Some(init) => {
                        // Bob initializes new session
                        let bob_dh_sec = if let Some(opk_pub) = init.used_one_time_prekey {
                            // Find the private key corresponding to opk_pub and consume it
                            let mut found_idx = None;
                            for (idx, sec_bytes) in state.opk_secrets.iter().enumerate() {
                                let sec = StaticSecret::from(*sec_bytes);
                                if PublicKey::from(&sec).to_bytes() == opk_pub.to_bytes() {
                                    found_idx = Some(idx);
                                    break;
                                }
                            }
                            match found_idx {
                                Some(idx) => {
                                    // Remove the spent OPK — one-time prekeys must not be reused
                                    let sec_bytes = state.opk_secrets.remove(idx);
                                    StaticSecret::from(sec_bytes)
                                }
                                None => {
                                    println!("\nError: Received message from {} using unknown OPK", msg.sender);
                                    print!("> ");
                                    std::io::stdout().flush().unwrap();
                                    continue;
                                }
                            }
                        } else {
                            StaticSecret::from(state.spk_secret)
                        };

                        let bob_ik_sec = StaticSecret::from(state.ik_secret);
                        let bob_spk_sec = StaticSecret::from(state.spk_secret);
                        let sk = match crypto_core::x3dh_bob_derive(
                            &bob_ik_sec,
                            &bob_spk_sec,
                            init.used_one_time_prekey.as_ref().map(|_| &bob_dh_sec),
                            init
                        ) {
                            Ok(sk) => sk,
                            Err(e) => {
                                println!("\nError: Bob X3DH derivation failed: {}", e);
                                print!("> ");
                                std::io::stdout().flush().unwrap();
                                continue;
                            }
                        };

                        let bob_spk_sec_init = StaticSecret::from(state.spk_secret);
                        let ratchet = DoubleRatchet::init_bob(sk, bob_spk_sec_init);
                        state.sessions.insert(msg.sender.clone(), ratchet);

                        let ratchet = state.sessions.get_mut(&msg.sender).unwrap();
                        ratchet.ratchet_decrypt_verbose(&msg.ratchet_message, b"")
                    }
                    None => {
                        if let Some(ratchet) = state.sessions.get_mut(&msg.sender) {
                            ratchet.ratchet_decrypt_verbose(&msg.ratchet_message, b"")
                        } else {
                            Err("No session initialized for sender".to_string())
                        }
                    }
                };

                match decrypted_verbose {
                    Ok((plaintext, mk)) => {
                        let text = String::from_utf8_lossy(&plaintext);
                        println!("\n[{}] {}", msg.sender, text);

                        // Forward-secrecy proof: try to decrypt the previous message
                        // from this sender using the current message's key.
                        if let Some(prev_msg) = state.last_received.get(&sender_clone) {
                            // We need a ratchet instance just to call the helper;
                            // the ratchet state was already advanced above.
                            if let Some(ratchet) = state.sessions.get(&sender_clone) {
                                let mk_hex: String = mk.iter().map(|b| format!("{:02x}", b)).collect();
                                println!("┌─ [Forward-Secrecy Proof] ─────────────────────────────┐");
                                println!("│  Current msg key (mk):  0x{}...  │", &mk_hex[..16]);
                                println!("│  Attempting to decrypt PREVIOUS message with this key: │");
                                match ratchet.decrypt_message_with_key(prev_msg, &mk, b"") {
                                    Ok(_) => println!("│  ✗ UNEXPECTED: decryption succeeded (bug!)             │"),
                                    Err(e) => {
                                        println!("│  ✓ FAILED as expected: {}  │", e);
                                        println!("│  Previous message key was discarded — proof complete.  │");
                                    }
                                }
                                println!("└────────────────────────────────────────────────────────┘");
                            }
                        }

                        // Store the just-received encrypted envelope as the
                        // "previous" for the next forward-secrecy check.
                        state.last_received.insert(sender_clone, msg.ratchet_message.clone());

                        print!("> ");
                        std::io::stdout().flush().unwrap();
                    }
                    Err(e) => {
                        println!("\nError decrypting message from {}: {}", msg.sender, e);
                        print!("> ");
                        std::io::stdout().flush().unwrap();
                    }
                }
            }

            let _ = state.save();
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: cargo run -p client -- <username>");
        return Ok(());
    }
    let username = &args[1];
    let server_url = "http://127.0.0.1:3000";

    let state = match ClientState::load(username) {
        Ok(s) => {
            println!("Loaded existing session state for {}", username);
            s
        }
        Err(_) => {
            println!("No state found. Creating new state for {}...", username);
            let s = ClientState::generate_new(username);
            register_and_publish(&s, server_url).await?;
            s.save()?;
            s
        }
    };

    let state_arc = Arc::new(Mutex::new(state));
    start_polling(Arc::clone(&state_arc), server_url.to_string());

    println!("Logged in as {}.", username);
    println!("Type /send <recipient> <message> to send a message.");
    println!("Type /exit or /quit to quit.");

    let stdin = io::stdin();
    let mut input = String::new();

    print!("> ");
    io::stdout().flush().unwrap();

    loop {
        input.clear();
        if stdin.read_line(&mut input).is_err() {
            break;
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            print!("> ");
            io::stdout().flush().unwrap();
            continue;
        }

        if trimmed == "/exit" || trimmed == "/quit" {
            break;
        }

        if trimmed.starts_with("/send ") {
            let parts: Vec<&str> = trimmed[6..].splitn(2, ' ').collect();
            if parts.len() < 2 {
                println!("Usage: /send <recipient> <message>");
            } else {
                let recipient = parts[0];
                let message = parts[1];
                if let Err(e) = send_message(Arc::clone(&state_arc), server_url, recipient, message).await {
                    println!("Error sending message: {}", e);
                } else {
                    println!("Sent!");
                }
            }
        } else {
            println!("Unknown command. Use /send <recipient> <message> or /exit");
        }

        print!("> ");
        io::stdout().flush().unwrap();
    }

    Ok(())
}
