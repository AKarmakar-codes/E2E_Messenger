use std::fs::File;
use std::io::Write;
use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use crypto_core::{PrekeyBundleAnnouncement, InboxMessage, X3DHInit, EncryptedMessage, MessageHeader, sign};

fn main() {
    // Generate Bob's keys
    let mut bob_ik_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut bob_ik_entropy);
    let bob_ik_sec = StaticSecret::from(bob_ik_entropy);
    let bob_ik_pub = PublicKey::from(&bob_ik_sec);

    let mut bob_spk_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut bob_spk_entropy);
    let bob_spk_sec = StaticSecret::from(bob_spk_entropy);
    let bob_spk_pub = PublicKey::from(&bob_spk_sec);

    let mut bob_sign_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut bob_sign_entropy);
    let bob_sign_key = SigningKey::from_bytes(&bob_sign_entropy);
    let bob_verify_key = bob_sign_key.verifying_key();

    let spk_bytes = bob_spk_pub.to_bytes();
    let spk_sig = sign(&bob_sign_key, &spk_bytes);

    let mut bob_opk_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut bob_opk_entropy);
    let bob_opk_sec = StaticSecret::from(bob_opk_entropy);
    let bob_opk_pub = PublicKey::from(&bob_opk_sec);

    let announcement = PrekeyBundleAnnouncement {
        identity_key: bob_ik_pub,
        identity_signing_key: bob_verify_key,
        signed_prekey: bob_spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekeys: vec![bob_opk_pub],
    };

    let announcement_json = serde_json::to_string_pretty(&announcement).unwrap();
    let mut file = File::create("bob_bundle_announcement.json").unwrap();
    file.write_all(announcement_json.as_bytes()).unwrap();
    println!("Wrote bob_bundle_announcement.json");

    // Generate Alice's initiation and message
    let mut alice_ik_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut alice_ik_entropy);
    let alice_ik_sec = StaticSecret::from(alice_ik_entropy);
    let alice_ik_pub = PublicKey::from(&alice_ik_sec);

    let mut alice_ek_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut alice_ek_entropy);
    let alice_ek_sec = StaticSecret::from(alice_ek_entropy);
    let alice_ek_pub = PublicKey::from(&alice_ek_sec);

    let x3dh_init = X3DHInit {
        alice_identity_key: alice_ik_pub,
        alice_ephemeral_key: alice_ek_pub,
        used_one_time_prekey: Some(bob_opk_pub),
    };

    let msg = InboxMessage {
        sender: "alice".to_string(),
        x3dh_init: Some(x3dh_init),
        ratchet_message: EncryptedMessage {
            header: MessageHeader {
                dh_pub: alice_ek_pub,
                n: 0,
                pn: 0,
            },
            ciphertext: vec![1, 2, 3, 4, 5],
        },
    };

    let msg_json = serde_json::to_string_pretty(&msg).unwrap();
    let mut file2 = File::create("alice_message.json").unwrap();
    file2.write_all(msg_json.as_bytes()).unwrap();
    println!("Wrote alice_message.json");
}
