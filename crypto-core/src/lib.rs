use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use rand::RngCore;

/// Performs Diffie-Hellman using X25519.
pub fn dh(private: &StaticSecret, public: &PublicKey) -> [u8; 32] {
    let shared = private.diffie_hellman(public);
    *shared.as_bytes()
}

/// Derives a key using HKDF-SHA256.
pub fn hkdf_derive(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("HKDF expansion failed");
    okm
}

/// Encrypts plaintext using ChaCha20-Poly1305 AEAD.
/// Returns the ciphertext with concatenated authentication tag (16 bytes).
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad,
    }).expect("AEAD encryption failed")
}

/// Decrypts ciphertext (which includes the concatenated tag) using ChaCha20-Poly1305 AEAD.
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad,
    })
}

/// Signs a message using Ed25519.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verifies an Ed25519 signature.
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

/// Generates a random 32-byte array using OsRng.
pub fn random_bytes_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generates a random 12-byte array using OsRng (useful for AEAD nonces).
pub fn random_bytes_12() -> [u8; 12] {
    let mut bytes = [0u8; 12];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i+2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_x25519_dh_rfc7748() {
        // RFC 7748 Section 6.1 test vectors
        let alice_private_hex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_public_hex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let bob_private_hex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        let bob_public_hex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        let expected_shared_hex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        let alice_private_bytes: [u8; 32] = decode_hex(alice_private_hex).try_into().unwrap();
        let alice_public_bytes: [u8; 32] = decode_hex(alice_public_hex).try_into().unwrap();
        let bob_private_bytes: [u8; 32] = decode_hex(bob_private_hex).try_into().unwrap();
        let bob_public_bytes: [u8; 32] = decode_hex(bob_public_hex).try_into().unwrap();
        let expected_shared_bytes: [u8; 32] = decode_hex(expected_shared_hex).try_into().unwrap();

        let alice_private = StaticSecret::from(alice_private_bytes);
        let alice_public = PublicKey::from(alice_public_bytes);
        let bob_private = StaticSecret::from(bob_private_bytes);
        let bob_public = PublicKey::from(bob_public_bytes);

        // Verify public keys derived match RFC vectors
        assert_eq!(PublicKey::from(&alice_private).to_bytes(), alice_public.to_bytes());
        assert_eq!(PublicKey::from(&bob_private).to_bytes(), bob_public.to_bytes());

        // Perform Diffie-Hellman from both sides
        let shared_alice = dh(&alice_private, &bob_public);
        let shared_bob = dh(&bob_private, &alice_public);

        assert_eq!(shared_alice, expected_shared_bytes);
        assert_eq!(shared_bob, expected_shared_bytes);
    }

    #[test]
    fn test_hkdf_rfc5869() {
        // RFC 5869 Test Case 1
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = decode_hex("000102030405060708090a0b0c");
        let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = decode_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        let okm = hkdf_derive(Some(&salt), &ikm, &info, 42);
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_chacha20poly1305_rfc8439() {
        // RFC 7539 Section 2.8.2 AEAD Test Vector
        let key_bytes: [u8; 32] = decode_hex("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f").try_into().unwrap();
        let nonce_bytes: [u8; 12] = decode_hex("07 00 00 00 40 41 42 43 44 45 46 47").try_into().unwrap();
        let aad = decode_hex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
        let plaintext = decode_hex(
            "4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c \
             65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73 \
             73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63 \
             6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f \
             6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20 \
             74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73 \
             63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69 \
             74 2e"
        );
        let expected_ciphertext = decode_hex(
            "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2 \
             a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6 \
             3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b \
             1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36 \
             92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58 \
             fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc \
             3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b \
             61 16"
        );
        let expected_tag = decode_hex("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91");

        let mut expected_combined = expected_ciphertext.clone();
        expected_combined.extend_from_slice(&expected_tag);

        // Test seal
        let ciphertext = aead_seal(&key_bytes, &nonce_bytes, &plaintext, &aad);
        assert_eq!(ciphertext, expected_combined);

        // Test open
        let decrypted = aead_open(&key_bytes, &nonce_bytes, &ciphertext, &aad).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test open fails with modified AAD
        let mut bad_aad = aad.clone();
        bad_aad[0] ^= 1;
        assert!(aead_open(&key_bytes, &nonce_bytes, &ciphertext, &bad_aad).is_err());
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let signing_key = SigningKey::from_bytes(&entropy);
        let verifying_key = verifying_key_from_signing(&signing_key);
        let message = b"Hello, world! This is a signed message.";

        let signature = sign(&signing_key, message);
        assert!(verify(&verifying_key, message, &signature));

        // Verification should fail if message is modified
        let mut tampered_message = message.to_vec();
        tampered_message[0] ^= 1;
        assert!(!verify(&verifying_key, &tampered_message, &signature));
    }

    fn verifying_key_from_signing(signing_key: &SigningKey) -> VerifyingKey {
        signing_key.verifying_key()
    }
}
