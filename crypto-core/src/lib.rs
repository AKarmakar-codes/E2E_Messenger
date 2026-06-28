use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

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

/// Represents Bob's public prekey bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBundle {
    pub identity_key: PublicKey,            // IK_B (X25519)
    pub identity_signing_key: VerifyingKey, // IK_sign_B (Ed25519)
    pub signed_prekey: PublicKey,           // SPK_B (X25519)
    pub signed_prekey_sig: Signature,       // Signature of SPK_B using IK_sign_B
    pub one_time_prekey: Option<PublicKey>, // OPK_B (X25519)
}

/// Represents the initiation parameters sent by Alice to Bob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3DHInit {
    pub alice_identity_key: PublicKey,      // IK_A (X25519)
    pub alice_ephemeral_key: PublicKey,     // EK_A (X25519)
    pub used_one_time_prekey: Option<PublicKey>, // Which OPK_B Alice used, if any
}

/// Alice derives the X3DH shared secret (SK) using Bob's KeyBundle.
/// Performs DH1, DH2, DH3, and optionally DH4, and verifies the signed prekey's signature.
pub fn x3dh_alice_derive(
    ik_a: &StaticSecret,
    ek_a: &StaticSecret,
    bob_bundle: &KeyBundle,
) -> Result<[u8; 32], String> {
    // 1. Verify Bob's SPK signature using his identity signing key
    let spk_bytes = bob_bundle.signed_prekey.to_bytes();
    if !verify(&bob_bundle.identity_signing_key, &spk_bytes, &bob_bundle.signed_prekey_sig) {
        return Err("SPK signature verification failed".to_string());
    }

    // 2. Compute DH values
    let dh1 = dh(ik_a, &bob_bundle.signed_prekey);
    let dh2 = dh(ek_a, &bob_bundle.identity_key);
    let dh3 = dh(ek_a, &bob_bundle.signed_prekey);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk) = &bob_bundle.one_time_prekey {
        let dh4 = dh(ek_a, opk);
        ikm.extend_from_slice(&dh4);
    }

    // 3. HKDF derivation
    let salt = [0u8; 32];
    let info = b"X3DH";
    let sk_bytes = hkdf_derive(Some(&salt), &ikm, info, 32);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&sk_bytes);
    Ok(sk)
}

/// Bob derives the X3DH shared secret (SK) using Alice's initiation parameters (X3DHInit).
pub fn x3dh_bob_derive(
    ik_b: &StaticSecret,
    spk_b: &StaticSecret,
    opk_b: Option<&StaticSecret>,
    alice_init: &X3DHInit,
) -> Result<[u8; 32], String> {
    // 1. Compute DH values
    let dh1 = dh(spk_b, &alice_init.alice_identity_key);
    let dh2 = dh(ik_b, &alice_init.alice_ephemeral_key);
    let dh3 = dh(spk_b, &alice_init.alice_ephemeral_key);

    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk_secret) = opk_b {
        let dh4 = dh(opk_secret, &alice_init.alice_ephemeral_key);
        ikm.extend_from_slice(&dh4);
    } else if alice_init.used_one_time_prekey.is_some() {
        return Err("Alice expected one-time prekey, but Bob didn't provide one".to_string());
    }

    // 2. HKDF derivation
    let salt = [0u8; 32];
    let info = b"X3DH";
    let sk_bytes = hkdf_derive(Some(&salt), &ikm, info, 32);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&sk_bytes);
    Ok(sk)
}

/// Derives the next chain key and a message key using HKDF-SHA256.
pub fn kdf_ck(ck: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let ck_bytes = hkdf_derive(Some(&ck), &[1], b"ChainKeyStep", 32);
    let mk_bytes = hkdf_derive(Some(&ck), &[2], b"MessageKeyDerivation", 32);
    let mut ck_new = [0u8; 32];
    let mut mk = [0u8; 32];
    ck_new.copy_from_slice(&ck_bytes);
    mk.copy_from_slice(&mk_bytes);
    (ck_new, mk)
}

/// Represents the header of a Double Ratchet message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    pub dh_pub: PublicKey,
    pub n: u32,
    pub pn: u32,
}

/// Represents a Double Ratchet encrypted message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

/// The state of a Double Ratchet session.
pub struct DoubleRatchet {
    pub dhs: StaticSecret,
    pub dhs_pub: PublicKey,
    pub dhr: Option<PublicKey>,
    pub rk: [u8; 32],
    pub ck_s: Option<[u8; 32]>,
    pub ck_r: Option<[u8; 32]>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub mk_skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl Serialize for DoubleRatchet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let dhs_bytes = self.dhs.to_bytes();
        let dhr_bytes = self.dhr.map(|k| k.to_bytes());
        let mk_skipped_vec: Vec<(([u8; 32], u32), [u8; 32])> = self.mk_skipped.iter().map(|(k, v)| (*k, *v)).collect();

        let state = SerializableDoubleRatchet {
            dhs_bytes,
            dhs_pub: self.dhs_pub.to_bytes(),
            dhr_bytes,
            rk: self.rk,
            ck_s: self.ck_s,
            ck_r: self.ck_r,
            ns: self.ns,
            nr: self.nr,
            pn: self.pn,
            mk_skipped: mk_skipped_vec,
        };
        state.serialize(serializer)
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableDoubleRatchet {
    dhs_bytes: [u8; 32],
    dhs_pub: [u8; 32],
    dhr_bytes: Option<[u8; 32]>,
    rk: [u8; 32],
    ck_s: Option<[u8; 32]>,
    ck_r: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    mk_skipped: Vec<(([u8; 32], u32), [u8; 32])>,
}

impl<'de> Deserialize<'de> for DoubleRatchet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let state = SerializableDoubleRatchet::deserialize(deserializer)?;
        let dhs = StaticSecret::from(state.dhs_bytes);
        let dhs_pub = PublicKey::from(state.dhs_pub);
        let dhr = state.dhr_bytes.map(PublicKey::from);
        let mk_skipped = state.mk_skipped.into_iter().collect();

        Ok(Self {
            dhs,
            dhs_pub,
            dhr,
            rk: state.rk,
            ck_s: state.ck_s,
            ck_r: state.ck_r,
            ns: state.ns,
            nr: state.nr,
            pn: state.pn,
            mk_skipped,
        })
    }
}

impl DoubleRatchet {
    const MAX_SKIP: u32 = 1000;

    /// Initialize Alice's Double Ratchet state (initiator).
    pub fn init_alice(sk: [u8; 32], bob_dh_pub: PublicKey) -> Self {
        let entropy = random_bytes_32();
        let dhs = StaticSecret::from(entropy);
        let dhs_pub = PublicKey::from(&dhs);

        // DH = dhs * bob_dh_pub
        let shared_dh = dh(&dhs, &bob_dh_pub);

        // KDF_RK(rk=sk, DH)
        let salt = sk;
        let info = b"WhisperRatchetRoot";
        let derived = hkdf_derive(Some(&salt), &shared_dh, info, 64);
        let mut rk = [0u8; 32];
        let mut ck_s = [0u8; 32];
        rk.copy_from_slice(&derived[0..32]);
        ck_s.copy_from_slice(&derived[32..64]);

        Self {
            dhs,
            dhs_pub,
            dhr: Some(bob_dh_pub),
            rk,
            ck_s: Some(ck_s),
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
        }
    }

    /// Initialize Bob's Double Ratchet state (responder).
    pub fn init_bob(sk: [u8; 32], bob_dh_sec: StaticSecret) -> Self {
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);
        Self {
            dhs: bob_dh_sec,
            dhs_pub: bob_dh_pub,
            dhr: None,
            rk: sk,
            ck_s: None,
            ck_r: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mk_skipped: HashMap::new(),
        }
    }

    /// Encrypts a message payload. Prepend 12-byte random nonce to ciphertext.
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<EncryptedMessage, String> {
        let ck_s = self.ck_s.ok_or_else(|| "Sending chain key not initialized".to_string())?;
        
        let (ck_s_next, mk) = kdf_ck(ck_s);
        self.ck_s = Some(ck_s_next);

        let header = MessageHeader {
            dh_pub: self.dhs_pub,
            n: self.ns,
            pn: self.pn,
        };
        self.ns += 1;

        let header_bytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(&header_bytes);

        let nonce = random_bytes_12();
        let ciphertext = aead_seal(&mk, &nonce, plaintext, &full_ad);

        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&ciphertext);

        Ok(EncryptedMessage {
            header,
            ciphertext: payload,
        })
    }

    /// Decrypts an encrypted message.
    pub fn ratchet_decrypt(&mut self, msg: &EncryptedMessage, ad: &[u8]) -> Result<Vec<u8>, String> {
        let (plaintext, _) = self.ratchet_decrypt_verbose(msg, ad)?;
        Ok(plaintext)
    }

    /// Decrypts an encrypted message and returns both the plaintext and the derived message key.
    pub fn ratchet_decrypt_verbose(&mut self, msg: &EncryptedMessage, ad: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
        let header_bytes = serde_json::to_vec(&msg.header).map_err(|e| e.to_string())?;
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(&header_bytes);

        let dh_pub_bytes = msg.header.dh_pub.to_bytes();

        // 1. Check if we already have the skipped message key
        if let Some(mk) = self.mk_skipped.remove(&(dh_pub_bytes, msg.header.n)) {
            let plaintext = self.decrypt_with_key(&msg.ciphertext, &mk, &full_ad)?;
            return Ok((plaintext, mk));
        }

        // 2. DH ratchet step if partner's DH key changed
        if Some(msg.header.dh_pub) != self.dhr {
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet(msg.header.dh_pub)?;
        }

        // 3. Skip message keys on current receiving chain up to msg.header.n
        self.skip_message_keys(msg.header.n)?;

        // 4. Derive message key for current message
        let ck_r = self.ck_r.ok_or_else(|| "Receiving chain key not initialized".to_string())?;
        let (ck_r_next, mk) = kdf_ck(ck_r);
        self.ck_r = Some(ck_r_next);
        self.nr += 1;

        // 5. Decrypt using newly derived key
        let plaintext = self.decrypt_with_key(&msg.ciphertext, &mk, &full_ad)?;
        Ok((plaintext, mk))
    }

    /// A helper method to attempt to decrypt an encrypted message with a specific message key.
    /// This is used to demonstrate forward secrecy.
    pub fn decrypt_message_with_key(&self, msg: &EncryptedMessage, mk: &[u8; 32], ad: &[u8]) -> Result<Vec<u8>, String> {
        let header_bytes = serde_json::to_vec(&msg.header).map_err(|e| e.to_string())?;
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(&header_bytes);
        self.decrypt_with_key(&msg.ciphertext, mk, &full_ad)
    }

    fn decrypt_with_key(&self, ciphertext: &[u8], mk: &[u8; 32], full_ad: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 12 {
            return Err("Ciphertext too short".to_string());
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&ciphertext[0..12]);
        let ciphertext_actual = &ciphertext[12..];

        aead_open(mk, &nonce, ciphertext_actual, full_ad)
            .map_err(|e| format!("AEAD decryption failed: {:?}", e))
    }

    fn skip_message_keys(&mut self, until_n: u32) -> Result<(), String> {
        if let Some(ck_r) = self.ck_r {
            if self.nr + Self::MAX_SKIP < until_n {
                return Err("Too many skipped messages".to_string());
            }
            let mut current_ck = ck_r;
            while self.nr < until_n {
                let (next_ck, mk) = kdf_ck(current_ck);
                let dhr_bytes = self.dhr.ok_or_else(|| "dhr is empty".to_string())?.to_bytes();
                self.mk_skipped.insert((dhr_bytes, self.nr), mk);
                current_ck = next_ck;
                self.nr += 1;
            }
            self.ck_r = Some(current_ck);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header_dh_pub: PublicKey) -> Result<(), String> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header_dh_pub);

        // DH(dhs, dhr)
        let shared_dh_recv = dh(&self.dhs, &header_dh_pub);
        // KDF_RK(rk, DH)
        let salt = self.rk;
        let info = b"WhisperRatchetRoot";
        let derived_recv = hkdf_derive(Some(&salt), &shared_dh_recv, info, 64);
        self.rk.copy_from_slice(&derived_recv[0..32]);
        let mut ck_r = [0u8; 32];
        ck_r.copy_from_slice(&derived_recv[32..64]);
        self.ck_r = Some(ck_r);

        // Generate new local DH key pair
        let entropy = random_bytes_32();
        let dhs_new = StaticSecret::from(entropy);
        let dhs_pub_new = PublicKey::from(&dhs_new);
        self.dhs = dhs_new;
        self.dhs_pub = dhs_pub_new;

        // DH(dhs, dhr)
        let shared_dh_send = dh(&self.dhs, &header_dh_pub);
        let salt_send = self.rk;
        let derived_send = hkdf_derive(Some(&salt_send), &shared_dh_send, info, 64);
        self.rk.copy_from_slice(&derived_send[0..32]);
        let mut ck_s = [0u8; 32];
        ck_s.copy_from_slice(&derived_send[32..64]);
        self.ck_s = Some(ck_s);

        Ok(())
    }
}

/// Represents Bob's public prekey bundle announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundleAnnouncement {
    pub identity_key: PublicKey,            // IK_B (X25519)
    pub identity_signing_key: VerifyingKey, // IK_sign_B (Ed25519)
    pub signed_prekey: PublicKey,           // SPK_B (X25519)
    pub signed_prekey_sig: Signature,       // Signature of SPK_B using IK_sign_B
    pub one_time_prekeys: Vec<PublicKey>,   // Pool of OPK_B (X25519)
}

/// Represents a message stored in a user's inbox on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxMessage {
    pub sender: String,
    pub x3dh_init: Option<X3DHInit>,
    pub ratchet_message: EncryptedMessage,
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

    #[test]
    fn test_x3dh_with_opk() {
        // Bob's keys
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

        // Sign Bob's SPK public bytes
        let spk_bytes = bob_spk_pub.to_bytes();
        let spk_sig = sign(&bob_sign_key, &spk_bytes);

        let mut bob_opk_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_opk_entropy);
        let bob_opk_sec = StaticSecret::from(bob_opk_entropy);
        let bob_opk_pub = PublicKey::from(&bob_opk_sec);

        let bob_bundle = KeyBundle {
            identity_key: bob_ik_pub,
            identity_signing_key: bob_verify_key,
            signed_prekey: bob_spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: Some(bob_opk_pub),
        };

        // Alice's keys
        let mut alice_ik_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ik_entropy);
        let alice_ik_sec = StaticSecret::from(alice_ik_entropy);
        let alice_ik_pub = PublicKey::from(&alice_ik_sec);

        let mut alice_ek_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ek_entropy);
        let alice_ek_sec = StaticSecret::from(alice_ek_entropy);
        let alice_ek_pub = PublicKey::from(&alice_ek_sec);

        // Alice derives SK
        let alice_sk = x3dh_alice_derive(&alice_ik_sec, &alice_ek_sec, &bob_bundle).unwrap();

        // Initiation params Alice sends to Bob
        let alice_init = X3DHInit {
            alice_identity_key: alice_ik_pub,
            alice_ephemeral_key: alice_ek_pub,
            used_one_time_prekey: Some(bob_opk_pub),
        };

        // Bob derives SK
        let bob_sk = x3dh_bob_derive(&bob_ik_sec, &bob_spk_sec, Some(&bob_opk_sec), &alice_init).unwrap();

        // Assert shared secrets match
        assert_eq!(alice_sk, bob_sk);
    }

    #[test]
    fn test_x3dh_without_opk() {
        // Bob's keys
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

        // Sign Bob's SPK public bytes
        let spk_bytes = bob_spk_pub.to_bytes();
        let spk_sig = sign(&bob_sign_key, &spk_bytes);

        let bob_bundle = KeyBundle {
            identity_key: bob_ik_pub,
            identity_signing_key: bob_verify_key,
            signed_prekey: bob_spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };

        // Alice's keys
        let mut alice_ik_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ik_entropy);
        let alice_ik_sec = StaticSecret::from(alice_ik_entropy);
        let alice_ik_pub = PublicKey::from(&alice_ik_sec);

        let mut alice_ek_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ek_entropy);
        let alice_ek_sec = StaticSecret::from(alice_ek_entropy);
        let alice_ek_pub = PublicKey::from(&alice_ek_sec);

        // Alice derives SK
        let alice_sk = x3dh_alice_derive(&alice_ik_sec, &alice_ek_sec, &bob_bundle).unwrap();

        // Initiation params Alice sends to Bob
        let alice_init = X3DHInit {
            alice_identity_key: alice_ik_pub,
            alice_ephemeral_key: alice_ek_pub,
            used_one_time_prekey: None,
        };

        // Bob derives SK
        let bob_sk = x3dh_bob_derive(&bob_ik_sec, &bob_spk_sec, None, &alice_init).unwrap();

        // Assert shared secrets match
        assert_eq!(alice_sk, bob_sk);
    }

    #[test]
    fn test_x3dh_signature_tamper() {
        // Bob's keys
        let mut bob_ik_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_ik_entropy);
        let bob_ik_pub = PublicKey::from(&StaticSecret::from(bob_ik_entropy));

        let mut bob_spk_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_spk_entropy);
        let bob_spk_pub = PublicKey::from(&StaticSecret::from(bob_spk_entropy));

        let mut bob_sign_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_sign_entropy);
        let bob_sign_key = SigningKey::from_bytes(&bob_sign_entropy);
        let bob_verify_key = bob_sign_key.verifying_key();

        // Sign Bob's SPK public bytes
        let spk_bytes = bob_spk_pub.to_bytes();
        let mut spk_sig = sign(&bob_sign_key, &spk_bytes);

        // Tamper signature bytes
        let mut sig_bytes = spk_sig.to_bytes();
        sig_bytes[0] ^= 1;
        spk_sig = Signature::from_bytes(&sig_bytes);

        let bob_bundle = KeyBundle {
            identity_key: bob_ik_pub,
            identity_signing_key: bob_verify_key,
            signed_prekey: bob_spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };

        // Alice's keys
        let mut alice_ik_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ik_entropy);
        let alice_ik_sec = StaticSecret::from(alice_ik_entropy);

        let mut alice_ek_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut alice_ek_entropy);
        let alice_ek_sec = StaticSecret::from(alice_ek_entropy);

        // Alice derives SK - should fail
        let alice_result = x3dh_alice_derive(&alice_ik_sec, &alice_ek_sec, &bob_bundle);
        assert!(alice_result.is_err());
        assert_eq!(alice_result.unwrap_err(), "SPK signature verification failed");
    }

    #[test]
    fn test_ratchet_in_order() {
        let sk = [42u8; 32];
        let mut bob_dh_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_entropy);
        let bob_dh_sec = StaticSecret::from(bob_dh_entropy);
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);

        let mut alice = DoubleRatchet::init_alice(sk, bob_dh_pub);
        let mut bob = DoubleRatchet::init_bob(sk, bob_dh_sec);

        let ad = b"AssociatedData";

        // Alice sends to Bob
        let msg1 = alice.ratchet_encrypt(b"Hello Bob!", ad).unwrap();
        let dec1 = bob.ratchet_decrypt(&msg1, ad).unwrap();
        assert_eq!(dec1, b"Hello Bob!");

        // Bob replies to Alice
        let msg2 = bob.ratchet_encrypt(b"Hello Alice!", ad).unwrap();
        let dec2 = alice.ratchet_decrypt(&msg2, ad).unwrap();
        assert_eq!(dec2, b"Hello Alice!");

        // Alice sends another one
        let msg3 = alice.ratchet_encrypt(b"How are you?", ad).unwrap();
        let dec3 = bob.ratchet_decrypt(&msg3, ad).unwrap();
        assert_eq!(dec3, b"How are you?");
    }

    #[test]
    fn test_ratchet_out_of_order() {
        let sk = [99u8; 32];
        let mut bob_dh_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_entropy);
        let bob_dh_sec = StaticSecret::from(bob_dh_entropy);
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);

        let mut alice = DoubleRatchet::init_alice(sk, bob_dh_pub);
        let mut bob = DoubleRatchet::init_bob(sk, bob_dh_sec);

        let ad = b"AssociatedData";

        // Alice encrypts 3 messages
        let msg1 = alice.ratchet_encrypt(b"Message 1", ad).unwrap();
        let msg2 = alice.ratchet_encrypt(b"Message 2", ad).unwrap();
        let msg3 = alice.ratchet_encrypt(b"Message 3", ad).unwrap();

        // Bob decrypts msg3 first (msg1 and msg2 keys will be skipped and cached)
        let dec3 = bob.ratchet_decrypt(&msg3, ad).unwrap();
        assert_eq!(dec3, b"Message 3");

        // Bob decrypts msg1 next (from skipped keys cache)
        let dec1 = bob.ratchet_decrypt(&msg1, ad).unwrap();
        assert_eq!(dec1, b"Message 1");

        // Bob decrypts msg2 next (from skipped keys cache)
        let dec2 = bob.ratchet_decrypt(&msg2, ad).unwrap();
        assert_eq!(dec2, b"Message 2");
    }

    #[test]
    fn test_ratchet_dropped_message() {
        let sk = [7u8; 32];
        let mut bob_dh_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_entropy);
        let bob_dh_sec = StaticSecret::from(bob_dh_entropy);
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);

        let mut alice = DoubleRatchet::init_alice(sk, bob_dh_pub);
        let mut bob = DoubleRatchet::init_bob(sk, bob_dh_sec);

        let ad = b"AssociatedData";

        let _msg1 = alice.ratchet_encrypt(b"Message 1", ad).unwrap();
        let msg2 = alice.ratchet_encrypt(b"Message 2", ad).unwrap(); // We will drop msg1

        let dec2 = bob.ratchet_decrypt(&msg2, ad).unwrap();
        assert_eq!(dec2, b"Message 2");
    }

    #[test]
    fn test_ratchet_simultaneous_send() {
        let sk = [111u8; 32];
        let mut bob_dh_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_entropy);
        let bob_dh_sec = StaticSecret::from(bob_dh_entropy);
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);

        let mut alice = DoubleRatchet::init_alice(sk, bob_dh_pub);
        let mut bob = DoubleRatchet::init_bob(sk, bob_dh_sec);

        let ad = b"AssociatedData";

        // Alice sends to Bob
        let a_to_b_1 = alice.ratchet_encrypt(b"Alice message 1", ad).unwrap();

        // Bob decrypts first Alice message so Bob's receiving chain is established
        let dec_b1 = bob.ratchet_decrypt(&a_to_b_1, ad).unwrap();
        assert_eq!(dec_b1, b"Alice message 1");

        // Now both send concurrently before receiving a reply
        let a_to_b_2 = alice.ratchet_encrypt(b"Alice message 2", ad).unwrap();
        let b_to_a_2 = bob.ratchet_encrypt(b"Bob message 2", ad).unwrap();

        // Alice decrypts Bob's message
        let dec_a2 = alice.ratchet_decrypt(&b_to_a_2, ad).unwrap();
        assert_eq!(dec_a2, b"Bob message 2");

        // Bob decrypts Alice's concurrent message
        let dec_b2 = bob.ratchet_decrypt(&a_to_b_2, ad).unwrap();
        assert_eq!(dec_b2, b"Alice message 2");
    }

    #[test]
    fn test_ratchet_serialization() {
        let sk = [77u8; 32];
        let mut bob_dh_entropy = [0u8; 32];
        OsRng.fill_bytes(&mut bob_dh_entropy);
        let bob_dh_sec = StaticSecret::from(bob_dh_entropy);
        let bob_dh_pub = PublicKey::from(&bob_dh_sec);

        let mut alice = DoubleRatchet::init_alice(sk, bob_dh_pub);
        let mut bob = DoubleRatchet::init_bob(sk, bob_dh_sec);

        let ad = b"AssociatedData";

        // Alice sends message 1
        let msg1 = alice.ratchet_encrypt(b"Hello", ad).unwrap();
        let dec1 = bob.ratchet_decrypt(&msg1, ad).unwrap();
        assert_eq!(dec1, b"Hello");

        // Serialize Alice and Bob states
        let alice_serialized = serde_json::to_vec(&alice).unwrap();
        let bob_serialized = serde_json::to_vec(&bob).unwrap();

        // Deserialize Alice and Bob states
        let mut alice_restored: DoubleRatchet = serde_json::from_slice(&alice_serialized).unwrap();
        let mut bob_restored: DoubleRatchet = serde_json::from_slice(&bob_serialized).unwrap();

        // Alice sends message 2 using restored state
        let msg2 = alice_restored.ratchet_encrypt(b"World", ad).unwrap();
        let dec2 = bob_restored.ratchet_decrypt(&msg2, ad).unwrap();
        assert_eq!(dec2, b"World");
    }

    fn verifying_key_from_signing(signing_key: &SigningKey) -> VerifyingKey {
        signing_key.verifying_key()
    }
}
