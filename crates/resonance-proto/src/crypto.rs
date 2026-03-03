use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SESSION_SALT: &[u8] = b"resonance-vpn-v1";
const SCRAMBLE_KEY_LABEL: &[u8] = b"scramble";
const MAC_KEY_LABEL: &[u8] = b"mac";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub scramble_key: [u8; 32],
    pub mac_key: [u8; 32],
}

impl SessionKeys {
    pub fn derive(key_material: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SESSION_SALT), key_material);

        let mut session_key = [0u8; 32];
        hk.expand(b"session", &mut session_key)
            .expect("HKDF expand failed");

        let scramble_key = blake3_derive(&session_key, SCRAMBLE_KEY_LABEL);
        let mac_key = blake3_derive(&session_key, MAC_KEY_LABEL);

        Self {
            scramble_key,
            mac_key,
        }
    }

    #[inline]
    pub fn xor_keystream(&self, data: &mut [u8], nonce: u64) {
        let mut hasher = Blake3Hasher::new_keyed(&self.scramble_key);
        hasher.update(&nonce.to_le_bytes());
        let mut output_reader = hasher.finalize_xof();

        const CHUNK_SIZE: usize = 64;
        let mut keystream_chunk = [0u8; CHUNK_SIZE];

        let full_chunks = data.len() / CHUNK_SIZE;
        let remainder = data.len() % CHUNK_SIZE;

        for i in 0..full_chunks {
            output_reader.fill(&mut keystream_chunk);
            let offset = i * CHUNK_SIZE;

            for j in (0..CHUNK_SIZE).step_by(8) {
                let data_slice = &mut data[offset + j..offset + j + 8];
                let key_slice = &keystream_chunk[j..j + 8];

                let d = u64::from_le_bytes(data_slice.try_into().unwrap());
                let k = u64::from_le_bytes(key_slice.try_into().unwrap());
                data_slice.copy_from_slice(&(d ^ k).to_le_bytes());
            }
        }

        if remainder > 0 {
            let offset = full_chunks * CHUNK_SIZE;
            output_reader.fill(&mut keystream_chunk[..remainder]);
            for i in 0..remainder {
                data[offset + i] ^= keystream_chunk[i];
            }
        }
    }

    pub fn compute_mac(&self, nonce: &[u8], encrypted_data: &[u8]) -> [u8; 16] {
        let mut hasher = Blake3Hasher::new_keyed(&self.mac_key);
        hasher.update(nonce);
        hasher.update(encrypted_data);

        let hash = hasher.finalize();
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&hash.as_bytes()[..16]);
        mac
    }

    pub fn verify_mac(&self, nonce: &[u8], encrypted_data: &[u8], expected_mac: &[u8; 16]) -> bool {
        let computed = self.compute_mac(nonce, encrypted_data);
        computed.ct_eq(expected_mac).into()
    }
}

fn blake3_derive(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

pub fn hash_psk(psk: &str) -> [u8; 32] {
    *blake3::hash(psk.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let keys1 = SessionKeys::derive(&[42u8; 32]);
        let keys2 = SessionKeys::derive(&[42u8; 32]);
        assert_eq!(keys1.scramble_key, keys2.scramble_key);
        assert_eq!(keys1.mac_key, keys2.mac_key);
    }

    #[test]
    fn test_key_derivation_different_input() {
        let keys1 = SessionKeys::derive(&[1u8; 32]);
        let keys2 = SessionKeys::derive(&[2u8; 32]);
        assert_ne!(keys1.scramble_key, keys2.scramble_key);
    }

    #[test]
    fn test_xor_roundtrip() {
        let keys = SessionKeys::derive(&[42u8; 32]);
        let original = b"Hello, World! This is a test.".to_vec();
        let nonce = 12345u64;

        let mut data = original.clone();
        keys.xor_keystream(&mut data, nonce);
        assert_ne!(data, original);

        keys.xor_keystream(&mut data, nonce);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_different_nonces() {
        let keys = SessionKeys::derive(&[42u8; 32]);
        let original = b"test data".to_vec();

        let mut data1 = original.clone();
        let mut data2 = original.clone();
        keys.xor_keystream(&mut data1, 1);
        keys.xor_keystream(&mut data2, 2);
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_mac_verification() {
        let keys = SessionKeys::derive(&[42u8; 32]);
        let nonce = 1u64.to_le_bytes();
        let data = b"encrypted payload";

        let mac = keys.compute_mac(&nonce, data);
        assert!(keys.verify_mac(&nonce, data, &mac));

        let mut bad_mac = mac;
        bad_mac[0] ^= 1;
        assert!(!keys.verify_mac(&nonce, data, &bad_mac));
    }

    #[test]
    fn test_hash_psk() {
        let hash1 = hash_psk("my-secret");
        let hash2 = hash_psk("my-secret");
        let hash3 = hash_psk("different");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
