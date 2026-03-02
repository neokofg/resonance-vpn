use bytes::{Bytes, BytesMut};

use crate::crypto::SessionKeys;

pub const NONCE_SIZE: usize = 8;
pub const MAC_SIZE: usize = 16;
pub const TYPE_SIZE: usize = 1;
pub const FRAME_OVERHEAD: usize = TYPE_SIZE + NONCE_SIZE + MAC_SIZE; // 25 bytes

const NONCE_REKEY_THRESHOLD: u64 = u64::MAX - 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x00,
    Control = 0x01,
}

#[derive(Debug)]
pub enum Frame {
    /// Encrypted IP packet
    Data(Bytes),
    /// Unencrypted protobuf control message
    Control(Bytes),
}

pub struct FrameEncoder {
    keys: SessionKeys,
    nonce_counter: u64,
}

impl FrameEncoder {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            nonce_counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<u64, FrameError> {
        if self.nonce_counter >= NONCE_REKEY_THRESHOLD {
            return Err(FrameError::NonceExhausted);
        }
        let nonce = self.nonce_counter;
        self.nonce_counter += 1;
        Ok(nonce)
    }

    /// Encrypt an IP packet into a data frame.
    /// Returns bytes ready to send as a WebSocket binary message.
    pub fn encode_data(&mut self, ip_packet: &[u8]) -> Result<Bytes, FrameError> {
        let nonce = self.next_nonce()?;
        let nonce_bytes = nonce.to_le_bytes();

        let mut encrypted = ip_packet.to_vec();
        self.keys.xor_keystream(&mut encrypted, nonce);

        let mac = self.keys.compute_mac(&nonce_bytes, &encrypted);

        let total = TYPE_SIZE + NONCE_SIZE + encrypted.len() + MAC_SIZE;
        let mut output = BytesMut::with_capacity(total);
        output.extend_from_slice(&[FrameType::Data as u8]);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted);
        output.extend_from_slice(&mac);

        Ok(output.freeze())
    }

    /// Encode a control message (not encrypted).
    pub fn encode_control(payload: &[u8]) -> Bytes {
        let mut output = BytesMut::with_capacity(TYPE_SIZE + payload.len());
        output.extend_from_slice(&[FrameType::Control as u8]);
        output.extend_from_slice(payload);
        output.freeze()
    }
}

pub struct FrameDecoder {
    keys: SessionKeys,
    last_nonce: u64,
    replay_bitmap: u128,
}

impl FrameDecoder {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            last_nonce: 0,
            replay_bitmap: 0,
        }
    }

    /// Decode a WebSocket binary message into a frame.
    pub fn decode(&mut self, data: &[u8]) -> Result<Frame, FrameError> {
        if data.is_empty() {
            return Err(FrameError::TooShort);
        }

        match data[0] {
            0x00 => self.decode_data(&data[1..]),
            0x01 => Ok(Frame::Control(Bytes::copy_from_slice(&data[1..]))),
            t => Err(FrameError::UnknownType(t)),
        }
    }

    fn decode_data(&mut self, data: &[u8]) -> Result<Frame, FrameError> {
        if data.len() < NONCE_SIZE + MAC_SIZE {
            return Err(FrameError::TooShort);
        }

        let nonce_bytes = &data[..NONCE_SIZE];
        let nonce = u64::from_le_bytes(nonce_bytes.try_into().unwrap());

        let encrypted = &data[NONCE_SIZE..data.len() - MAC_SIZE];
        let mac_slice = &data[data.len() - MAC_SIZE..];

        let mut expected_mac = [0u8; MAC_SIZE];
        expected_mac.copy_from_slice(mac_slice);

        if !self.keys.verify_mac(nonce_bytes, encrypted, &expected_mac) {
            return Err(FrameError::MacFailed);
        }

        if !self.check_replay(nonce) {
            return Err(FrameError::Replay);
        }

        let mut decrypted = encrypted.to_vec();
        self.keys.xor_keystream(&mut decrypted, nonce);

        Ok(Frame::Data(Bytes::from(decrypted)))
    }

    fn check_replay(&mut self, nonce: u64) -> bool {
        if nonce == 0 && self.last_nonce == 0 && self.replay_bitmap == 0 {
            self.replay_bitmap = 1;
            return true;
        }

        if nonce > self.last_nonce {
            let shift = (nonce - self.last_nonce).min(128) as u32;
            self.replay_bitmap = self.replay_bitmap.checked_shl(shift).unwrap_or(0);
            self.replay_bitmap |= 1;
            self.last_nonce = nonce;
            return true;
        }

        let diff = self.last_nonce - nonce;
        if diff >= 128 {
            return false;
        }

        let bit = 1u128 << diff;
        if self.replay_bitmap & bit != 0 {
            return false;
        }

        self.replay_bitmap |= bit;
        true
    }
}

/// Decode a control message without keys (used during handshake).
pub fn decode_control(data: &[u8]) -> Result<Bytes, FrameError> {
    if data.is_empty() {
        return Err(FrameError::TooShort);
    }
    if data[0] != FrameType::Control as u8 {
        return Err(FrameError::UnknownType(data[0]));
    }
    Ok(Bytes::copy_from_slice(&data[1..]))
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short")]
    TooShort,
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownType(u8),
    #[error("MAC verification failed")]
    MacFailed,
    #[error("replay attack detected")]
    Replay,
    #[error("nonce exhausted, reconnect required")]
    NonceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> SessionKeys {
        SessionKeys::derive(&[42u8; 32])
    }

    #[test]
    fn test_data_roundtrip() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let original = b"Hello IP packet data";
        let encoded = encoder.encode_data(original).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();

        match decoded {
            Frame::Data(data) => assert_eq!(&data[..], original),
            _ => panic!("expected data frame"),
        }
    }

    #[test]
    fn test_control_roundtrip() {
        let payload = b"protobuf data";
        let encoded = FrameEncoder::encode_control(payload);
        let decoded = decode_control(&encoded).unwrap();
        assert_eq!(&decoded[..], payload);
    }

    #[test]
    fn test_replay_rejected() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let encoded = encoder.encode_data(b"test").unwrap();
        decoder.decode(&encoded).unwrap(); // first time OK

        let result = decoder.decode(&encoded); // replay
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_mac_rejected() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let mut encoded = encoder.encode_data(b"test").unwrap().to_vec();
        let len = encoded.len();
        encoded[len - 1] ^= 1; // flip last MAC byte

        let result = decoder.decode(&encoded);
        assert!(result.is_err());
    }
}
