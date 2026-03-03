use bytes::{Bytes, BytesMut};

use crate::crypto::SessionKeys;

pub const NONCE_SIZE: usize = 8;
pub const MAC_SIZE: usize = 16;
pub const TYPE_SIZE: usize = 1;
pub const FRAME_OVERHEAD: usize = TYPE_SIZE + NONCE_SIZE + MAC_SIZE;

const NONCE_REKEY_THRESHOLD: u64 = u64::MAX - 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x00,
    Control = 0x01,
}

#[derive(Debug)]
pub enum Frame {
    Data(Bytes),
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

    pub fn encode_data(&mut self, ip_packet: &[u8]) -> Result<Bytes, FrameError> {
        let nonce = self.next_nonce()?;
        let nonce_bytes = nonce.to_le_bytes();

        let total = TYPE_SIZE + NONCE_SIZE + ip_packet.len() + MAC_SIZE;
        let mut output = BytesMut::with_capacity(total);
        output.extend_from_slice(&[FrameType::Data as u8]);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(ip_packet);

        let data_start = TYPE_SIZE + NONCE_SIZE;
        let data_end = data_start + ip_packet.len();
        self.keys
            .xor_keystream(&mut output[data_start..data_end], nonce);

        let mac = self
            .keys
            .compute_mac(&nonce_bytes, &output[data_start..data_end]);
        output.extend_from_slice(&mac);

        Ok(output.freeze())
    }

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

    pub fn decode_owned(&mut self, data: Bytes) -> Result<Frame, FrameError> {
        if data.is_empty() {
            return Err(FrameError::TooShort);
        }

        match data[0] {
            0x00 => match data.try_into_mut() {
                Ok(mut buf) => self.decode_data_mut(&mut buf),
                Err(data) => self.decode_data(&data[1..]),
            },
            0x01 => Ok(Frame::Control(data.slice(1..))),
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

    fn decode_data_mut(&mut self, buf: &mut BytesMut) -> Result<Frame, FrameError> {
        let total = buf.len();
        if total < TYPE_SIZE + NONCE_SIZE + MAC_SIZE {
            return Err(FrameError::TooShort);
        }

        let nonce_start = TYPE_SIZE;
        let data_start = TYPE_SIZE + NONCE_SIZE;
        let mac_start = total - MAC_SIZE;

        let nonce_bytes: [u8; NONCE_SIZE] = buf[nonce_start..data_start].try_into().unwrap();
        let nonce = u64::from_le_bytes(nonce_bytes);

        let mut expected_mac = [0u8; MAC_SIZE];
        expected_mac.copy_from_slice(&buf[mac_start..]);

        if !self
            .keys
            .verify_mac(&nonce_bytes, &buf[data_start..mac_start], &expected_mac)
        {
            return Err(FrameError::MacFailed);
        }

        if !self.check_replay(nonce) {
            return Err(FrameError::Replay);
        }

        self.keys
            .xor_keystream(&mut buf[data_start..mac_start], nonce);

        let frozen = buf.split().freeze();
        Ok(Frame::Data(frozen.slice(data_start..mac_start)))
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
        decoder.decode(&encoded).unwrap();

        let result = decoder.decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_mac_rejected() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let mut encoded = encoder.encode_data(b"test").unwrap().to_vec();
        let len = encoded.len();
        encoded[len - 1] ^= 1;

        let result = decoder.decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_data_roundtrip_zero_copy() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let original = b"Hello zero-copy decode path";
        let encoded = encoder.encode_data(original).unwrap();
        let decoded = decoder.decode_owned(encoded).unwrap();

        match decoded {
            Frame::Data(data) => assert_eq!(&data[..], original),
            _ => panic!("expected data frame"),
        }
    }
}
