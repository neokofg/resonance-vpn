use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use resonance_proto::crypto::SessionKeys;
use resonance_proto::frame::{self, Frame, FrameDecoder, FrameEncoder};
use resonance_proto::proto;

pub struct ClientSession {
    pub assigned_ip: Ipv4Addr,
    pub tx: mpsc::UnboundedSender<Bytes>,
}

pub type SessionMap = Arc<RwLock<HashMap<Ipv4Addr, ClientSession>>>;

pub struct IpPool {
    next: u32,
    max: u32,
}

impl IpPool {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Self {
        let base = u32::from(network);
        let host_bits = 32 - prefix;
        let max = base + (1 << host_bits) - 1;
        Self {
            next: base + 2,
            max: max - 1,
        }
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        if self.next > self.max {
            return None;
        }
        let ip = Ipv4Addr::from(self.next);
        self.next += 1;
        Some(ip)
    }

    pub fn release(&mut self, _ip: Ipv4Addr) {
        // Simple pool for 1-5 users
    }
}

pub async fn handle_client<S>(
    ws_stream: S,
    psk_hash: [u8; 32],
    sessions: SessionMap,
    ip_pool: Arc<tokio::sync::Mutex<IpPool>>,
    tun_tx: mpsc::UnboundedSender<(Ipv4Addr, Bytes)>,
) where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
        + Send
        + Unpin
        + 'static,
{
    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Step 1: Wait for AuthRequest
    let auth_msg = match ws_read.next().await {
        Some(Ok(WsMessage::Binary(data))) => data,
        _ => {
            log::warn!("Client disconnected before auth");
            return;
        }
    };

    let auth_payload = match frame::decode_control(&auth_msg) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Invalid auth frame: {e}");
            return;
        }
    };

    let auth_req = match proto::AuthRequest::decode(auth_payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Invalid AuthRequest: {e}");
            return;
        }
    };

    if auth_req.psk_hash.len() != 32 || auth_req.psk_hash[..] != psk_hash[..] {
        log::warn!("Auth failed: invalid PSK");
        let err = proto::Error {
            message: "Invalid PSK".to_string(),
        };
        let frame_data = FrameEncoder::encode_control(&err.encode_to_vec());
        let _ = ws_write
            .send(WsMessage::Binary(frame_data))
            .await;
        return;
    }

    let assigned_ip = match ip_pool.lock().await.allocate() {
        Some(ip) => ip,
        None => {
            log::error!("IP pool exhausted");
            return;
        }
    };

    let mut key_material = [0u8; 32];
    fastrand::fill(&mut key_material);

    let session_id = format!("{:016x}", fastrand::u64(..));

    let hello = proto::ServerHello {
        session_id: session_id.clone(),
        key_material: key_material.to_vec(),
        assigned_ip: assigned_ip.to_string(),
    };
    let hello_frame = FrameEncoder::encode_control(&hello.encode_to_vec());
    if ws_write
        .send(WsMessage::Binary(hello_frame))
        .await
        .is_err()
    {
        log::warn!("Failed to send ServerHello");
        return;
    }

    log::info!("Client authenticated: {session_id} -> {assigned_ip}");

    let keys = SessionKeys::derive(&key_material);
    let mut encoder = FrameEncoder::new(keys.clone());
    let mut decoder = FrameDecoder::new(keys);

    let (client_tx, mut client_rx) = mpsc::unbounded_channel::<Bytes>();

    {
        let mut sessions_w = sessions.write().await;
        sessions_w.insert(
            assigned_ip,
            ClientSession {
                assigned_ip,
                tx: client_tx,
            },
        );
    }

    let write_handle = tokio::spawn(async move {
        while let Some(ip_packet) = client_rx.recv().await {
            match encoder.encode_data(&ip_packet) {
                Ok(frame_data) => {
                    if ws_write
                        .send(WsMessage::Binary(frame_data))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    log::error!("Encode error: {e}");
                    break;
                }
            }
        }
    });

    while let Some(msg_result) = ws_read.next().await {
        match msg_result {
            Ok(WsMessage::Binary(data)) => match decoder.decode(&data) {
                Ok(Frame::Data(ip_packet)) => {
                    if tun_tx.send((assigned_ip, ip_packet)).is_err() {
                        break;
                    }
                }
                Ok(Frame::Control(payload)) => {
                    if let Ok(ping) = proto::Ping::decode(payload) {
                        log::debug!("Ping from {assigned_ip}: {}", ping.timestamp);
                    }
                }
                Err(e) => {
                    log::warn!("Decode error from {assigned_ip}: {e}");
                }
            },
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    log::info!("Client disconnected: {assigned_ip}");
    write_handle.abort();
    sessions.write().await.remove(&assigned_ip);
    ip_pool.lock().await.release(assigned_ip);
}
