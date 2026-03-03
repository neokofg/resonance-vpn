use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use subtle::ConstantTimeEq;
use tokio::sync::{RwLock, mpsc};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use resonance_proto::crypto::SessionKeys;
use resonance_proto::frame::{self, Frame, FrameDecoder, FrameEncoder};
use resonance_proto::proto;

pub struct ClientSession {
    pub tx: mpsc::Sender<Bytes>,
}

pub type SessionMap = Arc<RwLock<HashMap<Ipv4Addr, ClientSession>>>;

pub struct IpPool {
    next: u32,
    max: u32,
    released: Vec<u32>,
}

impl IpPool {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Self {
        let base = u32::from(network);
        let host_bits = 32 - prefix;
        let max = base + (1 << host_bits) - 1;
        Self {
            next: base + 2,
            max: max - 1,
            released: Vec::new(),
        }
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        if let Some(ip) = self.released.pop() {
            return Some(Ipv4Addr::from(ip));
        }
        if self.next > self.max {
            return None;
        }
        let ip = Ipv4Addr::from(self.next);
        self.next += 1;
        Some(ip)
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        self.released.push(u32::from(ip));
    }
}

pub async fn handle_client<S>(
    ws_stream: S,
    psk_hash: [u8; 32],
    sessions: SessionMap,
    ip_pool: Arc<tokio::sync::Mutex<IpPool>>,
    tun_tx: mpsc::Sender<(Ipv4Addr, Bytes)>,
) where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
        + Send
        + Unpin
        + 'static,
{
    let (mut ws_write, mut ws_read) = ws_stream.split();

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

    if auth_req.psk_hash.len() != 32 || !bool::from(auth_req.psk_hash.ct_eq(&psk_hash[..])) {
        log::warn!("Auth failed: invalid PSK");
        let err = proto::Error {
            message: "Invalid PSK".to_string(),
        };
        let frame_data = FrameEncoder::encode_control(&err.encode_to_vec());
        let _ = ws_write.send(WsMessage::Binary(frame_data)).await;
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
    if getrandom::getrandom(&mut key_material).is_err() {
        log::error!("Failed to generate key material");
        return;
    }

    let mut session_bytes = [0u8; 8];
    if getrandom::getrandom(&mut session_bytes).is_err() {
        log::error!("Failed to generate session ID");
        return;
    }
    let session_id = format!("{:016x}", u64::from_le_bytes(session_bytes));

    let hello = proto::ServerHello {
        session_id: session_id.clone(),
        key_material: key_material.to_vec(),
        assigned_ip: assigned_ip.to_string(),
    };
    let hello_frame = FrameEncoder::encode_control(&hello.encode_to_vec());
    if ws_write.send(WsMessage::Binary(hello_frame)).await.is_err() {
        log::warn!("Failed to send ServerHello");
        return;
    }

    log::info!("Client authenticated: {session_id} -> {assigned_ip}");

    let keys = SessionKeys::derive(&key_material);
    let mut encoder = FrameEncoder::new(keys.clone());
    let mut decoder = FrameDecoder::new(keys);

    let (client_tx, mut client_rx) = mpsc::channel::<Bytes>(256);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Bytes>(16);

    {
        let mut sessions_w = sessions.write().await;
        sessions_w.insert(
            assigned_ip,
            ClientSession {
                tx: client_tx,
            },
        );
    }

    let write_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(ip_packet) = client_rx.recv() => {
                    match encoder.encode_data(&ip_packet) {
                        Ok(frame_data) => {
                            if ws_write
                                .feed(WsMessage::Binary(frame_data))
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

                    let mut failed = false;
                    while let Ok(pkt) = client_rx.try_recv() {
                        match encoder.encode_data(&pkt) {
                            Ok(frame_data) => {
                                if ws_write
                                    .feed(WsMessage::Binary(frame_data))
                                    .await
                                    .is_err()
                                {
                                    failed = true;
                                    break;
                                }
                            }
                            Err(e) => {
                                log::error!("Encode error: {e}");
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed {
                        break;
                    }

                    if ws_write.flush().await.is_err() {
                        break;
                    }
                }
                Some(ctrl_frame) = ctrl_rx.recv() => {
                    if ws_write
                        .send(WsMessage::Binary(ctrl_frame))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                else => break,
            }
        }
    });

    while let Some(msg_result) = ws_read.next().await {
        match msg_result {
            Ok(WsMessage::Binary(data)) => match decoder.decode(&data) {
                Ok(Frame::Data(ip_packet)) => {
                    if tun_tx.send((assigned_ip, ip_packet)).await.is_err() {
                        break;
                    }
                }
                Ok(Frame::Control(payload)) => {
                    if let Ok(ping) = proto::Ping::decode(payload) {
                        let pong = proto::Pong {
                            timestamp: ping.timestamp,
                        };
                        let pong_frame = FrameEncoder::encode_control(&pong.encode_to_vec());
                        let _ = ctrl_tx.send(pong_frame).await;
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
