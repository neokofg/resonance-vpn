use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpStream;
use tokio::sync::watch;

use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

use resonance_proto::crypto::{self, SessionKeys};
use resonance_proto::frame::{self, Frame, FrameDecoder, FrameEncoder};
use resonance_proto::proto;
use resonance_tun::TunDevice;

type WsStream = WebSocketStream<tokio_boring::SslStream<TcpStream>>;

pub struct HandshakeResult {
    pub assigned_ip: String,
    pub session_id: String,
    ws_stream: WsStream,
    keys: SessionKeys,
}

/// Phase 1: TCP -> TLS -> WS -> Auth -> ServerHello.
/// Returns immediately after handshake without entering any forwarding loop.
pub async fn handshake(server: &str, psk: &str) -> anyhow::Result<HandshakeResult> {
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:443")
    };

    let tcp_stream = TcpStream::connect(&addr).await?;
    log::info!("TCP connected to {addr}");

    let tls_config = crate::tls::chrome_tls_config()?;
    let host = addr.split(':').next().unwrap_or(&addr);
    let tls_stream = tokio_boring::connect(tls_config, host, tcp_stream).await?;

    if let Some(proto) = tls_stream.ssl().selected_alpn_protocol() {
        log::info!("ALPN: {}", String::from_utf8_lossy(proto));
    }

    let ws_url = format!("wss://{host}/ws");
    let (ws_stream, _) = tokio_tungstenite::client_async(
        tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&ws_url)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .body(())
            .unwrap(),
        tls_stream,
    )
    .await?;

    log::info!("WebSocket connected");

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Send AuthRequest
    let psk_hash = crypto::hash_psk(psk);
    let auth_req = proto::AuthRequest {
        psk_hash: psk_hash.to_vec(),
    };
    let auth_frame = FrameEncoder::encode_control(&auth_req.encode_to_vec());
    ws_write
        .send(WsMessage::Binary(auth_frame))
        .await?;

    // Receive ServerHello
    let hello_msg = ws_read
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before ServerHello"))??;

    let hello_data = match hello_msg {
        WsMessage::Binary(d) => d,
        _ => anyhow::bail!("Expected binary ServerHello"),
    };

    let hello_payload = frame::decode_control(&hello_data)?;
    let hello = proto::ServerHello::decode(hello_payload)?;

    log::info!(
        "Authenticated: session={}, ip={}",
        hello.session_id,
        hello.assigned_ip
    );

    let keys = SessionKeys::derive(&hello.key_material);

    let ws_stream = ws_write
        .reunite(ws_read)
        .map_err(|_| anyhow::anyhow!("Failed to reunite WebSocket stream"))?;

    Ok(HandshakeResult {
        assigned_ip: hello.assigned_ip,
        session_id: hello.session_id,
        ws_stream,
        keys,
    })
}

/// Phase 2: Bidirectional TUN <-> WS forwarding with keepalive.
pub async fn run_forwarding(
    result: HandshakeResult,
    tun: Arc<TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let (mut ws_write, mut ws_read) = result.ws_stream.split();

    let mut encoder = FrameEncoder::new(result.keys.clone());
    let mut decoder = FrameDecoder::new(result.keys);

    // TUN -> WS writer (with batching: feed all available packets, then flush once)
    let tun_read = tun.clone();
    let mut shutdown_w = shutdown.clone();
    let write_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            tokio::select! {
                read_result = tun_read.read(&mut buf) => {
                    match read_result {
                        Ok(n) if n > 0 => {
                            match encoder.encode_data(&buf[..n]) {
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

                            // Drain all immediately available packets without waiting
                            let mut failed = false;
                            loop {
                                match tun_read.try_read(&mut buf) {
                                    Ok(n) if n > 0 => {
                                        match encoder.encode_data(&buf[..n]) {
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
                                    _ => break,
                                }
                            }
                            if failed {
                                break;
                            }

                            // Single flush for all buffered packets
                            if ws_write.flush().await.is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("TUN read error: {e}");
                            break;
                        }
                    }
                }
                _ = shutdown_w.changed() => {
                    log::info!("Writer shutting down");
                    break;
                }
            }
        }
    });

    // WS -> TUN reader
    let tun_write = tun.clone();

    loop {
        tokio::select! {
            msg = ws_read.next() => {
                match msg {
                    Some(Ok(WsMessage::Binary(data))) => {
                        match decoder.decode(&data) {
                            Ok(Frame::Data(ip_packet)) => {
                                if let Err(e) = tun_write.write(&ip_packet).await {
                                    log::error!("TUN write error: {e}");
                                }
                            }
                            Ok(Frame::Control(_)) => {}
                            Err(e) => {
                                log::warn!("Decode error: {e}");
                            }
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => {
                        log::info!("Server disconnected");
                        break;
                    }
                    Some(Err(e)) => {
                        log::error!("WS read error: {e}");
                        break;
                    }
                    _ => {}
                }
            }
            _ = shutdown.changed() => {
                log::info!("Reader shutting down");
                break;
            }
        }
    }

    write_handle.abort();
    Ok(())
}
