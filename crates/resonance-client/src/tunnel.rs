use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpStream;
use tokio::sync::watch;

use tokio_tungstenite::tungstenite::Message as WsMessage;

use resonance_proto::crypto::{self, SessionKeys};
use resonance_proto::frame::{self, Frame, FrameDecoder, FrameEncoder};
use resonance_proto::proto;
use resonance_tun::TunDevice;

pub struct ConnectResult {
    pub assigned_ip: String,
    pub session_id: String,
}

pub async fn connect_and_run(
    server: &str,
    psk: &str,
    tun: Arc<TunDevice>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<ConnectResult> {
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

    let result = ConnectResult {
        assigned_ip: hello.assigned_ip.clone(),
        session_id: hello.session_id.clone(),
    };

    let keys = SessionKeys::derive(&hello.key_material);
    let mut encoder = FrameEncoder::new(keys.clone());
    let mut decoder = FrameDecoder::new(keys);

    // TUN -> WS writer
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
    Ok(result)
}
