use boring::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVersion};
use std::path::Path;

pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;

    builder.set_alpn_select_callback(|_ssl, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });

    Ok(builder.build())
}
