use boring::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};

pub fn chrome_tls_config() -> anyhow::Result<boring::ssl::ConnectConfiguration> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // Protocol versions
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Chrome cipher suite order (TLS 1.2; TLS 1.3 ciphers are BoringSSL defaults)
    builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:\
         ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:\
         ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:\
         ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-RSA-AES128-SHA:\
         ECDHE-RSA-AES256-SHA:\
         AES128-GCM-SHA256:\
         AES256-GCM-SHA384:\
         AES128-SHA:\
         AES256-SHA",
    )?;

    // GREASE: random values in cipher suites and extensions (Chrome does this)
    builder.set_grease_enabled(true);

    // Extension permutation (Chrome 110+)
    builder.set_permute_extensions(true);

    // Supported curves (Chrome: X25519, P-256, P-384)
    builder.set_curves_list("X25519:P-256:P-384")?;

    // Signature algorithms
    builder.set_sigalgs_list(
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:\
         ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:\
         RSA-PSS+SHA512:RSA+SHA512",
    )?;

    // ALPN: h2 and http/1.1
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    // OCSP stapling
    builder.enable_ocsp_stapling();

    // Signed certificate timestamps
    builder.enable_signed_cert_timestamps();

    // SSL options
    builder.set_options(
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_COMPRESSION,
    );

    // Verify server certificates using system CA store
    builder.set_default_verify_paths()?;
    builder.set_verify(SslVerifyMode::PEER);

    let connector = builder.build();
    let config = connector.configure()?;

    Ok(config)
}
