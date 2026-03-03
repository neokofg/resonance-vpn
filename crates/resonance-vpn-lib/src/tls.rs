use boring::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};

pub fn chrome_tls_config(
    allow_self_signed: bool,
) -> anyhow::Result<boring::ssl::ConnectConfiguration> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

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

    builder.set_grease_enabled(true);

    builder.set_permute_extensions(true);

    builder.set_curves_list("X25519:P-256:P-384")?;

    builder.set_sigalgs_list(
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:\
         ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:\
         RSA-PSS+SHA512:RSA+SHA512",
    )?;

    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    builder.enable_ocsp_stapling();

    builder.enable_signed_cert_timestamps();

    builder.set_options(SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_COMPRESSION);

    if allow_self_signed {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder.set_default_verify_paths()?;
        builder.set_verify(SslVerifyMode::PEER);
    }

    let connector = builder.build();
    let mut config = connector.configure()?;

    if allow_self_signed {
        config.set_verify_hostname(false);
    }

    Ok(config)
}
