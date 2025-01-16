use actix_files::Files;
use actix_web::{middleware::Logger, App, HttpServer};
use anyhow::{Context, Result};
use clap::Parser;
use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

const CA_KEY_DER: &[u8] = include_bytes!("../cert/ca-key.der");
const CA_CERTIFICATE_DER: &[u8] = include_bytes!("../cert/ca-cert.der");

fn build_tls_config() -> Result<rustls::ServerConfig> {
    let ca_private_key = PrivatePkcs8KeyDer::from(CA_KEY_DER);
    let ca_keypair = KeyPair::try_from(&ca_private_key)?;
    let ca_certificate_params =
        CertificateParams::from_ca_cert_der(&CertificateDer::from(CA_CERTIFICATE_DER))?;

    let ca_certificate = ca_certificate_params.self_signed(&ca_keypair)?;

    let (server_certificate, server_keypair) = generate_certificate(&ca_certificate, &ca_keypair)?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_certificate.der().to_owned()],
            PrivateKeyDer::Pkcs8(server_keypair.serialize_der().into()),
        )
        .context("Failed to build TLS configuration")
}

fn generate_certificate(
    ca_certificate: &Certificate,
    ca_keypair: &KeyPair,
) -> Result<(Certificate, KeyPair)> {
    let mut certificate_params =
        CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    certificate_params
        .distinguished_name
        .push(DnType::CommonName, "Kypare");
    certificate_params.use_authority_key_identifier_extension = true;
    certificate_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    certificate_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let yesterday = OffsetDateTime::now_utc()
        .checked_sub(Duration::DAY)
        .unwrap();
    let in_a_year = OffsetDateTime::now_utc()
        .checked_add(Duration::DAY * 365)
        .unwrap();
    certificate_params.not_before = yesterday;
    certificate_params.not_after = in_a_year;

    let keypair = KeyPair::generate()?;

    Ok((
        certificate_params.signed_by(&keypair, ca_certificate, ca_keypair)?,
        keypair,
    ))
}

#[derive(clap::Parser)]
#[command(version)]
#[command(about = "A simple static file HTTPS server with a built-in self-signed certificate")]
struct Opts {
    /// The address to serve on
    #[arg(long, default_value_t = String::from("127.0.0.1"))]
    address: String,

    /// The port to serve on
    #[arg(long, default_value_t = 8443)]
    port: u16,

    /// The root directory to serve files from
    #[arg(long, default_value_t = String::from("."))]
    files_root: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    env_logger::init_from_env(
        // rustls logs TLS alerts on warning or even error level...
        env_logger::Env::default().default_filter_or("info,rustls::conn=off"),
    );

    let config = build_tls_config()?;

    log::info!(
        "Starting HTTPS server at https://{}:{}",
        opts.address,
        opts.port
    );

    HttpServer::new(move || {
        App::new().wrap(Logger::default()).service(
            Files::new("/", &opts.files_root)
                .index_file("index.html")
                .show_files_listing(),
        )
    })
    .bind_rustls_0_23((opts.address.as_ref(), opts.port), config)
    .context(format!("Failed to bind to {}:{}", opts.address, opts.port))?
    .run()
    .await
    .context("Failed to start server")
}
