use std::{
    fs::{self, create_dir_all, OpenOptions},
    io::Write,
    path::Path,
};

use actix_files::Files;
use actix_web::{middleware::Logger, App, HttpServer};
use anyhow::{bail, Context, Result};
use clap::Parser;
use directories::ProjectDirs;
use env_logger::Env;
use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::PrivateKeyDer;
use time::{Duration, OffsetDateTime};

fn write_ca_certificate(certificate: &Certificate, path: &Path) -> Result<()> {
    fs::write(path, certificate.pem())
        .with_context(|| format!("Failed to write CA certificate to {}", path.display()))
}

fn write_ca_keypair(keypair: &KeyPair, path: &Path) -> Result<()> {
    let mut open_options = OpenOptions::new();
    open_options.write(true).create(true);

    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }

    // TODO: Add security descriptors for Windows which is a lot more complicated

    let mut file = open_options.open(path)?;
    file.write_all(keypair.serialize_pem().as_bytes())
        .with_context(|| format!("Failed to write CA key to {}", path.display()))
}

fn load_ca_certificate(
    ca_certificate_path: &Path,
    ca_keypair_path: &Path,
) -> Result<(Certificate, KeyPair)> {
    log::debug!("Loading CA key from {}", ca_keypair_path.display());
    let key_data = fs::read_to_string(ca_keypair_path)?;
    let keypair = KeyPair::from_pem(&key_data)?;

    log::info!(
        "Loading CA certificate from {}",
        ca_certificate_path.display()
    );
    let certificate_data = fs::read_to_string(ca_certificate_path)?;
    let certificate_params = CertificateParams::from_ca_cert_pem(&certificate_data)?;
    let certificate = certificate_params.self_signed(&keypair)?;
    Ok((certificate, keypair))
}

fn generate_ca_certificate() -> Result<(Certificate, KeyPair)> {
    let mut certificate_params = CertificateParams::new(vec![]).unwrap();
    certificate_params
        .distinguished_name
        .push(DnType::CommonName, "Kypare");
    certificate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    certificate_params
        .distinguished_name
        .push(DnType::OrganizationName, "Kypare CA");
    certificate_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    certificate_params
        .key_usages
        .push(KeyUsagePurpose::KeyCertSign);

    let yesterday = OffsetDateTime::now_utc()
        .checked_sub(Duration::DAY)
        .unwrap();
    let in_five_years = OffsetDateTime::now_utc()
        .checked_add(Duration::DAY * 365 * 5)
        .unwrap();
    certificate_params.not_before = yesterday;
    certificate_params.not_after = in_five_years;

    let keypair = KeyPair::generate()?;

    Ok((certificate_params.self_signed(&keypair)?, keypair))
}

fn load_or_generate_ca_certificate(ca_certificate_dir: &Path) -> Result<(Certificate, KeyPair)> {
    let ca_certificate_path = ca_certificate_dir.join("cert.pem");
    let ca_keypair_path = ca_certificate_dir.join("key.pem");

    if ca_certificate_path.exists() && ca_keypair_path.exists() {
        load_ca_certificate(&ca_certificate_path, &ca_keypair_path)
    } else {
        log::info!(
            "No CA certificate found in {}, generating...",
            ca_certificate_dir.display()
        );
        let (ca_certificate, ca_keypair) = generate_ca_certificate()?;
        write_ca_certificate(&ca_certificate, &ca_certificate_path)?;
        write_ca_keypair(&ca_keypair, &ca_keypair_path)?;

        log::info!(
            "Wrote CA certificate to {}. Import it to your browser as a trusted root",
            ca_certificate_path.display()
        );
        Ok((ca_certificate, ca_keypair))
    }
}

fn build_tls_config(ca_certificate_dir: &Path) -> Result<rustls::ServerConfig> {
    let (ca_certificate, ca_keypair) = load_or_generate_ca_certificate(ca_certificate_dir)?;

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
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let Some(project_dirs) = ProjectDirs::from("", "", "kypare") else {
        bail!("Failed to determine home directory");
    };
    let data_dir = project_dirs.data_dir();
    create_dir_all(data_dir)
        .with_context(|| format!("Failed to create data directory {}", data_dir.display()))?;

    let config = build_tls_config(data_dir)?;

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
