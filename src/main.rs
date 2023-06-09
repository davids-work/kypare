use actix_files::Files;
use actix_web::{middleware::Logger, App, HttpServer};
use anyhow::{Context, Result};
use clap::Parser;
use rustls::{Certificate, PrivateKey};

const EC_KEY: &[u8] = include_bytes!("../cert/key.der");
const CERTIFICATE: &[u8] = include_bytes!("../cert/cert.der");

fn build_tls_config() -> Result<rustls::ServerConfig> {
    let rustls_certificate = Certificate(CERTIFICATE.to_vec());
    let rustls_privatekey = PrivateKey(EC_KEY.to_vec());

    rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_certificate], rustls_privatekey)
        .context("Failed to build TLS configuration")
}

#[derive(clap::Parser)]
#[command(version)]
#[command(about = "A simple static file HTTPS server with a built-in self-signed certificate")]
struct Opts {
    /// The address to serve on
    #[arg(long, default_value_t = String::from("127.0.0.1"))]
    address: String,

    /// The port to serve on
    #[arg(long, default_value_t = 8080)]
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
        App::new()
            .wrap(Logger::default())
            .service(Files::new("/", &opts.files_root).show_files_listing())
    })
    .bind_rustls((opts.address.as_ref(), opts.port), config)
    .context(format!("Failed to bind to {}:{}", opts.address, opts.port))?
    .run()
    .await
    .context("Failed to start server")
}
