use clap::Parser;
use http_body_util::Full;
use hyper::{
    Request, Response, body::Bytes, server::conn::http1, service::service_fn,
};
use std::fs;
use hyper_util::rt::TokioIo;
use percent_encoding::percent_decode_str;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpListener;
use tracing::{Level, info, warn, error};
use tracing_subscriber::{EnvFilter, fmt};
use std::error::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "tls")]
use rustls::ServerConfig;
#[cfg(feature = "tls")] 
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(feature = "tls")]
#[allow(unused_imports)]
use tokio_rustls::TlsAcceptor;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

#[cfg(feature = "tls")]
async fn wrap_stream(
    stream: tokio::net::TcpStream,
    tls_config: Option<Arc<ServerConfig>>,
) -> Result<TokioIo<Box<dyn AsyncReadWrite + Send + Sync>>, Box<dyn Error + Send + Sync>> {
    match tls_config {
        Some(config) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            let stream = acceptor.accept(stream).await?;
            Ok(TokioIo::new(Box::new(stream)))
        }
        None => Ok(TokioIo::new(Box::new(stream)))
    }
}

#[cfg(not(feature = "tls"))]
async fn wrap_stream(
    stream: tokio::net::TcpStream,
    _tls_config: Option<()>,
) -> Result<TokioIo<Box<dyn AsyncReadWrite + Send + Sync>>, Box<dyn Error + Send + Sync>> {
    Ok(TokioIo::new(Box::new(stream)))
}

mod auth;
mod responses;
mod file_handling;
mod security_headers;

use auth::validate_credentials;
use responses::not_found_response;
use file_handling::{validate_path, serve_file, list_directory};
use crate::security_headers::add_security_headers;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 8000)]
    port: u16,

    /// Directory to serve files from
    #[arg(short, long, default_value = ".")]
    directory: String,

    /// Username for basic auth (optional)
    #[arg(long)]
    username: Option<String>,

    /// Password for basic auth (optional)
    #[arg(long)]
    password: Option<String>,

    /// Logging level (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Enable TLS (requires cert and key)
    #[arg(long)]
    tls: bool,

    /// TLS certificate file path
    #[arg(long, requires = "tls")]
    tls_cert: Option<String>,

    /// TLS private key file path
    #[arg(long, requires = "tls")]
    tls_key: Option<String>,

    /// Forbid directory listing
    #[arg(long, default_value_t = false)]
    no_list_dirs: bool,
}

async fn handle_request(
    base_dir: PathBuf,
    req: Request<hyper::body::Incoming>,
    username: Option<String>,
    password: Option<String>,
    use_tls: bool,
    list_dirs: bool
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Check auth if credentials are provided
    if let (Some(username), Some(password)) = (&username, &password) {
        if let Some(response) = validate_credentials(req.headers().get(hyper::header::AUTHORIZATION), &username, &password) {
            return Ok(response);
        }
    }

    let path = req.uri().path();
    let full_path = if path == "/" {
        base_dir.clone()
    } else {
        let decoded_path = percent_decode_str(path.trim_start_matches('/')).decode_utf8_lossy();
        base_dir.join(Path::new(&*decoded_path))
    };

    let canonical_path = match validate_path(&full_path, &base_dir) {
        Ok(path) => path,
        Err(_) => return not_found_response(),
    };
    info!(uri_path=path, full_path=canonical_path.to_str());
    let response = match fs::metadata(&canonical_path) {
        Ok(metadata) if metadata.is_dir() => list_directory(&canonical_path, &base_dir, list_dirs),
        Ok(_) => serve_file(&canonical_path),
        Err(_) => not_found_response(),
    }?;

    add_security_headers(response, use_tls)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Initialize tracing subscriber with CLI-configured log level
    fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(args.log_level.parse().unwrap())
                .from_env_lossy()
        )
        .init();
    let base_dir = PathBuf::from(args.directory).canonicalize()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let username = args.username.clone();
    let password = args.password.clone();

    if username.is_some() && password.is_some() && !args.tls {
        warn!("Basic Auth is being used without TLS - credentials will be transmitted in plaintext!");
    }

    info!("Serving files from {} on port {}", base_dir.display(), args.port);

    #[cfg(feature = "tls")]
    let listener: (TcpListener, Option<Arc<ServerConfig>>) = if args.tls {
        let cert_file = fs::read(args.tls_cert.unwrap())?;
        let key_file = fs::read(args.tls_key.unwrap())?;
        let certs = vec![CertificateDer::from(cert_file)];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_file));
        
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        );

        let listener = TcpListener::bind(addr).await?;
        info!("Listening with TLS on {}", addr);
        (listener, Some(config))
    } else {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening without TLS on {}", addr);
        (listener, None)
    };

#[cfg(not(feature = "tls"))]
let listener: (TcpListener, Option<()>) = {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening without TLS on {}", addr);
        (listener, Some(()))
    };

    loop {
        let (stream, _) = listener.0.accept().await?;
        
        let io = wrap_stream(stream, listener.1.clone()).await?;
        let base_dir = base_dir.clone();
        let username = username.clone();
        let password = password.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let span = tracing::span!(
                            Level::INFO,
                            "request",
                            method = %format!("{:?}", req.method()),
                            uri = %req.uri(),
                            version = ?req.version()
                        );
                        let _enter = span.enter();
                        handle_request(base_dir.clone(), req, username.clone(), password.clone(), args.tls, !args.no_list_dirs)
                    }),
                )
                .await
            {
                error!("Error serving connection: {}", err);
            }
        });
    }
}
