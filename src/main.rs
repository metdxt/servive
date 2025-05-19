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
};
use tokio::net::TcpListener;
use tracing::{Level, info, error};
use tracing_subscriber::{EnvFilter, fmt};

mod auth;
mod responses;
mod file_handling;

use auth::validate_credentials;
use responses::not_found_response;
use file_handling::{validate_path, serve_file, list_directory};

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
}

async fn handle_request(
    base_dir: PathBuf,
    req: Request<hyper::body::Incoming>,
    username: Option<String>,
    password: Option<String>,
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

    info!("Handling request in {}", base_dir.display());
    let canonical_path = match validate_path(&full_path, &base_dir) {
        Ok(path) => path,
        Err(_) => return not_found_response(),
    };

    match fs::metadata(&canonical_path) {
        Ok(metadata) if metadata.is_dir() => list_directory(&canonical_path, &base_dir),
        Ok(_) => serve_file(&canonical_path),
        Err(_) => not_found_response(),
    }
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

    info!("Serving files from {} on port {}", base_dir.display(), args.port);

    let listener = TcpListener::bind(addr).await?;
    info!("Listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
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
                        handle_request(base_dir.clone(), req, username.clone(), password.clone())
                    }),
                )
                .await
            {
                error!("Error serving connection: {}", err);
            }
        });
    }
}
