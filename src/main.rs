use clap::Parser;
use http_auth_basic::Credentials;
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode, body::Bytes, header::AUTHORIZATION, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use mime_guess::from_path;
use percent_encoding::percent_decode_str;
use std::{
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::net::TcpListener;
use tracing::{Level, error, info, instrument, warn};
use tracing_subscriber::{EnvFilter, fmt};

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
}

async fn handle_request(
    base_dir: PathBuf,
    req: Request<hyper::body::Incoming>,
    username: Option<String>,
    password: Option<String>,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Check auth if credentials are provided
    if let (Some(username), Some(password)) = (&username, &password) {
        if let Some(auth_header) = req.headers().get(AUTHORIZATION) {
            if let Ok(credentials) = Credentials::from_header(auth_header.to_str()?.to_string()) {
                if credentials.user_id != *username || credentials.password != *password {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
                        .body(Full::new(Bytes::from("401 Unauthorized")))
                        .unwrap());
                }
            } else {
                return Ok(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
                    .body(Full::new(Bytes::from("401 Unauthorized")))
                    .unwrap());
            }
        } else {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
                .body(Full::new(Bytes::from("401 Unauthorized")))
                .unwrap());
        }
    }
    let path = req.uri().path();
    let full_path = if path == "/" {
        base_dir.clone()
    } else {
        let decoded_path = percent_decode_str(path.trim_start_matches('/')).decode_utf8_lossy();
        base_dir.join(Path::new(&*decoded_path))
    };

    // Security check - prevent path traversal
    let canonical_path = full_path.canonicalize().map_err(|e| {
    error!("Failed to canonicalize path: {}", e);
        Box::new(e) as Box<dyn std::error::Error + Send + Sync>
    })?;

    info!("Handling request in {}", base_dir.display());

    if !canonical_path.starts_with(&base_dir) {
        Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from("403 Forbidden")))
            .unwrap())
    } else {
        match fs::metadata(&canonical_path) {
            Ok(metadata) if metadata.is_dir() => {
                let mut entries = fs::read_dir(&canonical_path)
                    .unwrap()
                    .map(|res| res.map(|e| e.path()))
                    .collect::<Result<Vec<_>, io::Error>>()
                    .unwrap();

                entries.sort();

                let mut html = String::from("<h1>Directory listing</h1><ul>");
                for entry in entries {
                    let name = entry.file_name().unwrap().to_string_lossy();
                    let relative_path = entry.strip_prefix(&base_dir).unwrap();
                    html.push_str(&format!(
                        "<li><a href=\"{}\">{}</a></li>",
                        relative_path.display(),
                        name
                    ));
                }
                html.push_str("</ul>");

                Ok(Response::new(Full::new(Bytes::from(html))))
            }
            Ok(_) => {
                let mime_type = from_path(&canonical_path).first_or_octet_stream();
                let content = fs::read(&canonical_path).unwrap();
                Response::builder()
                    .header("Content-Type", mime_type.as_ref())
                    .body(Full::new(Bytes::from(content)))
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }
            Err(_) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("404 Not Found")))
                .unwrap()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing subscriber with JSON output
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let args = Args::parse();
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
