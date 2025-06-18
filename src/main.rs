// Internal modules
mod auth;
mod config;
mod directory_listing;
mod error;
mod file_serving;
mod networking;
mod path_validation;
mod responses;
mod security_headers;
mod size_parsing;
mod tls;

// Standard library imports
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

// External crate imports
use http_body_util::Full;
use hyper::{
    body::Bytes,
    server::conn::http1,
    service::service_fn,
    Request, Response,
};
use percent_encoding::percent_decode_str;
use tokio::net::TcpListener;
use tracing::{error, info, warn, Instrument, Level};
use tracing_subscriber::{fmt, EnvFilter};

// Internal crate imports
use crate::{
    error::{AppError, Result},
    security_headers::add_security_headers,
    tls::wrap_stream,
};

#[cfg(feature = "tls")]
use crate::tls::configure_tls;
#[cfg(feature = "tls")]
use rustls::server::ServerConfig;
use auth::validate_credentials;
use directory_listing::list_directory; 
use file_serving::serve_file;
use path_validation::validate_path;

async fn handle_request(
    base_dir: PathBuf,
    req: Request<hyper::body::Incoming>,
    username: Option<String>,
    password: Option<String>,
    use_tls: bool,
    list_dirs: bool,
    show_dotfiles: bool,
    enable_csp: bool,
    enable_hsts: bool,
    max_file_size: Option<crate::size_parsing::HumanSize>,
    ) -> Result<Response<Full<Bytes>>> {
    let span = tracing::span!(
        Level::INFO,
        "request",
        method = %format!("{:?}", req.method()),
        uri = %req.uri(),
        version = ?req.version(),
    );
    let _enter = span.enter();

    // Check auth if credentials are provided
    if let (Some(username), Some(password)) = (&username, &password) {
            match validate_credentials(
                req.headers().get(hyper::header::AUTHORIZATION),
                &username,
                &password,
            ) {
                Ok(Some(response)) => return Ok(response),
                Ok(None) => (),
                Err(e) => return Err(e),
            }
    }

    let path = req.uri().path();
    let full_path = if path == "/" {
        base_dir.clone()
    } else {
        let decoded_path = percent_decode_str(path.trim_start_matches('/')).decode_utf8_lossy();
        base_dir.join(Path::new(&*decoded_path))
    };

    let canonical_path = match validate_path(&full_path, &base_dir, show_dotfiles) {
        Ok(path) => path,
        Err(e) => return Err(AppError::from(e)),
    };
    
    let response = match fs::metadata(&canonical_path) {
        Ok(metadata) if metadata.is_dir() => list_directory(&canonical_path, &base_dir, list_dirs, show_dotfiles),
        Ok(_) => serve_file(&canonical_path, show_dotfiles, max_file_size.map(|h| h.0)),
        Err(e) => Err(AppError::NotFound {
            path: canonical_path.clone(),
            source: e
        })
    }?;
    info!(status=%response.status(), full_path = %canonical_path.to_string_lossy());
    add_security_headers(response, use_tls, enable_csp, enable_hsts)
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = config::Config::new()?;
    let tls_enabled = config.args.tls;
    let list_dirs = !config.args.no_list_dirs;
    let config::Config { args, base_dir } = config;

    // Initialize tracing subscriber with CLI-configured log level
    fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(args.log_level.parse().unwrap())
                .from_env_lossy(),
        )
        .init();
    let ip_addr: IpAddr = args.bind.parse().map_err(|_| AppError::InvalidBindAddress {
        address: args.bind.clone(),
    })?;
    let addr = SocketAddr::new(ip_addr, args.port);
    let username = args.username.clone();
    let password = args.password.clone();

    if username.is_some() && password.is_some() && !args.tls {
        warn!(
            "Basic Auth is being used without TLS - credentials will be transmitted in plaintext!"
        );
    }

    info!("Serving files from {} on port {}", base_dir.display(), args.port);

    let connection_urls = networking::generate_connection_urls(ip_addr, args.port, args.tls);
    crate::networking::log_connection_urls(&connection_urls);

    #[cfg(feature = "tls")]
    let listener: (TcpListener, Option<Arc<ServerConfig>>) = if args.tls {
        let tls_config = configure_tls(
            args.tls_cert.clone().unwrap(),
            args.tls_key.clone().unwrap(),
        ).map_err(AppError::from)?;

        let listener = TcpListener::bind(addr).await?;
        info!("Listening with TLS on {}", addr);
        (listener, Some(tls_config))
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

        let tls_enabled = tls_enabled;
        let list_dirs = list_dirs;
        
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn({
                        let base_dir = base_dir.clone();
                        let username = username.clone();
                        let password = password.clone();
                        let tls = tls_enabled;
                        let show_dotfiles = args.show_dotfiles;
                        let enable_csp = args.enable_csp;
                        let enable_hsts = args.enable_hsts;
                        
                        move |req| {
                            let span = tracing::span!(
                                Level::ERROR,
                                "connection",
                                method = %req.method(),
                                uri = %req.uri(),
                            );
                            let base_dir = base_dir.clone();
                            let username = username.clone();
                            let password = password.clone();
                            
                            async move {
                                match handle_request(
                                    base_dir,
                                    req,
                                    username,
                                    password,
                                    tls,
                                    list_dirs,
                                    show_dotfiles,
                            enable_csp,
                            enable_hsts,
                            args.max_file_size,
                                ).await {
                                    Ok(response) => Ok(response),
                                    Err(e) => {
                                        error!(error=%e, "Request failed");
                                        crate::responses::error_response(e)
                                    }
                                }
                            }
                            .instrument(span)
                        }
                    }),
                )
                .await
            {
                error!(error=%err, "Connection failed");
            }
        });
    }
}
