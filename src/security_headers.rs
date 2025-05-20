use hyper::{Response, body::Bytes};
use http_body_util::Full;
use std::error::Error;

pub fn add_security_headers(
    response: Response<Full<Bytes>>, 
    use_tls: bool,
) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    let is_error = response.status().is_client_error() || response.status().is_server_error();
    let (mut parts, body) = response.into_parts();

    // Set basic security headers
    parts.headers.insert("X-Content-Type-Options", "nosniff".parse()?);
    parts.headers.insert("X-Frame-Options", "DENY".parse()?);
    parts.headers.insert("X-XSS-Protection", "1; mode=block".parse()?);

    // Set HSTS if using TLS
    if use_tls {
        parts.headers.insert(
            "Strict-Transport-Security", 
            "max-age=63072000; includeSubDomains; preload".parse()?
        );
    }

    // Set CSP
    parts.headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:".parse()?
    );

    // Set cache control based on status
    if is_error {
        parts.headers.insert("Cache-Control", "no-store".parse()?);
    } else {
        parts.headers.insert("Cache-Control", "public, max-age=3600".parse()?);
    }

    Ok(Response::from_parts(parts, body))
}
