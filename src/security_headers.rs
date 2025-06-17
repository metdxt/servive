use hyper::{Response, body::Bytes};
use http_body_util::Full;
use crate::error::{AppError, Result};

pub fn add_security_headers(
    response: Response<Full<Bytes>>, 
    use_tls: bool,
    enable_csp: bool,
) -> Result<Response<Full<Bytes>>> {
    let is_error = response.status().is_client_error() || response.status().is_server_error();
    let (mut parts, body) = response.into_parts();

    // Set basic security headers
    parts.headers.insert("X-Content-Type-Options", "nosniff".parse().map_err(AppError::from)?);
    parts.headers.insert("X-Frame-Options", "DENY".parse().map_err(AppError::from)?);
    parts.headers.insert("X-XSS-Protection", "1; mode=block".parse().map_err(AppError::from)?);

    // Set HSTS if using TLS
    if use_tls {
        parts.headers.insert(
            "Strict-Transport-Security", 
            "max-age=63072000; includeSubDomains; preload".parse().map_err(AppError::from)?
        );
    }

    // Set CSP if enabled
    if enable_csp {
        parts.headers.insert(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:".parse().map_err(AppError::from)?
        );
    }

    // Set cache control based on status
    if is_error {
        parts.headers.insert("Cache-Control", "no-store".parse().map_err(AppError::from)?);
    } else {
        parts.headers.insert("Cache-Control", "public, max-age=3600".parse().map_err(AppError::from)?);
    }

    Ok(Response::from_parts(parts, body))
}
