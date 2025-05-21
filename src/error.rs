use std::{path::PathBuf, io};
use hyper::header::InvalidHeaderValue;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {

    #[error("Path traversal attempt detected: {path}")]
    PathTraversal {
        path: String,
    },

    #[error("File not found: {path}")]
    NotFound {
        path: PathBuf,
        #[source] source: std::io::Error,
    },

    #[error("Forbidden access to: {path}")]
    Forbidden {
        path: PathBuf,
    },

    #[error("IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source] source: std::io::Error,
    },

    #[error("Invalid bind address: {address}")]
    InvalidBindAddress {
        address: String,
    },

    #[error("TLS configuration error: {source}")]
    Tls {
        #[from] source: rustls::Error,
    },

    #[error("HTTP error: {source}")]
    Http {
        #[from] source: hyper::http::Error,
    },

    #[error("Header parse error: {source}")]
    HeaderParse {
        #[from] source: hyper::header::ToStrError,
    },

    #[error("IO error: {source}")]
    StdIo {
        #[from] source: io::Error,
    },

    #[error("Invalid header value: {source}")]
    InvalidHeader {
        #[from] source: InvalidHeaderValue,
    },
}

pub type Result<T> = std::result::Result<T, AppError>;
