use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use thiserror::Error;

#[cfg(feature = "tls")]
use rustls::ServerConfig;
#[cfg(feature = "tls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(feature = "tls")]
use tokio_rustls::TlsAcceptor;
use std::sync::Arc;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("TLS configuration error")]
    Config(#[from] rustls::Error),
    #[error("IO error")]
    Io(#[from] std::io::Error),
}

pub enum AsyncStream {
    Plain(tokio::net::TcpStream),
    #[cfg(feature = "tls")]
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl AsyncRead for AsyncStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AsyncStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            AsyncStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AsyncStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            AsyncStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            AsyncStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AsyncStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            AsyncStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            AsyncStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            AsyncStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(feature = "tls")]
pub fn configure_tls(
    cert_path: String,
    key_path: String,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_file = std::fs::read(cert_path)?;
    let key_file = std::fs::read(key_path)?;
    let certs = vec![CertificateDer::from(cert_file)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_file));

    Ok(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
}

pub async fn wrap_stream(
    stream: tokio::net::TcpStream,
    #[cfg(feature = "tls")] tls_config: Option<Arc<ServerConfig>>,
    #[cfg(not(feature = "tls"))] _tls_config: Option<()>,
) -> Result<TokioIo<AsyncStream>, TlsError> {
    #[cfg(feature = "tls")]
    {
        match tls_config {
            Some(config) => {
                let acceptor = TlsAcceptor::from(config);
                let stream = acceptor.accept(stream).await?;
                Ok(TokioIo::new(AsyncStream::Tls(stream)))
            }
            None => Ok(TokioIo::new(AsyncStream::Plain(stream))),
        }
    }

    #[cfg(not(feature = "tls"))]
    Ok(TokioIo::new(AsyncStream::Plain(stream)))
}
