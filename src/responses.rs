use hyper::{Response, header::HeaderValue};
use http_body_util::Full;
use bytes::Bytes;
use hyper::http::StatusCode;
use mime_guess::mime::Mime;
use crate::error::{AppError, Result};

pub fn unauthorized_response() -> Result<Response<Full<Bytes>>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", HeaderValue::from_static("Basic realm=\"Restricted\""))
        .body(Full::new(Bytes::from("401 Unauthorized")))
        .map_err(AppError::from)
}

pub fn forbidden_response() -> Result<Response<Full<Bytes>>> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::from("403 Forbidden")))
        .map_err(AppError::from)
}

pub fn error_response(err: AppError) -> Result<Response<Full<Bytes>>> {
    match err {
        AppError::NotFound { .. } => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("404 Not Found")))
                .map_err(AppError::from)
        }
        AppError::Forbidden { .. } => forbidden_response(),
        _ => {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("500 Internal Server Error")))
                .map_err(AppError::from)
        }
    }
}

pub fn ok_response(content: Vec<u8>, content_type: Mime) -> Result<Response<Full<Bytes>>> {
    Response::builder()
        .header("Content-Type", content_type.as_ref())
        .body(Full::new(Bytes::from(content)))
        .map_err(AppError::from)
}

pub fn html_response(html: String) -> Result<Response<Full<Bytes>>> {
    Response::builder()
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(html)))
        .map_err(AppError::from)
}
