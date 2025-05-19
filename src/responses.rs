use hyper::Response;
use http_body_util::Full;
use bytes::Bytes;
use hyper::http::StatusCode;
use mime_guess::mime::Mime;
use std::error::Error;

pub fn forbidden_response() -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    Ok(Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Full::new(Bytes::from("403 Forbidden")))
        .unwrap())
}

pub fn not_found_response() -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("404 Not Found")))
        .unwrap())
}

pub fn ok_response(content: Vec<u8>, content_type: Mime) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    Ok(Response::builder()
        .header("Content-Type", content_type.as_ref())
        .body(Full::new(Bytes::from(content)))
        .unwrap())
}

pub fn html_response(html: String) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    Ok(Response::builder()
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(html)))
        .unwrap())
}
