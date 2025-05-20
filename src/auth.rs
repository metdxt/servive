use http_auth_basic::Credentials;
use hyper::{Response, StatusCode};
use http_body_util::Full;
use bytes::Bytes;
use subtle::ConstantTimeEq;

pub fn validate_credentials(
    auth_header: Option<&hyper::header::HeaderValue>,
    username: &str,
    password: &str,
) -> Option<Response<Full<Bytes>>> {
    match auth_header {
        Some(header) => {
            if let Ok(credentials) = Credentials::from_header(header.to_str().unwrap().to_string()) {
                if !credentials.user_id.as_bytes().ct_eq(username.as_bytes()).unwrap_u8() == 1 || 
                   !credentials.password.as_bytes().ct_eq(password.as_bytes()).unwrap_u8() == 1 {
                    return Some(unauthorized_response());
                }
            } else {
                return Some(unauthorized_response());
            }
        }
        None => return Some(unauthorized_response()),
    }
    None
}

pub fn unauthorized_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Basic realm=\"Restricted\"")
        .body(Full::new(Bytes::from("401 Unauthorized")))
        .unwrap()
}
