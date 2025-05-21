use http_auth_basic::Credentials;
use hyper::header::HeaderValue;
use subtle::ConstantTimeEq;
use crate::error::AppError;
use crate::responses::unauthorized_response;

pub fn validate_credentials(
    auth_header: Option<&HeaderValue>,
    username: &str,
    password: &str,
) -> Result<Option<hyper::Response<http_body_util::Full<bytes::Bytes>>>, AppError> {
    match auth_header {
        Some(header) => {
            let header_str = header.to_str()?;
            if let Ok(credentials) = Credentials::from_header(header_str.to_string()) {
                if !credentials.user_id.as_bytes().ct_eq(username.as_bytes()).unwrap_u8() == 1 || 
                   !credentials.password.as_bytes().ct_eq(password.as_bytes()).unwrap_u8() == 1 {
                    return Ok(Some(unauthorized_response()?));
                }
            } else {
                return Ok(Some(unauthorized_response()?));
            }
        }
        None => return Ok(Some(unauthorized_response()?)),
    }
    Ok(None)
}
