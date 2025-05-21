use std::path::PathBuf;
use std::fs;
use mime_guess::from_path;
use tracing::warn;
use crate::error::{AppError, Result};
use crate::responses::ok_response;
use crate::common::MAX_FILE_SIZE;

pub fn serve_file(path: &PathBuf) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if metadata.len() > MAX_FILE_SIZE as u64 {
                warn!(error="File size exceeds limit of bytes", path=%path.to_string_lossy(), file_size=%metadata.len(), limit=%MAX_FILE_SIZE);
                return Err(AppError::Forbidden {
                    path: path.clone()
                });
            }

            let mime_type = from_path(path).first_or_octet_stream();
            match fs::read(path) {
                Ok(content) => ok_response(content, mime_type),
                Err(e) => Err(AppError::NotFound {
                    path: path.clone(),
                    source: e
                })
            }
        }
        Err(e) => Err(AppError::NotFound {
            path: path.clone(),
            source: e
        }),
    }
}
