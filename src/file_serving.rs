use std::path::PathBuf;
use std::fs;
use mime_guess::from_path;
use tracing::warn;
use crate::error::AppError;
use crate::responses::ok_response;
use crate::common::MAX_FILE_SIZE;
use crate::path_validation::contains_dotfile;

pub fn serve_file(
    path: &PathBuf,
    show_dotfiles: bool,
) -> std::result::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, AppError> {
    if !show_dotfiles && contains_dotfile(path, show_dotfiles) {
        return Err(AppError::NotFound {
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "Dotfile not accessible")
        });
    }

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
                Err(e) => {
                    warn!("Failed to read file {}: {}", path.display(), e);
                    Err(AppError::NotFound {
                        path: path.clone(),
                        source: e
                    })
                }
            }
        }
        Err(e) => {
            warn!("File not found: {}: {}", path.display(), e);
            Err(AppError::NotFound {
                path: path.clone(),
                source: e
            })
        },
    }
}
