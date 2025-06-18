use crate::error::AppError;
use crate::path_validation::contains_dotfile;
use crate::responses::ok_response;
use mime_guess::from_path;
use std::fs;
use std::path::PathBuf;
use tracing::warn;

pub fn serve_file(
    path: &PathBuf,
    show_dotfiles: bool,
    max_file_size: Option<u64>,
) -> std::result::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, AppError> {
    if !show_dotfiles && contains_dotfile(path, show_dotfiles) {
        return Err(AppError::NotFound {
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "Dotfile not accessible"),
        });
    }

    match fs::metadata(path) {
        Ok(metadata) => {
            if let Some(max_size) = max_file_size {
                if max_size < metadata.len() {
                    warn!(error="File size exceeds limit of bytes", path=%path.to_string_lossy(), file_size=%metadata.len(), limit=%max_size);
                    return Err(AppError::Forbidden { path: path.clone() });
                }
            }

            let mime_type = from_path(path).first_or_octet_stream();
            match fs::read(path) {
                Ok(content) => ok_response(content, mime_type),
                Err(e) => {
                    warn!("Failed to read file {}: {}", path.display(), e);
                    Err(AppError::NotFound {
                        path: path.clone(),
                        source: e,
                    })
                }
            }
        }
        Err(e) => {
            warn!("File not found: {}: {}", path.display(), e);
            Err(AppError::NotFound {
                path: path.clone(),
                source: e,
            })
        }
    }
}
