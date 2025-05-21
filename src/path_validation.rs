use std::path::{Path, PathBuf};
use tracing::error;
use crate::error::AppError;

pub fn contains_dotfile(path: &Path, show_dotfiles: bool) -> bool {
    if show_dotfiles {
        false
    } else {
        path.components()
            .any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s.starts_with('.') && s != ".." && s != "."
            })
    }
}

pub fn validate_path(
    path: &PathBuf,
    base_dir: &Path,
    show_dotfiles: bool,
) -> std::result::Result<PathBuf, AppError> {
    if !show_dotfiles && contains_dotfile(path, show_dotfiles) {
        return Err(AppError::NotFound {
            path: path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "Dotfile not accessible")
        });
    }

    match path.canonicalize() {
        Ok(canonical_path) => {
            if canonical_path.starts_with(base_dir) {
                Ok(canonical_path)
            } else {
                error!("Path traversal attempt detected: {}", path.display());
                Err(AppError::PathTraversal {
                    path: path.display().to_string()
                })
            }
        }
        Err(e) => {
            error!(error=%e, path=%path.to_string_lossy());
            Err(AppError::NotFound {
                path: path.clone(),
                source: e
            })
        }
    }
}
