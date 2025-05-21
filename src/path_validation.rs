use std::path::{Path, PathBuf};
use tracing::error;
use crate::error::{AppError, Result};

pub fn validate_path(
    path: &PathBuf,
    base_dir: &Path,
) -> Result<PathBuf> {
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
