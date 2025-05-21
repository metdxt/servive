use std::path::{Path, PathBuf};
use std::fs;
use tracing::error;
use crate::error::{AppError, Result};
use crate::responses::{forbidden_response, html_response};

pub fn list_directory(
    path: &PathBuf, 
    base_dir: &Path,
    enable_listing: bool,
) -> Result<hyper::Response<http_body_util::Full<bytes::Bytes>>> {
    if !enable_listing {
        return forbidden_response();
    }

    match fs::read_dir(path) {
        Ok(entries) => {
            let mut paths = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| AppError::StdIo { source: e })?;
                paths.push(entry.path());
            }

            paths.sort();

            let mut html = String::from("<h1>Directory listing</h1><ul>");
            for path in &paths {
                let name = path.file_name().unwrap().to_string_lossy();
                let relative_path = path.strip_prefix(base_dir)
                    .map_err(|_| AppError::PathTraversal {
                        path: path.display().to_string()
                    })?;
                html.push_str(&format!(
                    "<li><a href=\"{}\">{}</a></li>",
                    relative_path.display(),
                    name
                ));
            }
            html.push_str("</ul>");

            html_response(html)
        }
        Err(e) => {
            error!("Failed to read directory {}: {}", path.display(), e);
            Err(AppError::NotFound {
                path: path.clone(),
                source: e
            })
        }
    }
}
