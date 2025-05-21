use std::path::{Path, PathBuf};
use std::fs;
use crate::error::AppError;
use crate::responses::{forbidden_response, html_response};
use crate::path_validation::contains_dotfile;

pub fn list_directory(
    path: &PathBuf, 
    base_dir: &Path,
    enable_listing: bool,
    show_dotfiles: bool,
) -> std::result::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, AppError> {
    if !enable_listing {
        return forbidden_response();
    }

    match fs::read_dir(path) {
        Ok(entries) => {
            let mut paths = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| AppError::StdIo { source: e })?;
                let path = entry.path();
                if show_dotfiles || !contains_dotfile(&path, show_dotfiles) {
                    paths.push(path);
                }
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
            Err(AppError::NotFound {
                path: path.clone(),
                source: e
            })
        }
    }
}
