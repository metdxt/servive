use std::{
    fs, io,
    path::{Path, PathBuf},
};
use mime_guess::from_path;
use hyper::Response;
use http_body_util::Full;
use bytes::Bytes;
use tracing::error;
use std::error::Error;
use crate::responses::{forbidden_response, not_found_response, ok_response, html_response};

pub fn validate_path(
    path: &PathBuf,
    base_dir: &Path,
) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
    match path.canonicalize() {
        Ok(canonical_path) => {
            if canonical_path.starts_with(base_dir) {
                Ok(canonical_path)
            } else {
                error!("Path traversal attempt detected");
                forbidden_response()?;
                Err("Forbidden".into())
            }
        }
        Err(e) => {
            error!("Failed to canonicalize path: {}", e);
            not_found_response()?;
            Err("Not found".into())
        }
    }
}

pub fn serve_file(path: &PathBuf) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    match fs::metadata(path) {
        Ok(_) => {
            let mime_type = from_path(path).first_or_octet_stream();
            match fs::read(path) {
                Ok(content) => ok_response(content, mime_type),
                Err(_) => not_found_response()
            }
        }
        Err(_) => not_found_response(),
    }
}

pub fn list_directory(path: &PathBuf, base_dir: &Path) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
    match fs::read_dir(path) {
        Ok(entries) => {
            let mut entries = entries
                .map(|res| res.map(|e| e.path()))
                .collect::<Result<Vec<_>, io::Error>>()
                .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

            entries.sort();

            let mut html = String::from("<h1>Directory listing</h1><ul>");
            for entry in entries {
                let name = entry.file_name().unwrap().to_string_lossy();
                let relative_path = entry.strip_prefix(base_dir).unwrap();
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
            error!("Failed to read directory: {}", e);
            not_found_response()
        }
    }
}
