use clap::Parser;
use std::path::PathBuf;
use crate::error::{AppError, Result};

#[derive(Parser, Debug)]
#[command(version = concat!(
    env!("CARGO_PKG_VERSION"), 
    " (commit: ", env!("GIT_HASH"), ")", 
    ", features: [", env!("COMPILED_FEATURES"), "]"
), 
    about="A stupid simple program to serve files over HTTP")
]
pub struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 8000)]
    pub port: u16,

    /// Directory to serve files from
    #[arg(short, long, default_value = ".")]
    pub directory: String,

    /// Username for basic auth (optional)
    #[arg(long)]
    pub username: Option<String>,

    /// Password for basic auth (optional)
    #[arg(long)]
    pub password: Option<String>,

    /// Logging level (error, warn, info, debug, trace)
    #[arg(short, long, default_value = "info")]
    pub log_level: String,

    /// Enable TLS (requires cert and key)
    #[arg(long)]
    pub tls: bool,

    /// TLS certificate file path
    #[arg(long, requires = "tls")]
    pub tls_cert: Option<String>,

    /// TLS private key file path
    #[arg(long, requires = "tls")]
    pub tls_key: Option<String>,

    /// Forbid directory listing
    #[arg(long, default_value_t = false)]
    pub no_list_dirs: bool,

    /// Bind address (IPv4 or IPv6)
    #[arg(short, long, value_name="ADDRESS", default_value = "127.0.0.1")]
    pub bind: String,

    /// Show dotfiles (hidden by default)
    #[arg(long, default_value_t = false)]
    pub show_dotfiles: bool,

    /// Enable Content Security Policy headers (disabled by default)
    #[arg(long, default_value_t = false)]
    pub enable_csp: bool,
}

pub struct Config {
    pub args: Args,
    pub base_dir: PathBuf,
}

impl Config {
    pub fn new() -> Result<Self> {
        let args = Args::parse();
        let directory = args.directory.clone();
        let base_dir = PathBuf::from(&directory)
            .canonicalize()
            .map_err(|e| AppError::Io {
                path: PathBuf::from(directory),
                source: e,
            })?;

        Ok(Self { args, base_dir })
    }
}
