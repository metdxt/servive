# servive - Simple HTTP File Server

A lightweight, secure HTTP file server written in Rust with TLS and basic
authentication support.

## Features

- Serve files over HTTP/HTTPS
- Basic authentication support
- TLS encryption (via rustls)
- Optional directory listing
- Security headers (CSP, XSS protection, etc.)
- Configurable logging levels
- CLI configuration interface

## Installation

### From crates.io

```sh
cargo install servive
```

### From source

```sh
git clone https://github.com/metdxt/servive.git
cd servive
cargo install --path .
```

## Usage

### Basic usage

```sh
servive -p 8080 -d ./public
```

### With authentication

```sh
servive --username admin --password secret
```

### With TLS

```sh
servive --tls --tls-cert cert.pem --tls-key key.pem
```

### Disable directory listing

```sh
servive --no-list-dirs
```

### Enable Content Security Policy

```sh
servive --enable-csp
```

### Enable HSTS (requires TLS)

```sh
servive --tls --enable-hsts
```

### With specific bind address

IPv4:
```sh
servive -b 192.168.1.100
```

IPv6:
```sh
servive -b ::1
```

## Configuration Options

| Option              | Description                                     | Default         |
| ------------------- | ----------------------------------------------- | --------------- |
| `-p`, `--port`      | Port to listen on                               | 8000            |
| `-d`, `--directory` | Directory to serve files from                   | . (current dir) |
| `--username`        | Username for basic auth                         | None            |
| `--password`        | Password for basic auth                         | None            |
| `--log-level`       | Logging level (error, warn, info, debug, trace) | info            |
| `--tls`             | Enable TLS                                      | false           |
| `--tls-cert`        | TLS certificate file path                       | None            |
| `--tls-key`         | TLS private key file path                       | None            |
| `--no-list-dirs`    | Disable directory listing                       | false           |
| `-b`, `--bind`      | Bind address (IPv4 or IPv6)                     | 127.0.0.1       |
| `--show-dotfiles`   | Show dotfiles (hidden by default)               | false           |
| `--enable-csp`      | Enable Content Security Policy headers          | false           |
| `--enable-hsts`     | Enable HTTP Strict Transport Security headers   | false           |
| `--max-file-size`   | Maximum file size in bytes (0 for unlimited)    | unlimited       |

## File Size Limits

If you wish to limit file size served to clients you can:
- Set a custom limit with `--max-file-size BYTES`
- Allow unlimited file sizes with `--max-file-size 0` (this is default)

If limit is set servive will return `403 Forbidden` if requested file is larger than the limit.

## Security Considerations

- Basic authentication credentials are transmitted in plaintext when not using
  TLS
- Always use TLS in production environments
- The server adds security headers by default:
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection
- Content-Security-Policy is optional (enabled with --enable-csp)
- HSTS (HTTP Strict Transport Security) is now opt-in (enabled with --enable-hsts when using TLS)

## Building from Source

1. Clone the repository:

```sh
git clone https://github.com/metdxt/servive.git
cd servive
```

2. Build in release mode:

```sh
cargo build --release
```

The binary will be available at `target/release/servive`

## License

The project is distributed under the MIT license
