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
| `--bind-all`        | Bind server to 0.0.0.0                          | false           |

## Security Considerations

- Basic authentication credentials are transmitted in plaintext when not using
  TLS
- Always use TLS in production environments
- The server adds security headers by default:
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
  - X-XSS-Protection

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
