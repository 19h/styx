# styx

A high-performance reverse proxy written in Rust, designed as a drop-in replacement for h2o with configuration compatibility.

## Features

- **Protocol Support**: HTTP/1.1, HTTP/2 (end-to-end via ALPN), HTTP/3 (QUIC), TLS 1.2/1.3
- **Reverse Proxy**: Connection pooling, header manipulation, X-Forwarded-* injection, streaming
- **TCP Proxy**: Layer 4 proxying with weighted load balancing and health checks
- **Static Files**: Directory listing, gzip pre-compression, range requests, ETag support
- **TLS**: SNI-based certificate selection, wildcard certificates, session resumption, transparent upgrade
- **Load Balancing**: Weighted distribution, latency-aware routing, active health monitoring
- **Security**: Request body limits, directory traversal protection, rate limiting

## Installation

```bash
cargo build --release
```

Binary will be at `target/release/styx`.

## Usage

```
styx [OPTIONS]

Options:
  -c, --config <CONFIG>       Configuration file [default: /etc/styx/styx.yaml]
  -l, --log-level <LEVEL>     Log level: trace, debug, info, warn, error [default: info]
      --json-logs             Enable JSON structured logging
  -t, --test                  Test configuration and exit
  -w, --workers <WORKERS>     Worker threads [default: auto-detect]
  -h, --help                  Print help
  -V, --version               Print version
```

## Configuration

styx uses h2o-compatible YAML configuration.

### Minimal Example

```yaml
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/":
        proxy.reverse.url: "http://localhost:8080"
```

### Full Example

```yaml
# Global settings
num-threads: 4
pid-file: /var/run/styx.pid

# Protocol settings
http2-enabled: ON
http2-idle-timeout: 180
http2-max-concurrent-streams: 256
http3-enabled: OFF

# Request limits
limit-request-body: 10485760

# Proxy defaults
proxy.preserve-host: ON
proxy.timeout.io: 30000

# Static file settings
file.send-gzip: ON

hosts:
  "example.com:443":
    listen:
      host: 0.0.0.0
      port: 443
      ssl:
        certificate-file: /etc/ssl/certs/example.pem
        key-file: /etc/ssl/private/example.key
        minimum-version: "TLSv1.2"

    paths:
      "/":
        proxy.reverse.url: "http://backend:8080"
        header.set:
          - "X-Forwarded-Proto: https"

      "/static/":
        file.dir: /var/www/static
        file.index:
          - index.html
        expires: "7 days"

      "/api/":
        proxy.reverse.url: "http://api-backend:3000"
        proxy.preserve-host: OFF
        header.set:
          - "Cache-Control: no-store"
```

### TCP Proxy with Load Balancing

```yaml
hosts:
  "tcp.example.com:3306":
    listen:
      host: 0.0.0.0
      port: 3306
      type: tcp

    backends:
      - host: "db1.internal"
        port: 3306
        weight: 100
      - host: "db2.internal"
        port: 3306
        weight: 50

    health:
      interval: 5000
      timeout: 2000
      unhealthy-threshold: 3
      healthy-threshold: 3
      latency-aware: ON
```

### Header Manipulation

```yaml
# Set header (overwrite if exists)
header.set:
  - "X-Custom: value"

# Set only if header doesn't exist
header.setifempty:
  - "X-Powered-By: styx"

# Append to existing header
header.merge:
  - "Cache-Control: public"

# Remove header
header.unset:
  - "Server"
  - "X-Powered-By"
```

### Configuration Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `num-threads` | CPU count | Worker thread count |
| `pid-file` | (none) | PID file path |
| `limit-request-body` | 10485760 | Max request body size (bytes) |
| `file.send-gzip` | OFF | Serve pre-compressed .gz files |
| `proxy.preserve-host` | OFF | Preserve Host header when proxying |
| `proxy.timeout.io` | 30000 | Proxy I/O timeout (ms) |
| `http2-enabled` | ON | Enable HTTP/2 |
| `http2-idle-timeout` | 180 | HTTP/2 idle timeout (seconds) |
| `http2-max-concurrent-streams` | 256 | Max streams per connection |
| `http2-initial-stream-window` | 1048576 | HTTP/2 stream window size (bytes) |
| `http2-initial-connection-window` | 2097152 | HTTP/2 connection window size (bytes) |
| `http2-max-frame-size` | 16384 | HTTP/2 max frame size (bytes) |
| `http3-enabled` | OFF | Enable HTTP/3 (QUIC) |
| `http3-idle-timeout` | 30 | HTTP/3 idle timeout (seconds) |
| `http3-max-concurrent-streams` | 256 | HTTP/3 max streams per connection |

## Routing

Routes use longest-prefix matching. More specific paths take priority:

```yaml
paths:
  "/":           # Catch-all
  "/api":        # Matches /api, /api/users, /api/v1
  "/api/v2":     # Matches /api/v2, /api/v2/users (takes priority over /api)
  "/static/":    # Only matches paths starting with /static/
```

Path matching prevents false prefixes: `/api` does not match `/apikey`.

## TLS

### Basic TLS

```yaml
listen:
  host: 0.0.0.0
  port: 443
  ssl:
    certificate-file: /path/to/cert.pem
    key-file: /path/to/key.pem
```

### SNI with Multiple Certificates

Configure multiple hosts on the same port. styx selects certificates based on SNI:

```yaml
hosts:
  "site-a.com:443":
    listen:
      port: 443
      ssl:
        certificate-file: /certs/site-a.pem
        key-file: /keys/site-a.key
    paths:
      "/":
        proxy.reverse.url: "http://backend-a:8080"

  "site-b.com:443":
    listen:
      port: 443
      ssl:
        certificate-file: /certs/site-b.pem
        key-file: /keys/site-b.key
    paths:
      "/":
        proxy.reverse.url: "http://backend-b:8080"
```

### Transparent TLS Upgrade (TCP Proxy)

Accept both plain and TLS connections on the same port for TCP proxy:

```yaml
hosts:
  "tcp.example.com:8080":
    listen:
      host: 0.0.0.0
      port: 8080
      type: tcp
    tls:
      certificate-file: /path/to/cert.pem
      key-file: /path/to/key.pem
      transparent-upgrade: ON
    backends:
      - host: "backend.internal"
        port: 8080
```

## Static File Serving

```yaml
paths:
  "/static/":
    file.dir: /var/www/static
    file.index:
      - index.html
      - index.htm
    file.dirlisting: ON
    expires: "30 days"
```

Features:
- Automatic MIME type detection
- Serves `.gz` files when `Accept-Encoding: gzip` is present
- ETag and If-None-Match support
- Range request support (partial content)
- Directory traversal protection

## Health Checks

For TCP proxy backends:

```yaml
health:
  interval: 5000          # Check every 5 seconds
  timeout: 2000           # 2 second timeout per check
  unhealthy-threshold: 3  # 3 failures to mark unhealthy
  healthy-threshold: 3    # 3 successes to mark healthy
  latency-aware: ON       # Route less traffic to slow backends
  sigma-threshold: 2.0    # Latency std deviation threshold
```

## Development

```bash
# Build
cargo build                    # Debug
cargo build --release          # Release

# Test
cargo test                     # All tests
cargo test --lib               # Unit tests
cargo test --test integration_tests

# Lint
cargo clippy
cargo fmt

# Benchmark
cargo bench
cargo bench --bench routing
cargo bench --bench proxy
```

## License

See LICENSE file.
