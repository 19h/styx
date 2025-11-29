//! Reverse proxy implementation
//!
//! This module handles proxying requests to upstream servers with:
//! - Connection pooling
//! - Host preservation
//! - Header manipulation
//! - Timeout handling
//! - Streaming body support

use crate::config::HeaderRules;
use crate::middleware::{apply_request_headers, apply_response_headers};
use crate::pool::{ConnectionPool, PoolConfig};
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, Uri, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// ALPN protocol identifiers
const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Proxy configuration
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// I/O timeout
    pub io_timeout: Duration,
    /// Maximum request body size
    pub max_body_size: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10MB - secure default
        }
    }
}

/// Reverse proxy handler
pub struct ReverseProxy {
    pool: Arc<ConnectionPool>,
    config: ProxyConfig,
}

impl ReverseProxy {
    /// Create a new reverse proxy
    pub fn new(config: ProxyConfig) -> Arc<Self> {
        let pool_config = PoolConfig {
            max_connections_per_host: 256,
            idle_timeout: Duration::from_secs(90),
            connect_timeout: Duration::from_secs(10),
            max_idle_per_host: 64,
        };

        Arc::new(Self {
            pool: ConnectionPool::new(pool_config),
            config,
        })
    }

    /// Proxy a request to an upstream server with streaming support
    /// This method automatically chooses between pooled (buffered) and streaming based on Content-Length
    pub async fn proxy(
        &self,
        request: Request<Incoming>,
        upstream_url: &str,
        preserve_host: bool,
        proxy_headers: &HeaderRules,
        response_headers: &HeaderRules,
        client_ip: Option<std::net::IpAddr>,
        client_scheme: &str,
    ) -> Result<Response<Incoming>, ProxyError> {
        // Check Content-Length to decide streaming strategy
        const STREAMING_THRESHOLD: u64 = 1024 * 1024; // 1MB

        let content_length = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // Use streaming for large bodies or if Content-Length is unknown
        if content_length.map(|len| len >= STREAMING_THRESHOLD).unwrap_or(false) {
            return self.proxy_streaming(
                request,
                upstream_url,
                preserve_host,
                proxy_headers,
                response_headers,
                client_ip,
                client_scheme,
            ).await;
        }

        // Use pooled connection for small bodies
        self.proxy_buffered(
            request,
            upstream_url,
            preserve_host,
            proxy_headers,
            response_headers,
            client_ip,
            client_scheme,
        ).await
    }

    /// Proxy with streaming request body (bypasses connection pool)
    async fn proxy_streaming(
        &self,
        request: Request<Incoming>,
        upstream_url: &str,
        preserve_host: bool,
        proxy_headers: &HeaderRules,
        response_headers: &HeaderRules,
        client_ip: Option<std::net::IpAddr>,
        client_scheme: &str,
    ) -> Result<Response<Incoming>, ProxyError> {
        // Parse upstream URL
        let upstream = parse_upstream_url(upstream_url, request.uri())?;
        let (host, port) = extract_host_port(&upstream)?;
        
        // Prepare headers
        let mut headers = request.headers().clone();

        // Extract original host from request BEFORE modifying headers
        // HTTP/2 uses :authority pseudo-header (may be in URI or headers), HTTP/1.1 uses Host header
        let uri_authority = request.uri().authority().map(|a| a.to_string());
        let host_header = headers.get(header::HOST).and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let authority_header = headers.get(":authority").and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        let original_host = uri_authority.or(host_header).or(authority_header);

        // Validate Host header
        if let Some(host_hdr) = headers.get(header::HOST) {
            if let Ok(host_str) = host_hdr.to_str() {
                validate_host_header(host_str)?;
            }
        }

        strip_forwarded_headers(&mut headers);

        // Set host header
        if preserve_host {
            // Use original request host (from :authority or Host header)
            if let Some(orig_host) = &original_host {
                if let Ok(host_value) = HeaderValue::from_str(orig_host.as_str()) {
                    headers.insert(header::HOST, host_value);
                }
            }
        } else {
            let host_with_port = if port == 80 || port == 443 {
                host.clone()
            } else {
                format!("{}:{}", host, port)
            };
            if let Ok(host_value) = HeaderValue::from_str(&host_with_port) {
                headers.insert(header::HOST, host_value);
            }
        }

        add_forwarded_headers(&mut headers, client_scheme, original_host.as_deref());

        if let Some(ip) = client_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                headers.insert(HeaderName::from_static("x-forwarded-for"), value);
            }
        }

        apply_request_headers(&mut headers, proxy_headers);
        remove_hop_headers(&mut headers);

        // Build streaming request
        // When preserve_host is true, use origin-form (path only) to prevent backend from using URL
        // When preserve_host is false, use absolute-form (full URL)
        let request_uri = if preserve_host {
            // Origin form: extract path and query from the combined upstream URL
            let upstream_uri: Uri = upstream.parse()
                .map_err(|e| ProxyError::InvalidUpstream(format!("Failed to parse upstream URL: {}", e)))?;
            upstream_uri.path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string())
        } else {
            // Absolute form: full upstream URL
            upstream.clone()
        };

        let mut proxy_request = Request::builder()
            .method(request.method().clone())
            .uri(request_uri)
            .version(Version::HTTP_11);
        
        for (name, value) in headers.iter() {
            proxy_request = proxy_request.header(name.clone(), value.clone());
        }
        
        let proxy_request = proxy_request
            .body(request.into_body())
            .map_err(|e| ProxyError::Request(e.to_string()))?;
        
        // Create direct connection (bypass pool)
        let parsed_upstream: Uri = upstream.parse().unwrap();
        let use_tls = parsed_upstream.scheme_str() == Some("https");
        
        let response = tokio::time::timeout(
            self.config.io_timeout,
            self.send_streaming_request(&host, port, use_tls, proxy_request),
        )
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;
        
        // Apply response headers
        let (mut parts, body) = response.into_parts();
        remove_hop_headers(&mut parts.headers);
        
        let mut temp_response = Response::from_parts(parts.clone(), Full::new(Bytes::new()));
        apply_response_headers(&mut temp_response, response_headers);
        let (modified_parts, _) = temp_response.into_parts();
        
        Ok(Response::from_parts(modified_parts, body))
    }

    /// Proxy with buffered request body (uses connection pool)
    async fn proxy_buffered(
        &self,
        mut request: Request<Incoming>,
        upstream_url: &str,
        preserve_host: bool,
        proxy_headers: &HeaderRules,
        response_headers: &HeaderRules,
        client_ip: Option<std::net::IpAddr>,
        client_scheme: &str,
    ) -> Result<Response<Incoming>, ProxyError> {
        // Parse upstream URL
        let upstream = parse_upstream_url(upstream_url, request.uri())?;

        // Build the proxied request
        let (host, port) = extract_host_port(&upstream)?;

        // Collect the request body for pooled connections
        // Note: This is only used for small bodies (<1MB). Large bodies use proxy_streaming()
        // which bypasses the pool and streams directly.
        let body_bytes = collect_body(request.body_mut(), self.config.max_body_size).await?;

        // Build new request
        // When preserve_host is true, use origin-form (path only) to prevent backend from using URL
        // When preserve_host is false, use absolute-form (full URL)
        let request_uri = if preserve_host {
            // Origin form: extract path and query from the combined upstream URL
            let upstream_uri: Uri = upstream.parse()
                .map_err(|e| ProxyError::InvalidUpstream(format!("Failed to parse upstream URL: {}", e)))?;
            upstream_uri.path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string())
        } else {
            // Absolute form: full upstream URL
            upstream.clone()
        };

        let mut proxy_request = Request::builder()
            .method(request.method().clone())
            .uri(request_uri)
            .version(Version::HTTP_11);

        // Copy headers
        let mut headers = request.headers().clone();

        // Extract original host from request BEFORE modifying headers
        // HTTP/2 uses :authority pseudo-header (may be in URI or headers), HTTP/1.1 uses Host header
        let uri_authority = request.uri().authority().map(|a| a.to_string());
        let host_header = headers.get(header::HOST).and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let authority_header = headers.get(":authority").and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        let original_host = uri_authority.or(host_header).or(authority_header);

        // Validate Host header to prevent injection attacks
        if let Some(host_hdr) = headers.get(header::HOST) {
            if let Ok(host_str) = host_hdr.to_str() {
                validate_host_header(host_str)?;
            }
        }

        // Remove untrusted X-Forwarded-* headers from client to prevent injection
        strip_forwarded_headers(&mut headers);

        // Set or preserve host header
        if preserve_host {
            // Use original request host (from :authority or Host header)
            if let Some(orig_host) = &original_host {
                if let Ok(host_value) = HeaderValue::from_str(orig_host.as_str()) {
                    headers.insert(header::HOST, host_value);
                }
            }
        } else {
            // Set Host to upstream
            let host_with_port = if port == 80 || port == 443 {
                host.clone()
            } else {
                format!("{}:{}", host, port)
            };
            if let Ok(host_value) = HeaderValue::from_str(&host_with_port) {
                headers.insert(header::HOST, host_value);
            }
        }

        // Add X-Forwarded headers (now trusted)
        add_forwarded_headers(&mut headers, client_scheme, original_host.as_deref());

        // Add X-Forwarded-For with client IP
        if let Some(ip) = client_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                headers.insert(
                    HeaderName::from_static("x-forwarded-for"),
                    value,
                );
            }
        }

        // Apply proxy header rules
        apply_request_headers(&mut headers, proxy_headers);

        // Remove hop-by-hop headers
        remove_hop_headers(&mut headers);

        // Build final request
        for (name, value) in headers.iter() {
            proxy_request = proxy_request.header(name.clone(), value.clone());
        }

        let proxy_request = proxy_request
            .body(Full::new(body_bytes))
            .map_err(|e| ProxyError::Request(e.to_string()))?;

        // Determine if we should use TLS based on the upstream scheme
        let parsed_upstream: Uri = upstream.parse().unwrap(); // Already validated earlier
        let use_tls = parsed_upstream.scheme_str() == Some("https");

        // Send request through connection pool
        let response = tokio::time::timeout(
            self.config.io_timeout,
            self.pool.send_request(&host, port, use_tls, proxy_request),
        )
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        // Apply response headers
        let (mut parts, body) = response.into_parts();

        // Remove hop-by-hop headers from response
        remove_hop_headers(&mut parts.headers);

        // Apply response header rules
        let mut temp_response = Response::from_parts(parts.clone(), Full::new(Bytes::new()));
        apply_response_headers(&mut temp_response, response_headers);

        let (modified_parts, _) = temp_response.into_parts();

        Ok(Response::from_parts(modified_parts, body))
    }

    /// Proxy a request with a pre-collected body (for HTTP/3 support)
    /// This method is used when the request body has already been read
    pub async fn proxy_with_body(
        &self,
        method: http::Method,
        uri: &http::Uri,
        headers: HeaderMap,
        body: Bytes,
        upstream_url: &str,
        preserve_host: bool,
        proxy_headers: &HeaderRules,
        response_headers: &HeaderRules,
        client_ip: Option<std::net::IpAddr>,
        client_scheme: &str,
    ) -> Result<Response<Bytes>, ProxyError> {
        // Parse upstream URL
        let upstream = parse_upstream_url(upstream_url, uri)?;
        let (host, port) = extract_host_port(&upstream)?;

        // Prepare headers
        let mut headers = headers;

        // Extract original host from URI or headers BEFORE modifying headers
        // HTTP/2+ uses :authority pseudo-header (may be in URI or headers), HTTP/1.1 uses Host header
        let uri_authority = uri.authority().map(|a| a.to_string());
        let host_header = headers.get(header::HOST).and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let authority_header = headers.get(":authority").and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let original_host = uri_authority.or(host_header).or(authority_header);

        // Validate Host header
        if let Some(host_hdr) = headers.get(header::HOST) {
            if let Ok(host_str) = host_hdr.to_str() {
                validate_host_header(host_str)?;
            }
        }

        strip_forwarded_headers(&mut headers);

        // Set host header
        if preserve_host {
            // Use original request host (from :authority or Host header)
            if let Some(orig_host) = &original_host {
                if let Ok(host_value) = HeaderValue::from_str(orig_host.as_str()) {
                    headers.insert(header::HOST, host_value);
                }
            }
        } else {
            let host_with_port = if port == 80 || port == 443 {
                host.clone()
            } else {
                format!("{}:{}", host, port)
            };
            if let Ok(host_value) = HeaderValue::from_str(&host_with_port) {
                headers.insert(header::HOST, host_value);
            }
        }

        // Add X-Forwarded-Proto using actual client scheme
        if let Ok(value) = HeaderValue::from_str(client_scheme) {
            headers.insert(HeaderName::from_static("x-forwarded-proto"), value);
        }

        // Add X-Forwarded-Host from ORIGINAL client host (not the possibly-modified Host header)
        if let Some(orig_host) = &original_host {
            if let Ok(value) = HeaderValue::from_str(orig_host) {
                headers.insert(HeaderName::from_static("x-forwarded-host"), value);
            }
        }

        // Add X-Forwarded-For with client IP
        if let Some(ip) = client_ip {
            if let Ok(value) = HeaderValue::from_str(&ip.to_string()) {
                headers.insert(HeaderName::from_static("x-forwarded-for"), value);
            }
        }

        apply_request_headers(&mut headers, proxy_headers);
        remove_hop_headers(&mut headers);

        // Build request
        // When preserve_host is true, use origin-form (path only) to prevent backend from using URL
        // When preserve_host is false, use absolute-form (full URL)
        let request_uri = if preserve_host {
            // Origin form: extract path and query from the combined upstream URL
            let upstream_uri: Uri = upstream.parse()
                .map_err(|e| ProxyError::InvalidUpstream(format!("Failed to parse upstream URL: {}", e)))?;
            upstream_uri.path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string())
        } else {
            // Absolute form: full upstream URL
            upstream.clone()
        };

        let mut proxy_request = Request::builder()
            .method(method)
            .uri(request_uri)
            .version(Version::HTTP_11);

        for (name, value) in headers.iter() {
            proxy_request = proxy_request.header(name.clone(), value.clone());
        }

        let proxy_request = proxy_request
            .body(Full::new(body))
            .map_err(|e| ProxyError::Request(e.to_string()))?;

        // Determine if we should use TLS
        let parsed_upstream: Uri = upstream.parse().unwrap();
        let use_tls = parsed_upstream.scheme_str() == Some("https");

        // Send request through connection pool
        let response = tokio::time::timeout(
            self.config.io_timeout,
            self.pool.send_request(&host, port, use_tls, proxy_request),
        )
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        // Apply response headers and collect body
        let (mut parts, body) = response.into_parts();
        remove_hop_headers(&mut parts.headers);

        // Apply response header rules
        let mut temp_response = Response::from_parts(parts.clone(), Full::new(Bytes::new()));
        apply_response_headers(&mut temp_response, response_headers);
        let (modified_parts, _) = temp_response.into_parts();

        // Collect response body
        let body_bytes = collect_body_incoming(body, self.config.max_body_size).await?;

        Ok(Response::from_parts(modified_parts, body_bytes))
    }

    /// Send a streaming request using a direct connection (no pooling)
    /// Supports HTTP/2 for TLS connections via ALPN negotiation
    async fn send_streaming_request(
        &self,
        host: &str,
        port: u16,
        use_tls: bool,
        request: Request<Incoming>,
    ) -> Result<Response<Incoming>, ProxyError> {
        // Resolve host
        let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
            .await
            .map_err(|e| ProxyError::Upstream(format!("DNS resolution failed: {}", e)))?
            .next()
            .ok_or_else(|| ProxyError::Upstream("No addresses resolved".to_string()))?;

        // Connect to upstream
        let stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| ProxyError::Upstream("Connect timeout".to_string()))?
        .map_err(|e| ProxyError::Upstream(format!("Connect failed: {}", e)))?;

        stream.set_nodelay(true).ok();

        if use_tls {
            // TLS connection with HTTP/2 ALPN support
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            // Prefer HTTP/2 for TLS connections
            config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];

            let connector = TlsConnector::from(Arc::new(config));
            let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|_| ProxyError::Upstream("Invalid DNS name".to_string()))?;

            let tls_stream = connector
                .connect(domain, stream)
                .await
                .map_err(|e| ProxyError::Upstream(format!("TLS handshake failed: {}", e)))?;

            // Check which protocol was negotiated
            let alpn = tls_stream.get_ref().1.alpn_protocol();

            if alpn == Some(ALPN_H2) {
                // HTTP/2 connection
                let io = TokioIo::new(tls_stream);

                let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
                    .await
                    .map_err(|e| ProxyError::Upstream(format!("HTTP/2 handshake failed: {}", e)))?;

                // Spawn connection task
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("HTTP/2 streaming connection error: {}", e);
                    }
                });

                // Send request
                sender
                    .send_request(request)
                    .await
                    .map_err(|e| ProxyError::Upstream(format!("HTTP/2 request failed: {}", e)))
            } else {
                // HTTP/1.1 connection
                let io = TokioIo::new(tls_stream);

                let (mut sender, conn) = http1::handshake(io)
                    .await
                    .map_err(|e| ProxyError::Upstream(format!("HTTP handshake failed: {}", e)))?;

                // Spawn connection task
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("Streaming connection error: {}", e);
                    }
                });

                // Send request
                sender
                    .send_request(request)
                    .await
                    .map_err(|e| ProxyError::Upstream(format!("Request failed: {}", e)))
            }
        } else {
            // Plain HTTP connection (HTTP/1.1 only, no h2c support for now)
            let io = TokioIo::new(stream);

            // HTTP/1 handshake
            let (mut sender, conn) = http1::handshake(io)
                .await
                .map_err(|e| ProxyError::Upstream(format!("HTTP handshake failed: {}", e)))?;

            // Spawn connection task
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    tracing::debug!("Streaming connection error: {}", e);
                }
            });

            // Send request
            sender
                .send_request(request)
                .await
                .map_err(|e| ProxyError::Upstream(format!("Request failed: {}", e)))
        }
    }
}

/// Parse upstream URL and combine with request path
fn parse_upstream_url(upstream: &str, request_uri: &Uri) -> Result<String, ProxyError> {
    // Parse the upstream URL
    let upstream_uri: Uri = upstream
        .parse()
        .map_err(|e| ProxyError::InvalidUpstream(format!("Invalid upstream URL: {}", e)))?;

    let scheme = upstream_uri.scheme_str().unwrap_or("http");

    // Only allow http/https schemes to prevent SSRF via file://, etc.
    if scheme != "http" && scheme != "https" {
        return Err(ProxyError::InvalidUpstream(format!("Unsupported scheme: {}", scheme)));
    }

    let authority = upstream_uri
        .authority()
        .ok_or_else(|| ProxyError::InvalidUpstream("Missing authority in upstream URL".to_string()))?;

    // Get the path from upstream URL
    let upstream_path = upstream_uri.path();

    // Get the request path
    let request_path = request_uri.path();

    // Combine paths intelligently
    // If upstream ends with specific path (not just /), use that path
    // Otherwise, append the request path
    let final_path = if upstream_path == "/" || upstream_path.is_empty() {
        request_path.to_string()
    } else if request_path.starts_with(upstream_path) {
        // Request path already includes upstream path prefix
        request_path.to_string()
    } else {
        // Check if the upstream path should replace or be appended
        // For paths like /api -> http://api:3000, we want to preserve /api/endpoint
        format!("{}{}", upstream_path.trim_end_matches('/'), request_path)
    };

    // Include query string
    let query = request_uri
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    Ok(format!("{}://{}{}{}", scheme, authority, final_path, query))
}

/// Extract host and port from URI
fn extract_host_port(uri: &str) -> Result<(String, u16), ProxyError> {
    let parsed: Uri = uri
        .parse()
        .map_err(|_| ProxyError::InvalidUpstream("Cannot parse URI".to_string()))?;

    let host = parsed
        .host()
        .ok_or_else(|| ProxyError::InvalidUpstream("Missing host".to_string()))?
        .to_string();

    let port = parsed.port_u16().unwrap_or_else(|| {
        if parsed.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    Ok((host, port))
}

/// Collect body into bytes with size limit (enforced during streaming)
async fn collect_body(body: &mut Incoming, max_size: u64) -> Result<Bytes, ProxyError> {
    use bytes::BytesMut;

    let mut buf = BytesMut::new();

    // Stream body frames and check size as we go
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| ProxyError::Body(e.to_string()))?;

        if let Some(data) = frame.data_ref() {
            // Check size BEFORE adding to buffer
            let new_size = buf.len() + data.len();
            if new_size as u64 > max_size {
                return Err(ProxyError::BodyTooLarge);
            }
            buf.extend_from_slice(data);
        }
    }

    Ok(buf.freeze())
}

/// Collect body from Incoming into Bytes with size limit
async fn collect_body_incoming(mut body: Incoming, max_size: u64) -> Result<Bytes, ProxyError> {
    use bytes::BytesMut;

    let mut buf = BytesMut::new();

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| ProxyError::Body(e.to_string()))?;

        if let Some(data) = frame.data_ref() {
            let new_size = buf.len() + data.len();
            if new_size as u64 > max_size {
                return Err(ProxyError::BodyTooLarge);
            }
            buf.extend_from_slice(data);
        }
    }

    Ok(buf.freeze())
}

/// Validate Host header to prevent injection attacks
fn validate_host_header(host: &str) -> Result<(), ProxyError> {
    // Reject leading/trailing whitespace
    if host != host.trim() {
        return Err(ProxyError::Request("Invalid Host header: contains whitespace".to_string()));
    }

    // Check for CRLF injection
    if host.contains('\r') || host.contains('\n') {
        return Err(ProxyError::Request("Invalid Host header: contains CRLF".to_string()));
    }

    // Check for null bytes
    if host.contains('\0') {
        return Err(ProxyError::Request("Invalid Host header: contains null byte".to_string()));
    }

    // Check for excessive length (prevent DoS)
    if host.len() > 253 {
        return Err(ProxyError::Request("Invalid Host header: too long".to_string()));
    }

    // Validate IPv6 addresses in brackets
    if host.contains('[') {
        // Must be IPv6 in brackets like [::1] or [::1]:port
        if !host.starts_with('[') {
            return Err(ProxyError::Request("Invalid Host header: misplaced bracket".to_string()));
        }

        let end_bracket = host.find(']')
            .ok_or_else(|| ProxyError::Request("Invalid Host header: unclosed bracket".to_string()))?;

        let ipv6_part = &host[1..end_bracket];

        // Try to parse as IPv6
        if ipv6_part.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(ProxyError::Request("Invalid Host header: invalid IPv6".to_string()));
        }

        // After bracket, can only have :port or nothing
        if end_bracket + 1 < host.len() {
            let remainder = &host[end_bracket + 1..];
            if !remainder.starts_with(':') || !remainder[1..].chars().all(|c| c.is_ascii_digit()) {
                return Err(ProxyError::Request("Invalid Host header: invalid port after IPv6".to_string()));
            }
        }
    } else {
        // Basic format validation: should be hostname[:port]
        // Allow only alphanumeric, dots, and hyphens for hostname, colon for port
        if !host.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == ':') {
            return Err(ProxyError::Request("Invalid Host header: invalid characters".to_string()));
        }
    }

    Ok(())
}

/// Strip untrusted X-Forwarded-* headers from client
fn strip_forwarded_headers(headers: &mut HeaderMap) {
    headers.remove("x-forwarded-for");
    headers.remove("x-forwarded-proto");
    headers.remove("x-forwarded-host");
    headers.remove("x-forwarded-port");
    headers.remove("x-real-ip");
    headers.remove("forwarded");
}

/// Add X-Forwarded-* headers
fn add_forwarded_headers(headers: &mut HeaderMap, client_scheme: &str, original_host: Option<&str>) {
    // X-Forwarded-Proto - use the actual client scheme from the connection layer
    if let Ok(value) = HeaderValue::from_str(client_scheme) {
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            value,
        );
    }

    // X-Forwarded-Host from ORIGINAL client host (not the possibly-modified Host header)
    if let Some(orig_host) = original_host {
        if let Ok(value) = HeaderValue::from_str(orig_host) {
            headers.insert(
                HeaderName::from_static("x-forwarded-host"),
                value,
            );
        }
    }
}

/// Remove hop-by-hop headers
fn remove_hop_headers(headers: &mut HeaderMap) {
    const HOP_HEADERS: &[&str] = &[
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "http2-settings",
        // Additional hop-by-hop headers
        "alt-svc",
        "age",
        "proxy-features",
        "proxy-instruction",
    ];

    // Remove standard hop-by-hop headers (connection handled separately below)
    for header in HOP_HEADERS {
        headers.remove(*header);
    }

    // Handle Connection header value - remove headers it specifies (RFC 7230)
    // Must process ALL Connection headers (not just first) and read values BEFORE removing
    let mut headers_to_remove = Vec::new();

    for conn_value in headers.get_all("connection") {
        if let Ok(conn_str) = conn_value.to_str() {
            for token in conn_str.split(',') {
                let trimmed = token.trim().to_lowercase();
                if !trimmed.is_empty() && trimmed != "connection" {
                    headers_to_remove.push(trimmed);
                }
            }
        }
    }

    // Now remove the Connection header itself
    headers.remove("connection");

    // Remove additional headers specified in Connection
    for header_name in headers_to_remove {
        headers.remove(&header_name);
    }
}

/// Proxy errors
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("invalid upstream URL: {0}")]
    InvalidUpstream(String),

    #[error("request error: {0}")]
    Request(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("body error: {0}")]
    Body(String),

    #[error("request body too large")]
    BodyTooLarge,

    #[error("request timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // parse_upstream_url tests
    // =====================================================================

    #[test]
    fn test_parse_upstream_url_simple() {
        let uri: Uri = "/api/endpoint?foo=bar".parse().unwrap();
        let result = parse_upstream_url("http://backend:3000", &uri).unwrap();
        assert_eq!(result, "http://backend:3000/api/endpoint?foo=bar");
    }

    #[test]
    fn test_parse_upstream_url_with_path() {
        let uri: Uri = "/foo/bar".parse().unwrap();
        let result = parse_upstream_url("http://backend:3000/base", &uri).unwrap();
        assert!(result.contains("/base"));
    }

    #[test]
    fn test_parse_upstream_url_root_path() {
        let uri: Uri = "/".parse().unwrap();
        let result = parse_upstream_url("http://backend:80", &uri).unwrap();
        assert_eq!(result, "http://backend:80/");
    }

    #[test]
    fn test_parse_upstream_url_preserves_query_string() {
        let uri: Uri = "/search?q=test&page=1".parse().unwrap();
        let result = parse_upstream_url("http://backend:3000", &uri).unwrap();
        assert_eq!(result, "http://backend:3000/search?q=test&page=1");
    }

    #[test]
    fn test_parse_upstream_url_no_query_string() {
        let uri: Uri = "/path/to/resource".parse().unwrap();
        let result = parse_upstream_url("http://backend:3000", &uri).unwrap();
        assert_eq!(result, "http://backend:3000/path/to/resource");
    }

    #[test]
    fn test_parse_upstream_url_complex_path() {
        let uri: Uri = "/w/index.php?title=Main_Page&action=render".parse().unwrap();
        let result = parse_upstream_url("http://varnish:80", &uri).unwrap();
        assert_eq!(result, "http://varnish:80/w/index.php?title=Main_Page&action=render");
    }

    #[test]
    fn test_parse_upstream_url_with_upstream_path() {
        // When upstream has a specific path like /api
        let uri: Uri = "/users/123".parse().unwrap();
        let result = parse_upstream_url("http://api-server:3000/v1", &uri).unwrap();
        assert!(result.contains("api-server:3000"));
    }

    #[test]
    fn test_parse_upstream_url_https() {
        let uri: Uri = "/secure/endpoint".parse().unwrap();
        let result = parse_upstream_url("https://secure-backend:8443", &uri).unwrap();
        assert!(result.starts_with("https://"));
        assert!(result.contains("secure-backend:8443"));
    }

    #[test]
    fn test_parse_upstream_url_default_port() {
        let uri: Uri = "/test".parse().unwrap();

        // HTTP default
        let result = parse_upstream_url("http://backend", &uri).unwrap();
        assert!(result.contains("backend"));

        // HTTPS default
        let result = parse_upstream_url("https://backend", &uri).unwrap();
        assert!(result.contains("backend"));
    }

    #[test]
    fn test_parse_upstream_url_invalid() {
        let uri: Uri = "/test".parse().unwrap();

        // URL that will fail authority extraction (path-only style is handled gracefully by Uri)
        // Let's test edge cases that actually fail
        let result = parse_upstream_url("", &uri);
        assert!(result.is_err(), "Empty URL should fail");

        // Test with garbage that fails parse
        let result = parse_upstream_url("\0\0\0", &uri);
        assert!(result.is_err(), "Null bytes should fail");
    }

    #[test]
    fn test_parse_upstream_url_special_characters() {
        let uri: Uri = "/wiki/Test%20Page".parse().unwrap();
        let result = parse_upstream_url("http://varnish:80", &uri).unwrap();
        assert_eq!(result, "http://varnish:80/wiki/Test%20Page");
    }

    #[test]
    fn test_parse_upstream_url_unicode_in_query() {
        let uri: Uri = "/search?q=%E4%B8%AD%E6%96%87".parse().unwrap();
        let result = parse_upstream_url("http://backend:3000", &uri).unwrap();
        assert!(result.contains("q=%E4%B8%AD%E6%96%87"));
    }

    // =====================================================================
    // extract_host_port tests
    // =====================================================================

    #[test]
    fn test_extract_host_port_explicit() {
        let (host, port) = extract_host_port("http://example.com:8080/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_extract_host_port_http_default() {
        let (host, port) = extract_host_port("http://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_extract_host_port_https_default() {
        let (host, port) = extract_host_port("https://example.com/path").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_extract_host_port_custom_ports() {
        let test_cases = vec![
            ("http://localhost:3000", "localhost", 3000),
            ("http://api:8080", "api", 8080),
            ("http://192.168.1.1:9000", "192.168.1.1", 9000),
            ("https://secure:8443", "secure", 8443),
        ];

        for (uri, expected_host, expected_port) in test_cases {
            let (host, port) = extract_host_port(uri).unwrap();
            assert_eq!(host, expected_host);
            assert_eq!(port, expected_port);
        }
    }

    #[test]
    fn test_extract_host_port_with_path() {
        let (host, port) = extract_host_port("http://backend:3000/api/v1/users").unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 3000);
    }

    #[test]
    fn test_extract_host_port_with_query() {
        let (host, port) = extract_host_port("http://backend:3000/search?q=test").unwrap();
        assert_eq!(host, "backend");
        assert_eq!(port, 3000);
    }

    #[test]
    fn test_extract_host_port_docker_style() {
        // Docker-compose style hostnames
        let test_cases = vec![
            ("http://varnish:80", "varnish", 80),
            ("http://log-elasticsearch:9200", "log-elasticsearch", 9200),
            ("http://api-service:3000", "api-service", 3000),
        ];

        for (uri, expected_host, expected_port) in test_cases {
            let (host, port) = extract_host_port(uri).unwrap();
            assert_eq!(host, expected_host);
            assert_eq!(port, expected_port);
        }
    }

    #[test]
    fn test_extract_host_port_invalid() {
        // Missing host
        let result = extract_host_port("http:///path");
        assert!(result.is_err());
    }

    // =====================================================================
    // remove_hop_headers tests
    // =====================================================================

    #[test]
    fn test_remove_hop_headers_all() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        headers.insert("proxy-authenticate", HeaderValue::from_static("Basic"));
        headers.insert("proxy-authorization", HeaderValue::from_static("Basic creds"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("trailers", HeaderValue::from_static(""));

        // Also add a non-hop header
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        remove_hop_headers(&mut headers);

        // All hop-by-hop headers should be removed
        assert!(headers.get("connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("upgrade").is_none());
        assert!(headers.get("proxy-authenticate").is_none());
        assert!(headers.get("proxy-authorization").is_none());
        assert!(headers.get("te").is_none());
        assert!(headers.get("trailers").is_none());

        // Non-hop header should remain
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn test_remove_hop_headers_partial() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));
        headers.insert("x-custom", HeaderValue::from_static("value"));

        remove_hop_headers(&mut headers);

        assert!(headers.get("connection").is_none());
        assert!(headers.get("content-type").is_some());
        assert!(headers.get("x-custom").is_some());
    }

    #[test]
    fn test_remove_hop_headers_empty() {
        let mut headers = HeaderMap::new();
        remove_hop_headers(&mut headers);
        assert!(headers.is_empty());
    }

    // =====================================================================
    // add_forwarded_headers tests
    // =====================================================================

    #[test]
    fn test_add_forwarded_headers_http() {
        let mut headers = HeaderMap::new();
        add_forwarded_headers(&mut headers, "http", Some("example.com"));

        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "example.com");
    }

    #[test]
    fn test_add_forwarded_headers_https() {
        let mut headers = HeaderMap::new();
        add_forwarded_headers(&mut headers, "https", Some("secure.example.com"));

        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "secure.example.com");
    }

    #[test]
    fn test_add_forwarded_headers_overrides_client_headers() {
        // For security, we strip client-provided X-Forwarded headers
        // and set our own trusted values based on the actual request
        let mut headers = HeaderMap::new();
        // Simulate client trying to fake headers (these would be stripped by strip_forwarded_headers before this call)
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-host", HeaderValue::from_static("original.example.com"));

        add_forwarded_headers(&mut headers, "http", Some("example.com"));

        // Should override with actual request values, not preserve client values
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");  // Actual proto
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "example.com");  // Actual host
    }

    #[test]
    fn test_add_forwarded_headers_no_host() {
        let mut headers = HeaderMap::new();
        add_forwarded_headers(&mut headers, "http", None);

        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "http");
        // x-forwarded-host should not be set if no original host
        assert!(headers.get("x-forwarded-host").is_none());
    }

    // =====================================================================
    // ProxyConfig tests
    // =====================================================================

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();

        // Reduced timeouts and body size for security
        assert_eq!(config.io_timeout, Duration::from_millis(30000));
        assert_eq!(config.max_body_size, 10 * 1024 * 1024);  // 10MB
    }

    #[test]
    fn test_proxy_config_custom() {
        let config = ProxyConfig {
            io_timeout: Duration::from_secs(30),
            max_body_size: 1024 * 1024 * 100, // 100MB
        };

        assert_eq!(config.io_timeout, Duration::from_secs(30));
        assert_eq!(config.max_body_size, 104857600);
    }

    // =====================================================================
    // ProxyError tests
    // =====================================================================

    #[test]
    fn test_proxy_error_display() {
        let errors = vec![
            (ProxyError::InvalidUpstream("test".to_string()), "invalid upstream URL: test"),
            (ProxyError::Request("test".to_string()), "request error: test"),
            (ProxyError::Upstream("test".to_string()), "upstream error: test"),
            (ProxyError::Body("test".to_string()), "body error: test"),
            (ProxyError::BodyTooLarge, "request body too large"),
            (ProxyError::Timeout, "request timeout"),
        ];

        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }

    // =====================================================================
    // Integration scenarios (unit tests for combinations)
    // =====================================================================

    #[test]
    fn test_real_world_upstream_patterns() {
        // Test various real-world upstream URL patterns from h2o config

        let test_cases = vec![
            // Standard proxy to varnish
            ("http://varnish:80", "/wiki/Main_Page", "http://varnish:80/wiki/Main_Page"),
            // API endpoint
            ("http://api:3000", "/graphql", "http://api:3000/graphql"),
            // With specific path in upstream
            ("http://varnish:80/w", "/index.php", "http://varnish:80/w/index.php"),
            // Favicon
            ("http://varnish:80/favicon.ico", "/", "http://varnish:80/favicon.ico/"),
            // External service
            ("http://deb.xanmod.org:80", "/", "http://deb.xanmod.org:80/"),
        ];

        for (upstream, request_path, expected_prefix) in test_cases {
            let uri: Uri = request_path.parse().unwrap();
            let result = parse_upstream_url(upstream, &uri).unwrap();
            assert!(
                result.starts_with(expected_prefix.split('?').next().unwrap()),
                "For upstream '{}' and path '{}', expected prefix '{}' but got '{}'",
                upstream, request_path, expected_prefix, result
            );
        }
    }

    #[test]
    fn test_complex_query_strings() {
        let test_cases = vec![
            "/wiki/Special:Search?search=test&go=Go",
            "/w/index.php?title=Main&action=edit&section=1",
            "/api/v1/substances?filter[name]=dmt&include=effects,interactions",
        ];

        for path in test_cases {
            let uri: Uri = path.parse().unwrap();
            let result = parse_upstream_url("http://backend:3000", &uri).unwrap();

            // Query string should be preserved
            if let Some(query) = uri.query() {
                assert!(result.contains(query), "Query string '{}' not found in '{}'", query, result);
            }
        }
    }
}
