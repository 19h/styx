//! HTTP/3 server implementation using Quinn and h3
//!
//! This module provides HTTP/3 support via QUIC transport, enabling
//! low-latency connections with built-in multiplexing and encryption.

use crate::config::{HeaderRules, Http3Config, ResolvedConfig, RouteAction, TlsListenerConfig};
use crate::middleware::{
    apply_expires, apply_response_headers, default_security_headers, redirect_response,
    status_response,
};
use crate::proxy::ReverseProxy;
use crate::routing::{MatchResult, Router};
use crate::server::static_files::{serve_static_h3, StaticFileConfig};

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

/// ALPN protocol identifier for HTTP/3
pub const ALPN_H3: &[u8] = b"h3";

/// HTTP/3 server statistics
#[derive(Default)]
pub struct Http3Stats {
    /// Total requests handled
    pub requests: AtomicU64,
    /// Active connections
    pub active_connections: AtomicUsize,
    /// Request errors
    pub errors: AtomicU64,
    /// QUIC handshakes started
    pub handshakes_started: AtomicU64,
    /// QUIC handshakes completed
    pub handshakes_completed: AtomicU64,
    /// QUIC handshakes failed
    pub handshakes_failed: AtomicU64,
}

/// HTTP/3 server instance
pub struct Http3Server {
    config: Arc<ResolvedConfig>,
    router: Arc<Router>,
    proxy: Arc<ReverseProxy>,
    stats: Arc<Http3Stats>,
    h3_config: Http3Config,
}

impl Http3Server {
    /// Create a new HTTP/3 server
    pub fn new(
        config: Arc<ResolvedConfig>,
        router: Arc<Router>,
        proxy: Arc<ReverseProxy>,
    ) -> Self {
        let h3_config = config.http3.clone();
        Self {
            config,
            router,
            proxy,
            stats: Arc::new(Http3Stats::default()),
            h3_config,
        }
    }

    /// Run HTTP/3 listeners for all TLS-enabled listeners
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        if !self.h3_config.enabled {
            debug!("HTTP/3 is disabled, not starting QUIC listeners");
            return Ok(());
        }

        let mut handles = Vec::new();

        // Start HTTP/3 on all TLS-enabled listeners (same ports as HTTPS)
        for listener in &self.config.listeners {
            if let Some(tls_config) = &listener.tls_config {
                let server = Arc::clone(&self);
                let addr = listener.addr;
                let tls_cfg = Arc::clone(tls_config);

                let handle = tokio::spawn(async move {
                    if let Err(e) = server.run_quic_listener(addr, tls_cfg).await {
                        error!("HTTP/3 listener {} failed: {}", addr, e);
                    }
                });

                handles.push(handle);
            }
        }

        if handles.is_empty() {
            info!("No TLS listeners configured, HTTP/3 not available");
            return Ok(());
        }

        info!("Started {} HTTP/3 listeners", handles.len());

        // Wait for all listeners
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }

    /// Run a single QUIC/HTTP3 listener
    async fn run_quic_listener(
        self: Arc<Self>,
        addr: SocketAddr,
        tls_config: Arc<TlsListenerConfig>,
    ) -> anyhow::Result<()> {
        // Load TLS configuration
        let server_config = self.build_quic_server_config(&tls_config)?;

        // Create QUIC endpoint
        let endpoint = quinn::Endpoint::server(server_config, addr)?;
        info!("HTTP/3 listening on {} (UDP)", addr);

        // Accept connections
        while let Some(incoming) = endpoint.accept().await {
            self.stats.handshakes_started.fetch_add(1, Ordering::Relaxed);

            let server = Arc::clone(&self);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        server.stats.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                        server.stats.active_connections.fetch_add(1, Ordering::Relaxed);

                        let peer_addr = connection.remote_address();
                        if let Err(e) = server.handle_connection(connection, peer_addr).await {
                            trace!("HTTP/3 connection error: {}", e);
                            server.stats.errors.fetch_add(1, Ordering::Relaxed);
                        }

                        server.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        server.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
                        debug!("QUIC handshake failed: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    /// Build QUIC server configuration
    fn build_quic_server_config(
        &self,
        tls_config: &TlsListenerConfig,
    ) -> anyhow::Result<quinn::ServerConfig> {
        // Load certificates
        let cert_file = File::open(&tls_config.cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to open cert file {:?}: {}", tls_config.cert_path, e))?;
        let mut cert_reader = BufReader::new(cert_file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            anyhow::bail!("No certificates found in {:?}", tls_config.cert_path);
        }

        // Load private key
        let key_file = File::open(&tls_config.key_path)
            .map_err(|e| anyhow::anyhow!("Failed to open key file {:?}: {}", tls_config.key_path, e))?;
        let mut key_reader = BufReader::new(key_file);

        let key = load_private_key(&mut key_reader)?;

        // Build rustls config
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        // Set ALPN for HTTP/3
        server_crypto.alpn_protocols = vec![ALPN_H3.to_vec()];

        // Convert to QUIC config
        let quic_server_config = QuicServerConfig::try_from(server_crypto)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC config: {}", e))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        // Configure transport settings
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();

        // Set max concurrent bidirectional streams
        transport_config.max_concurrent_bidi_streams(
            self.h3_config.max_concurrent_streams.into()
        );

        // h3 needs unidirectional streams for control/QPACK
        transport_config.max_concurrent_uni_streams(3_u8.into());

        // Set idle timeout
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(self.h3_config.idle_timeout)
                .try_into()
                .unwrap_or(quinn::IdleTimeout::from(quinn::VarInt::from_u32(30_000)))
        ));

        // Set receive window sizes
        transport_config.stream_receive_window(
            self.h3_config.stream_receive_window.into()
        );
        transport_config.receive_window(
            self.h3_config.connection_receive_window.into()
        );

        Ok(server_config)
    }

    /// Handle a single QUIC connection
    async fn handle_connection(
        &self,
        connection: quinn::Connection,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        trace!("HTTP/3 connection from {}", peer_addr);

        // Create h3 connection using builder pattern
        // Explicitly specify Bytes as the buffer type
        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
            .build(h3_quinn::Connection::new(connection))
            .await?;

        // Accept requests
        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    self.stats.requests.fetch_add(1, Ordering::Relaxed);

                    // Resolve the request to get (request, stream)
                    let stats = Arc::clone(&self.stats);
                    let router = Arc::clone(&self.router);
                    let proxy = Arc::clone(&self.proxy);
                    let config = Arc::clone(&self.config);

                    tokio::spawn(async move {
                        match resolver.resolve_request().await {
                            Ok((request, stream)) => {
                                if let Err(e) = handle_request(
                                    request,
                                    stream,
                                    peer_addr,
                                    router,
                                    proxy,
                                    config,
                                ).await {
                                    debug!("HTTP/3 request error: {}", e);
                                    stats.errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(e) => {
                                debug!("Failed to resolve HTTP/3 request: {}", e);
                                stats.errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    });
                }
                Ok(None) => {
                    // Connection closed gracefully
                    trace!("HTTP/3 connection closed gracefully");
                    break;
                }
                Err(e) => {
                    warn!("HTTP/3 connection error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle a single HTTP/3 request
async fn handle_request<S>(
    request: Request<()>,
    mut stream: RequestStream<S, Bytes>,
    peer_addr: SocketAddr,
    router: Arc<Router>,
    proxy: Arc<ReverseProxy>,
    config: Arc<ResolvedConfig>,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    let host = request
        .headers()
        .get(http::header::HOST)
        .or_else(|| request.headers().get(":authority"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let path = request.uri().path();

    trace!("HTTP/3 request: {} {} {} from {}", request.method(), host, path, peer_addr);

    // Route the request
    let result = match router.route(host, path) {
        Some(r) => r,
        None => {
            debug!("No route for {} {}", host, path);
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(())
                .unwrap();
            stream.send_response(response).await?;
            stream.send_data(Bytes::from("Not Found")).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // Read request body from stream (needed for proxy)
    let request_body = read_request_body(&mut stream).await.unwrap_or_default();

    // Execute the action
    let response = match execute_action(&request, request_body, &result, &proxy, &config, peer_addr).await {
        Ok(r) => r,
        Err(e) => {
            warn!("HTTP/3 request error: {}", e);
            let response = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap();
            stream.send_response(response).await?;
            stream.send_data(Bytes::from(format!("Proxy error: {}", e))).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // Send response
    let (parts, body) = response.into_parts();
    let response = Response::from_parts(parts, ());
    stream.send_response(response).await?;

    if !body.is_empty() {
        stream.send_data(body).await?;
    }

    stream.finish().await?;

    Ok(())
}

/// Read the request body from an HTTP/3 stream
async fn read_request_body<S>(stream: &mut RequestStream<S, Bytes>) -> anyhow::Result<Bytes>
where
    S: h3::quic::BidiStream<Bytes> + Send,
{
    use bytes::BytesMut;

    let mut body = BytesMut::new();
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB limit

    while let Some(data) = stream.recv_data().await? {
        if body.len() + data.remaining() > MAX_BODY_SIZE {
            anyhow::bail!("Request body too large");
        }
        body.extend_from_slice(data.chunk());
    }

    Ok(body.freeze())
}

/// Execute a route action
async fn execute_action(
    request: &Request<()>,
    request_body: Bytes,
    route: &MatchResult,
    proxy: &ReverseProxy,
    config: &ResolvedConfig,
    peer_addr: SocketAddr,
) -> Result<Response<Bytes>, anyhow::Error> {
    let global_headers = default_security_headers().merge_with(&config.global_headers);

    match &route.action {
        RouteAction::Redirect { url, status } => {
            let mut response = redirect_response(*status, url);
            let merged_headers = global_headers.merge_with(&route.headers);
            apply_response_headers(&mut response, &merged_headers);
            apply_expires(&mut response, route.expires);

            // Convert to Bytes body
            let (parts, body) = response.into_parts();
            let body_bytes = body.collect().await?.to_bytes();
            Ok(Response::from_parts(parts, body_bytes))
        }

        RouteAction::Status => {
            let mut response = status_response();
            let merged_headers = global_headers.merge_with(&route.headers);
            apply_response_headers(&mut response, &merged_headers);
            apply_expires(&mut response, route.expires);

            let (parts, body) = response.into_parts();
            let body_bytes = body.collect().await?.to_bytes();
            Ok(Response::from_parts(parts, body_bytes))
        }

        RouteAction::StaticFiles { dir, index, send_gzip, dirlisting } => {
            let static_config = StaticFileConfig {
                root: dir.clone(),
                index: index.clone(),
                send_gzip: *send_gzip,
                dirlisting: *dirlisting,
                prefix: route.matched_path.clone(),
            };

            match serve_static_h3(request, &static_config).await {
                Ok(mut response) => {
                    let merged_headers = global_headers.merge_with(&route.headers);
                    apply_response_headers(&mut response, &merged_headers);
                    apply_expires(&mut response, route.expires);
                    Ok(response)
                }
                Err(e) => {
                    let status = e.status_code();
                    Ok(Response::builder()
                        .status(status)
                        .body(Bytes::from(e.to_string()))
                        .unwrap())
                }
            }
        }

        RouteAction::Proxy { upstream, preserve_host } => {
            // Merge proxy headers
            let merged_proxy_headers = global_headers.merge_with(&route.headers);
            let response_headers = HeaderRules::default();

            // Forward the request to the upstream
            let response = proxy.proxy_with_body(
                request.method().clone(),
                request.uri(),
                request.headers().clone(),
                request_body,
                upstream,
                *preserve_host,
                &merged_proxy_headers,
                &response_headers,
                Some(peer_addr.ip()),
            ).await?;

            // Apply response headers
            let (parts, body) = response.into_parts();
            let merged_response_headers = global_headers.merge_with(&route.headers);

            // Create temp response to apply headers
            let mut temp_response = Response::from_parts(parts.clone(), Bytes::new());
            apply_response_headers(&mut temp_response, &merged_response_headers);
            apply_expires(&mut temp_response, route.expires);

            let (modified_parts, _) = temp_response.into_parts();

            Ok(Response::from_parts(modified_parts, body))
        }
    }
}

/// Load a private key from a PEM file
fn load_private_key<R: std::io::BufRead>(reader: &mut R) -> anyhow::Result<PrivateKeyDer<'static>> {
    loop {
        match rustls_pemfile::read_one(reader)? {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(rustls_pemfile::Item::Sec1Key(key)) => {
                return Ok(PrivateKeyDer::Sec1(key));
            }
            None => break,
            _ => continue,
        }
    }

    anyhow::bail!("No private key found")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Http2Config, Http3Config};
    use std::collections::HashMap;
    use std::path::PathBuf;

    // =========================================================================
    // Http3Stats tests
    // =========================================================================

    #[test]
    fn test_http3_stats_default() {
        let stats = Http3Stats::default();
        assert_eq!(stats.requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 0);
        assert_eq!(stats.handshakes_started.load(Ordering::Relaxed), 0);
        assert_eq!(stats.handshakes_completed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.handshakes_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_http3_stats_atomic_operations() {
        let stats = Http3Stats::default();

        stats.requests.fetch_add(10, Ordering::Relaxed);
        stats.active_connections.fetch_add(5, Ordering::Relaxed);
        stats.errors.fetch_add(2, Ordering::Relaxed);

        assert_eq!(stats.requests.load(Ordering::Relaxed), 10);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 5);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_http3_stats_handshake_tracking() {
        let stats = Http3Stats::default();

        // Simulate handshake lifecycle
        stats.handshakes_started.fetch_add(100, Ordering::Relaxed);
        stats.handshakes_completed.fetch_add(95, Ordering::Relaxed);
        stats.handshakes_failed.fetch_add(5, Ordering::Relaxed);

        assert_eq!(stats.handshakes_started.load(Ordering::Relaxed), 100);
        assert_eq!(stats.handshakes_completed.load(Ordering::Relaxed), 95);
        assert_eq!(stats.handshakes_failed.load(Ordering::Relaxed), 5);

        // Verify started = completed + failed
        assert_eq!(
            stats.handshakes_started.load(Ordering::Relaxed),
            stats.handshakes_completed.load(Ordering::Relaxed)
                + stats.handshakes_failed.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn test_http3_stats_concurrent_updates() {
        use std::thread;

        let stats = Arc::new(Http3Stats::default());
        let mut handles = vec![];

        // Spawn multiple threads updating stats
        for _ in 0..10 {
            let stats_clone = Arc::clone(&stats);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    stats_clone.requests.fetch_add(1, Ordering::Relaxed);
                    stats_clone.active_connections.fetch_add(1, Ordering::Relaxed);
                    stats_clone.active_connections.fetch_sub(1, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(stats.requests.load(Ordering::Relaxed), 1000);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    // =========================================================================
    // ALPN constant tests
    // =========================================================================

    #[test]
    fn test_alpn_h3_constant() {
        assert_eq!(ALPN_H3, b"h3");
    }

    #[test]
    fn test_alpn_h3_is_valid_utf8() {
        assert!(std::str::from_utf8(ALPN_H3).is_ok());
        assert_eq!(std::str::from_utf8(ALPN_H3).unwrap(), "h3");
    }

    // =========================================================================
    // Http3Config tests
    // =========================================================================

    #[test]
    fn test_http3_config_default() {
        let config = Http3Config::default();
        assert!(!config.enabled);
        assert_eq!(config.max_concurrent_streams, 256);
        assert_eq!(config.idle_timeout, 30);
        assert_eq!(config.stream_receive_window, 1024 * 1024);
        assert_eq!(config.connection_receive_window, 2 * 1024 * 1024);
    }

    #[test]
    fn test_http3_config_custom() {
        let config = Http3Config {
            enabled: true,
            max_concurrent_streams: 512,
            idle_timeout: 60,
            stream_receive_window: 2 * 1024 * 1024,
            connection_receive_window: 4 * 1024 * 1024,
        };

        assert!(config.enabled);
        assert_eq!(config.max_concurrent_streams, 512);
        assert_eq!(config.idle_timeout, 60);
    }

    #[test]
    fn test_http3_config_clone() {
        let config1 = Http3Config {
            enabled: true,
            max_concurrent_streams: 100,
            idle_timeout: 45,
            stream_receive_window: 512 * 1024,
            connection_receive_window: 1024 * 1024,
        };

        let config2 = config1.clone();

        assert_eq!(config1.enabled, config2.enabled);
        assert_eq!(config1.max_concurrent_streams, config2.max_concurrent_streams);
        assert_eq!(config1.idle_timeout, config2.idle_timeout);
    }

    // =========================================================================
    // load_private_key tests
    // =========================================================================

    #[test]
    fn test_load_private_key_empty_reader() {
        let mut reader = std::io::Cursor::new(Vec::<u8>::new());
        let result = load_private_key(&mut reader);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No private key found"));
    }

    #[test]
    fn test_load_private_key_invalid_pem() {
        let invalid_pem = b"not a valid pem file";
        let mut reader = std::io::Cursor::new(invalid_pem.as_slice());
        let result = load_private_key(&mut reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_certificate_only() {
        // A PEM file with only a certificate, no private key
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIBkjCB/AIJAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC6mCz0rj2/P6rLkhT7RBHN
gXE6kW6VVl5Y0J/GkEHqJA8RWEA8jPx7w7tOQ8cPj+3oKx8I+qVhKqIbEf1Gi/LN
AgMBAAEwDQYJKoZIhvcNAQELBQADQQBU9VLRvlVux3r2wPhi/HEvOIB9FQg4NDNF
cjSBFnGNTJhEj8LnALVkOW7VG8cWB0fZ/M7X9qvB3R0u9RvOYl5E
-----END CERTIFICATE-----"#;
        let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
        let result = load_private_key(&mut reader);
        assert!(result.is_err());
    }

    // =========================================================================
    // Http3Server creation tests
    // =========================================================================

    fn create_test_config() -> ResolvedConfig {
        ResolvedConfig {
            num_threads: 4,
            pid_file: None,
            hosts: HashMap::new(),
            listeners: vec![],
            global_headers: HeaderRules::default(),
            proxy_timeout_io: Duration::from_secs(30),
            limit_request_body: 10 * 1024 * 1024,
            tcp_listeners: vec![],
            http2: Http2Config::default(),
            http3: Http3Config {
                enabled: true,
                max_concurrent_streams: 256,
                idle_timeout: 30,
                stream_receive_window: 1024 * 1024,
                connection_receive_window: 2 * 1024 * 1024,
            },
            sni_fallback: false,
        }
    }

    #[tokio::test]
    async fn test_http3_server_creation() {
        let config = Arc::new(create_test_config());
        let router = Arc::new(Router::new(&config.hosts));
        let proxy = ReverseProxy::new(crate::proxy::ProxyConfig::default());

        let server = Http3Server::new(
            Arc::clone(&config),
            router,
            proxy,
        );

        assert!(server.h3_config.enabled);
        assert_eq!(server.h3_config.max_concurrent_streams, 256);
    }

    #[tokio::test]
    async fn test_http3_server_disabled() {
        let mut config = create_test_config();
        config.http3.enabled = false;
        let config = Arc::new(config);
        let router = Arc::new(Router::new(&config.hosts));
        let proxy = ReverseProxy::new(crate::proxy::ProxyConfig::default());

        let server = Http3Server::new(
            Arc::clone(&config),
            router,
            proxy,
        );

        assert!(!server.h3_config.enabled);
    }

    // =========================================================================
    // Route action tests (execute_action)
    // =========================================================================

    #[tokio::test]
    async fn test_execute_action_redirect() {
        let config = create_test_config();
        let proxy = ReverseProxy::new(crate::proxy::ProxyConfig::default());

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/old-page")
            .body(())
            .unwrap();

        let route = MatchResult {
            action: RouteAction::Redirect {
                url: "https://example.com/new-page".to_string(),
                status: 301,
            },
            headers: HeaderRules::default(),
            proxy_headers: HeaderRules::default(),
            matched_path: "/old-page".to_string(),
            expires: None,
        };

        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = execute_action(&request, Bytes::new(), &route, &proxy, &config, peer_addr).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert!(response.headers().get("location").is_some());
    }

    #[tokio::test]
    async fn test_execute_action_status() {
        let config = create_test_config();
        let proxy = ReverseProxy::new(crate::proxy::ProxyConfig::default());

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/status")
            .body(())
            .unwrap();

        let route = MatchResult {
            action: RouteAction::Status,
            headers: HeaderRules::default(),
            proxy_headers: HeaderRules::default(),
            matched_path: "/status".to_string(),
            expires: None,
        };

        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = execute_action(&request, Bytes::new(), &route, &proxy, &config, peer_addr).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_execute_action_static_not_found() {
        let config = create_test_config();
        let proxy = ReverseProxy::new(crate::proxy::ProxyConfig::default());

        // Use temp directory which exists but has no files
        let temp_dir = std::env::temp_dir();

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/definitely_nonexistent_file_12345.html")
            .body(())
            .unwrap();

        let route = MatchResult {
            action: RouteAction::StaticFiles {
                dir: temp_dir,
                index: vec!["index.html".to_string()],
                send_gzip: false,
                dirlisting: false,
            },
            headers: HeaderRules::default(),
            proxy_headers: HeaderRules::default(),
            matched_path: "/".to_string(),
            expires: None,
        };

        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = execute_action(&request, Bytes::new(), &route, &proxy, &config, peer_addr).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // =========================================================================
    // Request/Response header tests
    // =========================================================================

    #[test]
    fn test_host_header_from_uri() {
        // In HTTP/3, the authority comes from the URI, not a header
        // The http crate doesn't allow pseudo-headers as regular headers
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.com/path")
            .body(())
            .unwrap();

        // Extract host from URI authority
        let host = request.uri().host().unwrap_or("");
        assert_eq!(host, "example.com");
    }

    #[test]
    fn test_host_header_fallback() {
        // Test fallback to Host header when :authority is missing
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/path")
            .header("host", "fallback.com")
            .body(())
            .unwrap();

        let host = request
            .headers()
            .get(http::header::HOST)
            .or_else(|| request.headers().get(":authority"))
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        assert_eq!(host, "fallback.com");
    }

    #[test]
    fn test_empty_host_header() {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/path")
            .body(())
            .unwrap();

        let host = request
            .headers()
            .get(http::header::HOST)
            .or_else(|| request.headers().get(":authority"))
            .and_then(|h| h.to_str().ok())
            .unwrap_or("default.host");

        assert_eq!(host, "default.host");
    }

    // =========================================================================
    // Integration-style tests
    // =========================================================================

    #[test]
    fn test_quic_transport_config_values() {
        let config = Http3Config {
            enabled: true,
            max_concurrent_streams: 100,
            idle_timeout: 60,
            stream_receive_window: 512 * 1024,
            connection_receive_window: 1024 * 1024,
        };

        // Verify VarInt conversions work for all config values
        let _streams: quinn::VarInt = config.max_concurrent_streams.into();
        let _stream_window: quinn::VarInt = config.stream_receive_window.into();
        let _conn_window: quinn::VarInt = config.connection_receive_window.into();

        // Verify timeout conversion works
        let timeout = Duration::from_secs(config.idle_timeout);
        assert_eq!(timeout.as_secs(), 60);
    }

    #[test]
    fn test_response_building() {
        // Test that we can build responses correctly for HTTP/3
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(())
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn test_error_response_building() {
        let statuses = vec![
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
        ];

        for status in statuses {
            let response = Response::builder()
                .status(status)
                .body(Bytes::from("error"))
                .unwrap();

            assert_eq!(response.status(), status);
            assert!(!response.body().is_empty());
        }
    }

    // =========================================================================
    // Proxy integration tests
    // =========================================================================

    #[tokio::test]
    async fn test_proxy_action_with_invalid_upstream() {
        let config = create_test_config();
        let proxy = ReverseProxy::new(crate::proxy::ProxyConfig::default());

        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/api/test")
            .header("host", "example.com")
            .body(())
            .unwrap();

        // Invalid upstream URL that will fail validation
        let route = MatchResult {
            action: RouteAction::Proxy {
                upstream: "http://127.0.0.1:99999".to_string(), // Invalid - localhost blocked
                preserve_host: false,
            },
            headers: HeaderRules::default(),
            proxy_headers: HeaderRules::default(),
            matched_path: "/api".to_string(),
            expires: None,
        };

        let peer_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let result = execute_action(&request, Bytes::new(), &route, &proxy, &config, peer_addr).await;

        // Should fail due to SSRF protection (localhost is blocked)
        assert!(result.is_err());
    }

    // =========================================================================
    // Bytes body handling tests
    // =========================================================================

    #[test]
    fn test_bytes_empty() {
        let body = Bytes::new();
        assert!(body.is_empty());
        assert_eq!(body.len(), 0);
    }

    #[test]
    fn test_bytes_from_static() {
        let body = Bytes::from("Hello, HTTP/3!");
        assert!(!body.is_empty());
        assert_eq!(body.len(), 14);
    }

    #[test]
    fn test_bytes_from_vec() {
        let data = vec![1u8, 2, 3, 4, 5];
        let body = Bytes::from(data);
        assert_eq!(body.len(), 5);
        assert_eq!(body.chunk(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_response_with_bytes_body() {
        let body = Bytes::from("Test response body");
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .header("content-length", body.len().to_string())
            .body(body.clone())
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body().len(), 18);
    }
}
