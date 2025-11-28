//! HTTP/3 server implementation using Quinn and h3
//!
//! This module provides HTTP/3 support via QUIC transport, enabling
//! low-latency connections with built-in multiplexing and encryption.

use crate::config::{Http3Config, ResolvedConfig, RouteAction, TlsListenerConfig};
use crate::middleware::{
    apply_expires, apply_response_headers, default_security_headers, redirect_response,
    status_response,
};
use crate::proxy::ReverseProxy;
use crate::routing::{MatchResult, Router};
use crate::server::static_files::{serve_static_h3, StaticFileConfig};

use bytes::Bytes;
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
                    let config = Arc::clone(&self.config);

                    tokio::spawn(async move {
                        match resolver.resolve_request().await {
                            Ok((request, stream)) => {
                                if let Err(e) = handle_request(
                                    request,
                                    stream,
                                    peer_addr,
                                    router,
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

    // Execute the action
    let response = match execute_action(&request, &result, &config).await {
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

/// Execute a route action
async fn execute_action(
    request: &Request<()>,
    route: &MatchResult,
    config: &ResolvedConfig,
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

        RouteAction::Proxy { upstream: _, preserve_host: _ } => {
            // HTTP/3 proxy support is not yet implemented
            // Proxying requires reading the request body from the QUIC stream
            // and forwarding it to the upstream, which needs more work
            Ok(Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Bytes::from("HTTP/3 proxy support coming soon"))
                .unwrap())
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

    #[test]
    fn test_http3_stats_default() {
        let stats = Http3Stats::default();
        assert_eq!(stats.requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 0);
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
    fn test_alpn_h3_constant() {
        assert_eq!(ALPN_H3, b"h3");
    }
}
