//! HTTP server implementation
//!
//! This module contains the main HTTP/HTTPS server that handles incoming
//! connections, routes requests, and dispatches to appropriate handlers.

pub mod static_files;

use crate::config::{HeaderRules, ResolvedConfig, RouteAction};
use crate::middleware::{
    apply_expires, apply_response_headers, default_security_headers, error_response,
    redirect_response, status_response,
};
use crate::proxy::{ProxyConfig, ProxyError, ReverseProxy};
use crate::routing::{MatchResult, Router};
use crate::tls::TlsManager;
use bytes::Bytes;
use dashmap::DashMap;
use http::{header, HeaderValue, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lru::LruCache;
use std::num::NonZeroUsize;
use static_files::{serve_static, StaticFileConfig};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};

/// Server statistics
#[derive(Default)]
pub struct ServerStats {
    /// Total requests handled
    pub requests: AtomicU64,
    /// Active connections
    pub active_connections: AtomicUsize,
    /// Request errors
    pub errors: AtomicU64,
}

/// Per-IP rate limiting state
struct IpRateLimit {
    connections: AtomicUsize,
    last_request: parking_lot::Mutex<Instant>,
    created_at: Instant,
}

/// Normalize IP address for rate limiting
/// For IPv6, use /64 prefix to prevent bypass via multiple addresses
fn normalize_ip_for_rate_limiting(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip, // IPv4 uses full address
        IpAddr::V6(ipv6) => {
            // Extract first 64 bits (8 bytes) and zero out the rest
            let segments = ipv6.segments();
            let normalized = std::net::Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3],
                0, 0, 0, 0
            );
            IpAddr::V6(normalized)
        }
    }
}

/// Main HTTP server
pub struct Server {
    config: Arc<ResolvedConfig>,
    router: Arc<Router>,
    proxy: Arc<ReverseProxy>,
    tls_manager: Arc<TlsManager>,
    stats: Arc<ServerStats>,
    global_headers: HeaderRules,
    /// Connection limiter for DoS protection
    connection_semaphore: Arc<Semaphore>,
    /// Per-IP rate limiting (bounded LRU to prevent memory exhaustion)
    ip_rate_limits: Arc<parking_lot::Mutex<LruCache<IpAddr, Arc<IpRateLimit>>>>,
    /// Maximum request body size
    #[allow(dead_code)]
    max_body_size: u64,
}

impl Server {
    /// Create a new server from configuration
    pub fn new(config: ResolvedConfig) -> Arc<Self> {
        let router = Arc::new(Router::new(&config.hosts));

        let proxy_config = ProxyConfig {
            io_timeout: config.proxy_timeout_io,
            keepalive_timeout: config.proxy_timeout_keepalive,
            max_body_size: config.limit_request_body,
        };
        let proxy = ReverseProxy::new(proxy_config);

        let tls_manager = Arc::new(TlsManager::new());

        // Merge global headers with security defaults
        let global_headers = default_security_headers().merge_with(&config.global_headers);

        // Connection limit: reduce from 65536 to more reasonable default
        let max_connections = 10000;

        Arc::new(Self {
            max_body_size: config.limit_request_body,
            config: Arc::new(config),
            router,
            proxy,
            tls_manager,
            stats: Arc::new(ServerStats::default()),
            global_headers,
            connection_semaphore: Arc::new(Semaphore::new(max_connections)),
            // Bounded LRU cache: max 100k IPs to prevent memory exhaustion
            ip_rate_limits: Arc::new(parking_lot::Mutex::new(
                LruCache::new(NonZeroUsize::new(100_000).unwrap())
            )),
        })
    }

    /// Run the server
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        info!("Starting styx reverse proxy");

        let mut handles = Vec::new();

        // Note: LRU cache automatically evicts old entries, no cleanup task needed

        // Start listeners
        for listener_config in &self.config.listeners {
            let server = Arc::clone(&self);
            let addr = listener_config.addr;
            let tls_config = listener_config.tls_config.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = server.run_listener(addr, tls_config).await {
                    error!("Listener {} failed: {}", addr, e);
                }
            });

            handles.push(handle);
        }

        // Wait for all listeners
        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    /// Run a single listener
    async fn run_listener(
        self: Arc<Self>,
        addr: SocketAddr,
        tls_config: Option<Arc<crate::config::TlsListenerConfig>>,
    ) -> anyhow::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on {}{}", addr, if tls_config.is_some() { " (TLS)" } else { "" });

        // Build TLS acceptor if needed
        let tls_acceptor = if let Some(tls_cfg) = &tls_config {
            // Load certificate for this listener
            self.tls_manager
                .load_cert("*", &tls_cfg.cert_path, &tls_cfg.key_path)?;

            let server_config = self.tls_manager.build_server_config()?;
            Some(TlsAcceptor::from(server_config))
        } else {
            None
        };

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Accept error: {}", e);
                    continue;
                }
            };

            // Check per-IP rate limit
            // For IPv6, rate limit by /64 prefix to prevent bypass
            const MAX_CONNECTIONS_PER_IP: usize = 100;
            let ip_addr = normalize_ip_for_rate_limiting(peer_addr.ip());

            let now = Instant::now();
            let ip_limit = {
                let mut cache = self.ip_rate_limits.lock();
                cache.get_or_insert(ip_addr, || Arc::new(IpRateLimit {
                    connections: AtomicUsize::new(0),
                    last_request: parking_lot::Mutex::new(now),
                    created_at: now,
                })).clone()
            };

            let ip_conns = ip_limit.connections.fetch_add(1, Ordering::Relaxed);
            if ip_conns >= MAX_CONNECTIONS_PER_IP {
                warn!("Per-IP connection limit reached for {}, rejecting", peer_addr);
                ip_limit.connections.fetch_sub(1, Ordering::Relaxed);
                drop(stream);
                continue;
            }

            // Acquire global connection permit
            let permit = match self.connection_semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("Global connection limit reached, rejecting {}", peer_addr);
                    ip_limit.connections.fetch_sub(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
            };

            self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

            let server = Arc::clone(&self);
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                let result = if let Some(acceptor) = tls_acceptor {
                    server.clone().handle_tls_connection(stream, peer_addr, acceptor).await
                } else {
                    server.clone().handle_connection(stream, peer_addr).await
                };

                if let Err(e) = result {
                    trace!("Connection {} error: {}", peer_addr, e);
                    server.stats.errors.fetch_add(1, Ordering::Relaxed);
                }

                server.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                ip_limit.connections.fetch_sub(1, Ordering::Relaxed);
                drop(permit);
            });
        }
    }

    /// Handle a plain HTTP connection
    async fn handle_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;

        let io = TokioIo::new(stream);
        let server = Arc::clone(&self);

        let mut builder = http1::Builder::new();
        builder.keep_alive(true);

        // Serve connection with overall timeout (5 minutes max per connection)
        tokio::time::timeout(
            Duration::from_secs(300),
            builder.serve_connection(
                io,
                service_fn(move |req| {
                    let server = Arc::clone(&server);
                    // Per-request timeout (2 minutes)
                    async move {
                        tokio::time::timeout(
                            Duration::from_secs(120),
                            server.handle_request(req, peer_addr)
                        )
                        .await
                        .unwrap_or_else(|_| {
                            Ok(error_response(StatusCode::REQUEST_TIMEOUT, "Request timeout")
                                .map(|body| body.map_err(|e| match e {}).boxed()))
                        })
                    }
                }),
            )
        )
        .await??;

        Ok(())
    }

    /// Handle a TLS connection
    async fn handle_tls_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer_addr: SocketAddr,
        acceptor: TlsAcceptor,
    ) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;

        self.tls_manager.record_handshake_start();

        // TLS handshake with timeout
        let tls_stream = match tokio::time::timeout(
            Duration::from_secs(10),
            acceptor.accept(stream),
        )
        .await
        {
            Ok(Ok(stream)) => {
                self.tls_manager.record_handshake_complete();
                stream
            }
            Ok(Err(e)) => {
                self.tls_manager.record_handshake_failed();
                return Err(anyhow::anyhow!("TLS handshake failed: {}", e));
            }
            Err(_) => {
                self.tls_manager.record_handshake_failed();
                return Err(anyhow::anyhow!("TLS handshake timeout"));
            }
        };

        let io = TokioIo::new(tls_stream);
        let server = Arc::clone(&self);

        let mut builder = http1::Builder::new();
        builder.keep_alive(true);

        // Serve connection with overall timeout (5 minutes max per connection)
        tokio::time::timeout(
            Duration::from_secs(300),
            builder.serve_connection(
                io,
                service_fn(move |req| {
                    let server = Arc::clone(&server);
                    // Per-request timeout (2 minutes)
                    async move {
                        tokio::time::timeout(
                            Duration::from_secs(120),
                            server.handle_request(req, peer_addr)
                        )
                        .await
                        .unwrap_or_else(|_| {
                            Ok(error_response(StatusCode::REQUEST_TIMEOUT, "Request timeout")
                                .map(|body| body.map_err(|e| match e {}).boxed()))
                        })
                    }
                }),
            )
        )
        .await??;

        Ok(())
    }

    /// Handle a single HTTP request (streaming)
    async fn handle_request(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);

        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|h: &HeaderValue| h.to_str().ok())
            .unwrap_or("");

        let path = request.uri().path();

        trace!("Request: {} {} {} from {}", request.method(), host, path, peer_addr);

        // Route the request
        let result = match self.router.route(host, path) {
            Some(r) => r,
            None => {
                debug!("No route for {} {}", host, path);
                let resp = error_response(StatusCode::NOT_FOUND, "Not Found");
                return Ok(resp.map(|body| body.map_err(|e| match e {}).boxed()));
            }
        };

        // Execute the action
        let response = match self.execute_action(request, &result, peer_addr).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Request error: {}", e);
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                let resp = error_response(StatusCode::BAD_GATEWAY, &format!("Proxy error: {}", e));
                resp.map(|body| body.map_err(|e| match e {}).boxed())
            }
        };

        Ok(response)
    }

    /// Execute a route action (streaming)
    async fn execute_action(
        &self,
        request: Request<Incoming>,
        route: &MatchResult,
        peer_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, ProxyError> {
        match &route.action {
            RouteAction::Redirect { url, status } => {
                // Apply header rules to redirect response
                let mut response = redirect_response(*status, url);
                let merged_headers = self.global_headers.merge_with(&route.headers);
                apply_response_headers(&mut response, &merged_headers);
                apply_expires(&mut response, route.expires);
                Ok(response.map(|body| body.map_err(|e| match e {}).boxed()))
            }

            RouteAction::Status => {
                let mut response = status_response();
                let merged_headers = self.global_headers.merge_with(&route.headers);
                apply_response_headers(&mut response, &merged_headers);
                apply_expires(&mut response, route.expires);
                Ok(response.map(|body| body.map_err(|e| match e {}).boxed()))
            }

            RouteAction::StaticFiles { dir, index, send_gzip, dirlisting } => {
                let config = StaticFileConfig {
                    root: dir.clone(),
                    index: index.clone(),
                    send_gzip: *send_gzip,
                    dirlisting: *dirlisting,
                    prefix: route.matched_path.clone(),
                };

                match serve_static(&request, &config).await {
                    Ok(mut response) => {
                        let merged_headers = self.global_headers.merge_with(&route.headers);
                        apply_response_headers(&mut response, &merged_headers);
                        apply_expires(&mut response, route.expires);
                        Ok(response.map(|body| body.map_err(|e| match e {}).boxed()))
                    }
                    Err(e) => {
                        let status = e.status_code();
                        let msg = e.to_string();
                        Ok(error_response(status, &msg).map(|body| body.map_err(|e| match e {}).boxed()))
                    }
                }
            }

            RouteAction::Proxy { upstream, preserve_host } => {
                let merged_response_headers = self.global_headers.merge_with(&route.headers);

                // Streaming proxy - no body buffering
                let mut response: Response<Incoming> = self
                    .proxy
                    .proxy(
                        request,
                        upstream,
                        *preserve_host,
                        &route.proxy_headers,
                        &merged_response_headers,
                        Some(peer_addr.ip()), // Pass client IP for X-Forwarded-For
                    )
                    .await?;

                // Apply expires header
                apply_expires(&mut response, route.expires);

                // Box the body to unify types (streaming, no conversion)
                Ok(response.map(|body| body.boxed()))
            }
        }
    }

    /// Get server statistics
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    // IP rate limit cleanup removed - LRU cache handles eviction automatically
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_stats() {
        let stats = ServerStats::default();
        assert_eq!(stats.requests.load(Ordering::Relaxed), 0);
        stats.requests.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
    }
}
