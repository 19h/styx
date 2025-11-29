//! Connection pooling for backend services
//!
//! This module provides efficient connection pooling to upstream servers,
//! supporting both HTTP/1.1 and HTTP/2 connections with intelligent
//! connection reuse and health monitoring.

use bytes::Bytes;
use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::{debug, trace};

/// ALPN protocol identifiers for client connections
const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Configuration for the connection pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per host
    pub max_connections_per_host: usize,
    /// Connection idle timeout
    pub idle_timeout: Duration,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Maximum idle connections per host
    pub max_idle_per_host: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 256,
            idle_timeout: Duration::from_secs(90),
            connect_timeout: Duration::from_secs(10),
            max_idle_per_host: 32,
        }
    }
}

/// Protocol version for pooled connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PooledProtocol {
    Http1,
    Http2,
}

/// A pooled HTTP/1.1 connection
struct PooledHttp1Connection {
    sender: http1::SendRequest<Full<Bytes>>,
    #[allow(dead_code)]
    created_at: Instant,
    last_used: Instant,
}

/// A pooled HTTP/2 connection (multiplexed, can be shared)
struct PooledHttp2Connection {
    sender: http2::SendRequest<Full<Bytes>>,
    #[allow(dead_code)]
    created_at: Instant,
    last_used: Instant,
}

/// Connection pool entry for a single host (lock-free design)
struct HostPool {
    /// Idle HTTP/1.1 connections ready for reuse (lock-free queue)
    idle_http1: Arc<SegQueue<PooledHttp1Connection>>,
    /// HTTP/2 connection (multiplexed, one per host)
    http2_conn: parking_lot::RwLock<Option<PooledHttp2Connection>>,
    /// Semaphore to limit concurrent connections
    semaphore: Arc<Semaphore>,
    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    /// Current idle HTTP/1.1 connection count (approximate)
    idle_count: AtomicUsize,
    /// Whether this host supports HTTP/2 (discovered via ALPN)
    supports_h2: parking_lot::RwLock<Option<bool>>,
}

impl HostPool {
    fn new(max_connections: usize) -> Self {
        Self {
            idle_http1: Arc::new(SegQueue::new()),
            http2_conn: parking_lot::RwLock::new(None),
            semaphore: Arc::new(Semaphore::new(max_connections)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            idle_count: AtomicUsize::new(0),
            supports_h2: parking_lot::RwLock::new(None),
        }
    }
}

/// High-performance connection pool (lock-free design)
pub struct ConnectionPool {
    config: PoolConfig,
    pools: DashMap<String, Arc<HostPool>>,
    /// Global statistics
    total_requests: AtomicU64,
    active_connections: AtomicUsize,
}

impl ConnectionPool {
    /// Create a new connection pool with the given configuration
    pub fn new(config: PoolConfig) -> Arc<Self> {
        let pool = Arc::new(Self {
            config,
            pools: DashMap::new(),
            total_requests: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
        });

        // Start background cleanup task
        let pool_clone = Arc::clone(&pool);
        tokio::spawn(async move {
            pool_clone.cleanup_loop().await;
        });

        pool
    }

    /// Get or create pool for a host
    fn get_or_create_pool(&self, key: &str) -> Arc<HostPool> {
        self.pools
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(HostPool::new(self.config.max_connections_per_host)))
            .clone()
    }

    /// Send a request through the pool (supports HTTP/1.1 and HTTP/2)
    pub async fn send_request(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        use_tls: bool,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, PoolError> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let key = format!("{}:{}:{}", if use_tls { "https" } else { "http" }, host, port);
        let pool = self.get_or_create_pool(&key);

        // For TLS connections, try HTTP/2 first if supported
        if use_tls {
            // Check if we know this host supports HTTP/2
            let supports_h2 = *pool.supports_h2.read();

            if supports_h2 != Some(false) {
                // Try to use existing HTTP/2 connection
                if let Some(response) = self.try_http2_request(&pool, request.clone()).await {
                    pool.hits.fetch_add(1, Ordering::Relaxed);
                    return response;
                }
            }

            // If we haven't discovered protocol support yet, try to establish HTTP/2
            if supports_h2.is_none() {
                match self.create_http2_connection(host, port).await {
                    Ok(conn) => {
                        *pool.supports_h2.write() = Some(true);
                        debug!("Host {}:{} supports HTTP/2", host, port);

                        let mut sender = conn.sender.clone();
                        let response = sender.send_request(request).await.map_err(|e| {
                            PoolError::Request(e.to_string())
                        })?;

                        // Store HTTP/2 connection for reuse
                        *pool.http2_conn.write() = Some(conn);
                        pool.hits.fetch_add(1, Ordering::Relaxed);
                        self.active_connections.fetch_add(1, Ordering::Relaxed);

                        return Ok(response);
                    }
                    Err(_) => {
                        // HTTP/2 not supported, fall through to HTTP/1.1
                        *pool.supports_h2.write() = Some(false);
                        debug!("Host {}:{} does not support HTTP/2, using HTTP/1.1", host, port);
                    }
                }
            }
        }

        // HTTP/1.1 path
        self.send_http1_request(&pool, host, port, use_tls, request).await
    }

    /// Try to send request over existing HTTP/2 connection
    async fn try_http2_request(
        &self,
        pool: &Arc<HostPool>,
        request: Request<Full<Bytes>>,
    ) -> Option<Result<Response<Incoming>, PoolError>> {
        // Get the sender clone while holding the lock briefly
        let sender_clone = {
            let conn_guard = pool.http2_conn.read();
            if let Some(conn) = conn_guard.as_ref() {
                // Check if HTTP/2 connection is still usable
                if conn.sender.is_ready() {
                    Some(conn.sender.clone())
                } else {
                    None
                }
            } else {
                None
            }
            // Lock is dropped here
        };

        // Now send the request without holding any locks
        if let Some(mut sender) = sender_clone {
            match sender.send_request(request).await {
                Ok(response) => return Some(Ok(response)),
                Err(e) => {
                    // Connection failed, clear it
                    *pool.http2_conn.write() = None;
                    debug!("HTTP/2 connection failed: {}, will retry", e);
                    return None;
                }
            }
        }

        None
    }

    /// Send request using HTTP/1.1
    async fn send_http1_request(
        self: &Arc<Self>,
        pool: &Arc<HostPool>,
        host: &str,
        port: u16,
        use_tls: bool,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, PoolError> {
        // Try to get an idle HTTP/1.1 connection
        let mut conn = self.get_idle_http1_connection(pool);
        let semaphore = pool.semaphore.clone();

        if conn.is_some() {
            pool.hits.fetch_add(1, Ordering::Relaxed);
        }

        // If no idle connection, create a new one
        if conn.is_none() {
            // Acquire semaphore permit with timeout
            let _permit = tokio::time::timeout(
                Duration::from_secs(30),
                semaphore.acquire_owned()
            )
            .await
            .map_err(|_| PoolError::AcquireTimeout)?
            .map_err(|_| PoolError::PoolExhausted)?;

            pool.misses.fetch_add(1, Ordering::Relaxed);

            conn = Some(self.create_http1_connection(host, port, use_tls).await?);
            self.active_connections.fetch_add(1, Ordering::Relaxed);
        }

        let mut sender = conn.unwrap();

        // Send the request
        let response = sender.sender.send_request(request).await.map_err(|e| {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            PoolError::Request(e.to_string())
        })?;

        // Return connection to pool if still usable
        if sender.sender.is_ready() {
            sender.last_used = Instant::now();
            let current_idle = pool.idle_count.load(Ordering::Relaxed);
            if current_idle < self.config.max_idle_per_host {
                pool.idle_http1.push(sender);
                pool.idle_count.fetch_add(1, Ordering::Relaxed);
            } else {
                self.active_connections.fetch_sub(1, Ordering::Relaxed);
            }
        } else {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }

        Ok(response)
    }

    /// Get an idle HTTP/1.1 connection from the pool
    fn get_idle_http1_connection(&self, pool: &Arc<HostPool>) -> Option<PooledHttp1Connection> {
        let now = Instant::now();

        // Try to pop connections until we find a valid one
        loop {
            match pool.idle_http1.pop() {
                Some(conn) => {
                    pool.idle_count.fetch_sub(1, Ordering::Relaxed);

                    // Check if connection is still valid
                    if now.duration_since(conn.last_used) < self.config.idle_timeout
                        && conn.sender.is_ready()
                    {
                        return Some(conn);
                    }
                    // Connection expired, drop it and try next
                    self.active_connections.fetch_sub(1, Ordering::Relaxed);
                }
                None => return None,
            }
        }
    }

    /// Create a new HTTP/1.1 connection to the upstream
    async fn create_http1_connection(&self, host: &str, port: u16, use_tls: bool) -> Result<PooledHttp1Connection, PoolError> {
        // Resolve all addresses for Happy Eyeballs
        let addrs = resolve_host_all(host, port).await?;

        // Happy Eyeballs: try all addresses with quick fallback
        let (stream, _connected_addr) = tokio::time::timeout(
            self.config.connect_timeout,
            connect_with_happy_eyeballs(&addrs, self.config.connect_timeout),
        )
        .await
        .map_err(|_| PoolError::ConnectTimeout)?
        .map_err(|e| e)?;

        // Set TCP options
        stream.set_nodelay(true).ok();

        if use_tls {
            // Create TLS connector with HTTP/1.1 only ALPN
            let mut root_store = RootCertStore::empty();
            root_store.extend(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned()
            );

            let mut config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            // Only advertise HTTP/1.1 for this connection type
            config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

            let connector = TlsConnector::from(Arc::new(config));

            // Perform TLS handshake
            let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|_| PoolError::Handshake("Invalid DNS name".to_string()))?;

            let tls_stream = connector
                .connect(domain, stream)
                .await
                .map_err(|e| PoolError::Handshake(format!("TLS handshake failed: {}", e)))?;

            let io = TokioIo::new(tls_stream);

            let (sender, conn) = http1::handshake(io)
                .await
                .map_err(|e| PoolError::Handshake(e.to_string()))?;

            // Spawn connection driver
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    trace!("Connection closed: {}", e);
                }
            });

            Ok(PooledHttp1Connection {
                sender,
                created_at: Instant::now(),
                last_used: Instant::now(),
            })
        } else {
            // Plain HTTP connection
            let io = TokioIo::new(stream);

            let (sender, conn) = http1::handshake(io)
                .await
                .map_err(|e| PoolError::Handshake(e.to_string()))?;

            // Spawn connection driver
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    trace!("Connection closed: {}", e);
                }
            });

            Ok(PooledHttp1Connection {
                sender,
                created_at: Instant::now(),
                last_used: Instant::now(),
            })
        }
    }

    /// Create a new HTTP/2 connection to the upstream (TLS only)
    async fn create_http2_connection(&self, host: &str, port: u16) -> Result<PooledHttp2Connection, PoolError> {
        // Resolve all addresses for Happy Eyeballs
        let addrs = resolve_host_all(host, port).await?;

        // Happy Eyeballs: try all addresses with quick fallback
        let (stream, _connected_addr) = tokio::time::timeout(
            self.config.connect_timeout,
            connect_with_happy_eyeballs(&addrs, self.config.connect_timeout),
        )
        .await
        .map_err(|_| PoolError::ConnectTimeout)?
        .map_err(|e| e)?;

        // Set TCP options
        stream.set_nodelay(true).ok();

        // Create TLS connector with HTTP/2 ALPN
        let mut root_store = RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
        );

        let mut config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Prefer HTTP/2, fall back to HTTP/1.1
        config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];

        let connector = TlsConnector::from(Arc::new(config));

        // Perform TLS handshake
        let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| PoolError::Handshake("Invalid DNS name".to_string()))?;

        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| PoolError::Handshake(format!("TLS handshake failed: {}", e)))?;

        // Check if HTTP/2 was negotiated
        let alpn = tls_stream.get_ref().1.alpn_protocol();
        if alpn != Some(ALPN_H2) {
            return Err(PoolError::Handshake("HTTP/2 not supported by server".to_string()));
        }

        let io = TokioIo::new(tls_stream);

        let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| PoolError::Handshake(format!("HTTP/2 handshake failed: {}", e)))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                trace!("HTTP/2 connection closed: {}", e);
            }
        });

        Ok(PooledHttp2Connection {
            sender,
            created_at: Instant::now(),
            last_used: Instant::now(),
        })
    }

    /// Background cleanup of idle connections (lock-free)
    async fn cleanup_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;

            let now = Instant::now();

            for entry in self.pools.iter() {
                let pool = entry.value();
                let mut removed = 0;
                let mut valid_conns = Vec::new();

                // Drain all HTTP/1.1 connections from the queue
                while let Some(conn) = pool.idle_http1.pop() {
                    pool.idle_count.fetch_sub(1, Ordering::Relaxed);

                    if now.duration_since(conn.last_used) < self.config.idle_timeout
                        && conn.sender.is_ready()
                    {
                        // Still valid, keep it
                        valid_conns.push(conn);
                    } else {
                        // Expired or dead, drop it
                        removed += 1;
                    }
                }

                // Push valid connections back
                for conn in valid_conns {
                    pool.idle_http1.push(conn);
                    pool.idle_count.fetch_add(1, Ordering::Relaxed);
                }

                // Check HTTP/2 connection
                {
                    let mut h2_guard = pool.http2_conn.write();
                    if let Some(ref conn) = *h2_guard {
                        if now.duration_since(conn.last_used) >= self.config.idle_timeout
                            || !conn.sender.is_ready()
                        {
                            *h2_guard = None;
                            removed += 1;
                            trace!("Cleaned up idle HTTP/2 connection for {}", entry.key());
                        }
                    }
                }

                if removed > 0 {
                    self.active_connections.fetch_sub(removed, Ordering::Relaxed);
                    trace!("Cleaned up {} idle connections for {}", removed, entry.key());
                }
            }
        }
    }

}

/// Resolve hostname to all socket addresses (for Happy Eyeballs)
async fn resolve_host_all(host: &str, port: u16) -> Result<Vec<SocketAddr>, PoolError> {
    use tokio::net::lookup_host;

    let addr_str = format!("{}:{}", host, port);

    let addrs: Vec<SocketAddr> = lookup_host(&addr_str)
        .await
        .map_err(|e| PoolError::Resolve(e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(PoolError::Resolve(format!("No addresses found for {}", host)));
    }

    Ok(addrs)
}

/// Happy Eyeballs connection: try all addresses with quick timeout
async fn connect_with_happy_eyeballs(addrs: &[SocketAddr], _connect_timeout: Duration) -> Result<(TcpStream, SocketAddr), PoolError> {
    let mut last_error = None;
    
    // Try each address with a short timeout (300ms per RFC 8305 recommendation)
    for addr in addrs {
        match tokio::time::timeout(
            Duration::from_millis(300),
            TcpStream::connect(addr)
        ).await {
            Ok(Ok(stream)) => {
                trace!("Successfully connected to {}", addr);
                return Ok((stream, *addr));
            }
            Ok(Err(e)) => {
                trace!("Failed to connect to {}: {}", addr, e);
                last_error = Some(e.to_string());
            }
            Err(_) => {
                trace!("Timeout connecting to {}", addr);
                last_error = Some(format!("Connection timeout to {}", addr));
            }
        }
    }

    // All addresses failed
    Err(PoolError::Connect(
        last_error.unwrap_or_else(|| "All resolved addresses failed".to_string())
    ))
}


/// Pool errors
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("connection pool exhausted")]
    PoolExhausted,

    #[error("timeout waiting for connection pool slot")]
    AcquireTimeout,

    #[error("connection timeout")]
    ConnectTimeout,

    #[error("connection error: {0}")]
    Connect(String),

    #[error("handshake error: {0}")]
    Handshake(String),

    #[error("request error: {0}")]
    Request(String),

    #[error("DNS resolution error: {0}")]
    Resolve(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // PoolConfig tests
    // =====================================================================

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();

        assert_eq!(config.max_connections_per_host, 256);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.max_idle_per_host, 32);
    }

    #[test]
    fn test_pool_config_custom() {
        let config = PoolConfig {
            max_connections_per_host: 128,
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(5),
            max_idle_per_host: 16,
        };

        assert_eq!(config.max_connections_per_host, 128);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.max_idle_per_host, 16);
    }

    // =====================================================================
    // ConnectionPool creation tests
    // =====================================================================

    #[tokio::test]
    async fn test_pool_creation() {
        let config = PoolConfig::default();
        let _pool = ConnectionPool::new(config);
    }

    #[tokio::test]
    async fn test_pool_creation_custom_config() {
        let config = PoolConfig {
            max_connections_per_host: 64,
            idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            max_idle_per_host: 8,
        };

        let pool = ConnectionPool::new(config.clone());
        assert_eq!(pool.config.max_connections_per_host, 64);
    }

    #[tokio::test]
    async fn test_pool_get_or_create_pool() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config);

        // First call should create a new pool
        let host_pool1 = pool.get_or_create_pool("backend:3000");

        // Second call should return the same pool
        let host_pool2 = pool.get_or_create_pool("backend:3000");

        // Different host should create a new pool
        let host_pool3 = pool.get_or_create_pool("other:8080");

        // Should be the same pool instance for the same key
        assert!(Arc::ptr_eq(&host_pool1, &host_pool2));

        // Should be different pool instances for different keys
        assert!(!Arc::ptr_eq(&host_pool1, &host_pool3));
    }

    // =====================================================================
    // PoolError tests
    // =====================================================================

    #[test]
    fn test_pool_error_display() {
        let errors = vec![
            (PoolError::PoolExhausted, "connection pool exhausted"),
            (PoolError::ConnectTimeout, "connection timeout"),
            (PoolError::Connect("failed".to_string()), "connection error: failed"),
            (PoolError::Handshake("failed".to_string()), "handshake error: failed"),
            (PoolError::Request("failed".to_string()), "request error: failed"),
            (PoolError::Resolve("failed".to_string()), "DNS resolution error: failed"),
        ];

        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }

    // =====================================================================
    // HostPool tests
    // =====================================================================

    #[test]
    fn test_host_pool_creation() {
        let pool = HostPool::new(100);

        assert!(pool.idle_http1.is_empty());
        assert!(pool.http2_conn.read().is_none());
        assert_eq!(pool.hits.load(Ordering::Relaxed), 0);
        assert_eq!(pool.misses.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_host_pool_semaphore_permits() {
        let pool = HostPool::new(50);

        // Should have 50 permits available
        assert_eq!(pool.semaphore.available_permits(), 50);
    }

    // =====================================================================
    // resolve_host_all tests
    // =====================================================================

    #[tokio::test]
    async fn test_resolve_localhost() {
        // localhost should resolve
        let result = resolve_host_all("localhost", 80).await;
        assert!(result.is_ok());

        let addrs = result.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|addr| addr.port() == 80));
    }

    #[tokio::test]
    async fn test_resolve_ip_address() {
        // IP addresses should resolve immediately
        let result = resolve_host_all("127.0.0.1", 8080).await;
        assert!(result.is_ok());

        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 8080);
        assert!(addrs[0].ip().is_loopback());
    }

    #[tokio::test]
    async fn test_resolve_invalid_host() {
        // Non-existent host should fail
        let result = resolve_host_all("definitely-not-a-real-host-abc123xyz.invalid", 80).await;
        assert!(result.is_err());

        match result {
            Err(PoolError::Resolve(_)) => {}
            _ => panic!("Expected Resolve error"),
        }
    }

    #[tokio::test]
    async fn test_happy_eyeballs_single_address() {
        // Test with single address
        let addrs = vec![SocketAddr::from(([127, 0, 0, 1], 1))];
        let result = connect_with_happy_eyeballs(&addrs, Duration::from_secs(5)).await;
        // This will fail because nothing is listening, but we're testing the logic
        assert!(result.is_err());
    }

    // =====================================================================
    // Edge cases
    // =====================================================================

    #[tokio::test]
    async fn test_pool_multiple_hosts() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config);

        // Create pools for multiple hosts
        pool.get_or_create_pool("host1:80");
        pool.get_or_create_pool("host2:80");
        pool.get_or_create_pool("host3:80");

        // Stats should show all pools
        // Note: stats uses try_lock, so we need to check pools exist in DashMap
        assert_eq!(pool.pools.len(), 3);
    }

    #[tokio::test]
    async fn test_pool_concurrent_access() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config);

        // Simulate concurrent pool creation
        let pool1 = Arc::clone(&pool);
        let pool2 = Arc::clone(&pool);

        let (key1, key2) = tokio::join!(
            async move {
                pool1.get_or_create_pool("shared:80");
                "shared:80"
            },
            async move {
                pool2.get_or_create_pool("shared:80");
                "shared:80"
            }
        );

        // Both should have used the same key
        assert_eq!(key1, key2);

        // Only one pool should exist
        assert_eq!(pool.pools.len(), 1);
    }

    #[test]
    fn test_pool_config_clone() {
        let config = PoolConfig {
            max_connections_per_host: 100,
            idle_timeout: Duration::from_secs(45),
            connect_timeout: Duration::from_secs(15),
            max_idle_per_host: 20,
        };

        let cloned = config.clone();

        assert_eq!(config.max_connections_per_host, cloned.max_connections_per_host);
        assert_eq!(config.idle_timeout, cloned.idle_timeout);
        assert_eq!(config.connect_timeout, cloned.connect_timeout);
        assert_eq!(config.max_idle_per_host, cloned.max_idle_per_host);
    }

    #[test]
    fn test_pool_error_debug() {
        let errors = vec![
            PoolError::PoolExhausted,
            PoolError::ConnectTimeout,
            PoolError::Connect("test".to_string()),
        ];

        for error in errors {
            // Should not panic when debug printing
            let _ = format!("{:?}", error);
        }
    }

    #[tokio::test]
    async fn test_pool_host_key_format() {
        let config = PoolConfig::default();
        let pool = ConnectionPool::new(config);

        // Test various host:port combinations
        pool.get_or_create_pool("example.com:80");
        pool.get_or_create_pool("api.example.com:443");
        pool.get_or_create_pool("192.168.1.1:8080");

        assert!(pool.pools.contains_key("example.com:80"));
        assert!(pool.pools.contains_key("api.example.com:443"));
        assert!(pool.pools.contains_key("192.168.1.1:8080"));
    }
}
