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
use hyper::client::conn::http1;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use tracing::trace;

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
    /// Keepalive timeout
    pub keepalive_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 256,
            idle_timeout: Duration::from_secs(90),
            connect_timeout: Duration::from_secs(10),
            max_idle_per_host: 32,
            keepalive_timeout: Duration::from_secs(59),
        }
    }
}

/// A pooled HTTP/1.1 connection
struct PooledConnection {
    sender: http1::SendRequest<Full<Bytes>>,
    #[allow(dead_code)]
    created_at: Instant,
    last_used: Instant,
}

/// Connection pool entry for a single host (lock-free design)
struct HostPool {
    /// Idle connections ready for reuse (lock-free queue)
    idle: Arc<SegQueue<PooledConnection>>,
    /// Semaphore to limit concurrent connections
    semaphore: Arc<Semaphore>,
    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    /// Current idle connection count (approximate)
    idle_count: AtomicUsize,
}

impl HostPool {
    fn new(max_connections: usize) -> Self {
        Self {
            idle: Arc::new(SegQueue::new()),
            semaphore: Arc::new(Semaphore::new(max_connections)),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            idle_count: AtomicUsize::new(0),
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

    /// Send a request through the pool (lock-free)
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

        // Try to get an idle connection (lock-free!)
        let mut conn = self.get_idle_connection(&pool);
        let semaphore = pool.semaphore.clone();
        
        if conn.is_some() {
            pool.hits.fetch_add(1, Ordering::Relaxed);
        }

        // If no idle connection, create a new one
        if conn.is_none() {
            // Acquire semaphore permit with timeout
            let _permit = tokio::time::timeout(
                Duration::from_secs(30), // Don't wait forever
                semaphore.acquire_owned()
            )
            .await
            .map_err(|_| PoolError::AcquireTimeout)?
            .map_err(|_| PoolError::PoolExhausted)?;

            pool.misses.fetch_add(1, Ordering::Relaxed);

            conn = Some(self.create_connection(host, port, use_tls).await?);
            self.active_connections.fetch_add(1, Ordering::Relaxed);
        }

        let mut sender = conn.unwrap();

        // Send the request
        let response = sender.sender.send_request(request).await.map_err(|e| {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            PoolError::Request(e.to_string())
        })?;

        // Return connection to pool if still usable (lock-free!)
        if sender.sender.is_ready() {
            sender.last_used = Instant::now();
            let current_idle = pool.idle_count.load(Ordering::Relaxed);
            if current_idle < self.config.max_idle_per_host {
                pool.idle.push(sender);
                pool.idle_count.fetch_add(1, Ordering::Relaxed);
            } else {
                self.active_connections.fetch_sub(1, Ordering::Relaxed);
            }
        } else {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }

        Ok(response)
    }

    /// Get an idle connection from the pool (lock-free)
    fn get_idle_connection(&self, pool: &Arc<HostPool>) -> Option<PooledConnection> {
        let now = Instant::now();

        // Try to pop connections until we find a valid one
        loop {
            match pool.idle.pop() {
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

    /// Create a new connection to the upstream
    async fn create_connection(&self, host: &str, port: u16, use_tls: bool) -> Result<PooledConnection, PoolError> {
        // Resolve all addresses for Happy Eyeballs
        let addrs = resolve_host_all(host, port).await?;

        // Validate all resolved IPs to prevent DNS rebinding attacks
        for addr in &addrs {
            validate_resolved_ip(addr.ip())?;
        }

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
            // Create TLS connector with system root certificates
            let mut root_store = RootCertStore::empty();
            root_store.extend(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned()
            );

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

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

            Ok(PooledConnection {
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

            Ok(PooledConnection {
                sender,
                created_at: Instant::now(),
                last_used: Instant::now(),
            })
        }
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

                // Drain all connections from the queue
                while let Some(conn) = pool.idle.pop() {
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
                    pool.idle.push(conn);
                    pool.idle_count.fetch_add(1, Ordering::Relaxed);
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

/// Validate resolved IP address to prevent DNS rebinding
pub fn validate_resolved_ip(ip: std::net::IpAddr) -> Result<(), PoolError> {
    use std::net::{IpAddr, Ipv4Addr};

    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();

            // Block private/internal IP ranges
            if ipv4.is_loopback() // 127.0.0.0/8
                || ipv4.is_private() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || ipv4.is_link_local() // 169.254.0.0/16
                || ipv4.is_unspecified() // 0.0.0.0
                || ipv4.is_broadcast() // 255.255.255.255
                || octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127 // 100.64.0.0/10
            {
                return Err(PoolError::Connect(format!(
                    "DNS resolved to blocked private IP: {}",
                    ipv4
                )));
            }

            // Block AWS metadata endpoint
            if ipv4 == Ipv4Addr::new(169, 254, 169, 254) {
                return Err(PoolError::Connect(
                    "DNS resolved to metadata service endpoint".to_string()
                ));
            }
        }
        IpAddr::V6(ipv6) => {
            // Block private/internal IPv6 ranges
            if ipv6.is_loopback() // ::1
                || ipv6.is_unspecified() // ::
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 (Unique local)
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 (Link-local)
            {
                return Err(PoolError::Connect(format!(
                    "DNS resolved to blocked private IPv6: {}",
                    ipv6
                )));
            }

            // Block IPv4-mapped IPv6 (::ffff:127.0.0.1)
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                // Recursively validate the IPv4 address
                return validate_resolved_ip(IpAddr::V4(ipv4));
            }

            // Block IPv4-compatible IPv6 (::127.0.0.1)
            let segments = ipv6.segments();
            if segments[0..6].iter().all(|&s| s == 0) {
                // Last 32 bits contain IPv4
                let ipv4 = Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                return validate_resolved_ip(IpAddr::V4(ipv4));
            }
        }
    }

    Ok(())
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
        assert_eq!(config.keepalive_timeout, Duration::from_secs(59));
    }

    #[test]
    fn test_pool_config_custom() {
        let config = PoolConfig {
            max_connections_per_host: 128,
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(5),
            max_idle_per_host: 16,
            keepalive_timeout: Duration::from_secs(30),
        };

        assert_eq!(config.max_connections_per_host, 128);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.max_idle_per_host, 16);
        assert_eq!(config.keepalive_timeout, Duration::from_secs(30));
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
            keepalive_timeout: Duration::from_secs(15),
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

        assert!(pool.idle.is_empty());
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
            keepalive_timeout: Duration::from_secs(30),
        };

        let cloned = config.clone();

        assert_eq!(config.max_connections_per_host, cloned.max_connections_per_host);
        assert_eq!(config.idle_timeout, cloned.idle_timeout);
        assert_eq!(config.connect_timeout, cloned.connect_timeout);
        assert_eq!(config.max_idle_per_host, cloned.max_idle_per_host);
        assert_eq!(config.keepalive_timeout, cloned.keepalive_timeout);
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
