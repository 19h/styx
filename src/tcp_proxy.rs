//! TCP proxy implementation with weighted load balancing and health checking
//!
//! This module provides Layer 4 (TCP) proxying with:
//! - Weighted random backend selection
//! - Health checking with configurable thresholds
//! - Latency-aware load balancing (optional)
//! - Bidirectional stream copying

use crate::config::{ResolvedBackend, ResolvedHealthConfig, ResolvedTcpListener};
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

/// Statistics for a TCP proxy listener
#[derive(Default)]
pub struct TcpProxyStats {
    /// Total connections handled
    pub connections: AtomicU64,
    /// Active connections
    pub active_connections: AtomicU64,
    /// Failed connection attempts
    pub failed_connections: AtomicU64,
    /// Bytes transferred (client -> backend)
    pub bytes_sent: AtomicU64,
    /// Bytes transferred (backend -> client)
    pub bytes_received: AtomicU64,
}

/// Backend state with health tracking
pub struct BackendState {
    /// Backend address
    pub addr: SocketAddr,
    /// Original configured weight
    pub base_weight: u32,
    /// Current effective weight (adjusted by health/latency)
    pub effective_weight: AtomicU32,
    /// Whether backend is healthy
    pub healthy: AtomicBool,
    /// Consecutive health check successes
    pub consecutive_successes: AtomicU32,
    /// Consecutive health check failures
    pub consecutive_failures: AtomicU32,
    /// Recent latency samples (rolling window)
    latency_samples: RwLock<LatencyWindow>,
}

/// Rolling window of latency samples
struct LatencyWindow {
    samples: Vec<u64>, // microseconds
    index: usize,
    count: usize,
}

impl LatencyWindow {
    const WINDOW_SIZE: usize = 100;

    fn new() -> Self {
        Self {
            samples: vec![0; Self::WINDOW_SIZE],
            index: 0,
            count: 0,
        }
    }

    fn add(&mut self, latency_us: u64) {
        self.samples[self.index] = latency_us;
        self.index = (self.index + 1) % Self::WINDOW_SIZE;
        if self.count < Self::WINDOW_SIZE {
            self.count += 1;
        }
    }

    fn mean(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let sum: u64 = self.samples[..self.count].iter().sum();
        sum as f64 / self.count as f64
    }

    fn std_dev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance: f64 = self.samples[..self.count]
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / (self.count - 1) as f64;
        variance.sqrt()
    }
}

impl BackendState {
    fn new(backend: &ResolvedBackend) -> Self {
        Self {
            addr: backend.addr,
            base_weight: backend.weight,
            effective_weight: AtomicU32::new(backend.weight),
            healthy: AtomicBool::new(true), // Start healthy, prove otherwise
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            latency_samples: RwLock::new(LatencyWindow::new()),
        }
    }

    fn record_latency(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        self.latency_samples.write().add(micros);
    }

    fn get_latency_stats(&self) -> (f64, f64) {
        let window = self.latency_samples.read();
        (window.mean(), window.std_dev())
    }

    fn mark_healthy(&self, healthy_threshold: u32) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        if successes >= healthy_threshold && !self.healthy.load(Ordering::Relaxed) {
            self.healthy.store(true, Ordering::Relaxed);
            self.effective_weight.store(self.base_weight, Ordering::Relaxed);
            info!("Backend {} marked healthy after {} successes", self.addr, successes);
        }
    }

    fn mark_unhealthy(&self, unhealthy_threshold: u32) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= unhealthy_threshold && self.healthy.load(Ordering::Relaxed) {
            self.healthy.store(false, Ordering::Relaxed);
            self.effective_weight.store(0, Ordering::Relaxed);
            warn!("Backend {} marked unhealthy after {} failures", self.addr, failures);
        }
    }
}

/// TCP proxy for a single listener
pub struct TcpProxy {
    /// Listen address
    addr: SocketAddr,
    /// Backend servers with state
    backends: Vec<Arc<BackendState>>,
    /// Health configuration
    health_config: ResolvedHealthConfig,
    /// Statistics
    stats: Arc<TcpProxyStats>,
    /// Total weight for selection (cached)
    total_weight: AtomicU32,
}

impl TcpProxy {
    /// Create a new TCP proxy from configuration
    pub fn new(config: &ResolvedTcpListener) -> Arc<Self> {
        let backends: Vec<Arc<BackendState>> = config
            .backends
            .iter()
            .map(|b| Arc::new(BackendState::new(b)))
            .collect();

        let total_weight: u32 = backends.iter().map(|b| b.base_weight).sum();

        Arc::new(Self {
            addr: config.addr,
            backends,
            health_config: config.health.clone(),
            stats: Arc::new(TcpProxyStats::default()),
            total_weight: AtomicU32::new(total_weight),
        })
    }

    /// Run the TCP proxy
    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(
            "TCP proxy listening on {} with {} backends",
            self.addr,
            self.backends.len()
        );

        // Start health check task
        let health_proxy = Arc::clone(&self);
        tokio::spawn(async move {
            health_proxy.health_check_loop().await;
        });

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let proxy = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = proxy.handle_connection(stream, peer_addr).await {
                            trace!("Connection from {} error: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    warn!("TCP proxy accept error: {}", e);
                }
            }
        }
    }

    /// Select a backend using weighted random selection
    fn select_backend(&self) -> Option<Arc<BackendState>> {
        // Recalculate total weight from healthy backends
        let healthy_backends: Vec<_> = self
            .backends
            .iter()
            .filter(|b| b.healthy.load(Ordering::Relaxed))
            .cloned()
            .collect();

        if healthy_backends.is_empty() {
            warn!("No healthy backends available");
            return None;
        }

        let total_weight: u32 = healthy_backends
            .iter()
            .map(|b| b.effective_weight.load(Ordering::Relaxed))
            .sum();

        if total_weight == 0 {
            // Fallback to round-robin if all weights are 0
            let idx = (self.stats.connections.load(Ordering::Relaxed) as usize) % healthy_backends.len();
            return Some(healthy_backends[idx].clone());
        }

        // Weighted random selection
        let mut rng_value = fastrand::u32(0..total_weight);
        for backend in &healthy_backends {
            let weight = backend.effective_weight.load(Ordering::Relaxed);
            if rng_value < weight {
                return Some(backend.clone());
            }
            rng_value -= weight;
        }

        // Fallback (shouldn't happen)
        healthy_backends.last().cloned()
    }

    /// Handle a single TCP connection
    async fn handle_connection(
        &self,
        mut client: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

        let result = self.proxy_connection(&mut client, peer_addr).await;

        self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        result
    }

    async fn proxy_connection(
        &self,
        client: &mut TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        // Select backend
        let backend = match self.select_backend() {
            Some(b) => b,
            None => {
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("No healthy backends"));
            }
        };

        trace!("Proxying {} -> {}", peer_addr, backend.addr);

        // Connect to backend with timeout
        let start = Instant::now();
        let backend_stream = match tokio::time::timeout(
            self.health_config.connect_timeout,
            TcpStream::connect(backend.addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                backend.record_latency(start.elapsed());
                backend.mark_healthy(self.health_config.healthy_threshold);
                stream
            }
            Ok(Err(e)) => {
                backend.mark_unhealthy(self.health_config.unhealthy_threshold);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("Backend connect error: {}", e));
            }
            Err(_) => {
                backend.mark_unhealthy(self.health_config.unhealthy_threshold);
                self.stats.failed_connections.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("Backend connect timeout"));
            }
        };

        // Set TCP options
        let _ = client.set_nodelay(true);
        let _ = backend_stream.set_nodelay(true);

        // Bidirectional copy
        let (bytes_sent, bytes_received) = self.copy_bidirectional(client, backend_stream).await?;

        self.stats.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(bytes_received, Ordering::Relaxed);

        Ok(())
    }

    /// Copy data bidirectionally between client and backend
    async fn copy_bidirectional(
        &self,
        client: &mut TcpStream,
        mut backend: TcpStream,
    ) -> anyhow::Result<(u64, u64)> {
        let (mut client_read, mut client_write) = client.split();
        let (mut backend_read, mut backend_write) = backend.split();

        let io_timeout = self.health_config.io_timeout;

        // Copy client -> backend
        let client_to_backend = async {
            let mut total = 0u64;
            let mut buf = vec![0u8; 64 * 1024]; // 64KB buffer

            loop {
                let n = match tokio::time::timeout(io_timeout, client_read.read(&mut buf)).await {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(anyhow::anyhow!("Client read error: {}", e)),
                    Err(_) => break, // Timeout, end gracefully
                };

                if let Err(e) = tokio::time::timeout(io_timeout, backend_write.write_all(&buf[..n])).await {
                    return Err(anyhow::anyhow!("Backend write error: {:?}", e));
                }
                total += n as u64;
            }

            let _ = backend_write.shutdown().await;
            Ok(total)
        };

        // Copy backend -> client
        let backend_to_client = async {
            let mut total = 0u64;
            let mut buf = vec![0u8; 64 * 1024]; // 64KB buffer

            loop {
                let n = match tokio::time::timeout(io_timeout, backend_read.read(&mut buf)).await {
                    Ok(Ok(0)) => break, // EOF
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(anyhow::anyhow!("Backend read error: {}", e)),
                    Err(_) => break, // Timeout, end gracefully
                };

                if let Err(e) = tokio::time::timeout(io_timeout, client_write.write_all(&buf[..n])).await {
                    return Err(anyhow::anyhow!("Client write error: {:?}", e));
                }
                total += n as u64;
            }

            let _ = client_write.shutdown().await;
            Ok(total)
        };

        // Run both directions concurrently
        let (sent_result, received_result) = tokio::join!(client_to_backend, backend_to_client);

        Ok((sent_result.unwrap_or(0), received_result.unwrap_or(0)))
    }

    /// Background health check loop
    async fn health_check_loop(&self) {
        let interval = self.health_config.interval;
        let timeout = self.health_config.timeout;

        loop {
            tokio::time::sleep(interval).await;

            for backend in &self.backends {
                let addr = backend.addr;
                let backend = Arc::clone(backend);
                let healthy_threshold = self.health_config.healthy_threshold;
                let unhealthy_threshold = self.health_config.unhealthy_threshold;

                // Perform health check
                let start = Instant::now();
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        backend.record_latency(start.elapsed());
                        backend.mark_healthy(healthy_threshold);
                        trace!("Health check passed for {}", addr);
                    }
                    Ok(Err(e)) => {
                        debug!("Health check failed for {}: {}", addr, e);
                        backend.mark_unhealthy(unhealthy_threshold);
                    }
                    Err(_) => {
                        debug!("Health check timeout for {}", addr);
                        backend.mark_unhealthy(unhealthy_threshold);
                    }
                }
            }

            // Update effective weights based on latency (if enabled)
            if self.health_config.latency_aware {
                self.update_latency_weights();
            }
        }
    }

    /// Update backend weights based on latency statistics
    fn update_latency_weights(&self) {
        let sigma = self.health_config.sigma_threshold;

        // Calculate global mean and std dev
        let mut all_means: Vec<f64> = Vec::new();
        for backend in &self.backends {
            if backend.healthy.load(Ordering::Relaxed) {
                let (mean, _) = backend.get_latency_stats();
                if mean > 0.0 {
                    all_means.push(mean);
                }
            }
        }

        if all_means.is_empty() {
            return;
        }

        let global_mean: f64 = all_means.iter().sum::<f64>() / all_means.len() as f64;
        let global_std_dev: f64 = if all_means.len() > 1 {
            let variance: f64 = all_means
                .iter()
                .map(|&m| (m - global_mean).powi(2))
                .sum::<f64>()
                / (all_means.len() - 1) as f64;
            variance.sqrt()
        } else {
            0.0
        };

        // Adjust weights based on latency
        for backend in &self.backends {
            if !backend.healthy.load(Ordering::Relaxed) {
                continue;
            }

            let (mean, _) = backend.get_latency_stats();
            if mean <= 0.0 {
                continue;
            }

            // Calculate z-score
            let z_score = if global_std_dev > 0.0 {
                (mean - global_mean) / global_std_dev
            } else {
                0.0
            };

            // Reduce weight for backends with high latency
            let weight_factor = if z_score > sigma {
                // Exponential decay for high-latency backends
                (1.0 / (1.0 + (z_score - sigma))).max(0.1)
            } else if z_score < -sigma {
                // Slight boost for fast backends
                1.2
            } else {
                1.0
            };

            let new_weight = ((backend.base_weight as f64) * weight_factor) as u32;
            backend.effective_weight.store(new_weight.max(1), Ordering::Relaxed);
        }

        // Update total weight cache
        let total: u32 = self
            .backends
            .iter()
            .filter(|b| b.healthy.load(Ordering::Relaxed))
            .map(|b| b.effective_weight.load(Ordering::Relaxed))
            .sum();
        self.total_weight.store(total, Ordering::Relaxed);
    }

    /// Get proxy statistics
    pub fn stats(&self) -> &TcpProxyStats {
        &self.stats
    }

    /// Get backend states for monitoring
    pub fn backend_states(&self) -> Vec<BackendInfo> {
        self.backends
            .iter()
            .map(|b| {
                let (mean_latency, _) = b.get_latency_stats();
                BackendInfo {
                    addr: b.addr,
                    healthy: b.healthy.load(Ordering::Relaxed),
                    base_weight: b.base_weight,
                    effective_weight: b.effective_weight.load(Ordering::Relaxed),
                    mean_latency_us: mean_latency as u64,
                }
            })
            .collect()
    }
}

/// Backend information for monitoring
#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub addr: SocketAddr,
    pub healthy: bool,
    pub base_weight: u32,
    pub effective_weight: u32,
    pub mean_latency_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_window() {
        let mut window = LatencyWindow::new();

        // Empty window
        assert_eq!(window.mean(), 0.0);
        assert_eq!(window.std_dev(), 0.0);

        // Single sample
        window.add(100);
        assert_eq!(window.mean(), 100.0);
        assert_eq!(window.std_dev(), 0.0); // Need at least 2 samples

        // Multiple samples
        window.add(200);
        window.add(300);
        assert_eq!(window.mean(), 200.0);
        assert!(window.std_dev() > 0.0);
    }

    #[test]
    fn test_backend_state_healthy_transition() {
        let backend = ResolvedBackend {
            addr: "127.0.0.1:8080".parse().unwrap(),
            weight: 100,
        };
        let state = BackendState::new(&backend);

        assert!(state.healthy.load(Ordering::Relaxed));

        // Mark unhealthy after threshold failures
        state.mark_unhealthy(3);
        assert!(state.healthy.load(Ordering::Relaxed)); // Still healthy (1 failure)
        state.mark_unhealthy(3);
        assert!(state.healthy.load(Ordering::Relaxed)); // Still healthy (2 failures)
        state.mark_unhealthy(3);
        assert!(!state.healthy.load(Ordering::Relaxed)); // Now unhealthy (3 failures)

        // Mark healthy after threshold successes
        state.mark_healthy(3);
        assert!(!state.healthy.load(Ordering::Relaxed)); // Still unhealthy (1 success)
        state.mark_healthy(3);
        assert!(!state.healthy.load(Ordering::Relaxed)); // Still unhealthy (2 successes)
        state.mark_healthy(3);
        assert!(state.healthy.load(Ordering::Relaxed)); // Now healthy (3 successes)
    }

    #[test]
    fn test_backend_state_weight_adjustment() {
        let backend = ResolvedBackend {
            addr: "127.0.0.1:8080".parse().unwrap(),
            weight: 100,
        };
        let state = BackendState::new(&backend);

        assert_eq!(state.effective_weight.load(Ordering::Relaxed), 100);

        // When marked unhealthy, weight should be 0
        state.mark_unhealthy(1);
        assert_eq!(state.effective_weight.load(Ordering::Relaxed), 0);

        // When marked healthy again, weight should be restored
        state.mark_healthy(1);
        assert_eq!(state.effective_weight.load(Ordering::Relaxed), 100);
    }
}
