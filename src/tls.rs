//! TLS termination with SNI-based certificate selection
//!
//! This module provides TLS termination using rustls with support for:
//! - SNI-based certificate selection
//! - Session resumption
//! - Modern cipher suites
//! - TLS 1.2 and 1.3

use dashmap::DashMap;
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::ServerConfig;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::info;

/// TLS configuration manager
pub struct TlsManager {
    /// Certificate resolver
    resolver: Arc<SniResolver>,
    /// Statistics
    stats: TlsStats,
}

/// TLS statistics
#[derive(Default)]
pub struct TlsStats {
    pub handshakes_started: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub handshakes_failed: AtomicU64,
}

/// SNI-based certificate resolver
pub struct SniResolver {
    /// Certified keys indexed by hostname
    certs: DashMap<String, Arc<rustls::sign::CertifiedKey>>,
    /// Default certificate for unknown SNI
    default_cert: RwLock<Option<Arc<rustls::sign::CertifiedKey>>>,
}

impl fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SniResolver")
            .field("cert_count", &self.certs.len())
            .field("has_default", &self.default_cert.read().is_some())
            .finish()
    }
}

impl SniResolver {
    pub fn new() -> Self {
        Self {
            certs: DashMap::new(),
            default_cert: RwLock::new(None),
        }
    }

    /// Add a certificate for a hostname
    pub fn add_cert(&self, hostname: &str, certified_key: Arc<rustls::sign::CertifiedKey>) {
        self.certs.insert(hostname.to_lowercase(), certified_key);
    }

    /// Set the default certificate
    pub fn set_default(&self, certified_key: Arc<rustls::sign::CertifiedKey>) {
        *self.default_cert.write() = Some(certified_key);
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let sni_lower = sni.to_lowercase();

        // Try exact match first
        if let Some(cert) = self.certs.get(&sni_lower) {
            return Some(cert.clone());
        }

        // Try wildcard match
        if let Some(dot_pos) = sni_lower.find('.') {
            let wildcard = format!("*{}", &sni_lower[dot_pos..]);
            if let Some(cert) = self.certs.get(&wildcard) {
                return Some(cert.clone());
            }
        }

        // Fall back to default
        self.default_cert.read().clone()
    }
}

impl TlsManager {
    /// Create a new TLS manager
    pub fn new() -> Self {
        let resolver = Arc::new(SniResolver::new());

        Self {
            resolver,
            stats: TlsStats::default(),
        }
    }

    /// Load a certificate and key for a hostname
    pub fn load_cert<P: AsRef<Path>>(
        &self,
        hostname: &str,
        cert_path: P,
        key_path: P,
    ) -> anyhow::Result<()> {
        let certified_key = load_certified_key(cert_path.as_ref(), key_path.as_ref())?;
        let certified_key = Arc::new(certified_key);

        self.resolver.add_cert(hostname, certified_key.clone());

        // Set as default if this is the first cert
        if self.resolver.default_cert.read().is_none() {
            self.resolver.set_default(certified_key);
        }

        info!("Loaded TLS certificate for {}", hostname);
        Ok(())
    }

    /// Build the server configuration
    pub fn build_server_config(&self) -> anyhow::Result<Arc<ServerConfig>> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.resolver.clone());

        Ok(Arc::new(config))
    }

    /// Record a handshake start
    pub fn record_handshake_start(&self) {
        self.stats.handshakes_started.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful handshake
    pub fn record_handshake_complete(&self) {
        self.stats.handshakes_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed handshake
    pub fn record_handshake_failed(&self) {
        self.stats.handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Load a certificate chain and private key
fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<rustls::sign::CertifiedKey> {
    // Load certificates
    let cert_file = File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to open cert file {:?}: {}", cert_path, e))?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {:?}", cert_path);
    }

    // Load private key
    let key_file = File::open(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to open key file {:?}: {}", key_path, e))?;
    let mut key_reader = BufReader::new(key_file);

    let key = load_private_key(&mut key_reader)?;

    // Create signing key
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {:?}", e))?;

    Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
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

    // =====================================================================
    // TlsManager tests
    // =====================================================================

    #[test]
    fn test_tls_manager_creation() {
        let manager = TlsManager::new();
        assert_eq!(manager.stats.handshakes_started.load(Ordering::Relaxed), 0);
        assert_eq!(manager.stats.handshakes_completed.load(Ordering::Relaxed), 0);
        assert_eq!(manager.stats.handshakes_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tls_manager_stats_recording() {
        let manager = TlsManager::new();

        manager.record_handshake_start();
        manager.record_handshake_start();
        manager.record_handshake_start();

        assert_eq!(manager.stats.handshakes_started.load(Ordering::Relaxed), 3);

        manager.record_handshake_complete();
        manager.record_handshake_complete();

        assert_eq!(manager.stats.handshakes_completed.load(Ordering::Relaxed), 2);

        manager.record_handshake_failed();

        assert_eq!(manager.stats.handshakes_failed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_tls_manager_stats_concurrent() {
        let manager = TlsManager::new();

        // Simulate concurrent updates
        for _ in 0..1000 {
            manager.record_handshake_start();
        }

        assert_eq!(manager.stats.handshakes_started.load(Ordering::Relaxed), 1000);
    }

    // =====================================================================
    // SniResolver tests
    // =====================================================================

    #[test]
    fn test_sni_resolver_creation() {
        let resolver = SniResolver::new();
        assert!(resolver.certs.is_empty());
        assert!(resolver.default_cert.read().is_none());
    }

    #[test]
    fn test_sni_resolver_debug() {
        let resolver = SniResolver::new();
        let debug_str = format!("{:?}", resolver);
        assert!(debug_str.contains("SniResolver"));
        assert!(debug_str.contains("cert_count"));
        assert!(debug_str.contains("has_default"));
    }

    // =====================================================================
    // TlsStats tests
    // =====================================================================

    #[test]
    fn test_tls_stats_default() {
        let stats = TlsStats::default();
        assert_eq!(stats.handshakes_started.load(Ordering::Relaxed), 0);
        assert_eq!(stats.handshakes_completed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.handshakes_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_tls_stats_atomic_operations() {
        let stats = TlsStats::default();

        stats.handshakes_started.fetch_add(10, Ordering::Relaxed);
        stats.handshakes_completed.fetch_add(8, Ordering::Relaxed);
        stats.handshakes_failed.fetch_add(2, Ordering::Relaxed);

        assert_eq!(stats.handshakes_started.load(Ordering::Relaxed), 10);
        assert_eq!(stats.handshakes_completed.load(Ordering::Relaxed), 8);
        assert_eq!(stats.handshakes_failed.load(Ordering::Relaxed), 2);
    }

    // =====================================================================
    // Error handling tests
    // =====================================================================

    #[test]
    fn test_load_cert_nonexistent_file() {
        let manager = TlsManager::new();
        let result = manager.load_cert(
            "test.example.com",
            "/nonexistent/path/cert.pem",
            "/nonexistent/path/key.pem",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_empty_reader() {
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(Vec::<u8>::new()));
        let result = load_private_key(&mut reader);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No private key found"));
    }

    #[test]
    fn test_load_private_key_invalid_pem() {
        let invalid_data = b"not a valid PEM file";
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(invalid_data.to_vec()));
        let result = load_private_key(&mut reader);

        assert!(result.is_err());
    }

    // =====================================================================
    // Integration-style tests
    // =====================================================================

    #[test]
    fn test_manager_workflow() {
        let manager = TlsManager::new();

        // Simulate a series of handshakes
        for i in 0..100 {
            manager.record_handshake_start();

            if i % 10 == 0 {
                manager.record_handshake_failed();
            } else {
                manager.record_handshake_complete();
            }
        }

        assert_eq!(manager.stats.handshakes_started.load(Ordering::Relaxed), 100);
        assert_eq!(manager.stats.handshakes_completed.load(Ordering::Relaxed), 90);
        assert_eq!(manager.stats.handshakes_failed.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn test_manager_build_server_config() {
        // Install the ring crypto provider for this test
        let _ = rustls::crypto::ring::default_provider().install_default();

        let manager = TlsManager::new();

        // Should be able to build config even without certs (will fail on actual use)
        let config = manager.build_server_config();
        assert!(config.is_ok());
    }
}
