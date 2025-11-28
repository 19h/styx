//! Configuration module for styx reverse proxy
//!
//! This module handles parsing and representing h2o-compatible configuration.

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Root configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// User to run as (informational, not enforced by styx)
    #[serde(default)]
    pub user: Option<String>,

    /// Access log path
    #[serde(default = "default_access_log")]
    pub access_log: PathBuf,

    /// Error log path
    #[serde(default = "default_error_log")]
    pub error_log: PathBuf,

    /// PID file path
    #[serde(default)]
    pub pid_file: Option<PathBuf>,

    /// Number of worker threads
    #[serde(default = "default_num_threads")]
    pub num_threads: usize,

    /// Global file.send-gzip setting
    #[serde(default, rename = "file.send-gzip")]
    pub file_send_gzip: OnOff,

    /// Global compress setting
    #[serde(default)]
    pub compress: OnOff,

    /// Request body size limit in bytes
    #[serde(default = "default_limit_request_body")]
    pub limit_request_body: u64,

    /// HTTP/2 CASPER (cache-aware server push)
    #[serde(default)]
    pub http2_casper: OnOff,

    /// HTTP/2 idle timeout in seconds
    #[serde(default = "default_http2_idle_timeout")]
    pub http2_idle_timeout: u64,

    /// Global proxy.preserve-host setting
    #[serde(default, rename = "proxy.preserve-host")]
    pub proxy_preserve_host: OnOff,

    /// Proxy I/O timeout in milliseconds
    #[serde(default = "default_proxy_timeout_io", rename = "proxy.timeout.io")]
    pub proxy_timeout_io: u64,

    /// Proxy keepalive timeout in milliseconds
    #[serde(default = "default_proxy_timeout_keepalive", rename = "proxy.timeout.keepalive")]
    pub proxy_timeout_keepalive: u64,

    /// Duration stats
    #[serde(default)]
    pub duration_stats: OnOff,

    /// SSL session resumption settings
    #[serde(default)]
    pub ssl_session_resumption: Option<SslSessionResumption>,

    /// Global headers to set if empty
    #[serde(default, rename = "header.setifempty")]
    pub header_setifempty: HeaderValue,

    /// Global headers to unset
    #[serde(default, rename = "header.unset")]
    pub header_unset: HeaderValue,

    /// Global headers to merge
    #[serde(default, rename = "header.merge")]
    pub header_merge: HeaderValue,

    /// Global headers to set
    #[serde(default, rename = "header.set")]
    pub header_set: HeaderValue,

    /// Listen directives (with YAML anchors support)
    #[serde(default)]
    pub listen: Option<serde_yaml::Value>,

    /// Host configurations
    #[serde(default)]
    pub hosts: IndexMap<String, HostConfig>,
}

fn default_access_log() -> PathBuf {
    PathBuf::from("/dev/null")
}

fn default_error_log() -> PathBuf {
    PathBuf::from("/dev/stderr")
}

fn default_num_threads() -> usize {
    num_cpus::get()
}

fn default_limit_request_body() -> u64 {
    10 * 1024 * 1024 // Reduced from 20GB to 10MB for security
}

fn default_http2_idle_timeout() -> u64 {
    180
}

fn default_proxy_timeout_io() -> u64 {
    30000 // Reduced from 59s to 30s for security
}

fn default_proxy_timeout_keepalive() -> u64 {
    30000 // Reduced from 59s to 30s for security
}

/// ON/OFF toggle
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnOff {
    On,
    #[default]
    Off,
}

impl<'de> Deserialize<'de> for OnOff {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.to_uppercase().as_str() {
            "ON" | "TRUE" | "YES" | "1" => Ok(OnOff::On),
            "OFF" | "FALSE" | "NO" | "0" => Ok(OnOff::Off),
            _ => Err(serde::de::Error::custom(format!("invalid on/off value: {}", s))),
        }
    }
}

impl Serialize for OnOff {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OnOff::On => serializer.serialize_str("ON"),
            OnOff::Off => serializer.serialize_str("OFF"),
        }
    }
}

impl OnOff {
    pub fn is_on(&self) -> bool {
        matches!(self, OnOff::On)
    }
}

/// Header value that can be a single string or list of strings
#[derive(Debug, Clone, Default)]
pub struct HeaderValue(pub Vec<String>);

impl<'de> Deserialize<'de> for HeaderValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrVec {
            String(String),
            Vec(Vec<String>),
        }

        match Option::<StringOrVec>::deserialize(deserializer)? {
            Some(StringOrVec::String(s)) => Ok(HeaderValue(vec![s])),
            Some(StringOrVec::Vec(v)) => Ok(HeaderValue(v)),
            None => Ok(HeaderValue(vec![])),
        }
    }
}

impl Serialize for HeaderValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() == 1 {
            self.0[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

/// SSL session resumption configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SslSessionResumption {
    #[serde(default = "default_ssl_mode")]
    pub mode: String,
}

fn default_ssl_mode() -> String {
    "all".to_string()
}

/// Listen configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    #[serde(default = "default_host")]
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub ssl: Option<SslConfig>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

impl ListenConfig {
    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], self.port)))
    }
}

/// SSL/TLS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SslConfig {
    #[serde(default = "default_min_tls_version")]
    pub minimum_version: String,

    #[serde(default = "default_cipher_preference")]
    pub cipher_preference: String,

    #[serde(default)]
    pub cipher_suite: Option<String>,

    #[serde(default)]
    pub dh_file: Option<PathBuf>,

    pub certificate_file: PathBuf,

    pub key_file: PathBuf,

    #[serde(default)]
    pub ocsp_update_interval: u64,
}

fn default_min_tls_version() -> String {
    "TLSv1.2".to_string()
}

fn default_cipher_preference() -> String {
    "server".to_string()
}

/// Host configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostConfig {
    /// Listen configuration (can be a reference via YAML anchor)
    #[serde(default)]
    pub listen: Option<serde_yaml::Value>,

    /// Path configurations
    #[serde(default)]
    pub paths: IndexMap<String, PathConfig>,

    /// Host-level headers
    #[serde(default, rename = "header.set")]
    pub header_set: HeaderValue,

    #[serde(default, rename = "header.setifempty")]
    pub header_setifempty: HeaderValue,

    #[serde(default, rename = "header.unset")]
    pub header_unset: HeaderValue,

    #[serde(default, rename = "header.merge")]
    pub header_merge: HeaderValue,
}

/// Path configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PathConfig {
    /// Redirect URL
    #[serde(default)]
    pub redirect: Option<String>,

    /// Status endpoint
    #[serde(default)]
    pub status: OnOff,

    /// Expiration setting
    #[serde(default)]
    pub expires: Option<String>,

    /// Static file directory
    #[serde(default, rename = "file.dir")]
    pub file_dir: Option<PathBuf>,

    /// Index files for directory listing
    #[serde(default, rename = "file.index")]
    pub file_index: Option<Vec<String>>,

    /// Enable directory listing when no index file found
    #[serde(default, rename = "file.dirlisting")]
    pub file_dirlisting: OnOff,

    /// Reverse proxy URL
    #[serde(default, rename = "proxy.reverse.url")]
    pub proxy_reverse_url: Option<String>,

    /// Override preserve-host for this path
    #[serde(default, rename = "proxy.preserve-host")]
    pub proxy_preserve_host: Option<OnOff>,

    /// Headers to set on response
    #[serde(default, rename = "header.set")]
    pub header_set: HeaderValue,

    /// Headers to set if empty
    #[serde(default, rename = "header.setifempty")]
    pub header_setifempty: HeaderValue,

    /// Headers to unset
    #[serde(default, rename = "header.unset")]
    pub header_unset: HeaderValue,

    /// Headers to merge
    #[serde(default, rename = "header.merge")]
    pub header_merge: HeaderValue,

    /// Headers to add to proxy request
    #[serde(default, rename = "proxy.header.add")]
    pub proxy_header_add: HeaderValue,

    /// Headers to set on proxy request
    #[serde(default, rename = "proxy.header.set")]
    pub proxy_header_set: HeaderValue,
}

/// Parsed and resolved configuration ready for use
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub num_threads: usize,
    pub access_log: PathBuf,
    pub error_log: PathBuf,
    pub pid_file: Option<PathBuf>,
    pub limit_request_body: u64,
    pub http2_idle_timeout: Duration,
    pub proxy_timeout_io: Duration,
    pub proxy_timeout_keepalive: Duration,
    pub file_send_gzip: bool,
    pub global_headers: HeaderRules,
    pub listeners: Vec<ResolvedListener>,
    pub hosts: HashMap<String, Arc<ResolvedHost>>,
}

/// Resolved listener configuration
#[derive(Debug, Clone)]
pub struct ResolvedListener {
    pub addr: SocketAddr,
    pub tls_config: Option<Arc<TlsListenerConfig>>,
}

/// TLS configuration for a listener
#[derive(Debug)]
pub struct TlsListenerConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub min_version: rustls::ProtocolVersion,
}

/// Resolved host configuration
#[derive(Debug, Clone)]
pub struct ResolvedHost {
    pub name: String,
    pub routes: Vec<ResolvedRoute>,
    pub headers: HeaderRules,
}

/// Resolved route configuration
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    pub path: String,
    pub action: RouteAction,
    pub headers: HeaderRules,
    pub proxy_headers: HeaderRules,
    /// Parsed expires value (None = not set, Some(None) = "off", Some(Some(secs)) = max-age)
    pub expires: Option<Option<u64>>,
}

/// Route action
#[derive(Debug, Clone)]
pub enum RouteAction {
    Redirect {
        url: String,
        status: u16,
    },
    Status,
    StaticFiles {
        dir: PathBuf,
        index: Vec<String>,
        send_gzip: bool,
        dirlisting: bool,
    },
    Proxy {
        upstream: String,
        preserve_host: bool,
    },
}

/// Header manipulation rules
#[derive(Debug, Clone, Default)]
pub struct HeaderRules {
    pub set: Vec<(String, String)>,
    pub set_if_empty: Vec<(String, String)>,
    pub merge: Vec<(String, String)>,
    pub unset: Vec<String>,
}

impl HeaderRules {
    pub fn from_config(
        set: &HeaderValue,
        set_if_empty: &HeaderValue,
        merge: &HeaderValue,
        unset: &HeaderValue,
    ) -> Self {
        Self {
            set: parse_headers(&set.0),
            set_if_empty: parse_headers(&set_if_empty.0),
            merge: parse_headers(&merge.0),
            unset: unset.0.clone(),
        }
    }

    pub fn merge_with(&self, other: &HeaderRules) -> HeaderRules {
        let mut result = self.clone();
        result.set.extend(other.set.iter().cloned());
        result.set_if_empty.extend(other.set_if_empty.iter().cloned());
        result.merge.extend(other.merge.iter().cloned());
        result.unset.extend(other.unset.iter().cloned());
        result
    }
}

fn parse_headers(headers: &[String]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|h| {
            let parts: Vec<&str> = h.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
            } else {
                None
            }
        })
        .collect()
}

/// Parse h2o-style expires directive
/// Returns: None = not set, Some(None) = "off", Some(Some(secs)) = max-age in seconds
fn parse_expires(value: &Option<String>) -> Option<Option<u64>> {
    let value = value.as_ref()?;
    let value = value.trim().to_lowercase();

    if value == "off" {
        return Some(None);
    }

    // Parse duration: "N unit" where unit is seconds, minutes, hours, days, weeks, months, years
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 2 {
        // Try parsing as just a number (seconds)
        if let Ok(secs) = value.parse::<u64>() {
            return Some(Some(secs));
        }
        return None;
    }

    let amount: u64 = match parts[0].parse() {
        Ok(n) => n,
        Err(_) => return None,
    };

    let unit = parts[1].trim_end_matches('s'); // handle plural
    let multiplier: u64 = match unit {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        "day" => 86400,
        "week" => 604800,
        "month" => 2592000,  // 30 days
        "year" => 31536000,  // 365 days
        _ => return None,
    };

    Some(Some(amount * multiplier))
}

impl Config {
    /// Load configuration from a file
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Resolve configuration into runtime format
    pub fn resolve(&self) -> anyhow::Result<ResolvedConfig> {
        let global_headers = HeaderRules::from_config(
            &self.header_set,
            &self.header_setifempty,
            &self.header_merge,
            &self.header_unset,
        );

        let mut hosts = HashMap::new();
        let mut listeners = Vec::new();
        let mut seen_addrs = std::collections::HashSet::new();

        for (host_name, host_config) in &self.hosts {
            // Parse host:port from name
            let (hostname, _port) = parse_host_port(host_name)?;

            // Resolve listen config
            if let Some(listen_value) = &host_config.listen {
                if let Ok(listen_config) = serde_yaml::from_value::<ListenConfig>(listen_value.clone()) {
                    let addr = listen_config.socket_addr();
                    if !seen_addrs.contains(&addr) {
                        seen_addrs.insert(addr);
                        let tls_config = if let Some(ssl) = &listen_config.ssl {
                            Some(Arc::new(TlsListenerConfig {
                                cert_path: ssl.certificate_file.clone(),
                                key_path: ssl.key_file.clone(),
                                min_version: parse_tls_version(&ssl.minimum_version),
                            }))
                        } else {
                            None
                        };
                        listeners.push(ResolvedListener { addr, tls_config });
                    }
                }
            }

            // Resolve routes
            let mut routes = Vec::new();
            let host_headers = HeaderRules::from_config(
                &host_config.header_set,
                &host_config.header_setifempty,
                &host_config.header_merge,
                &host_config.header_unset,
            );

            // Sort paths by length descending for longest-prefix matching
            let mut paths: Vec<_> = host_config.paths.iter().collect();
            paths.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

            for (path, path_config) in paths {
                let action = if let Some(redirect) = &path_config.redirect {
                    RouteAction::Redirect {
                        url: redirect.clone(),
                        status: 301,
                    }
                } else if path_config.status.is_on() {
                    RouteAction::Status
                } else if let Some(dir) = &path_config.file_dir {
                    RouteAction::StaticFiles {
                        dir: dir.clone(),
                        index: path_config.file_index.clone().unwrap_or_else(|| vec!["index.html".to_string()]),
                        send_gzip: self.file_send_gzip.is_on(),
                        dirlisting: path_config.file_dirlisting.is_on(),
                    }
                } else if let Some(upstream) = &path_config.proxy_reverse_url {
                    let preserve_host = path_config
                        .proxy_preserve_host
                        .map(|v| v.is_on())
                        .unwrap_or(self.proxy_preserve_host.is_on());
                    RouteAction::Proxy {
                        upstream: upstream.clone(),
                        preserve_host,
                    }
                } else {
                    continue;
                };

                let path_headers = HeaderRules::from_config(
                    &path_config.header_set,
                    &path_config.header_setifempty,
                    &path_config.header_merge,
                    &path_config.header_unset,
                );

                let proxy_headers = HeaderRules::from_config(
                    &path_config.proxy_header_set,
                    &Default::default(),
                    &Default::default(),
                    &Default::default(),
                );
                // Add proxy.header.add as well
                let mut proxy_headers = proxy_headers;
                for h in &path_config.proxy_header_add.0 {
                    if let Some((k, v)) = h.split_once(':') {
                        proxy_headers.set.push((k.trim().to_string(), v.trim().to_string()));
                    }
                }

                routes.push(ResolvedRoute {
                    path: path.clone(),
                    action,
                    headers: path_headers,
                    proxy_headers,
                    expires: parse_expires(&path_config.expires),
                });
            }

            let resolved_host = Arc::new(ResolvedHost {
                name: hostname.clone(),
                routes,
                headers: host_headers,
            });

            hosts.insert(host_name.clone(), resolved_host);
        }

        // Ensure we have at least the default listeners
        if listeners.is_empty() {
            listeners.push(ResolvedListener {
                addr: SocketAddr::from(([0, 0, 0, 0], 80)),
                tls_config: None,
            });
        }

        Ok(ResolvedConfig {
            num_threads: self.num_threads,
            access_log: self.access_log.clone(),
            error_log: self.error_log.clone(),
            pid_file: self.pid_file.clone(),
            limit_request_body: self.limit_request_body,
            http2_idle_timeout: Duration::from_secs(self.http2_idle_timeout),
            proxy_timeout_io: Duration::from_millis(self.proxy_timeout_io),
            proxy_timeout_keepalive: Duration::from_millis(self.proxy_timeout_keepalive),
            file_send_gzip: self.file_send_gzip.is_on(),
            global_headers,
            listeners,
            hosts,
        })
    }
}

fn parse_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port = s[idx + 1..].parse::<u16>()?;
        Ok((host.to_string(), port))
    } else {
        Ok((s.to_string(), 80))
    }
}

fn parse_tls_version(s: &str) -> rustls::ProtocolVersion {
    match s.to_uppercase().as_str() {
        "TLSV1" | "TLSV1.0" => {
            // TLS 1.0 is deprecated and insecure, force upgrade to 1.2
            warn!("TLS 1.0 is deprecated and insecure - forcing upgrade to TLS 1.2 minimum");
            rustls::ProtocolVersion::TLSv1_2
        }
        "TLSV1.1" => {
            // TLS 1.1 is deprecated and insecure, force upgrade to 1.2
            warn!("TLS 1.1 is deprecated and insecure - forcing upgrade to TLS 1.2 minimum");
            rustls::ProtocolVersion::TLSv1_2
        }
        "TLSV1.2" => rustls::ProtocolVersion::TLSv1_2,
        "TLSV1.3" => rustls::ProtocolVersion::TLSv1_3,
        _ => {
            warn!("Unknown TLS version '{}' - defaulting to TLS 1.2", s);
            rustls::ProtocolVersion::TLSv1_2
        }
    }
}

// Add num_cpus helper
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // OnOff parsing tests
    // =====================================================================

    #[test]
    fn test_on_off_parsing_on_variants() {
        let test_cases = ["ON", "on", "On", "TRUE", "true", "True", "YES", "yes", "Yes", "1"];
        for case in test_cases {
            let yaml = format!("\"{}\"", case);
            let result: OnOff = serde_yaml::from_str(&yaml).unwrap();
            assert!(result.is_on(), "Expected '{}' to parse as ON", case);
        }
    }

    #[test]
    fn test_on_off_parsing_off_variants() {
        let test_cases = ["OFF", "off", "Off", "FALSE", "false", "False", "NO", "no", "No", "0"];
        for case in test_cases {
            let yaml = format!("\"{}\"", case);
            let result: OnOff = serde_yaml::from_str(&yaml).unwrap();
            assert!(!result.is_on(), "Expected '{}' to parse as OFF", case);
        }
    }

    #[test]
    fn test_on_off_parsing_invalid() {
        let invalid_cases = ["maybe", "enabled", "disabled", "2", "-1", ""];
        for case in invalid_cases {
            let yaml = format!("\"{}\"", case);
            let result: Result<OnOff, _> = serde_yaml::from_str(&yaml);
            assert!(result.is_err(), "Expected '{}' to fail parsing", case);
        }
    }

    #[test]
    fn test_on_off_default() {
        let default = OnOff::default();
        assert!(!default.is_on());
        assert_eq!(default, OnOff::Off);
    }

    #[test]
    fn test_on_off_serialize() {
        let on_yaml = serde_yaml::to_string(&OnOff::On).unwrap();
        assert!(on_yaml.contains("ON"));

        let off_yaml = serde_yaml::to_string(&OnOff::Off).unwrap();
        assert!(off_yaml.contains("OFF"));
    }

    // =====================================================================
    // HeaderValue parsing tests
    // =====================================================================

    #[test]
    fn test_header_value_parsing_single() {
        let single: HeaderValue = serde_yaml::from_str("\"X-Test: value\"").unwrap();
        assert_eq!(single.0.len(), 1);
        assert_eq!(single.0[0], "X-Test: value");
    }

    #[test]
    fn test_header_value_parsing_multiple() {
        let multi: HeaderValue = serde_yaml::from_str("[\"X-Test: value1\", \"X-Test2: value2\"]").unwrap();
        assert_eq!(multi.0.len(), 2);
        assert_eq!(multi.0[0], "X-Test: value1");
        assert_eq!(multi.0[1], "X-Test2: value2");
    }

    #[test]
    fn test_header_value_parsing_empty_list() {
        let empty: HeaderValue = serde_yaml::from_str("[]").unwrap();
        assert!(empty.0.is_empty());
    }

    #[test]
    fn test_header_value_parsing_null() {
        let null: HeaderValue = serde_yaml::from_str("~").unwrap();
        assert!(null.0.is_empty());
    }

    #[test]
    fn test_header_value_default() {
        let default = HeaderValue::default();
        assert!(default.0.is_empty());
    }

    #[test]
    fn test_header_value_serialize_single() {
        let single = HeaderValue(vec!["X-Test: value".to_string()]);
        let yaml = serde_yaml::to_string(&single).unwrap();
        // Should contain the header value
        assert!(yaml.contains("X-Test"));
        assert!(yaml.contains("value"));
    }

    #[test]
    fn test_header_value_serialize_multiple() {
        let multi = HeaderValue(vec!["X-Test: a".to_string(), "X-Other: b".to_string()]);
        let yaml = serde_yaml::to_string(&multi).unwrap();
        assert!(yaml.contains("X-Test: a"));
        assert!(yaml.contains("X-Other: b"));
    }

    // =====================================================================
    // parse_host_port tests
    // =====================================================================

    #[test]
    fn test_parse_host_port_standard() {
        let (host, port) = parse_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_http() {
        let (host, port) = parse_host_port("example.com:80").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_no_port_defaults_to_80() {
        let (host, port) = parse_host_port("example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_ip_address() {
        let (host, port) = parse_host_port("192.168.1.1:8080").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        // IPv6 addresses can have colons, so rfind is important
        let (host, port) = parse_host_port("[::1]:443").unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_subdomain() {
        let (host, port) = parse_host_port("api.sub.example.com:3000").unwrap();
        assert_eq!(host, "api.sub.example.com");
        assert_eq!(port, 3000);
    }

    #[test]
    fn test_parse_host_port_onion() {
        let (host, port) = parse_host_port("abc123xyz.onion:80").unwrap();
        assert_eq!(host, "abc123xyz.onion");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        let result = parse_host_port("example.com:notaport");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host_port_port_too_large() {
        let result = parse_host_port("example.com:99999");
        assert!(result.is_err());
    }

    // =====================================================================
    // parse_tls_version tests
    // =====================================================================

    #[test]
    fn test_parse_tls_version_v1() {
        // TLS 1.0 is deprecated, forced upgrade to 1.2
        let version = parse_tls_version("TLSv1");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_parse_tls_version_v10() {
        // TLS 1.0 is deprecated, forced upgrade to 1.2
        let version = parse_tls_version("TLSv1.0");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_parse_tls_version_v11() {
        // TLS 1.1 is deprecated, forced upgrade to 1.2
        let version = parse_tls_version("TLSv1.1");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_parse_tls_version_v12() {
        let version = parse_tls_version("TLSv1.2");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_parse_tls_version_v13() {
        let version = parse_tls_version("TLSv1.3");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_3);
    }

    #[test]
    fn test_parse_tls_version_lowercase() {
        let version = parse_tls_version("tlsv1.2");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_parse_tls_version_unknown_defaults_to_12() {
        let version = parse_tls_version("SSLv3");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);

        let version = parse_tls_version("invalid");
        assert_eq!(version, rustls::ProtocolVersion::TLSv1_2);
    }

    // =====================================================================
    // HeaderRules tests
    // =====================================================================

    #[test]
    fn test_header_rules_from_config() {
        let set = HeaderValue(vec!["X-Set: setval".to_string()]);
        let set_if_empty = HeaderValue(vec!["X-IfEmpty: ifemptyval".to_string()]);
        let merge = HeaderValue(vec!["Cache-Control: max-age=3600".to_string()]);
        let unset = HeaderValue(vec!["X-Powered-By".to_string()]);

        let rules = HeaderRules::from_config(&set, &set_if_empty, &merge, &unset);

        assert_eq!(rules.set.len(), 1);
        assert_eq!(rules.set[0], ("X-Set".to_string(), "setval".to_string()));

        assert_eq!(rules.set_if_empty.len(), 1);
        assert_eq!(rules.set_if_empty[0], ("X-IfEmpty".to_string(), "ifemptyval".to_string()));

        assert_eq!(rules.merge.len(), 1);
        assert_eq!(rules.merge[0], ("Cache-Control".to_string(), "max-age=3600".to_string()));

        assert_eq!(rules.unset.len(), 1);
        assert_eq!(rules.unset[0], "X-Powered-By");
    }

    #[test]
    fn test_header_rules_merge_with() {
        let rules1 = HeaderRules {
            set: vec![("X-A".to_string(), "a".to_string())],
            set_if_empty: vec![("X-B".to_string(), "b".to_string())],
            merge: vec![],
            unset: vec!["X-Remove".to_string()],
        };

        let rules2 = HeaderRules {
            set: vec![("X-C".to_string(), "c".to_string())],
            set_if_empty: vec![],
            merge: vec![("Cache-Control".to_string(), "public".to_string())],
            unset: vec!["X-Other".to_string()],
        };

        let merged = rules1.merge_with(&rules2);

        assert_eq!(merged.set.len(), 2);
        assert_eq!(merged.set_if_empty.len(), 1);
        assert_eq!(merged.merge.len(), 1);
        assert_eq!(merged.unset.len(), 2);
    }

    #[test]
    fn test_header_rules_default() {
        let rules = HeaderRules::default();
        assert!(rules.set.is_empty());
        assert!(rules.set_if_empty.is_empty());
        assert!(rules.merge.is_empty());
        assert!(rules.unset.is_empty());
    }

    // =====================================================================
    // parse_headers tests
    // =====================================================================

    #[test]
    fn test_parse_headers_basic() {
        let headers = vec!["X-Test: value".to_string()];
        let parsed = parse_headers(&headers);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ("X-Test".to_string(), "value".to_string()));
    }

    #[test]
    fn test_parse_headers_with_whitespace() {
        let headers = vec!["  X-Test  :   value with spaces  ".to_string()];
        let parsed = parse_headers(&headers);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ("X-Test".to_string(), "value with spaces".to_string()));
    }

    #[test]
    fn test_parse_headers_value_with_colons() {
        // Value can contain colons (like in URLs)
        let headers = vec!["X-URL: http://example.com:8080/path".to_string()];
        let parsed = parse_headers(&headers);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ("X-URL".to_string(), "http://example.com:8080/path".to_string()));
    }

    #[test]
    fn test_parse_headers_invalid_format_skipped() {
        let headers = vec![
            "X-Valid: value".to_string(),
            "InvalidNoColon".to_string(),
            "X-Also-Valid: another".to_string(),
        ];
        let parsed = parse_headers(&headers);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "X-Valid");
        assert_eq!(parsed[1].0, "X-Also-Valid");
    }

    #[test]
    fn test_parse_headers_empty() {
        let headers: Vec<String> = vec![];
        let parsed = parse_headers(&headers);
        assert!(parsed.is_empty());
    }

    // =====================================================================
    // ListenConfig tests
    // =====================================================================

    #[test]
    fn test_listen_config_socket_addr() {
        let config = ListenConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            ssl: None,
        };
        let addr = config.socket_addr();
        assert_eq!(addr.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_listen_config_socket_addr_all_interfaces() {
        let config = ListenConfig {
            host: "0.0.0.0".to_string(),
            port: 443,
            ssl: None,
        };
        let addr = config.socket_addr();
        assert_eq!(addr.to_string(), "0.0.0.0:443");
    }

    #[test]
    fn test_listen_config_default_host() {
        assert_eq!(default_host(), "0.0.0.0");
    }

    // =====================================================================
    // Config loading and parsing tests
    // =====================================================================

    #[test]
    fn test_minimal_config_parse() {
        let yaml = r#"
hosts:
  "example.com:80":
    paths:
      "/":
        redirect: "https://example.com/"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.hosts.len(), 1);
        assert!(config.hosts.contains_key("example.com:80"));
    }

    #[test]
    fn test_config_defaults() {
        let yaml = r#"
hosts: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.access_log, PathBuf::from("/dev/null"));
        assert_eq!(config.error_log, PathBuf::from("/dev/stderr"));
        // Reduced default from 20GB to 10MB for security
        assert_eq!(config.limit_request_body, 10 * 1024 * 1024);
        assert_eq!(config.http2_idle_timeout, 180);
        // Reduced proxy timeouts for security
        assert_eq!(config.proxy_timeout_io, 30000);
        assert_eq!(config.proxy_timeout_keepalive, 30000);
        assert!(!config.file_send_gzip.is_on());
        assert!(!config.compress.is_on());
    }

    #[test]
    fn test_config_with_global_headers() {
        let yaml = r#"
header.set: "X-Custom: value"
header.setifempty:
  - "X-XSS-Protection: 1"
  - "X-Frame-Options: DENY"
header.unset: "X-Powered-By"
header.merge: "Cache-Control: public"
hosts: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.header_set.0.len(), 1);
        assert_eq!(config.header_setifempty.0.len(), 2);
        assert_eq!(config.header_unset.0.len(), 1);
        assert_eq!(config.header_merge.0.len(), 1);
    }

    #[test]
    fn test_config_with_proxy_settings() {
        let yaml = r#"
proxy.preserve-host: ON
proxy.timeout.io: 30000
proxy.timeout.keepalive: 60000
hosts: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert!(config.proxy_preserve_host.is_on());
        assert_eq!(config.proxy_timeout_io, 30000);
        assert_eq!(config.proxy_timeout_keepalive, 60000);
    }

    #[test]
    fn test_host_config_with_paths() {
        let yaml = r#"
hosts:
  "example.com:443":
    listen:
      host: 0.0.0.0
      port: 443
      ssl:
        certificate-file: /tls/cert.pem
        key-file: /tls/key.pem
    paths:
      "/api":
        proxy.reverse.url: "http://api:3000"
        proxy.preserve-host: ON
      "/static":
        file.dir: /var/www/static
        file.index:
          - index.html
          - index.htm
      "/health":
        status: ON
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        let host = config.hosts.get("example.com:443").unwrap();
        assert_eq!(host.paths.len(), 3);

        let api_path = host.paths.get("/api").unwrap();
        assert_eq!(api_path.proxy_reverse_url, Some("http://api:3000".to_string()));
        assert!(api_path.proxy_preserve_host.unwrap().is_on());

        let static_path = host.paths.get("/static").unwrap();
        assert_eq!(static_path.file_dir, Some(PathBuf::from("/var/www/static")));
        assert_eq!(static_path.file_index.as_ref().unwrap().len(), 2);

        let health_path = host.paths.get("/health").unwrap();
        assert!(health_path.status.is_on());
    }

    #[test]
    fn test_path_config_redirect() {
        let yaml = r#"
hosts:
  "example.com:80":
    paths:
      "/":
        redirect: "https://example.com/"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let host = config.hosts.get("example.com:80").unwrap();
        let path = host.paths.get("/").unwrap();

        assert_eq!(path.redirect, Some("https://example.com/".to_string()));
    }

    #[test]
    fn test_path_config_headers() {
        let yaml = r#"
hosts:
  "example.com:443":
    paths:
      "/api":
        proxy.reverse.url: "http://api:3000"
        header.set: "X-API: true"
        header.merge: "Cache-Control: no-cache"
        proxy.header.set: "X-Forwarded-Proto: https"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let host = config.hosts.get("example.com:443").unwrap();
        let path = host.paths.get("/api").unwrap();

        assert_eq!(path.header_set.0.len(), 1);
        assert_eq!(path.header_merge.0.len(), 1);
        assert_eq!(path.proxy_header_set.0.len(), 1);
    }

    // =====================================================================
    // Config resolve tests
    // =====================================================================

    #[test]
    fn test_resolve_minimal_config() {
        let yaml = r#"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/":
        redirect: "https://example.com/"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        assert_eq!(resolved.hosts.len(), 1);
        assert!(resolved.hosts.contains_key("example.com:80"));

        let host = resolved.hosts.get("example.com:80").unwrap();
        assert_eq!(host.routes.len(), 1);

        match &host.routes[0].action {
            RouteAction::Redirect { url, status } => {
                assert_eq!(url, "https://example.com/");
                assert_eq!(*status, 301);
            }
            _ => panic!("Expected redirect action"),
        }
    }

    #[test]
    fn test_resolve_creates_default_listener() {
        let yaml = r#"
hosts:
  "example.com:80":
    paths:
      "/":
        status: ON
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        // Should create default listener on 0.0.0.0:80
        assert!(!resolved.listeners.is_empty());
    }

    #[test]
    fn test_resolve_proxy_route() {
        let yaml = r#"
proxy.preserve-host: ON
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();
        match &host.routes[0].action {
            RouteAction::Proxy { upstream, preserve_host } => {
                assert_eq!(upstream, "http://backend:3000");
                assert!(*preserve_host);
            }
            _ => panic!("Expected proxy action"),
        }
    }

    #[test]
    fn test_resolve_static_files_route() {
        let yaml = r#"
file.send-gzip: ON
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/static":
        file.dir: /var/www
        file.index:
          - index.html
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();
        match &host.routes[0].action {
            RouteAction::StaticFiles { dir, index, send_gzip, .. } => {
                assert_eq!(dir, &PathBuf::from("/var/www"));
                assert_eq!(index, &vec!["index.html".to_string()]);
                assert!(*send_gzip);
            }
            _ => panic!("Expected static files action"),
        }
    }

    #[test]
    fn test_resolve_status_route() {
        let yaml = r#"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/health":
        status: ON
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();
        match &host.routes[0].action {
            RouteAction::Status => {}
            _ => panic!("Expected status action"),
        }
    }

    #[test]
    fn test_resolve_header_rules_inheritance() {
        let yaml = r#"
header.set: "X-Global: global"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    header.set: "X-Host: host"
    paths:
      "/":
        status: ON
        header.set: "X-Path: path"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        // Global headers should be in global_headers
        assert_eq!(resolved.global_headers.set.len(), 1);
        assert_eq!(resolved.global_headers.set[0].0, "X-Global");

        let host = resolved.hosts.get("example.com:80").unwrap();
        // Host headers
        assert_eq!(host.headers.set.len(), 1);
        assert_eq!(host.headers.set[0].0, "X-Host");

        // Path headers
        assert_eq!(host.routes[0].headers.set.len(), 1);
        assert_eq!(host.routes[0].headers.set[0].0, "X-Path");
    }

    #[test]
    fn test_resolve_proxy_headers() {
        let yaml = r#"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
        proxy.header.set: "X-Backend: true"
        proxy.header.add: "X-Added: value"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();
        let proxy_headers = &host.routes[0].proxy_headers;

        // Both proxy.header.set and proxy.header.add should be in set
        assert_eq!(proxy_headers.set.len(), 2);
    }

    #[test]
    fn test_resolve_multiple_hosts_same_port() {
        let yaml = r#"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/":
        redirect: "https://example.com/"
  "other.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/":
        redirect: "https://other.com/"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        assert_eq!(resolved.hosts.len(), 2);
        // Should only have one listener for port 80 (deduped)
        assert_eq!(resolved.listeners.len(), 1);
    }

    #[test]
    fn test_resolve_tls_listener() {
        let yaml = r#"
hosts:
  "example.com:443":
    listen:
      host: 0.0.0.0
      port: 443
      ssl:
        minimum-version: TLSv1.2
        certificate-file: /tls/cert.pem
        key-file: /tls/key.pem
    paths:
      "/":
        status: ON
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let listener = &resolved.listeners[0];
        assert!(listener.tls_config.is_some());

        let tls = listener.tls_config.as_ref().unwrap();
        assert_eq!(tls.cert_path, PathBuf::from("/tls/cert.pem"));
        assert_eq!(tls.key_path, PathBuf::from("/tls/key.pem"));
        assert_eq!(tls.min_version, rustls::ProtocolVersion::TLSv1_2);
    }

    #[test]
    fn test_resolve_preserve_host_override() {
        let yaml = r#"
proxy.preserve-host: ON
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/api":
        proxy.reverse.url: "http://api:3000"
      "/external":
        proxy.reverse.url: "http://external.com:80"
        proxy.preserve-host: OFF
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();

        // /api should inherit global preserve-host: ON
        // /external should override to OFF
        for route in &host.routes {
            match &route.action {
                RouteAction::Proxy { preserve_host, upstream } => {
                    if upstream.contains("api") {
                        assert!(*preserve_host, "api should preserve host");
                    } else {
                        assert!(!*preserve_host, "external should not preserve host");
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_resolve_durations() {
        let yaml = r#"
proxy.timeout.io: 30000
proxy.timeout.keepalive: 60000
http2-idle-timeout: 120
hosts: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        assert_eq!(resolved.proxy_timeout_io, Duration::from_millis(30000));
        assert_eq!(resolved.proxy_timeout_keepalive, Duration::from_millis(60000));
        assert_eq!(resolved.http2_idle_timeout, Duration::from_secs(120));
    }

    // =====================================================================
    // SslConfig tests
    // =====================================================================

    #[test]
    fn test_ssl_config_defaults() {
        let yaml = r#"
certificate-file: /tls/cert.pem
key-file: /tls/key.pem
"#;
        let ssl: SslConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(ssl.minimum_version, "TLSv1.2");
        assert_eq!(ssl.cipher_preference, "server");
        assert!(ssl.cipher_suite.is_none());
        assert!(ssl.dh_file.is_none());
        assert_eq!(ssl.ocsp_update_interval, 0);
    }

    #[test]
    fn test_ssl_config_full() {
        let yaml = r#"
minimum-version: TLSv1.3
cipher-preference: client
cipher-suite: "TLS_AES_256_GCM_SHA384"
dh-file: /tls/dhparams.pem
certificate-file: /tls/cert.pem
key-file: /tls/key.pem
ocsp-update-interval: 3600
"#;
        let ssl: SslConfig = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(ssl.minimum_version, "TLSv1.3");
        assert_eq!(ssl.cipher_preference, "client");
        assert_eq!(ssl.cipher_suite, Some("TLS_AES_256_GCM_SHA384".to_string()));
        assert_eq!(ssl.dh_file, Some(PathBuf::from("/tls/dhparams.pem")));
        assert_eq!(ssl.ocsp_update_interval, 3600);
    }

    // =====================================================================
    // SslSessionResumption tests
    // =====================================================================

    #[test]
    fn test_ssl_session_resumption_default() {
        let yaml = r#"
mode: ticket
"#;
        let resumption: SslSessionResumption = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(resumption.mode, "ticket");
    }

    #[test]
    fn test_ssl_session_resumption_all() {
        let yaml = r#"
mode: all
"#;
        let resumption: SslSessionResumption = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(resumption.mode, "all");
    }

    // =====================================================================
    // Edge cases and error handling
    // =====================================================================

    #[test]
    fn test_empty_paths_host() {
        let yaml = r#"
hosts:
  "example.com:80":
    paths: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();
        assert!(host.routes.is_empty());
    }

    #[test]
    fn test_path_with_no_action_skipped() {
        let yaml = r#"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/valid":
        status: ON
      "/invalid":
        expires: "1 day"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        let resolved = config.resolve().unwrap();

        let host = resolved.hosts.get("example.com:80").unwrap();
        // Only /valid should be included (has status: ON)
        // /invalid has no action (just expires, which is not an action by itself)
        assert_eq!(host.routes.len(), 1);
        assert_eq!(host.routes[0].path, "/valid");
    }

    #[test]
    fn test_unicode_in_headers() {
        let yaml = r#"
header.set: "X-Custom: héllo wörld"
hosts: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.header_set.0[0], "X-Custom: héllo wörld");
    }

    #[test]
    fn test_large_limit_request_body() {
        let yaml = r#"
limit-request-body: 107374182400
hosts: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.limit_request_body, 107374182400); // 100GB
    }
}
