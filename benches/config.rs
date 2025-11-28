//! Configuration parsing benchmarks
//!
//! Benchmarks for YAML parsing, config resolution, and header rule processing.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

// =============================================================================
// Types (mirroring config module)
// =============================================================================

/// ON/OFF toggle
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum OnOff {
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
            _ => Err(serde::de::Error::custom(format!(
                "invalid on/off value: {}",
                s
            ))),
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

/// Header value that can be a single string or list
#[derive(Debug, Clone, Default)]
struct HeaderValue(Vec<String>);

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

/// Simplified config for benchmarking
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct BenchConfig {
    #[serde(default)]
    user: Option<String>,

    #[serde(default = "default_num_threads")]
    num_threads: usize,

    #[serde(default, rename = "file.send-gzip")]
    file_send_gzip: OnOff,

    #[serde(default)]
    compress: OnOff,

    #[serde(default = "default_limit_request_body")]
    limit_request_body: u64,

    #[serde(default, rename = "proxy.preserve-host")]
    proxy_preserve_host: OnOff,

    #[serde(default = "default_proxy_timeout_io", rename = "proxy.timeout.io")]
    proxy_timeout_io: u64,

    #[serde(default, rename = "header.setifempty")]
    header_setifempty: HeaderValue,

    #[serde(default, rename = "header.unset")]
    header_unset: HeaderValue,

    #[serde(default, rename = "header.set")]
    header_set: HeaderValue,

    #[serde(default)]
    hosts: HashMap<String, HostConfig>,
}

fn default_num_threads() -> usize {
    4
}

fn default_limit_request_body() -> u64 {
    21474836480
}

fn default_proxy_timeout_io() -> u64 {
    59000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HostConfig {
    #[serde(default)]
    paths: HashMap<String, PathConfig>,

    #[serde(default, rename = "header.set")]
    header_set: HeaderValue,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct PathConfig {
    #[serde(default)]
    proxy_reverse_url: Option<String>,

    #[serde(default, rename = "file.dir")]
    file_dir: Option<String>,

    #[serde(default)]
    redirect: Option<String>,

    #[serde(default)]
    status: Option<u16>,

    #[serde(default, rename = "header.set")]
    header_set: HeaderValue,
}

// =============================================================================
// Config YAML samples
// =============================================================================

fn minimal_config() -> &'static str {
    r#"
num-threads: 4
hosts:
  "example.com:80":
    paths:
      "/":
        proxy.reverse.url: "http://backend:80"
"#
}

fn medium_config() -> &'static str {
    r#"
user: www-data
num-threads: 8
file.send-gzip: "ON"
compress: "ON"
limit-request-body: 104857600
proxy.preserve-host: "ON"
proxy.timeout.io: 30000

header.setifempty:
  - "X-Content-Type-Options: nosniff"
  - "X-Frame-Options: DENY"

header.unset:
  - "X-Powered-By"
  - "Server"

hosts:
  "example.com:80":
    header.set: "X-Host: example"
    paths:
      "/":
        proxy.reverse.url: "http://backend:80"
      "/api":
        proxy.reverse.url: "http://api:3000"
      "/static":
        file.dir: "/var/www/static"
  "api.example.com:80":
    paths:
      "/":
        proxy.reverse.url: "http://api:3000"
      "/v1":
        proxy.reverse.url: "http://api-v1:3000"
      "/v2":
        proxy.reverse.url: "http://api-v2:3000"
"#
}

fn large_config() -> &'static str {
    r#"
user: www-data
num-threads: 16
file.send-gzip: "ON"
compress: "ON"
limit-request-body: 21474836480
proxy.preserve-host: "ON"
proxy.timeout.io: 59000

header.setifempty:
  - "X-Xss-Protection: 1; mode=block"
  - "X-Content-Type-Options: nosniff"
  - "Access-Control-Allow-Origin: *"
  - "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept"
  - "Referrer-Policy: origin"

header.unset:
  - "X-Powered-By"
  - "Via"
  - "x-varnish"
  - "Server"
  - "X-AspNet-Version"

header.set:
  - "X-Proxy: styx"

hosts:
  "wiki.example.com:80":
    header.set: "Surrogate-Key: wiki"
    paths:
      "/":
        proxy.reverse.url: "http://varnish:80"
      "/w":
        proxy.reverse.url: "http://varnish:80"
      "/wiki":
        proxy.reverse.url: "http://varnish:80"
      "/api":
        proxy.reverse.url: "http://api:3000"
      "/api/rest_v1":
        proxy.reverse.url: "http://restbase:7231"
      "/static":
        file.dir: "/var/www/static"

  "api.example.com:80":
    paths:
      "/":
        proxy.reverse.url: "http://api-gateway:8080"
      "/v1":
        proxy.reverse.url: "http://api-v1:3000"
      "/v2":
        proxy.reverse.url: "http://api-v2:3000"
      "/graphql":
        proxy.reverse.url: "http://graphql:4000"
      "/health":
        status: 200
      "/metrics":
        proxy.reverse.url: "http://prometheus:9090"

  "www.example.com:80":
    paths:
      "/":
        redirect: "https://example.com/"

  "cdn.example.com:80":
    paths:
      "/":
        file.dir: "/var/www/cdn"
      "/images":
        file.dir: "/var/www/cdn/images"
      "/js":
        file.dir: "/var/www/cdn/js"
      "/css":
        file.dir: "/var/www/cdn/css"

  "admin.example.com:80":
    paths:
      "/":
        proxy.reverse.url: "http://admin:8080"
      "/api":
        proxy.reverse.url: "http://admin-api:3000"
"#
}

fn generate_large_hosts_config(num_hosts: usize, paths_per_host: usize) -> String {
    let mut config = String::from(
        r#"
num-threads: 16
file.send-gzip: "ON"
proxy.preserve-host: "ON"
hosts:
"#,
    );

    for h in 0..num_hosts {
        config.push_str(&format!("  \"host{}.example.com:80\":\n", h));
        config.push_str("    paths:\n");

        for p in 0..paths_per_host {
            config.push_str(&format!("      \"/path{}\":\n", p));
            config.push_str(&format!(
                "        proxy.reverse.url: \"http://backend{}:80\"\n",
                p
            ));
        }
    }

    config
}

// =============================================================================
// Benchmarks
// =============================================================================

fn bench_yaml_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("yaml_parsing");

    group.throughput(Throughput::Elements(1));

    group.bench_function("minimal", |b| {
        let yaml = minimal_config();
        b.iter(|| serde_yaml::from_str::<BenchConfig>(black_box(yaml)))
    });

    group.bench_function("medium", |b| {
        let yaml = medium_config();
        b.iter(|| serde_yaml::from_str::<BenchConfig>(black_box(yaml)))
    });

    group.bench_function("large", |b| {
        let yaml = large_config();
        b.iter(|| serde_yaml::from_str::<BenchConfig>(black_box(yaml)))
    });

    group.finish();
}

fn bench_yaml_parsing_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("yaml_parsing_scaling");
    group.throughput(Throughput::Elements(1));

    for (hosts, paths) in [(1, 5), (5, 5), (10, 10), (20, 10), (50, 20)].iter() {
        let yaml = generate_large_hosts_config(*hosts, *paths);
        let id = format!("{}hosts_{}paths", hosts, paths);

        group.bench_with_input(BenchmarkId::new("config", &id), &yaml, |b, yaml| {
            b.iter(|| serde_yaml::from_str::<BenchConfig>(black_box(yaml)))
        });
    }

    group.finish();
}

fn bench_onoff_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("onoff_parsing");
    group.throughput(Throughput::Elements(1));

    let variants = vec![
        ("on_upper", "ON"),
        ("off_upper", "OFF"),
        ("true", "TRUE"),
        ("false", "FALSE"),
        ("yes", "YES"),
        ("no", "NO"),
        ("one", "1"),
        ("zero", "0"),
    ];

    for (name, value) in variants {
        let yaml = format!("\"{}\"", value);
        group.bench_with_input(BenchmarkId::new("value", name), &yaml, |b, yaml| {
            b.iter(|| serde_yaml::from_str::<OnOff>(black_box(yaml)))
        });
    }

    group.finish();
}

fn bench_header_value_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_value_parsing");
    group.throughput(Throughput::Elements(1));

    // Single value
    group.bench_function("single", |b| {
        let yaml = "\"X-Custom: value\"";
        b.iter(|| serde_yaml::from_str::<HeaderValue>(black_box(yaml)))
    });

    // Array of values
    group.bench_function("array_small", |b| {
        let yaml = r#"
- "X-Header-1: value1"
- "X-Header-2: value2"
- "X-Header-3: value3"
"#;
        b.iter(|| serde_yaml::from_str::<HeaderValue>(black_box(yaml)))
    });

    group.bench_function("array_large", |b| {
        let yaml: String = (0..20)
            .map(|i| format!("- \"X-Header-{}: value{}\"", i, i))
            .collect::<Vec<_>>()
            .join("\n");
        b.iter(|| serde_yaml::from_str::<HeaderValue>(black_box(&yaml)))
    });

    group.finish();
}

fn bench_config_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_serialization");
    group.throughput(Throughput::Elements(1));

    group.bench_function("minimal", |b| {
        let config: BenchConfig = serde_yaml::from_str(minimal_config()).unwrap();
        b.iter(|| serde_yaml::to_string(black_box(&config)))
    });

    group.bench_function("medium", |b| {
        let config: BenchConfig = serde_yaml::from_str(medium_config()).unwrap();
        b.iter(|| serde_yaml::to_string(black_box(&config)))
    });

    group.bench_function("large", |b| {
        let config: BenchConfig = serde_yaml::from_str(large_config()).unwrap();
        b.iter(|| serde_yaml::to_string(black_box(&config)))
    });

    group.finish();
}

fn bench_host_port_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("host_port_parsing");
    group.throughput(Throughput::Elements(1));

    // Manual host:port parsing (as done in config resolution)
    fn parse_host_port(s: &str) -> Option<(&str, u16)> {
        if let Some(idx) = s.rfind(':') {
            let host = &s[..idx];
            let port = s[idx + 1..].parse().ok()?;
            Some((host, port))
        } else {
            Some((s, 80))
        }
    }

    group.bench_function("with_port", |b| {
        b.iter(|| parse_host_port(black_box("example.com:8080")))
    });

    group.bench_function("without_port", |b| {
        b.iter(|| parse_host_port(black_box("example.com")))
    });

    group.bench_function("long_hostname", |b| {
        b.iter(|| parse_host_port(black_box("very-long-hostname.subdomain.example.com:443")))
    });

    group.bench_function("ipv4", |b| {
        b.iter(|| parse_host_port(black_box("192.168.1.100:9000")))
    });

    group.finish();
}

fn bench_header_rule_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_rule_parsing");
    group.throughput(Throughput::Elements(1));

    // Parse header rule string like "X-Custom: value"
    fn parse_header_rule(s: &str) -> Option<(&str, &str)> {
        let idx = s.find(':')?;
        let name = s[..idx].trim();
        let value = s[idx + 1..].trim();
        Some((name, value))
    }

    group.bench_function("simple", |b| {
        b.iter(|| parse_header_rule(black_box("X-Custom: value")))
    });

    group.bench_function("with_spaces", |b| {
        b.iter(|| parse_header_rule(black_box("  X-Custom  :   value with spaces  ")))
    });

    group.bench_function("long_value", |b| {
        let header = format!("Cache-Control: {}", "public, max-age=31536000, immutable");
        b.iter(|| parse_header_rule(black_box(&header)))
    });

    group.bench_function("complex_value", |b| {
        let header = "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Authorization";
        b.iter(|| parse_header_rule(black_box(header)))
    });

    group.finish();
}

fn bench_path_normalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_normalization");
    group.throughput(Throughput::Elements(1));

    // Normalize path for routing
    fn normalize_path(path: &str) -> String {
        let path = if path.is_empty() { "/" } else { path };

        // Remove trailing slash except for root
        if path.len() > 1 && path.ends_with('/') {
            path[..path.len() - 1].to_string()
        } else {
            path.to_string()
        }
    }

    group.bench_function("root", |b| {
        b.iter(|| normalize_path(black_box("/")))
    });

    group.bench_function("simple", |b| {
        b.iter(|| normalize_path(black_box("/api")))
    });

    group.bench_function("with_trailing_slash", |b| {
        b.iter(|| normalize_path(black_box("/api/")))
    });

    group.bench_function("deep_path", |b| {
        b.iter(|| normalize_path(black_box("/api/v1/users/123/profile/")))
    });

    group.bench_function("empty", |b| {
        b.iter(|| normalize_path(black_box("")))
    });

    group.finish();
}

fn bench_config_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_lookup");
    group.throughput(Throughput::Elements(1));

    // Parse and build lookup table
    let config: BenchConfig = serde_yaml::from_str(large_config()).unwrap();

    group.bench_function("host_lookup_existing", |b| {
        b.iter(|| config.hosts.get(black_box("wiki.example.com:80")))
    });

    group.bench_function("host_lookup_missing", |b| {
        b.iter(|| config.hosts.get(black_box("nonexistent.example.com:80")))
    });

    // Nested path lookup
    if let Some(host) = config.hosts.get("wiki.example.com:80") {
        group.bench_function("path_lookup_existing", |b| {
            b.iter(|| host.paths.get(black_box("/api")))
        });

        group.bench_function("path_lookup_missing", |b| {
            b.iter(|| host.paths.get(black_box("/nonexistent")))
        });
    }

    group.finish();
}

fn bench_yaml_value_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("yaml_value_access");
    group.throughput(Throughput::Elements(1));

    // Raw YAML value access (for anchor resolution)
    let yaml: serde_yaml::Value = serde_yaml::from_str(medium_config()).unwrap();

    group.bench_function("mapping_get", |b| {
        b.iter(|| yaml.get(black_box("hosts")))
    });

    group.bench_function("nested_access", |b| {
        b.iter(|| {
            yaml.get("hosts")
                .and_then(|h| h.get("example.com:80"))
                .and_then(|h| h.get("paths"))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_yaml_parsing,
    bench_yaml_parsing_scaling,
    bench_onoff_parsing,
    bench_header_value_parsing,
    bench_config_serialization,
    bench_host_port_parsing,
    bench_header_rule_parsing,
    bench_path_normalization,
    bench_config_lookup,
    bench_yaml_value_access,
);

criterion_main!(benches);
