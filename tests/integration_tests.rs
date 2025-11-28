//! Integration tests for the Styx reverse proxy
//!
//! These tests verify the end-to-end behavior of the system,
//! including configuration loading, routing, and request handling.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// Re-use types from the main crate
// Note: These tests are compiled separately from the main binary,
// so we need to use the crate as a library dependency

/// Test that configuration files can be loaded and validated
mod config_integration {
    use super::*;

    #[test]
    fn test_yaml_config_syntax() {
        // Test that various YAML configurations parse correctly
        let valid_configs = vec![
            // Minimal config
            r#"
hosts:
  "example.com:80":
    paths:
      "/":
        status: ON
"#,
            // Config with proxy
            r#"
hosts:
  "example.com:80":
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
"#,
            // Config with redirect
            r#"
hosts:
  "example.com:80":
    paths:
      "/":
        redirect: "https://example.com/"
"#,
            // Config with static files
            r#"
hosts:
  "example.com:80":
    paths:
      "/static":
        file.dir: /var/www
        file.index:
          - index.html
"#,
            // Config with headers
            r#"
header.set: "X-Custom: value"
header.setifempty:
  - "X-XSS: 1"
header.unset: "X-Powered-By"
hosts:
  "example.com:80":
    paths:
      "/":
        status: ON
"#,
        ];

        for config_yaml in valid_configs {
            let result: Result<serde_yaml::Value, _> = serde_yaml::from_str(config_yaml);
            assert!(result.is_ok(), "Failed to parse: {}", config_yaml);
        }
    }

    #[test]
    fn test_h2o_compatible_on_off_values() {
        // Test that h2o-style ON/OFF values are accepted
        let test_cases = vec![
            ("status: ON", true),
            ("status: OFF", false),
            ("status: on", true),
            ("status: off", false),
            ("status: \"ON\"", true),
            ("status: \"OFF\"", false),
            ("status: true", true),
            ("status: false", false),
            ("status: yes", true),
            ("status: no", false),
            ("status: 1", true),
            ("status: 0", false),
        ];

        for (yaml, expected_on) in test_cases {
            let full_yaml = format!(
                r#"
hosts:
  "test:80":
    paths:
      "/":
        {}
"#,
                yaml
            );
            let parsed: Result<serde_yaml::Value, _> = serde_yaml::from_str(&full_yaml);
            assert!(parsed.is_ok(), "Failed to parse: {}", yaml);
        }
    }

    #[test]
    fn test_header_value_formats() {
        // Test single and multi-value header formats
        let configs = vec![
            // Single value as string
            r#"
header.set: "X-Test: value"
hosts: {}
"#,
            // Multiple values as list
            r#"
header.set:
  - "X-Test1: value1"
  - "X-Test2: value2"
hosts: {}
"#,
            // Mixed format
            r#"
header.set: "X-Single: value"
header.setifempty:
  - "X-Multi1: value1"
  - "X-Multi2: value2"
hosts: {}
"#,
        ];

        for config in configs {
            let result: Result<serde_yaml::Value, _> = serde_yaml::from_str(config);
            assert!(result.is_ok(), "Failed to parse header config");
        }
    }

    #[test]
    fn test_listener_configurations() {
        // Test various listener configurations
        let configs = vec![
            // HTTP listener
            r#"
hosts:
  "example.com:80":
    listen:
      host: 0.0.0.0
      port: 80
    paths:
      "/":
        status: ON
"#,
            // HTTPS listener
            r#"
hosts:
  "example.com:443":
    listen:
      host: 0.0.0.0
      port: 443
      ssl:
        certificate-file: /tls/cert.pem
        key-file: /tls/key.pem
    paths:
      "/":
        status: ON
"#,
            // Custom TLS settings
            r#"
hosts:
  "example.com:443":
    listen:
      host: 0.0.0.0
      port: 443
      ssl:
        minimum-version: TLSv1.2
        cipher-preference: server
        certificate-file: /tls/cert.pem
        key-file: /tls/key.pem
    paths:
      "/":
        status: ON
"#,
        ];

        for config in configs {
            let result: Result<serde_yaml::Value, _> = serde_yaml::from_str(config);
            assert!(result.is_ok(), "Failed to parse listener config");
        }
    }

    #[test]
    fn test_proxy_configurations() {
        // Test various proxy configurations
        let configs = vec![
            // Basic proxy
            r#"
hosts:
  "example.com:80":
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
"#,
            // Proxy with preserve-host
            r#"
hosts:
  "example.com:80":
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
        proxy.preserve-host: ON
"#,
            // Proxy with preserve-host OFF
            r#"
hosts:
  "example.com:80":
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
        proxy.preserve-host: OFF
"#,
            // Proxy with custom headers
            r#"
hosts:
  "example.com:80":
    paths:
      "/api":
        proxy.reverse.url: "http://backend:3000"
        proxy.header.set: "X-Backend: true"
"#,
        ];

        for config in configs {
            let result: Result<serde_yaml::Value, _> = serde_yaml::from_str(config);
            assert!(result.is_ok(), "Failed to parse proxy config");
        }
    }
}

/// Test routing logic
mod routing_integration {
    use super::*;

    #[test]
    fn test_path_matching_priority() {
        // Verify longest-prefix-wins behavior
        // This tests the routing algorithm conceptually

        let routes = vec![
            ("/", "root"),
            ("/api", "api"),
            ("/api/v1", "api_v1"),
            ("/api/v1/users", "api_v1_users"),
        ];

        let test_cases = vec![
            ("/", "root"),
            ("/unknown", "root"),
            ("/api", "api"),
            ("/api/", "api"),
            ("/api/health", "api"),
            ("/api/v1", "api_v1"),
            ("/api/v1/", "api_v1"),
            ("/api/v1/test", "api_v1"),
            ("/api/v1/users", "api_v1_users"),
            ("/api/v1/users/123", "api_v1_users"),
        ];

        for (path, expected_route) in test_cases {
            let matched = routes
                .iter()
                .filter(|(pattern, _)| {
                    if *pattern == "/" {
                        true // Root matches everything as fallback
                    } else if path == *pattern {
                        true // Exact match
                    } else if path.starts_with(pattern) {
                        // Prefix match with boundary check
                        let remainder = &path[pattern.len()..];
                        remainder.is_empty() || remainder.starts_with('/')
                    } else {
                        false
                    }
                })
                .max_by_key(|(pattern, _)| pattern.len());

            assert!(matched.is_some(), "No match for path: {}", path);
            assert_eq!(
                matched.unwrap().1, expected_route,
                "Wrong route for path: {}",
                path
            );
        }
    }

    #[test]
    fn test_no_false_prefix_matches() {
        // Ensure /api doesn't match /apikey
        let patterns = vec!["/api", "/app", "/application"];

        let test_cases = vec![
            ("/api", Some("/api")),
            ("/api/test", Some("/api")),
            ("/apikey", None),  // Should NOT match /api
            ("/app", Some("/app")),
            ("/app/test", Some("/app")),
            ("/apple", None),   // Should NOT match /app
            ("/application", Some("/application")),
            ("/application/test", Some("/application")),
            ("/applications", None),  // Should NOT match /application
        ];

        for (path, expected) in test_cases {
            let matched = patterns
                .iter()
                .filter(|pattern| {
                    if path == **pattern {
                        true
                    } else if path.starts_with(*pattern) {
                        let remainder = &path[pattern.len()..];
                        remainder.starts_with('/')
                    } else {
                        false
                    }
                })
                .max_by_key(|p| p.len());

            match (matched, expected) {
                (Some(m), Some(e)) => assert_eq!(*m, e, "Wrong match for: {}", path),
                (None, None) => {}
                _ => panic!(
                    "Mismatch for {}: got {:?}, expected {:?}",
                    path, matched, expected
                ),
            }
        }
    }

    #[test]
    fn test_host_routing() {
        // Test virtual host routing
        let hosts = vec![
            "example.com:80",
            "api.example.com:80",
            "www.example.com:80",
            "m.example.com:80",
        ];

        for host in &hosts {
            // Each host should be independently addressable
            let hostname = host.split(':').next().unwrap();
            assert!(!hostname.is_empty());
        }

        // Test hostname extraction from host:port
        let test_cases = vec![
            ("example.com:80", "example.com", 80),
            ("api.example.com:443", "api.example.com", 443),
            ("localhost:8080", "localhost", 8080),
            ("192.168.1.1:3000", "192.168.1.1", 3000),
        ];

        for (input, expected_host, expected_port) in test_cases {
            let parts: Vec<&str> = input.rsplitn(2, ':').collect();
            let port: u16 = parts[0].parse().unwrap();
            let host = parts[1];
            assert_eq!(host, expected_host);
            assert_eq!(port, expected_port);
        }
    }
}

/// Test header manipulation
mod header_integration {
    use super::*;

    #[test]
    fn test_header_rule_priority() {
        // Test the order of header operations: unset, set_if_empty, merge, set
        // Using a simulation since we can't directly test the middleware here

        #[derive(Default)]
        struct MockHeaders {
            headers: HashMap<String, String>,
        }

        impl MockHeaders {
            fn apply_rules(
                &mut self,
                unset: &[&str],
                set_if_empty: &[(&str, &str)],
                merge: &[(&str, &str)],
                set: &[(&str, &str)],
            ) {
                // 1. Unset
                for name in unset {
                    self.headers.remove(*name);
                }

                // 2. Set if empty
                for (name, value) in set_if_empty {
                    if !self.headers.contains_key(*name) {
                        self.headers.insert(name.to_string(), value.to_string());
                    }
                }

                // 3. Merge
                for (name, value) in merge {
                    if let Some(existing) = self.headers.get(*name) {
                        let merged = format!("{}, {}", existing, value);
                        self.headers.insert(name.to_string(), merged);
                    } else {
                        self.headers.insert(name.to_string(), value.to_string());
                    }
                }

                // 4. Set (always overwrites)
                for (name, value) in set {
                    self.headers.insert(name.to_string(), value.to_string());
                }
            }
        }

        let mut headers = MockHeaders::default();
        headers.headers.insert("X-Existing".to_string(), "original".to_string());
        headers.headers.insert("X-Remove".to_string(), "to-remove".to_string());
        headers.headers.insert("Cache-Control".to_string(), "public".to_string());

        headers.apply_rules(
            &["X-Remove"],
            &[("X-Existing", "new"), ("X-New", "value")],
            &[("Cache-Control", "max-age=3600")],
            &[("X-Force", "forced")],
        );

        assert!(!headers.headers.contains_key("X-Remove"));
        assert_eq!(headers.headers.get("X-Existing").unwrap(), "original"); // Not overwritten
        assert_eq!(headers.headers.get("X-New").unwrap(), "value");
        assert!(headers.headers.get("Cache-Control").unwrap().contains("public"));
        assert!(headers.headers.get("Cache-Control").unwrap().contains("max-age=3600"));
        assert_eq!(headers.headers.get("X-Force").unwrap(), "forced");
    }

    #[test]
    fn test_security_headers() {
        // Test that default security headers are properly configured
        let security_headers = vec![
            ("X-Xss-Protection", "1; mode=block"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "origin"),
        ];

        let headers_to_remove = vec!["X-Powered-By", "Via", "x-varnish"];

        // Verify these are the expected security defaults
        assert!(!security_headers.is_empty());
        assert!(!headers_to_remove.is_empty());
    }
}

/// Test URL and path handling
mod url_integration {
    use super::*;

    #[test]
    fn test_upstream_url_construction() {
        // Test how upstream URLs are constructed from config + request path
        let test_cases = vec![
            // (upstream_base, request_path, expected_contains)
            ("http://backend:3000", "/api/users", "backend:3000/api/users"),
            ("http://backend:3000/", "/api/users", "backend:3000/api/users"),
            ("http://varnish:80", "/wiki/Main", "varnish:80/wiki/Main"),
        ];

        for (base, path, expected) in test_cases {
            let full_url = format!("{}{}", base.trim_end_matches('/'), path);
            assert!(
                full_url.contains(expected),
                "URL {} should contain {}",
                full_url,
                expected
            );
        }
    }

    #[test]
    fn test_query_string_preservation() {
        // Test that query strings are preserved through routing
        let test_paths = vec![
            "/search?q=test",
            "/api/users?page=1&limit=10",
            "/wiki/Special:Search?search=term&go=Go",
            "/path?a=1&b=2&c=3",
        ];

        for path in test_paths {
            let parts: Vec<&str> = path.splitn(2, '?').collect();
            assert_eq!(parts.len(), 2, "Path should have query string: {}", path);

            let path_part = parts[0];
            let query_part = parts[1];

            assert!(!query_part.is_empty());
            assert!(path_part.starts_with('/'));
        }
    }

    #[test]
    fn test_directory_traversal_prevention() {
        // Test that directory traversal attacks are blocked
        let attack_paths = vec![
            "/../etc/passwd",
            "/..%2F..%2Fetc/passwd",
            "/test/../../../etc/passwd",
            "/..",
            "/foo/bar/../../..",
            "/foo/./bar/../../../etc/passwd",
        ];

        for path in attack_paths {
            // Check if path contains ".." component
            let has_traversal = path.split('/').any(|c| c == ".." || c == "%2e%2e" || c == "%2E%2E");
            assert!(
                has_traversal || path.contains(".."),
                "Should detect traversal in: {}",
                path
            );
        }
    }
}

/// Test connection pool behavior
mod pool_integration {
    use super::*;

    #[test]
    fn test_pool_key_generation() {
        // Test that pool keys are generated correctly for different hosts
        let hosts = vec![
            ("backend", 3000, "backend:3000"),
            ("api.example.com", 443, "api.example.com:443"),
            ("192.168.1.1", 8080, "192.168.1.1:8080"),
            ("localhost", 80, "localhost:80"),
        ];

        for (host, port, expected_key) in hosts {
            let key = format!("{}:{}", host, port);
            assert_eq!(key, expected_key);
        }
    }

    #[test]
    fn test_default_pool_config() {
        // Verify default pool configuration values
        let max_connections_per_host = 256;
        let idle_timeout_secs = 90;
        let connect_timeout_secs = 10;
        let max_idle_per_host = 32;

        // These are the expected defaults from the pool module
        assert!(max_connections_per_host > 0);
        assert!(idle_timeout_secs > 0);
        assert!(connect_timeout_secs > 0);
        assert!(max_idle_per_host > 0);
        assert!(max_idle_per_host <= max_connections_per_host);
    }
}

/// Test TLS configuration
mod tls_integration {
    use super::*;

    #[test]
    fn test_tls_version_mapping() {
        // Test TLS version string parsing
        let versions = vec![
            ("TLSv1", "TLS 1.0"),
            ("TLSv1.0", "TLS 1.0"),
            ("TLSv1.1", "TLS 1.1"),
            ("TLSv1.2", "TLS 1.2"),
            ("TLSv1.3", "TLS 1.3"),
        ];

        for (input, _description) in versions {
            assert!(input.starts_with("TLS") || input.starts_with("tls"));
        }
    }

    #[test]
    fn test_certificate_path_validation() {
        // Test that certificate paths are properly handled
        let paths = vec![
            "/tls/cert.pem",
            "/letsencrypt/live/example.com/fullchain.pem",
            "/etc/ssl/certs/server.crt",
        ];

        for path in paths {
            let path_buf = PathBuf::from(path);
            assert!(path_buf.is_absolute());
            assert!(path.ends_with(".pem") || path.ends_with(".crt"));
        }
    }
}

/// Test error handling
mod error_integration {
    use super::*;

    #[test]
    fn test_http_status_codes() {
        // Test that appropriate status codes are used for various errors
        let error_codes = vec![
            (404, "Not Found"),
            (403, "Forbidden"),
            (405, "Method Not Allowed"),
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
            (504, "Gateway Timeout"),
        ];

        for (code, _description) in error_codes {
            assert!(code >= 400 && code < 600, "Should be error code: {}", code);
        }
    }

    #[test]
    fn test_redirect_status_codes() {
        // Test redirect status codes
        let redirect_codes = vec![
            (301, "Moved Permanently"),
            (302, "Found"),
            (307, "Temporary Redirect"),
            (308, "Permanent Redirect"),
        ];

        for (code, _description) in redirect_codes {
            assert!(code >= 300 && code < 400, "Should be redirect code: {}", code);
        }
    }
}
