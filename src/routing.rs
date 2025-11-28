//! Path-based routing with longest-prefix matching
//!
//! This module provides efficient routing based on the request path,
//! supporting exact matches, prefix matches, and the h2o-style
//! longest-prefix-wins matching behavior.

use crate::config::{HeaderRules, ResolvedHost, RouteAction};
use ahash::AHashMap;
use std::sync::Arc;
use tracing::trace;

/// Route matcher for a single host
pub struct RouteMatcher {
    /// Routes sorted by path length (longest first)
    routes: Vec<RouteEntry>,
    /// Header rules for the host
    host_headers: HeaderRules,
}

/// A single route entry
struct RouteEntry {
    /// Path pattern (may be prefix)
    path: String,
    /// Whether this is an exact match
    exact: bool,
    /// Action to take
    action: RouteAction,
    /// Header rules
    headers: HeaderRules,
    /// Proxy request headers
    proxy_headers: HeaderRules,
    /// Expires setting (None = not set, Some(None) = off, Some(Some(secs)) = max-age)
    expires: Option<Option<u64>>,
}

impl RouteMatcher {
    /// Create a new route matcher from a resolved host
    pub fn new(host: &ResolvedHost) -> Self {
        let mut routes: Vec<RouteEntry> = host
            .routes
            .iter()
            .map(|r| RouteEntry {
                path: r.path.clone(),
                exact: !r.path.ends_with('/') && r.path != "/",
                action: r.action.clone(),
                headers: r.headers.clone(),
                proxy_headers: r.proxy_headers.clone(),
                expires: r.expires,
            })
            .collect();

        // Sort by path length descending for longest-prefix matching
        routes.sort_by(|a, b| b.path.len().cmp(&a.path.len()));

        Self {
            routes,
            host_headers: host.headers.clone(),
        }
    }

    /// Match a request path to a route
    pub fn match_path(&self, path: &str) -> Option<MatchResult> {
        for route in &self.routes {
            if self.path_matches(&route.path, path) {
                return Some(MatchResult {
                    action: route.action.clone(),
                    headers: self.host_headers.merge_with(&route.headers),
                    proxy_headers: route.proxy_headers.clone(),
                    matched_path: route.path.clone(),
                    expires: route.expires,
                });
            }
        }

        // No match - try root path
        for route in &self.routes {
            if route.path == "/" {
                return Some(MatchResult {
                    action: route.action.clone(),
                    headers: self.host_headers.merge_with(&route.headers),
                    proxy_headers: route.proxy_headers.clone(),
                    matched_path: route.path.clone(),
                    expires: route.expires,
                });
            }
        }

        None
    }

    /// Check if a pattern matches a path
    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        if pattern == "/" {
            return true;
        }

        if path == pattern {
            return true;
        }

        // Prefix match: pattern "/foo/" or "/foo" should match "/foo/bar"
        if path.starts_with(pattern) {
            // If pattern ends with /, it's already a directory prefix - match anything under it
            if pattern.ends_with('/') {
                return true;
            }
            // For patterns without trailing slash, ensure we match at path boundary
            let remainder = &path[pattern.len()..];
            return remainder.is_empty() || remainder.starts_with('/');
        }

        // Also check if path matches pattern without trailing slash
        // e.g., pattern "/yolo/" should match path "/yolo"
        if pattern.ends_with('/') {
            let pattern_trimmed = pattern.trim_end_matches('/');
            if path == pattern_trimmed {
                return true;
            }
        }

        false
    }
}

/// Result of a route match
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Action to take
    pub action: RouteAction,
    /// Headers to apply to response
    pub headers: HeaderRules,
    /// Headers to apply to proxy request
    pub proxy_headers: HeaderRules,
    /// The path pattern that matched
    pub matched_path: String,
    /// Expires setting (None = not set, Some(None) = off, Some(Some(secs)) = max-age)
    pub expires: Option<Option<u64>>,
}

/// Global router managing all hosts
pub struct Router {
    /// Host matchers indexed by host:port
    hosts: AHashMap<String, Arc<RouteMatcher>>,
    /// Default matcher for unknown hosts
    default: Option<Arc<RouteMatcher>>,
}

impl Router {
    /// Create a new router from resolved hosts
    pub fn new(hosts: &std::collections::HashMap<String, Arc<ResolvedHost>>) -> Self {
        let mut host_matchers = AHashMap::new();

        for (name, host) in hosts {
            let matcher = Arc::new(RouteMatcher::new(host));
            host_matchers.insert(name.clone(), matcher.clone());

            // Also index by just hostname (without port)
            if let Some(idx) = name.rfind(':') {
                let hostname = &name[..idx];
                host_matchers.entry(hostname.to_string()).or_insert(matcher);
            }
        }

        Self {
            hosts: host_matchers,
            default: None,
        }
    }

    /// Route a request
    pub fn route(&self, host: &str, path: &str) -> Option<MatchResult> {
        // Try exact host:port match
        if let Some(matcher) = self.hosts.get(host) {
            if let Some(result) = matcher.match_path(path) {
                trace!("Matched {} {} -> {:?}", host, path, result.matched_path);
                return Some(result);
            }
        }

        // Try hostname only (strip port)
        if let Some(idx) = host.rfind(':') {
            let hostname = &host[..idx];
            if let Some(matcher) = self.hosts.get(hostname) {
                if let Some(result) = matcher.match_path(path) {
                    trace!("Matched {} {} -> {:?}", hostname, path, result.matched_path);
                    return Some(result);
                }
            }
        }

        // Try default
        if let Some(matcher) = &self.default {
            return matcher.match_path(path);
        }

        None
    }

    /// Get all registered hosts
    pub fn hosts(&self) -> impl Iterator<Item = &String> {
        self.hosts.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ResolvedHost, ResolvedRoute};

    fn make_test_host() -> ResolvedHost {
        ResolvedHost {
            name: "test.example.com".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Proxy {
                        upstream: "http://backend:80".to_string(),
                        preserve_host: true,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/api".to_string(),
                    action: RouteAction::Proxy {
                        upstream: "http://api:3000".to_string(),
                        preserve_host: true,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/static".to_string(),
                    action: RouteAction::StaticFiles {
                        dir: "/var/www".into(),
                        index: vec!["index.html".to_string()],
                        send_gzip: true,
                        dirlisting: false,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        }
    }

    // =====================================================================
    // RouteMatcher basic tests
    // =====================================================================

    #[test]
    fn test_exact_match() {
        let host = make_test_host();
        let matcher = RouteMatcher::new(&host);

        let result = matcher.match_path("/api").unwrap();
        assert_eq!(result.matched_path, "/api");
    }

    #[test]
    fn test_prefix_match() {
        let host = make_test_host();
        let matcher = RouteMatcher::new(&host);

        let result = matcher.match_path("/api/v1/users").unwrap();
        assert_eq!(result.matched_path, "/api");
    }

    #[test]
    fn test_root_fallback() {
        let host = make_test_host();
        let matcher = RouteMatcher::new(&host);

        let result = matcher.match_path("/unknown/path").unwrap();
        assert_eq!(result.matched_path, "/");
    }

    #[test]
    fn test_longest_prefix_wins() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Redirect {
                        url: "http://root".to_string(),
                        status: 301,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/w".to_string(),
                    action: RouteAction::Redirect {
                        url: "http://w".to_string(),
                        status: 301,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/w/index.php".to_string(),
                    action: RouteAction::Redirect {
                        url: "http://windex".to_string(),
                        status: 301,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // Should match longest prefix
        let result = matcher.match_path("/w/index.php").unwrap();
        assert_eq!(result.matched_path, "/w/index.php");

        let result = matcher.match_path("/w/other").unwrap();
        assert_eq!(result.matched_path, "/w");

        let result = matcher.match_path("/other").unwrap();
        assert_eq!(result.matched_path, "/");
    }

    // =====================================================================
    // Path matching edge cases
    // =====================================================================

    #[test]
    fn test_path_match_with_trailing_slash() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/api".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // /api should match /api/
        let result = matcher.match_path("/api/");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_path, "/api");
    }

    #[test]
    fn test_trailing_slash_pattern_matches_subpaths() {
        // Pattern WITH trailing slash should match all subpaths
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Redirect {
                        url: "https://redirect.com/".to_string(),
                        status: 301,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/yolo/".to_string(),
                    action: RouteAction::StaticFiles {
                        dir: "/home/test".into(),
                        index: vec![],
                        send_gzip: false,
                        dirlisting: true,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // /yolo/ pattern should match /yolo/Downloads/
        let result = matcher.match_path("/yolo/Downloads/");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_path, "/yolo/");

        // /yolo/ pattern should match /yolo/Downloads/subdir/file.txt
        let result = matcher.match_path("/yolo/Downloads/subdir/file.txt");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_path, "/yolo/");

        // /yolo/ pattern should match /yolo (without trailing slash)
        let result = matcher.match_path("/yolo");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_path, "/yolo/");

        // Unmatched paths should fall back to /
        let result = matcher.match_path("/other");
        assert!(result.is_some());
        assert_eq!(result.unwrap().matched_path, "/");
    }

    #[test]
    fn test_path_no_false_prefix_match() {
        // /api should NOT match /apikey
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/api".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // /apikey should NOT match /api (prefix doesn't end at boundary)
        let result = matcher.match_path("/apikey");
        assert!(result.is_none());
    }

    #[test]
    fn test_root_path_matches_everything() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        assert!(matcher.match_path("/").is_some());
        assert!(matcher.match_path("/anything").is_some());
        assert!(matcher.match_path("/deep/nested/path").is_some());
    }

    #[test]
    fn test_empty_host_no_routes() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        assert!(matcher.match_path("/").is_none());
        assert!(matcher.match_path("/anything").is_none());
    }

    #[test]
    fn test_deep_nested_routes() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/a".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/a/b".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/a/b/c".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/a/b/c/d".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        assert_eq!(matcher.match_path("/a/b/c/d").unwrap().matched_path, "/a/b/c/d");
        assert_eq!(matcher.match_path("/a/b/c/d/e").unwrap().matched_path, "/a/b/c/d");
        assert_eq!(matcher.match_path("/a/b/c").unwrap().matched_path, "/a/b/c");
        assert_eq!(matcher.match_path("/a/b").unwrap().matched_path, "/a/b");
        assert_eq!(matcher.match_path("/a").unwrap().matched_path, "/a");
        assert_eq!(matcher.match_path("/").unwrap().matched_path, "/");
    }

    #[test]
    fn test_similar_prefixes() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/app".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/application".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/apps".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        assert_eq!(matcher.match_path("/application").unwrap().matched_path, "/application");
        assert_eq!(matcher.match_path("/application/test").unwrap().matched_path, "/application");
        assert_eq!(matcher.match_path("/apps").unwrap().matched_path, "/apps");
        assert_eq!(matcher.match_path("/apps/list").unwrap().matched_path, "/apps");
        assert_eq!(matcher.match_path("/app").unwrap().matched_path, "/app");
        assert_eq!(matcher.match_path("/app/settings").unwrap().matched_path, "/app");

        // These should NOT match any of the above
        assert!(matcher.match_path("/apple").is_none());
        assert!(matcher.match_path("/applet").is_none());
    }

    #[test]
    fn test_query_string_not_part_of_path() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/api".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // Note: In actual use, query strings are stripped before matching
        // This tests that the path without query matches correctly
        assert_eq!(matcher.match_path("/api").unwrap().matched_path, "/api");
    }

    #[test]
    fn test_special_characters_in_path() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/wiki".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // Should match paths with URL-encoded characters
        assert_eq!(matcher.match_path("/wiki/Special:Search").unwrap().matched_path, "/wiki");
        assert_eq!(matcher.match_path("/wiki/Test%20Page").unwrap().matched_path, "/wiki");
    }

    // =====================================================================
    // Header merging tests
    // =====================================================================

    #[test]
    fn test_header_rules_merged_in_match_result() {
        let host_headers = HeaderRules {
            set: vec![("X-Host".to_string(), "value".to_string())],
            set_if_empty: vec![],
            merge: vec![],
            unset: vec![],
        };

        let route_headers = HeaderRules {
            set: vec![("X-Route".to_string(), "value".to_string())],
            set_if_empty: vec![],
            merge: vec![],
            unset: vec![],
        };

        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Status,
                    headers: route_headers,
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: host_headers,
        };

        let matcher = RouteMatcher::new(&host);
        let result = matcher.match_path("/").unwrap();

        // Headers should contain both host and route headers merged
        assert_eq!(result.headers.set.len(), 2);
    }

    #[test]
    fn test_proxy_headers_preserved() {
        let proxy_headers = HeaderRules {
            set: vec![("X-Forwarded-Proto".to_string(), "https".to_string())],
            set_if_empty: vec![],
            merge: vec![],
            unset: vec![],
        };

        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Proxy {
                        upstream: "http://backend:80".to_string(),
                        preserve_host: true,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: proxy_headers.clone(),
                    expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);
        let result = matcher.match_path("/").unwrap();

        assert_eq!(result.proxy_headers.set.len(), 1);
        assert_eq!(result.proxy_headers.set[0].0, "X-Forwarded-Proto");
    }

    // =====================================================================
    // Route action tests
    // =====================================================================

    #[test]
    fn test_redirect_action() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/old".to_string(),
                    action: RouteAction::Redirect {
                        url: "https://example.com/new".to_string(),
                        status: 301,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);
        let result = matcher.match_path("/old").unwrap();

        match result.action {
            RouteAction::Redirect { url, status } => {
                assert_eq!(url, "https://example.com/new");
                assert_eq!(status, 301);
            }
            _ => panic!("Expected redirect action"),
        }
    }

    #[test]
    fn test_status_action() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/health".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);
        let result = matcher.match_path("/health").unwrap();

        assert!(matches!(result.action, RouteAction::Status));
    }

    #[test]
    fn test_static_files_action() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/static".to_string(),
                    action: RouteAction::StaticFiles {
                        dir: "/var/www/static".into(),
                        index: vec!["index.html".to_string(), "index.htm".to_string()],
                        send_gzip: true,
                        dirlisting: false,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);
        let result = matcher.match_path("/static/file.js").unwrap();

        match result.action {
            RouteAction::StaticFiles { dir, index, send_gzip, .. } => {
                assert_eq!(dir.to_str().unwrap(), "/var/www/static");
                assert_eq!(index.len(), 2);
                assert!(send_gzip);
            }
            _ => panic!("Expected static files action"),
        }
    }

    #[test]
    fn test_proxy_action() {
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                ResolvedRoute {
                    path: "/api".to_string(),
                    action: RouteAction::Proxy {
                        upstream: "http://api-server:3000".to_string(),
                        preserve_host: false,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);
        let result = matcher.match_path("/api/v1/users").unwrap();

        match result.action {
            RouteAction::Proxy { upstream, preserve_host } => {
                assert_eq!(upstream, "http://api-server:3000");
                assert!(!preserve_host);
            }
            _ => panic!("Expected proxy action"),
        }
    }

    // =====================================================================
    // Router tests
    // =====================================================================

    #[test]
    fn test_router_exact_host_match() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "example.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Status,
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);
        let result = router.route("example.com:80", "/");

        assert!(result.is_some());
    }

    #[test]
    fn test_router_hostname_only_match() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "example.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Status,
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);

        // Should match when port is stripped from request host
        let result = router.route("example.com:8080", "/");
        assert!(result.is_some());
    }

    #[test]
    fn test_router_no_host_match() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "example.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Status,
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);
        let result = router.route("unknown.com:80", "/");

        assert!(result.is_none());
    }

    #[test]
    fn test_router_multiple_hosts() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "example.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Redirect {
                            url: "https://example.com/".to_string(),
                            status: 301,
                        },
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );
        hosts.insert(
            "other.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Redirect {
                            url: "https://other.com/".to_string(),
                            status: 301,
                        },
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);

        let result1 = router.route("example.com:80", "/").unwrap();
        match &result1.action {
            RouteAction::Redirect { url, .. } => assert!(url.contains("example.com")),
            _ => panic!("Expected redirect"),
        }

        let result2 = router.route("other.com:80", "/").unwrap();
        match &result2.action {
            RouteAction::Redirect { url, .. } => assert!(url.contains("other.com")),
            _ => panic!("Expected redirect"),
        }
    }

    #[test]
    fn test_router_hosts_iterator() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "a.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![],
                headers: HeaderRules::default(),
            }),
        );
        hosts.insert(
            "b.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);
        let registered_hosts: Vec<_> = router.hosts().collect();

        // Should have original hosts plus hostname-only versions
        assert!(registered_hosts.len() >= 2);
    }

    #[test]
    fn test_router_subdomain_routing() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "api.example.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Proxy {
                            upstream: "http://api:3000".to_string(),
                            preserve_host: true,
                        },
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );
        hosts.insert(
            "www.example.com:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Proxy {
                            upstream: "http://web:8080".to_string(),
                            preserve_host: true,
                        },
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);

        let api_result = router.route("api.example.com:80", "/v1/users").unwrap();
        match &api_result.action {
            RouteAction::Proxy { upstream, .. } => assert!(upstream.contains("api:3000")),
            _ => panic!("Expected proxy"),
        }

        let www_result = router.route("www.example.com:80", "/index.html").unwrap();
        match &www_result.action {
            RouteAction::Proxy { upstream, .. } => assert!(upstream.contains("web:8080")),
            _ => panic!("Expected proxy"),
        }
    }

    // =====================================================================
    // Edge cases
    // =====================================================================

    #[test]
    fn test_route_priority_order_preserved() {
        // Routes should be sorted by length, so longer paths match first
        let host = ResolvedHost {
            name: "test".to_string(),
            routes: vec![
                // Insert in wrong order - shorter first
                ResolvedRoute {
                    path: "/a".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/a/b/c".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
                ResolvedRoute {
                    path: "/a/b".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                        expires: None,
                },
            ],
            headers: HeaderRules::default(),
        };

        let matcher = RouteMatcher::new(&host);

        // Despite insertion order, longest should match
        assert_eq!(matcher.match_path("/a/b/c/d").unwrap().matched_path, "/a/b/c");
    }

    #[test]
    fn test_onion_and_i2p_hosts() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "abc123.onion:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Status,
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );
        hosts.insert(
            "site.i2p:80".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Status,
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);

        assert!(router.route("abc123.onion:80", "/").is_some());
        assert!(router.route("site.i2p:80", "/").is_some());
    }

    #[test]
    fn test_ipv4_host() {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "192.168.1.1:8080".to_string(),
            Arc::new(ResolvedHost {
                name: "test".to_string(),
                routes: vec![
                    ResolvedRoute {
                        path: "/".to_string(),
                        action: RouteAction::Status,
                        headers: HeaderRules::default(),
                        proxy_headers: HeaderRules::default(),
                        expires: None,
                    },
                ],
                headers: HeaderRules::default(),
            }),
        );

        let router = Router::new(&hosts);
        assert!(router.route("192.168.1.1:8080", "/").is_some());
    }
}
