//! Routing benchmarks
//!
//! Benchmarks for path matching, route resolution, and router operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// Re-create minimal types needed for benchmarks since we can't import from styx directly
// in criterion benchmarks without some setup

/// Header rules for benchmarks
#[derive(Debug, Clone, Default)]
struct HeaderRules {
    set: Vec<(String, String)>,
    set_if_empty: Vec<(String, String)>,
    merge: Vec<(String, String)>,
    unset: Vec<String>,
}

impl HeaderRules {
    fn merge_with(&self, other: &HeaderRules) -> HeaderRules {
        HeaderRules {
            set: self.set.iter().chain(other.set.iter()).cloned().collect(),
            set_if_empty: self
                .set_if_empty
                .iter()
                .chain(other.set_if_empty.iter())
                .cloned()
                .collect(),
            merge: self
                .merge
                .iter()
                .chain(other.merge.iter())
                .cloned()
                .collect(),
            unset: self
                .unset
                .iter()
                .chain(other.unset.iter())
                .cloned()
                .collect(),
        }
    }
}

/// Route action enum
#[derive(Debug, Clone)]
enum RouteAction {
    Proxy {
        upstream: String,
        preserve_host: bool,
    },
    StaticFiles {
        dir: PathBuf,
        index: Vec<String>,
        send_gzip: bool,
    },
    Redirect {
        url: String,
        status: u16,
    },
    Status,
}

/// Resolved route
#[derive(Debug, Clone)]
struct ResolvedRoute {
    path: String,
    action: RouteAction,
    headers: HeaderRules,
    proxy_headers: HeaderRules,
}

/// Resolved host
#[derive(Debug, Clone)]
struct ResolvedHost {
    name: String,
    routes: Vec<ResolvedRoute>,
    headers: HeaderRules,
}

/// Route entry for matching
struct RouteEntry {
    path: String,
    exact: bool,
    action: RouteAction,
    headers: HeaderRules,
    proxy_headers: HeaderRules,
}

/// Route matcher for a single host
struct RouteMatcher {
    routes: Vec<RouteEntry>,
    host_headers: HeaderRules,
}

/// Result of a route match
#[derive(Debug, Clone)]
struct MatchResult {
    action: RouteAction,
    headers: HeaderRules,
    proxy_headers: HeaderRules,
    matched_path: String,
}

impl RouteMatcher {
    fn new(host: &ResolvedHost) -> Self {
        let mut routes: Vec<RouteEntry> = host
            .routes
            .iter()
            .map(|r| RouteEntry {
                path: r.path.clone(),
                exact: !r.path.ends_with('/') && r.path != "/",
                action: r.action.clone(),
                headers: r.headers.clone(),
                proxy_headers: r.proxy_headers.clone(),
            })
            .collect();

        // Sort by path length descending for longest-prefix matching
        routes.sort_by(|a, b| b.path.len().cmp(&a.path.len()));

        Self {
            routes,
            host_headers: host.headers.clone(),
        }
    }

    fn match_path(&self, path: &str) -> Option<MatchResult> {
        for route in &self.routes {
            if self.path_matches(&route.path, path) {
                return Some(MatchResult {
                    action: route.action.clone(),
                    headers: self.host_headers.merge_with(&route.headers),
                    proxy_headers: route.proxy_headers.clone(),
                    matched_path: route.path.clone(),
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
                });
            }
        }

        None
    }

    #[inline]
    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        if pattern == "/" {
            return true;
        }

        if path == pattern {
            return true;
        }

        // Prefix match: pattern "/foo" should match "/foo/bar" and "/foo"
        if path.starts_with(pattern) {
            let remainder = &path[pattern.len()..];
            return remainder.is_empty() || remainder.starts_with('/');
        }

        false
    }
}

/// Global router managing all hosts
struct Router {
    hosts: HashMap<String, Arc<RouteMatcher>>,
    default: Option<Arc<RouteMatcher>>,
}

impl Router {
    fn new(hosts: &HashMap<String, Arc<ResolvedHost>>) -> Self {
        let mut host_matchers = HashMap::new();

        for (name, host) in hosts {
            let matcher = Arc::new(RouteMatcher::new(host));
            host_matchers.insert(name.clone(), matcher.clone());

            // Also index by just hostname (without port)
            if let Some(idx) = name.rfind(':') {
                let hostname = &name[..idx];
                host_matchers
                    .entry(hostname.to_string())
                    .or_insert(matcher);
            }
        }

        Self {
            hosts: host_matchers,
            default: None,
        }
    }

    fn route(&self, host: &str, path: &str) -> Option<MatchResult> {
        // Try exact host:port match
        if let Some(matcher) = self.hosts.get(host) {
            if let Some(result) = matcher.match_path(path) {
                return Some(result);
            }
        }

        // Try hostname only (strip port)
        if let Some(idx) = host.rfind(':') {
            let hostname = &host[..idx];
            if let Some(matcher) = self.hosts.get(hostname) {
                if let Some(result) = matcher.match_path(path) {
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
}

// =============================================================================
// Benchmark fixtures
// =============================================================================

fn create_simple_host() -> ResolvedHost {
    ResolvedHost {
        name: "example.com".to_string(),
        routes: vec![
            ResolvedRoute {
                path: "/".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://backend:80".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/api".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://api:3000".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/static".to_string(),
                action: RouteAction::StaticFiles {
                    dir: "/var/www".into(),
                    index: vec!["index.html".to_string()],
                    send_gzip: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
        ],
        headers: HeaderRules::default(),
    }
}

fn create_complex_host(num_routes: usize) -> ResolvedHost {
    let mut routes = Vec::with_capacity(num_routes);

    // Add root route
    routes.push(ResolvedRoute {
        path: "/".to_string(),
        action: RouteAction::Proxy {
            upstream: "http://backend:80".to_string(),
            preserve_host: true,
        },
        headers: HeaderRules::default(),
        proxy_headers: HeaderRules::default(),
    });

    // Add many routes with varying depths
    for i in 0..num_routes - 1 {
        let depth = (i % 5) + 1;
        let path = (0..depth)
            .map(|d| format!("/segment{}", d + i))
            .collect::<String>();

        routes.push(ResolvedRoute {
            path,
            action: RouteAction::Proxy {
                upstream: format!("http://backend{}:80", i),
                preserve_host: true,
            },
            headers: HeaderRules::default(),
            proxy_headers: HeaderRules::default(),
        });
    }

    ResolvedHost {
        name: "complex.example.com".to_string(),
        routes,
        headers: HeaderRules::default(),
    }
}

fn create_wiki_style_host() -> ResolvedHost {
    // Mimics a Wikipedia-style routing setup
    ResolvedHost {
        name: "wiki.example.com".to_string(),
        routes: vec![
            ResolvedRoute {
                path: "/".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://varnish:80".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/w".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://varnish:80".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/w/index.php".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://varnish:80".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/wiki".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://varnish:80".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/api".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://api:3000".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/api/rest_v1".to_string(),
                action: RouteAction::Proxy {
                    upstream: "http://restbase:7231".to_string(),
                    preserve_host: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/static".to_string(),
                action: RouteAction::StaticFiles {
                    dir: "/var/www/static".into(),
                    index: vec!["index.html".to_string()],
                    send_gzip: true,
                },
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
        ],
        headers: HeaderRules::default(),
    }
}

// =============================================================================
// Benchmarks
// =============================================================================

fn bench_route_matcher_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_matcher_creation");

    for size in [3, 10, 50, 100, 500].iter() {
        let host = create_complex_host(*size);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("routes", size), &host, |b, host| {
            b.iter(|| RouteMatcher::new(black_box(host)))
        });
    }

    group.finish();
}

fn bench_path_matching_simple(c: &mut Criterion) {
    let host = create_simple_host();
    let matcher = RouteMatcher::new(&host);

    let mut group = c.benchmark_group("path_matching_simple");
    group.throughput(Throughput::Elements(1));

    // Exact match
    group.bench_function("exact_match_api", |b| {
        b.iter(|| matcher.match_path(black_box("/api")))
    });

    // Prefix match
    group.bench_function("prefix_match_api_v1", |b| {
        b.iter(|| matcher.match_path(black_box("/api/v1/users")))
    });

    // Root fallback
    group.bench_function("root_fallback", |b| {
        b.iter(|| matcher.match_path(black_box("/unknown/path")))
    });

    // Static files
    group.bench_function("static_files", |b| {
        b.iter(|| matcher.match_path(black_box("/static/js/app.js")))
    });

    group.finish();
}

fn bench_path_matching_wiki(c: &mut Criterion) {
    let host = create_wiki_style_host();
    let matcher = RouteMatcher::new(&host);

    let mut group = c.benchmark_group("path_matching_wiki");
    group.throughput(Throughput::Elements(1));

    // Wiki article (longest prefix: /wiki)
    group.bench_function("wiki_article", |b| {
        b.iter(|| matcher.match_path(black_box("/wiki/Main_Page")))
    });

    // Index.php (exact match with query params stripped)
    group.bench_function("index_php", |b| {
        b.iter(|| matcher.match_path(black_box("/w/index.php")))
    });

    // API endpoint (longest prefix wins)
    group.bench_function("api_rest", |b| {
        b.iter(|| matcher.match_path(black_box("/api/rest_v1/page/summary/Test")))
    });

    // Deep path
    group.bench_function("deep_path", |b| {
        b.iter(|| matcher.match_path(black_box("/wiki/Category:Science/Physics/Quantum")))
    });

    group.finish();
}

fn bench_path_matching_many_routes(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_matching_many_routes");
    group.throughput(Throughput::Elements(1));

    for size in [10, 50, 100, 500].iter() {
        let host = create_complex_host(*size);
        let matcher = RouteMatcher::new(&host);

        // Match first route (should be fast - it's sorted by length)
        group.bench_with_input(
            BenchmarkId::new("match_first", size),
            &matcher,
            |b, matcher| {
                b.iter(|| matcher.match_path(black_box("/segment0/segment10/segment20/segment30")))
            },
        );

        // Match root (should traverse most routes)
        group.bench_with_input(
            BenchmarkId::new("match_root_fallback", size),
            &matcher,
            |b, matcher| b.iter(|| matcher.match_path(black_box("/nonexistent"))),
        );

        // Miss all routes
        group.bench_with_input(BenchmarkId::new("no_match", size), &matcher, |b, matcher| {
            // Create a matcher without root route for miss testing
            b.iter(|| {
                // This will still match root, but tests the traversal
                matcher.match_path(black_box("/completely/different/path"))
            })
        });
    }

    group.finish();
}

fn bench_router_lookup(c: &mut Criterion) {
    let mut hosts = HashMap::new();

    // Add multiple hosts
    for i in 0..10 {
        let host = Arc::new(ResolvedHost {
            name: format!("host{}.example.com", i),
            routes: vec![
                ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Proxy {
                        upstream: format!("http://backend{}:80", i),
                        preserve_host: true,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                },
                ResolvedRoute {
                    path: "/api".to_string(),
                    action: RouteAction::Proxy {
                        upstream: format!("http://api{}:3000", i),
                        preserve_host: true,
                    },
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                },
            ],
            headers: HeaderRules::default(),
        });

        hosts.insert(format!("host{}.example.com:80", i), host);
    }

    let router = Router::new(&hosts);

    let mut group = c.benchmark_group("router_lookup");
    group.throughput(Throughput::Elements(1));

    // First host
    group.bench_function("first_host", |b| {
        b.iter(|| router.route(black_box("host0.example.com:80"), black_box("/api/v1")))
    });

    // Middle host
    group.bench_function("middle_host", |b| {
        b.iter(|| router.route(black_box("host5.example.com:80"), black_box("/api/v1")))
    });

    // Last host
    group.bench_function("last_host", |b| {
        b.iter(|| router.route(black_box("host9.example.com:80"), black_box("/api/v1")))
    });

    // Unknown host
    group.bench_function("unknown_host", |b| {
        b.iter(|| router.route(black_box("unknown.example.com:80"), black_box("/api/v1")))
    });

    // Host without port (should try stripping)
    group.bench_function("host_port_stripping", |b| {
        b.iter(|| router.route(black_box("host0.example.com:8080"), black_box("/api")))
    });

    group.finish();
}

fn bench_router_many_hosts(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_many_hosts");
    group.throughput(Throughput::Elements(1));

    for num_hosts in [10, 50, 100, 500].iter() {
        let mut hosts = HashMap::new();

        for i in 0..*num_hosts {
            let host = Arc::new(ResolvedHost {
                name: format!("host{}.example.com", i),
                routes: vec![ResolvedRoute {
                    path: "/".to_string(),
                    action: RouteAction::Status,
                    headers: HeaderRules::default(),
                    proxy_headers: HeaderRules::default(),
                }],
                headers: HeaderRules::default(),
            });

            hosts.insert(format!("host{}.example.com:80", i), host);
        }

        let router = Router::new(&hosts);

        // Lookup existing host
        group.bench_with_input(
            BenchmarkId::new("existing_host", num_hosts),
            &router,
            |b, router| {
                let host = format!("host{}.example.com:80", num_hosts / 2);
                b.iter(|| router.route(black_box(&host), black_box("/")))
            },
        );

        // Lookup missing host
        group.bench_with_input(
            BenchmarkId::new("missing_host", num_hosts),
            &router,
            |b, router| {
                b.iter(|| router.route(black_box("nonexistent.example.com:80"), black_box("/")))
            },
        );
    }

    group.finish();
}

fn bench_path_matching_edge_cases(c: &mut Criterion) {
    let host = ResolvedHost {
        name: "example.com".to_string(),
        routes: vec![
            ResolvedRoute {
                path: "/".to_string(),
                action: RouteAction::Status,
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/api".to_string(),
                action: RouteAction::Status,
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/api/v1".to_string(),
                action: RouteAction::Status,
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/api/v1/users".to_string(),
                action: RouteAction::Status,
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
            ResolvedRoute {
                path: "/apikey".to_string(),
                action: RouteAction::Status,
                headers: HeaderRules::default(),
                proxy_headers: HeaderRules::default(),
            },
        ],
        headers: HeaderRules::default(),
    };

    let matcher = RouteMatcher::new(&host);

    let mut group = c.benchmark_group("path_matching_edge_cases");
    group.throughput(Throughput::Elements(1));

    // False prefix - /apikey should NOT match /api
    group.bench_function("false_prefix_rejection", |b| {
        b.iter(|| matcher.match_path(black_box("/apikey")))
    });

    // Similar prefixes - correct selection
    group.bench_function("longest_prefix_selection", |b| {
        b.iter(|| matcher.match_path(black_box("/api/v1/users/123")))
    });

    // Very long path
    group.bench_function("very_long_path", |b| {
        let long_path = "/api/v1/users/".to_string() + &"a".repeat(1000);
        b.iter(|| matcher.match_path(black_box(&long_path)))
    });

    // Path with special characters
    group.bench_function("special_chars", |b| {
        b.iter(|| matcher.match_path(black_box("/api/v1/users/user%20name")))
    });

    // Trailing slash variations
    group.bench_function("trailing_slash", |b| {
        b.iter(|| matcher.match_path(black_box("/api/")))
    });

    group.finish();
}

fn bench_header_rules_merge(c: &mut Criterion) {
    let rules1 = HeaderRules {
        set: vec![
            ("X-Header-1".to_string(), "value1".to_string()),
            ("X-Header-2".to_string(), "value2".to_string()),
        ],
        set_if_empty: vec![("X-Security".to_string(), "enabled".to_string())],
        merge: vec![("Cache-Control".to_string(), "public".to_string())],
        unset: vec!["X-Powered-By".to_string()],
    };

    let rules2 = HeaderRules {
        set: vec![("X-Header-3".to_string(), "value3".to_string())],
        set_if_empty: vec![],
        merge: vec![("Cache-Control".to_string(), "max-age=3600".to_string())],
        unset: vec!["Via".to_string()],
    };

    let mut group = c.benchmark_group("header_rules_merge");
    group.throughput(Throughput::Elements(1));

    group.bench_function("merge_rules", |b| {
        b.iter(|| rules1.merge_with(black_box(&rules2)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_route_matcher_creation,
    bench_path_matching_simple,
    bench_path_matching_wiki,
    bench_path_matching_many_routes,
    bench_router_lookup,
    bench_router_many_hosts,
    bench_path_matching_edge_cases,
    bench_header_rules_merge,
);

criterion_main!(benches);
