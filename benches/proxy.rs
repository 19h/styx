//! Proxy benchmarks
//!
//! Benchmarks for URL parsing, header manipulation, and proxy operations.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri};
use std::str::FromStr;

// =============================================================================
// URL Parsing benchmarks
// =============================================================================

/// Parse upstream URL and combine with request path (mirrors proxy::parse_upstream_url)
fn parse_upstream_url(upstream: &str, request_uri: &Uri) -> Result<String, &'static str> {
    let upstream_uri: Uri = upstream.parse().map_err(|_| "Invalid upstream URL")?;

    let scheme = upstream_uri.scheme_str().unwrap_or("http");
    let authority = upstream_uri
        .authority()
        .ok_or("Missing authority in upstream URL")?;

    let upstream_path = upstream_uri.path();
    let request_path = request_uri.path();

    let final_path = if upstream_path == "/" || upstream_path.is_empty() {
        request_path.to_string()
    } else if request_path.starts_with(upstream_path) {
        request_path.to_string()
    } else {
        format!(
            "{}{}",
            upstream_path.trim_end_matches('/'),
            request_path
        )
    };

    let query = request_uri
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    Ok(format!("{}://{}{}{}", scheme, authority, final_path, query))
}

/// Extract host and port from URI (mirrors proxy::extract_host_port)
fn extract_host_port(uri: &str) -> Result<(String, u16), &'static str> {
    let parsed: Uri = uri.parse().map_err(|_| "Cannot parse URI")?;

    let host = parsed.host().ok_or("Missing host")?.to_string();

    let port = parsed.port_u16().unwrap_or_else(|| {
        if parsed.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    Ok((host, port))
}

fn bench_parse_upstream_url(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_upstream_url");
    group.throughput(Throughput::Elements(1));

    // Simple proxy
    group.bench_function("simple", |b| {
        let uri: Uri = "/api/endpoint".parse().unwrap();
        b.iter(|| parse_upstream_url(black_box("http://backend:3000"), black_box(&uri)))
    });

    // With query string
    group.bench_function("with_query", |b| {
        let uri: Uri = "/search?q=test&page=1&limit=10".parse().unwrap();
        b.iter(|| parse_upstream_url(black_box("http://backend:3000"), black_box(&uri)))
    });

    // With upstream path
    group.bench_function("with_upstream_path", |b| {
        let uri: Uri = "/users/123".parse().unwrap();
        b.iter(|| parse_upstream_url(black_box("http://api:3000/v1"), black_box(&uri)))
    });

    // Complex wiki-style path
    group.bench_function("wiki_style", |b| {
        let uri: Uri = "/w/index.php?title=Main_Page&action=render".parse().unwrap();
        b.iter(|| parse_upstream_url(black_box("http://varnish:80"), black_box(&uri)))
    });

    // HTTPS upstream
    group.bench_function("https", |b| {
        let uri: Uri = "/secure/api".parse().unwrap();
        b.iter(|| parse_upstream_url(black_box("https://secure-backend:8443"), black_box(&uri)))
    });

    // Very long path
    group.bench_function("long_path", |b| {
        let long_path = format!("/api/v1/{}", "segment/".repeat(50));
        let uri: Uri = long_path.parse().unwrap();
        b.iter(|| parse_upstream_url(black_box("http://backend:3000"), black_box(&uri)))
    });

    group.finish();
}

fn bench_extract_host_port(c: &mut Criterion) {
    let mut group = c.benchmark_group("extract_host_port");
    group.throughput(Throughput::Elements(1));

    group.bench_function("http_explicit_port", |b| {
        b.iter(|| extract_host_port(black_box("http://example.com:8080/path")))
    });

    group.bench_function("http_default_port", |b| {
        b.iter(|| extract_host_port(black_box("http://example.com/path")))
    });

    group.bench_function("https_default_port", |b| {
        b.iter(|| extract_host_port(black_box("https://example.com/path")))
    });

    group.bench_function("localhost", |b| {
        b.iter(|| extract_host_port(black_box("http://localhost:3000")))
    });

    group.bench_function("docker_style", |b| {
        b.iter(|| extract_host_port(black_box("http://api-service-backend:8080")))
    });

    group.bench_function("ipv4", |b| {
        b.iter(|| extract_host_port(black_box("http://192.168.1.100:9000/api")))
    });

    group.finish();
}

// =============================================================================
// Header manipulation benchmarks
// =============================================================================

/// Remove hop-by-hop headers (mirrors proxy::remove_hop_headers)
fn remove_hop_headers(headers: &mut HeaderMap) {
    const HOP_HEADERS: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    for header in HOP_HEADERS {
        headers.remove(*header);
    }
}

/// Add X-Forwarded headers (mirrors proxy::add_forwarded_headers)
fn add_forwarded_headers<B>(headers: &mut HeaderMap, request: &Request<B>) {
    if !headers.contains_key("x-forwarded-proto") {
        let proto = if request.uri().scheme_str() == Some("https") {
            "https"
        } else {
            "http"
        };
        if let Ok(value) = HeaderValue::from_str(proto) {
            headers.insert(HeaderName::from_static("x-forwarded-proto"), value);
        }
    }

    if !headers.contains_key("x-forwarded-host") {
        if let Some(host_hdr) = headers.get(http::header::HOST) {
            headers.insert(
                HeaderName::from_static("x-forwarded-host"),
                host_hdr.clone(),
            );
        }
    }
}

fn bench_remove_hop_headers(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove_hop_headers");
    group.throughput(Throughput::Elements(1));

    // No hop headers present
    group.bench_function("no_hop_headers", |b| {
        b.iter_batched(
            || {
                let mut headers = HeaderMap::new();
                headers.insert("content-type", HeaderValue::from_static("application/json"));
                headers.insert("accept", HeaderValue::from_static("*/*"));
                headers.insert("x-custom", HeaderValue::from_static("value"));
                headers
            },
            |mut headers| {
                remove_hop_headers(black_box(&mut headers));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // All hop headers present
    group.bench_function("all_hop_headers", |b| {
        b.iter_batched(
            || {
                let mut headers = HeaderMap::new();
                headers.insert("connection", HeaderValue::from_static("keep-alive"));
                headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
                headers.insert("proxy-authenticate", HeaderValue::from_static("Basic"));
                headers.insert("proxy-authorization", HeaderValue::from_static("Basic creds"));
                headers.insert("te", HeaderValue::from_static("trailers"));
                headers.insert("trailers", HeaderValue::from_static(""));
                headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
                headers.insert("upgrade", HeaderValue::from_static("websocket"));
                headers.insert("content-type", HeaderValue::from_static("application/json"));
                headers
            },
            |mut headers| {
                remove_hop_headers(black_box(&mut headers));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Mixed headers (realistic scenario)
    group.bench_function("mixed_headers", |b| {
        b.iter_batched(
            || {
                let mut headers = HeaderMap::new();
                headers.insert("content-type", HeaderValue::from_static("application/json"));
                headers.insert("content-length", HeaderValue::from_static("1234"));
                headers.insert("connection", HeaderValue::from_static("keep-alive"));
                headers.insert("accept", HeaderValue::from_static("*/*"));
                headers.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
                headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
                headers.insert("x-request-id", HeaderValue::from_static("abc123"));
                headers
            },
            |mut headers| {
                remove_hop_headers(black_box(&mut headers));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Large header map
    group.bench_function("large_header_map", |b| {
        b.iter_batched(
            || {
                let mut headers = HeaderMap::new();
                for i in 0..50 {
                    let name = format!("x-custom-header-{}", i);
                    headers.insert(
                        HeaderName::from_str(&name).unwrap(),
                        HeaderValue::from_static("value"),
                    );
                }
                headers.insert("connection", HeaderValue::from_static("keep-alive"));
                headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
                headers
            },
            |mut headers| {
                remove_hop_headers(black_box(&mut headers));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_add_forwarded_headers(c: &mut Criterion) {
    let mut group = c.benchmark_group("add_forwarded_headers");
    group.throughput(Throughput::Elements(1));

    // HTTP request
    group.bench_function("http_request", |b| {
        b.iter_batched(
            || {
                let request = Request::builder()
                    .uri("http://example.com/path")
                    .header("host", "example.com")
                    .body(())
                    .unwrap();
                let headers = request.headers().clone();
                (request, headers)
            },
            |(request, mut headers)| {
                add_forwarded_headers(black_box(&mut headers), black_box(&request));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // HTTPS request
    group.bench_function("https_request", |b| {
        b.iter_batched(
            || {
                let request = Request::builder()
                    .uri("https://secure.example.com/path")
                    .header("host", "secure.example.com")
                    .body(())
                    .unwrap();
                let headers = request.headers().clone();
                (request, headers)
            },
            |(request, mut headers)| {
                add_forwarded_headers(black_box(&mut headers), black_box(&request));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Already has forwarded headers
    group.bench_function("existing_forwarded", |b| {
        b.iter_batched(
            || {
                let request = Request::builder()
                    .uri("http://example.com/path")
                    .header("host", "example.com")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "original.example.com")
                    .body(())
                    .unwrap();
                let headers = request.headers().clone();
                (request, headers)
            },
            |(request, mut headers)| {
                add_forwarded_headers(black_box(&mut headers), black_box(&request));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// Header rules application benchmarks
// =============================================================================

/// Header rules structure
#[derive(Debug, Clone, Default)]
struct HeaderRules {
    set: Vec<(String, String)>,
    set_if_empty: Vec<(String, String)>,
    merge: Vec<(String, String)>,
    unset: Vec<String>,
}

/// Apply header rules to response (mirrors middleware::apply_response_headers)
fn apply_response_headers<B>(response: &mut Response<B>, rules: &HeaderRules) {
    let headers = response.headers_mut();

    // First, apply unsets
    for name in &rules.unset {
        if let Ok(header_name) = HeaderName::from_str(name) {
            headers.remove(&header_name);
        }
    }

    // Apply set-if-empty
    for (name, value) in &rules.set_if_empty {
        if let (Ok(header_name), Ok(header_value)) =
            (HeaderName::from_str(name), HeaderValue::from_str(value))
        {
            if !headers.contains_key(&header_name) {
                headers.insert(header_name, header_value);
            }
        }
    }

    // Apply merges
    for (name, value) in &rules.merge {
        if let (Ok(header_name), Ok(header_value)) =
            (HeaderName::from_str(name), HeaderValue::from_str(value))
        {
            if let Some(existing) = headers.get(&header_name) {
                let merged = format!("{}, {}", existing.to_str().unwrap_or(""), value);
                if let Ok(merged_value) = HeaderValue::from_str(&merged) {
                    headers.insert(header_name, merged_value);
                }
            } else {
                headers.insert(header_name, header_value);
            }
        }
    }

    // Apply sets
    for (name, value) in &rules.set {
        if let (Ok(header_name), Ok(header_value)) =
            (HeaderName::from_str(name), HeaderValue::from_str(value))
        {
            headers.insert(header_name, header_value);
        }
    }
}

fn bench_apply_header_rules(c: &mut Criterion) {
    let mut group = c.benchmark_group("apply_header_rules");
    group.throughput(Throughput::Elements(1));

    // Empty rules
    group.bench_function("empty_rules", |b| {
        let rules = HeaderRules::default();
        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html")
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Security headers (typical production setup)
    group.bench_function("security_headers", |b| {
        let rules = HeaderRules {
            set_if_empty: vec![
                ("X-Xss-Protection".to_string(), "1; mode=block".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
                ("Referrer-Policy".to_string(), "origin".to_string()),
            ],
            unset: vec![
                "X-Powered-By".to_string(),
                "Via".to_string(),
                "x-varnish".to_string(),
            ],
            merge: vec![(
                "Cache-Control".to_string(),
                "public, max-age=7200".to_string(),
            )],
            set: vec![],
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html")
                    .header("X-Powered-By", "PHP")
                    .header("Via", "varnish")
                    .header("Cache-Control", "private")
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Many set rules
    group.bench_function("many_set_rules", |b| {
        let rules = HeaderRules {
            set: (0..20)
                .map(|i| (format!("X-Custom-{}", i), format!("value{}", i)))
                .collect(),
            ..Default::default()
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Complex mixed rules
    group.bench_function("complex_mixed", |b| {
        let rules = HeaderRules {
            set: vec![
                ("X-Server".to_string(), "styx".to_string()),
                ("Surrogate-Key".to_string(), "main api".to_string()),
            ],
            set_if_empty: vec![
                ("X-Frame-Options".to_string(), "DENY".to_string()),
                ("X-XSS-Protection".to_string(), "1; mode=block".to_string()),
            ],
            merge: vec![
                ("Vary".to_string(), "Accept-Encoding".to_string()),
                ("Cache-Control".to_string(), "max-age=3600".to_string()),
            ],
            unset: vec![
                "Server".to_string(),
                "X-Powered-By".to_string(),
                "X-AspNet-Version".to_string(),
            ],
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("server", "Apache")
                    .header("X-Powered-By", "PHP/7.4")
                    .header("Cache-Control", "public")
                    .header("Vary", "Cookie")
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// =============================================================================
// Response creation benchmarks
// =============================================================================

fn bench_response_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_creation");
    group.throughput(Throughput::Elements(1));

    // Error response
    group.bench_function("error_response", |b| {
        b.iter(|| {
            Response::builder()
                .status(black_box(StatusCode::NOT_FOUND))
                .header("Content-Type", "text/plain; charset=utf-8")
                .body("Page not found")
                .unwrap()
        })
    });

    // Redirect response
    group.bench_function("redirect_response", |b| {
        b.iter(|| {
            Response::builder()
                .status(black_box(StatusCode::MOVED_PERMANENTLY))
                .header("Location", "https://example.com/new-location")
                .header("Content-Type", "text/html; charset=utf-8")
                .body("<html><body>Redirecting...</body></html>")
                .unwrap()
        })
    });

    // Status response (JSON)
    group.bench_function("status_response", |b| {
        b.iter(|| {
            Response::builder()
                .status(black_box(StatusCode::OK))
                .header("Content-Type", "application/json")
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .body(r#"{"status":"ok"}"#)
                .unwrap()
        })
    });

    // Response with many headers
    group.bench_function("many_headers", |b| {
        b.iter(|| {
            Response::builder()
                .status(black_box(StatusCode::OK))
                .header("Content-Type", "text/html")
                .header("Content-Length", "12345")
                .header("Cache-Control", "public, max-age=3600")
                .header("ETag", "\"abc123\"")
                .header("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Frame-Options", "DENY")
                .header("X-XSS-Protection", "1; mode=block")
                .header("Strict-Transport-Security", "max-age=31536000")
                .header("Referrer-Policy", "origin")
                .body("Hello, World!")
                .unwrap()
        })
    });

    group.finish();
}

// =============================================================================
// URI parsing benchmarks
// =============================================================================

fn bench_uri_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("uri_parsing");
    group.throughput(Throughput::Elements(1));

    group.bench_function("simple_path", |b| {
        b.iter(|| black_box("/api/v1/users").parse::<Uri>())
    });

    group.bench_function("with_query", |b| {
        b.iter(|| black_box("/search?q=test&page=1&limit=10").parse::<Uri>())
    });

    group.bench_function("full_url", |b| {
        b.iter(|| black_box("http://example.com:8080/api/v1/users?id=123").parse::<Uri>())
    });

    group.bench_function("complex_path", |b| {
        b.iter(|| black_box("/w/index.php?title=Main_Page&action=render").parse::<Uri>())
    });

    group.bench_function("encoded_path", |b| {
        b.iter(|| black_box("/wiki/Test%20Page%2FSubpage").parse::<Uri>())
    });

    group.finish();
}

// =============================================================================
// Header map operations benchmarks
// =============================================================================

fn bench_header_map_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_map_operations");
    group.throughput(Throughput::Elements(1));

    // Insert
    group.bench_function("insert_single", |b| {
        b.iter_batched(
            HeaderMap::new,
            |mut map| {
                map.insert(
                    black_box(http::header::CONTENT_TYPE),
                    black_box(HeaderValue::from_static("application/json")),
                );
                map
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Get
    group.bench_function("get_existing", |b| {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        b.iter(|| map.get(black_box(http::header::CONTENT_TYPE)))
    });

    // Get missing
    group.bench_function("get_missing", |b| {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        b.iter(|| map.get(black_box(http::header::ACCEPT)))
    });

    // Contains
    group.bench_function("contains_key", |b| {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        b.iter(|| map.contains_key(black_box(http::header::CONTENT_TYPE)))
    });

    // Remove
    group.bench_function("remove", |b| {
        b.iter_batched(
            || {
                let mut map = HeaderMap::new();
                map.insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                map
            },
            |mut map| {
                map.remove(black_box(http::header::CONTENT_TYPE));
                map
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Clone header map
    group.bench_function("clone_small", |b| {
        let mut map = HeaderMap::new();
        map.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        map.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_static("1234"),
        );
        map.insert(http::header::HOST, HeaderValue::from_static("example.com"));
        b.iter(|| black_box(&map).clone())
    });

    group.bench_function("clone_large", |b| {
        let mut map = HeaderMap::new();
        for i in 0..50 {
            let name = format!("x-custom-{}", i);
            map.insert(
                HeaderName::from_str(&name).unwrap(),
                HeaderValue::from_static("value"),
            );
        }
        b.iter(|| black_box(&map).clone())
    });

    group.finish();
}

// =============================================================================
// Iteration benchmarks for scaling
// =============================================================================

fn bench_url_parsing_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("url_parsing_scaling");

    for path_segments in [1, 5, 10, 20, 50].iter() {
        let path = format!(
            "/{}",
            (0..*path_segments)
                .map(|i| format!("segment{}", i))
                .collect::<Vec<_>>()
                .join("/")
        );

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("path_segments", path_segments),
            &path,
            |b, path| {
                let uri: Uri = path.parse().unwrap();
                b.iter(|| parse_upstream_url(black_box("http://backend:3000"), black_box(&uri)))
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_upstream_url,
    bench_extract_host_port,
    bench_remove_hop_headers,
    bench_add_forwarded_headers,
    bench_apply_header_rules,
    bench_response_creation,
    bench_uri_parsing,
    bench_header_map_operations,
    bench_url_parsing_scaling,
);

criterion_main!(benches);
