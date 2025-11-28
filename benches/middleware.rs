//! Middleware benchmarks
//!
//! Benchmarks for header manipulation, response generation, and middleware operations.

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use http::{header, HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use std::str::FromStr;

// =============================================================================
// Types
// =============================================================================

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

// =============================================================================
// Middleware implementations (mirroring middleware module)
// =============================================================================

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
                let separator = if name.eq_ignore_ascii_case("cache-control")
                    || name.eq_ignore_ascii_case("pragma")
                {
                    ", "
                } else {
                    ", "
                };

                let merged = format!(
                    "{}{}{}",
                    existing.to_str().unwrap_or(""),
                    separator,
                    value
                );

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

fn apply_request_headers(headers: &mut HeaderMap, rules: &HeaderRules) {
    // Apply unsets
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
            headers.append(header_name, header_value);
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

fn default_security_headers() -> HeaderRules {
    HeaderRules {
        set_if_empty: vec![
            ("X-Xss-Protection".to_string(), "1; mode=block".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
            (
                "Access-Control-Allow-Headers".to_string(),
                "Origin, X-Requested-With, Content-Type, Accept".to_string(),
            ),
            ("Referrer-Policy".to_string(), "origin".to_string()),
        ],
        unset: vec![
            "X-Powered-By".to_string(),
            "Via".to_string(),
            "x-varnish".to_string(),
        ],
        merge: vec![(
            "Cache-Control".to_string(),
            "public, stale-while-revalidate=31536000, stale-if-error=31536000, max-age=7200, max-stale=86400".to_string(),
        )],
        set: vec![],
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(Bytes::from(message.to_string()))
        .unwrap()
}

fn redirect_response(status: u16, location: &str) -> Response<Bytes> {
    let body = format!(
        "<!DOCTYPE html>\n<html><head><title>Redirect</title></head>\n\
         <body><h1>{}</h1><p>Redirecting to <a href=\"{}\">{}</a></p></body></html>",
        status, location, location
    );

    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::MOVED_PERMANENTLY))
        .header("Location", location)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Bytes::from(body))
        .unwrap()
}

fn status_response() -> Response<Bytes> {
    let body = r#"{"status":"ok"}"#;

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(Bytes::from(body))
        .unwrap()
}

// =============================================================================
// Benchmarks
// =============================================================================

fn bench_header_manipulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_manipulation");
    group.throughput(Throughput::Elements(1));

    // Set headers
    group.bench_function("set_single", |b| {
        let rules = HeaderRules {
            set: vec![("X-Custom".to_string(), "value".to_string())],
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

    group.bench_function("set_multiple", |b| {
        let rules = HeaderRules {
            set: (0..10)
                .map(|i| (format!("X-Header-{}", i), format!("value{}", i)))
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

    // Unset headers
    group.bench_function("unset_single", |b| {
        let rules = HeaderRules {
            unset: vec!["X-Powered-By".to_string()],
            ..Default::default()
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("X-Powered-By", "PHP")
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

    group.bench_function("unset_multiple", |b| {
        let rules = HeaderRules {
            unset: vec![
                "X-Powered-By".to_string(),
                "Server".to_string(),
                "Via".to_string(),
                "X-Varnish".to_string(),
                "X-AspNet-Version".to_string(),
            ],
            ..Default::default()
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("X-Powered-By", "PHP")
                    .header("Server", "Apache")
                    .header("Via", "varnish")
                    .header("X-Varnish", "12345")
                    .header("X-AspNet-Version", "4.0")
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

    // Set-if-empty
    group.bench_function("set_if_empty_new", |b| {
        let rules = HeaderRules {
            set_if_empty: vec![("X-Security".to_string(), "enabled".to_string())],
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

    group.bench_function("set_if_empty_existing", |b| {
        let rules = HeaderRules {
            set_if_empty: vec![("X-Security".to_string(), "enabled".to_string())],
            ..Default::default()
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("X-Security", "already-set")
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

    // Merge
    group.bench_function("merge_new", |b| {
        let rules = HeaderRules {
            merge: vec![("Cache-Control".to_string(), "max-age=3600".to_string())],
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

    group.bench_function("merge_existing", |b| {
        let rules = HeaderRules {
            merge: vec![("Cache-Control".to_string(), "max-age=3600".to_string())],
            ..Default::default()
        };

        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Cache-Control", "public")
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

fn bench_security_headers(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_headers");
    group.throughput(Throughput::Elements(1));

    let security_rules = default_security_headers();

    // Clean response (no headers to remove)
    group.bench_function("clean_response", |b| {
        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html")
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&security_rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Dirty response (has headers to strip)
    group.bench_function("dirty_response", |b| {
        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html")
                    .header("X-Powered-By", "PHP/7.4")
                    .header("Via", "1.1 varnish")
                    .header("x-varnish", "12345 67890")
                    .header("Cache-Control", "private")
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&security_rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Partially secure (some headers already set)
    group.bench_function("partially_secure", |b| {
        b.iter_batched(
            || {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "DENY")
                    .body(())
                    .unwrap()
            },
            |mut response| {
                apply_response_headers(black_box(&mut response), black_box(&security_rules));
                response
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_request_headers(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_headers");
    group.throughput(Throughput::Elements(1));

    // Proxy headers (typical usage)
    group.bench_function("proxy_headers", |b| {
        let rules = HeaderRules {
            set: vec![
                ("X-Forwarded-Proto".to_string(), "https".to_string()),
                ("X-Real-IP".to_string(), "192.168.1.100".to_string()),
            ],
            unset: vec!["X-Internal-Token".to_string()],
            ..Default::default()
        };

        b.iter_batched(
            || {
                let mut headers = HeaderMap::new();
                headers.insert(header::HOST, HeaderValue::from_static("example.com"));
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                headers.insert(
                    HeaderName::from_static("x-internal-token"),
                    HeaderValue::from_static("secret"),
                );
                headers
            },
            |mut headers| {
                apply_request_headers(black_box(&mut headers), black_box(&rules));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    // Large request headers
    group.bench_function("large_request", |b| {
        let rules = HeaderRules {
            set: vec![("X-Proxy".to_string(), "styx".to_string())],
            ..Default::default()
        };

        b.iter_batched(
            || {
                let mut headers = HeaderMap::new();
                for i in 0..30 {
                    let name = format!("x-custom-{}", i);
                    headers.insert(
                        HeaderName::from_str(&name).unwrap(),
                        HeaderValue::from_static("value"),
                    );
                }
                headers
            },
            |mut headers| {
                apply_request_headers(black_box(&mut headers), black_box(&rules));
                headers
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_header_rules_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_rules_merge");
    group.throughput(Throughput::Elements(1));

    // Small rules merge
    group.bench_function("small", |b| {
        let rules1 = HeaderRules {
            set: vec![("X-Header-1".to_string(), "value1".to_string())],
            unset: vec!["X-Remove".to_string()],
            ..Default::default()
        };

        let rules2 = HeaderRules {
            set: vec![("X-Header-2".to_string(), "value2".to_string())],
            set_if_empty: vec![("X-Default".to_string(), "default".to_string())],
            ..Default::default()
        };

        b.iter(|| rules1.merge_with(black_box(&rules2)))
    });

    // Large rules merge
    group.bench_function("large", |b| {
        let rules1 = HeaderRules {
            set: (0..20)
                .map(|i| (format!("X-Set-A-{}", i), format!("value{}", i)))
                .collect(),
            set_if_empty: (0..10)
                .map(|i| (format!("X-Default-A-{}", i), format!("default{}", i)))
                .collect(),
            merge: (0..5)
                .map(|i| (format!("X-Merge-A-{}", i), format!("merge{}", i)))
                .collect(),
            unset: (0..10).map(|i| format!("X-Unset-A-{}", i)).collect(),
        };

        let rules2 = HeaderRules {
            set: (0..10)
                .map(|i| (format!("X-Set-B-{}", i), format!("value{}", i)))
                .collect(),
            set_if_empty: (0..5)
                .map(|i| (format!("X-Default-B-{}", i), format!("default{}", i)))
                .collect(),
            merge: (0..3)
                .map(|i| (format!("X-Merge-B-{}", i), format!("merge{}", i)))
                .collect(),
            unset: (0..5).map(|i| format!("X-Unset-B-{}", i)).collect(),
        };

        b.iter(|| rules1.merge_with(black_box(&rules2)))
    });

    group.finish();
}

fn bench_response_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_creation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("error_404", |b| {
        b.iter(|| error_response(black_box(StatusCode::NOT_FOUND), black_box("Page not found")))
    });

    group.bench_function("error_500", |b| {
        b.iter(|| {
            error_response(
                black_box(StatusCode::INTERNAL_SERVER_ERROR),
                black_box("Internal server error"),
            )
        })
    });

    group.bench_function("redirect_301", |b| {
        b.iter(|| redirect_response(black_box(301), black_box("https://example.com/new")))
    });

    group.bench_function("redirect_302", |b| {
        b.iter(|| redirect_response(black_box(302), black_box("https://example.com/temp")))
    });

    group.bench_function("status", |b| {
        b.iter(|| status_response())
    });

    // With long URLs
    group.bench_function("redirect_long_url", |b| {
        let url = format!(
            "https://example.com/very/long/path/{}?query=params&more=values",
            "segment/".repeat(20)
        );
        b.iter(|| redirect_response(black_box(301), black_box(&url)))
    });

    group.finish();
}

fn bench_header_name_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_name_parsing");
    group.throughput(Throughput::Elements(1));

    group.bench_function("standard", |b| {
        b.iter(|| HeaderName::from_str(black_box("Content-Type")))
    });

    group.bench_function("custom", |b| {
        b.iter(|| HeaderName::from_str(black_box("X-Custom-Header")))
    });

    group.bench_function("lowercase", |b| {
        b.iter(|| HeaderName::from_str(black_box("x-custom-header")))
    });

    group.bench_function("uppercase", |b| {
        b.iter(|| HeaderName::from_str(black_box("X-CUSTOM-HEADER")))
    });

    group.bench_function("long", |b| {
        b.iter(|| HeaderName::from_str(black_box("X-Very-Long-Custom-Header-Name-That-Spans-Many-Characters")))
    });

    group.finish();
}

fn bench_header_value_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_value_parsing");
    group.throughput(Throughput::Elements(1));

    group.bench_function("simple", |b| {
        b.iter(|| HeaderValue::from_str(black_box("value")))
    });

    group.bench_function("with_spaces", |b| {
        b.iter(|| HeaderValue::from_str(black_box("value with spaces")))
    });

    group.bench_function("url", |b| {
        b.iter(|| HeaderValue::from_str(black_box("https://example.com/path?query=value")))
    });

    group.bench_function("cache_control", |b| {
        b.iter(|| {
            HeaderValue::from_str(black_box(
                "public, max-age=31536000, stale-while-revalidate=86400, immutable",
            ))
        })
    });

    group.bench_function("cors_headers", |b| {
        b.iter(|| {
            HeaderValue::from_str(black_box(
                "Origin, X-Requested-With, Content-Type, Accept, Authorization",
            ))
        })
    });

    group.finish();
}

fn bench_combined_operations_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("combined_operations_scaling");
    group.throughput(Throughput::Elements(1));

    for num_rules in [1, 5, 10, 20, 50].iter() {
        let rules = HeaderRules {
            set: (0..*num_rules)
                .map(|i| (format!("X-Set-{}", i), format!("value{}", i)))
                .collect(),
            set_if_empty: (0..(*num_rules / 2))
                .map(|i| (format!("X-Default-{}", i), format!("default{}", i)))
                .collect(),
            unset: (0..(*num_rules / 4)).map(|i| format!("X-Unset-{}", i)).collect(),
            merge: (0..(*num_rules / 4))
                .map(|i| (format!("X-Merge-{}", i), format!("merge{}", i)))
                .collect(),
        };

        group.bench_with_input(
            BenchmarkId::new("num_rules", num_rules),
            &rules,
            |b, rules| {
                b.iter_batched(
                    || {
                        let mut response = Response::builder().status(StatusCode::OK);

                        // Add some headers that will be affected
                        for i in 0..(*num_rules / 4) {
                            response = response.header(format!("X-Unset-{}", i), "to-remove");
                            response = response.header(format!("X-Merge-{}", i), "base");
                        }

                        response.body(()).unwrap()
                    },
                    |mut response| {
                        apply_response_headers(black_box(&mut response), black_box(rules));
                        response
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_header_manipulation,
    bench_security_headers,
    bench_request_headers,
    bench_header_rules_merge,
    bench_response_creation,
    bench_header_name_parsing,
    bench_header_value_parsing,
    bench_combined_operations_scaling,
);

criterion_main!(benches);
