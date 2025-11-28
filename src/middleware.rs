//! Middleware for header manipulation and request/response processing
//!
//! This module implements h2o-compatible header manipulation:
//! - header.set: Always set the header value
//! - header.setifempty: Set only if header doesn't exist
//! - header.merge: Append value (comma-separated for most headers)
//! - header.unset: Remove the header

use crate::config::HeaderRules;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use http_body_util::Full;
use std::str::FromStr;

/// Apply header rules to a response
pub fn apply_response_headers<B>(response: &mut Response<B>, rules: &HeaderRules) {
    let headers = response.headers_mut();

    // First, apply unsets
    for name in &rules.unset {
        if let Ok(header_name) = HeaderName::from_str(name) {
            headers.remove(&header_name);
        }
    }

    // Apply set-if-empty
    for (name, value) in &rules.set_if_empty {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_str(name),
            HeaderValue::from_str(value),
        ) {
            if !headers.contains_key(&header_name) {
                headers.insert(header_name, header_value);
            }
        }
    }

    // Apply merges (append to existing)
    for (name, value) in &rules.merge {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_str(name),
            HeaderValue::from_str(value),
        ) {
            // Set-Cookie should use append, not comma merge
            if name.eq_ignore_ascii_case("set-cookie") {
                headers.append(header_name, header_value);
            } else if let Some(existing) = headers.get(&header_name) {
                // Merge: append with comma separator for most headers
                let separator = ", ";
                let existing_str = existing.to_str().unwrap_or("");

                // Check if value is already present in existing header (idempotent merge)
                // This prevents duplication in proxy loop scenarios
                // Handle both exact match and substring match with proper boundaries
                if existing_str == value {
                    // Exact match - value is already the entire header
                    continue;
                }

                // Check if value appears as a complete segment (with comma boundaries)
                // For "public, max-age=3600", check boundaries: start, ", {value}", or "{value}, "
                let value_with_leading = format!(", {}", value);
                let value_with_trailing = format!("{}, ", value);
                if existing_str.starts_with(&format!("{}, ", value))
                    || existing_str.ends_with(&value_with_leading)
                    || existing_str.contains(&value_with_trailing) {
                    // Value already present as a complete segment
                    continue;
                }

                let merged = format!(
                    "{}{}{}",
                    existing_str,
                    separator,
                    value
                );

                // Limit header value length to prevent unbounded growth
                const MAX_HEADER_VALUE_LENGTH: usize = 8192;
                if merged.len() > MAX_HEADER_VALUE_LENGTH {
                    // Silently truncate or skip - don't allow unbounded growth
                    continue;
                }

                if let Ok(merged_value) = HeaderValue::from_str(&merged) {
                    headers.insert(header_name, merged_value);
                }
            } else {
                // Check initial value length too
                if value.len() > 8192 {
                    continue;
                }
                headers.insert(header_name, header_value);
            }
        }
    }

    // Apply sets (override everything)
    for (name, value) in &rules.set {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_str(name),
            HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }
}

/// Apply header rules to a request (for proxy headers)
pub fn apply_request_headers(headers: &mut HeaderMap, rules: &HeaderRules) {
    // Apply unsets
    for name in &rules.unset {
        if let Ok(header_name) = HeaderName::from_str(name) {
            headers.remove(&header_name);
        }
    }

    // Apply set-if-empty
    for (name, value) in &rules.set_if_empty {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_str(name),
            HeaderValue::from_str(value),
        ) {
            if !headers.contains_key(&header_name) {
                headers.insert(header_name, header_value);
            }
        }
    }

    // Apply merges
    for (name, value) in &rules.merge {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_str(name),
            HeaderValue::from_str(value),
        ) {
            headers.append(header_name, header_value);
        }
    }

    // Apply sets
    for (name, value) in &rules.set {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_str(name),
            HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }
}

/// Standard security headers
///
/// Provides basic security headers that don't break functionality.
/// For stricter policies (CSP, HSTS, Permissions-Policy), configure them explicitly in your config.
pub fn default_security_headers() -> HeaderRules {
    HeaderRules {
        set_if_empty: vec![
            ("X-Xss-Protection".to_string(), "1; mode=block".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            ("Referrer-Policy".to_string(), "strict-origin-when-cross-origin".to_string()),
            ("X-Frame-Options".to_string(), "SAMEORIGIN".to_string()),
            // Cache-Control: only set if upstream doesn't provide it (use set_if_empty not merge)
            (
                "Cache-Control".to_string(),
                "public, stale-while-revalidate=31536000, stale-if-error=31536000, max-age=7200, max-stale=86400".to_string(),
            ),
            // CORS explicitly removed - admins should configure if needed
            // CSP removed from defaults - too strict, breaks directory listings and inline scripts
            // HSTS removed from defaults - should be opt-in as it locks users into HTTPS
            // Permissions-Policy removed from defaults - features not widely supported
        ],
        unset: vec![
            "X-Powered-By".to_string(),
            "Via".to_string(),
            "x-varnish".to_string(),
            "Server".to_string(), // Hide server version
        ],
        merge: vec![],
        set: vec![],
    }
}

/// Create an error response
pub fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    // Use unwrap_or_else instead of unwrap for safer error handling
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| {
            // Fallback: minimal response if builder fails
            Response::new(Full::new(Bytes::from("Internal Server Error")))
        })
}

/// Create a redirect response
pub fn redirect_response(status: u16, location: &str) -> Response<Full<Bytes>> {
    // Validate redirect URL
    if !is_safe_redirect_url(location) {
        // If URL is invalid/unsafe, return error instead of redirecting
        return error_response(StatusCode::BAD_REQUEST, "Invalid redirect URL");
    }

    // Sanitize location header value to prevent response splitting
    let sanitized_location = location
        .replace('\r', "")
        .replace('\n', "");

    let body = format!(
        "<!DOCTYPE html>\n<html><head><title>Redirect</title></head>\n\
         <body><h1>{}</h1><p>Redirecting to <a href=\"{}\">{}</a></p></body></html>",
        status,
        html_escape(&sanitized_location),
        html_escape(&sanitized_location)
    );

    // Use unwrap_or_else instead of unwrap for safer error handling
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::MOVED_PERMANENTLY))
        .header("Location", sanitized_location)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            // Fallback: minimal redirect response if builder fails
            Response::new(Full::new(Bytes::from("Redirect")))
        })
}

/// Validate redirect URL to prevent open redirect attacks
fn is_safe_redirect_url(url: &str) -> bool {
    // Check for CRLF injection
    if url.contains('\r') || url.contains('\n') || url.contains('\0') {
        return false;
    }

    // Check length to prevent DoS
    if url.len() > 2048 {
        return false;
    }

    // Reject backslash (Windows path confusion)
    if url.contains('\\') {
        return false;
    }

    // Reject URLs starting with @ (some browsers interpret /@evil.com as scheme://user@evil.com)
    if url.starts_with("/@") {
        return false;
    }

    // Allow relative URLs (safe - stay on same host)
    if url.starts_with('/') && !url.starts_with("//") {
        return true;
    }

    // For absolute URLs, validate scheme
    if let Ok(parsed) = url.parse::<http::Uri>() {
        if let Some(scheme) = parsed.scheme_str() {
            // Only allow http/https schemes
            if scheme == "http" || scheme == "https" {
                // Could add additional host validation here if needed
                return true;
            }
        }
    }

    // Reject javascript:, data:, file:, etc.
    false
}

/// HTML escape for use in redirect response body
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Create a status page response
pub fn status_response() -> Response<Full<Bytes>> {
    let body = r#"{"status":"ok"}"#;

    // Use unwrap_or_else instead of unwrap for safer error handling
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            // Fallback: minimal status response if builder fails
            Response::new(Full::new(Bytes::from(r#"{"status":"ok"}"#)))
        })
}

/// Apply expires directive to response headers
/// - None: don't modify headers
/// - Some(None): expires "off" - remove cache headers
/// - Some(Some(0)): expires "0 seconds" - no-cache
/// - Some(Some(secs)): expires "N unit" - set max-age
pub fn apply_expires<B>(response: &mut Response<B>, expires: Option<Option<u64>>) {
    let headers = response.headers_mut();

    match expires {
        None => {
            // No expires directive - don't modify
        }
        Some(None) => {
            // expires: off - remove cache control headers
            headers.remove("Cache-Control");
            headers.remove("Expires");
        }
        Some(Some(0)) => {
            // expires: 0 seconds - no caching
            if let Ok(value) = HeaderValue::from_str("no-cache, no-store, must-revalidate") {
                headers.insert("Cache-Control", value);
            }
        }
        Some(Some(secs)) => {
            // expires: N unit - set max-age
            let cache_control = format!("max-age={}", secs);
            if let Ok(value) = HeaderValue::from_str(&cache_control) {
                headers.insert("Cache-Control", value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // apply_response_headers - set tests
    // =====================================================================

    #[test]
    fn test_apply_set_header() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![("X-Custom".to_string(), "value".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(
            response.headers().get("X-Custom").unwrap(),
            "value"
        );
    }

    #[test]
    fn test_apply_set_overwrites_existing() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Custom", "original")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![("X-Custom".to_string(), "new_value".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(
            response.headers().get("X-Custom").unwrap(),
            "new_value"
        );
    }

    #[test]
    fn test_apply_set_multiple_headers() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![
                ("X-Header-1".to_string(), "value1".to_string()),
                ("X-Header-2".to_string(), "value2".to_string()),
                ("X-Header-3".to_string(), "value3".to_string()),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(response.headers().get("X-Header-1").unwrap(), "value1");
        assert_eq!(response.headers().get("X-Header-2").unwrap(), "value2");
        assert_eq!(response.headers().get("X-Header-3").unwrap(), "value3");
    }

    #[test]
    fn test_apply_set_case_insensitive() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("x-custom", "original")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![("X-CUSTOM".to_string(), "new".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        // HTTP headers are case-insensitive
        assert_eq!(
            response.headers().get("x-custom").unwrap(),
            "new"
        );
    }

    // =====================================================================
    // apply_response_headers - set_if_empty tests
    // =====================================================================

    #[test]
    fn test_apply_set_if_empty() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Existing", "original")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set_if_empty: vec![
                ("X-Existing".to_string(), "new".to_string()),
                ("X-New".to_string(), "value".to_string()),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        // Existing header should not be changed
        assert_eq!(
            response.headers().get("X-Existing").unwrap(),
            "original"
        );
        // New header should be set
        assert_eq!(
            response.headers().get("X-New").unwrap(),
            "value"
        );
    }

    #[test]
    fn test_apply_set_if_empty_all_new() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set_if_empty: vec![
                ("X-Security".to_string(), "enabled".to_string()),
                ("X-Frame-Options".to_string(), "DENY".to_string()),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(response.headers().get("X-Security").unwrap(), "enabled");
        assert_eq!(response.headers().get("X-Frame-Options").unwrap(), "DENY");
    }

    #[test]
    fn test_apply_set_if_empty_case_insensitive() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("x-existing", "original")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set_if_empty: vec![("X-EXISTING".to_string(), "new".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        // Should NOT overwrite because header exists (case-insensitive)
        assert_eq!(
            response.headers().get("x-existing").unwrap(),
            "original"
        );
    }

    // =====================================================================
    // apply_response_headers - unset tests
    // =====================================================================

    #[test]
    fn test_apply_unset() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Remove-Me", "value")
            .header("X-Keep-Me", "value")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            unset: vec!["X-Remove-Me".to_string()],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert!(response.headers().get("X-Remove-Me").is_none());
        assert!(response.headers().get("X-Keep-Me").is_some());
    }

    #[test]
    fn test_apply_unset_multiple() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Powered-By", "PHP")
            .header("Via", "proxy")
            .header("X-Varnish", "12345")
            .header("X-Keep", "value")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            unset: vec![
                "X-Powered-By".to_string(),
                "Via".to_string(),
                "X-Varnish".to_string(),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert!(response.headers().get("X-Powered-By").is_none());
        assert!(response.headers().get("Via").is_none());
        assert!(response.headers().get("X-Varnish").is_none());
        assert!(response.headers().get("X-Keep").is_some());
    }

    #[test]
    fn test_apply_unset_nonexistent_header() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Existing", "value")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            unset: vec!["X-Nonexistent".to_string()],
            ..Default::default()
        };

        // Should not panic
        apply_response_headers(&mut response, &rules);

        assert!(response.headers().get("X-Existing").is_some());
    }

    #[test]
    fn test_apply_unset_case_insensitive() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("x-powered-by", "value")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            unset: vec!["X-POWERED-BY".to_string()],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert!(response.headers().get("x-powered-by").is_none());
    }

    // =====================================================================
    // apply_response_headers - merge tests
    // =====================================================================

    #[test]
    fn test_apply_merge() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "public")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            merge: vec![("Cache-Control".to_string(), "max-age=3600".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        let cc = response.headers().get("Cache-Control").unwrap().to_str().unwrap();
        assert!(cc.contains("public"));
        assert!(cc.contains("max-age=3600"));
    }

    #[test]
    fn test_apply_merge_creates_if_missing() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            merge: vec![("Cache-Control".to_string(), "max-age=3600".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        let cc = response.headers().get("Cache-Control").unwrap().to_str().unwrap();
        assert_eq!(cc, "max-age=3600");
    }

    #[test]
    fn test_apply_merge_multiple_values() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "public")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            merge: vec![
                ("Cache-Control".to_string(), "max-age=3600".to_string()),
                ("Cache-Control".to_string(), "must-revalidate".to_string()),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        let cc = response.headers().get("Cache-Control").unwrap().to_str().unwrap();
        assert!(cc.contains("public"));
        assert!(cc.contains("max-age=3600"));
        // Note: The current implementation replaces each time, so the final
        // value depends on the order of merge operations
    }

    #[test]
    fn test_apply_merge_idempotent() {
        // Test that merging the same value multiple times doesn't duplicate it
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "public")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            merge: vec![("Cache-Control".to_string(), "max-age=3600".to_string())],
            ..Default::default()
        };

        // Apply the same merge rule multiple times (simulating proxy loop)
        apply_response_headers(&mut response, &rules);
        apply_response_headers(&mut response, &rules);
        apply_response_headers(&mut response, &rules);

        let cc = response.headers().get("Cache-Control").unwrap().to_str().unwrap();

        // Should only appear once, not three times
        assert_eq!(cc, "public, max-age=3600");
    }

    #[test]
    fn test_apply_merge_idempotent_complex() {
        // Test idempotent merge with complex cache-control value
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            merge: vec![(
                "Cache-Control".to_string(),
                "public, stale-while-revalidate=31536000, stale-if-error=31536000, max-age=7200, max-stale=86400".to_string()
            )],
            ..Default::default()
        };

        // Apply multiple times (simulating proxy loop with 10 iterations)
        for _ in 0..10 {
            apply_response_headers(&mut response, &rules);
        }

        let cc = response.headers().get("Cache-Control").unwrap().to_str().unwrap();

        // Should still only be the original value, not duplicated
        assert_eq!(cc, "public, stale-while-revalidate=31536000, stale-if-error=31536000, max-age=7200, max-stale=86400");
    }

    // =====================================================================
    // apply_response_headers - combined rules tests
    // =====================================================================

    #[test]
    fn test_apply_combined_rules_order() {
        // Rules are applied in order: unset, set_if_empty, merge, set
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Remove", "to-remove")
            .header("X-IfEmpty", "original")
            .header("X-Merge", "base")
            .header("X-Set", "original")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            unset: vec!["X-Remove".to_string()],
            set_if_empty: vec![
                ("X-IfEmpty".to_string(), "new".to_string()),
                ("X-NewEmpty".to_string(), "value".to_string()),
            ],
            merge: vec![("X-Merge".to_string(), "merged".to_string())],
            set: vec![("X-Set".to_string(), "overwritten".to_string())],
        };

        apply_response_headers(&mut response, &rules);

        // Unset should remove
        assert!(response.headers().get("X-Remove").is_none());

        // Set-if-empty should NOT overwrite existing
        assert_eq!(response.headers().get("X-IfEmpty").unwrap(), "original");

        // Set-if-empty should add new
        assert_eq!(response.headers().get("X-NewEmpty").unwrap(), "value");

        // Merge should append
        let merge_val = response.headers().get("X-Merge").unwrap().to_str().unwrap();
        assert!(merge_val.contains("base"));
        assert!(merge_val.contains("merged"));

        // Set should overwrite
        assert_eq!(response.headers().get("X-Set").unwrap(), "overwritten");
    }

    #[test]
    fn test_apply_empty_rules() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Original", "value")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules::default();

        apply_response_headers(&mut response, &rules);

        // Should remain unchanged
        assert_eq!(response.headers().get("X-Original").unwrap(), "value");
    }

    // =====================================================================
    // apply_request_headers tests
    // =====================================================================

    #[test]
    fn test_apply_request_headers_set() {
        let mut headers = HeaderMap::new();

        let rules = HeaderRules {
            set: vec![("X-Forwarded-Proto".to_string(), "https".to_string())],
            ..Default::default()
        };

        apply_request_headers(&mut headers, &rules);

        assert_eq!(headers.get("X-Forwarded-Proto").unwrap(), "https");
    }

    #[test]
    fn test_apply_request_headers_unset() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-internal"),
            HeaderValue::from_static("secret"),
        );

        let rules = HeaderRules {
            unset: vec!["X-Internal".to_string()],
            ..Default::default()
        };

        apply_request_headers(&mut headers, &rules);

        assert!(headers.get("x-internal").is_none());
    }

    #[test]
    fn test_apply_request_headers_set_if_empty() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-existing"),
            HeaderValue::from_static("original"),
        );

        let rules = HeaderRules {
            set_if_empty: vec![
                ("X-Existing".to_string(), "new".to_string()),
                ("X-New".to_string(), "value".to_string()),
            ],
            ..Default::default()
        };

        apply_request_headers(&mut headers, &rules);

        assert_eq!(headers.get("x-existing").unwrap(), "original");
        assert_eq!(headers.get("x-new").unwrap(), "value");
    }

    #[test]
    fn test_apply_request_headers_merge() {
        let mut headers = HeaderMap::new();

        let rules = HeaderRules {
            merge: vec![
                ("X-Custom".to_string(), "value1".to_string()),
                ("X-Custom".to_string(), "value2".to_string()),
            ],
            ..Default::default()
        };

        apply_request_headers(&mut headers, &rules);

        // Request headers use append instead of merge
        let values: Vec<_> = headers.get_all("x-custom").iter().collect();
        assert_eq!(values.len(), 2);
    }

    // =====================================================================
    // default_security_headers tests
    // =====================================================================

    #[test]
    fn test_default_security_headers_content() {
        let rules = default_security_headers();

        // Check set_if_empty headers
        assert!(rules.set_if_empty.iter().any(|(n, _)| n == "X-Xss-Protection"));
        assert!(rules.set_if_empty.iter().any(|(n, _)| n == "X-Content-Type-Options"));
        // Removed overly permissive CORS header from defaults
        // assert!(rules.set_if_empty.iter().any(|(n, _)| n == "Access-Control-Allow-Origin"));
        assert!(rules.set_if_empty.iter().any(|(n, _)| n == "Referrer-Policy"));

        // Cache-Control moved to set_if_empty to avoid duplication with upstream headers
        assert!(rules.set_if_empty.iter().any(|(n, _)| n == "Cache-Control"));

        // Check unset headers
        assert!(rules.unset.contains(&"X-Powered-By".to_string()));
        assert!(rules.unset.contains(&"Via".to_string()));
        assert!(rules.unset.contains(&"x-varnish".to_string()));

        // Merge should be empty (Cache-Control moved to set_if_empty)
        assert!(rules.merge.is_empty());
    }

    #[test]
    fn test_default_security_headers_application() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Powered-By", "PHP")
            .header("Via", "proxy")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = default_security_headers();
        apply_response_headers(&mut response, &rules);

        // Sensitive headers should be removed
        assert!(response.headers().get("X-Powered-By").is_none());
        assert!(response.headers().get("Via").is_none());

        // Security headers should be added
        assert!(response.headers().get("X-Xss-Protection").is_some());
        assert!(response.headers().get("X-Content-Type-Options").is_some());
    }

    // =====================================================================
    // error_response tests
    // =====================================================================

    #[test]
    fn test_error_response_not_found() {
        let response = error_response(StatusCode::NOT_FOUND, "Page not found");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn test_error_response_internal_server_error() {
        let response = error_response(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_response_bad_gateway() {
        let response = error_response(StatusCode::BAD_GATEWAY, "Upstream failed");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_error_response_various_codes() {
        let codes = vec![
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::METHOD_NOT_ALLOWED,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ];

        for code in codes {
            let response = error_response(code, "Test message");
            assert_eq!(response.status(), code);
        }
    }

    // =====================================================================
    // redirect_response tests
    // =====================================================================

    #[test]
    fn test_redirect_response_301() {
        let response = redirect_response(301, "https://example.com/");

        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers().get("Location").unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[test]
    fn test_redirect_response_302() {
        let response = redirect_response(302, "https://example.com/temp");

        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get("Location").unwrap(),
            "https://example.com/temp"
        );
    }

    #[test]
    fn test_redirect_response_307() {
        let response = redirect_response(307, "https://example.com/temp");

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    }

    #[test]
    fn test_redirect_response_308() {
        let response = redirect_response(308, "https://example.com/permanent");

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    }

    #[test]
    fn test_redirect_response_invalid_status_uses_provided() {
        // Invalid status codes will be used as-is if they're valid HTTP status codes
        // The function uses StatusCode::from_u16 which accepts any u16 in range 100-999
        let response = redirect_response(999, "https://example.com/");

        // 999 is a valid status code number (even if non-standard)
        // If it fails to parse, it defaults to MOVED_PERMANENTLY
        // Let's verify the location header is set correctly regardless
        assert_eq!(
            response.headers().get("Location").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_redirect_response_with_path() {
        let response = redirect_response(301, "https://example.com/new/path?query=value");

        assert_eq!(
            response.headers().get("Location").unwrap(),
            "https://example.com/new/path?query=value"
        );
    }

    // =====================================================================
    // status_response tests
    // =====================================================================

    #[test]
    fn test_status_response() {
        let response = status_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get("Cache-Control").unwrap(),
            "no-cache, no-store, must-revalidate"
        );
    }

    // =====================================================================
    // Edge cases and special characters
    // =====================================================================

    #[test]
    fn test_header_with_special_characters() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![
                ("X-Custom".to_string(), "value with spaces".to_string()),
                ("X-Url".to_string(), "http://example.com/path?a=1&b=2".to_string()),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(
            response.headers().get("X-Custom").unwrap(),
            "value with spaces"
        );
        assert_eq!(
            response.headers().get("X-Url").unwrap(),
            "http://example.com/path?a=1&b=2"
        );
    }

    #[test]
    fn test_empty_header_value() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![("X-Empty".to_string(), "".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(response.headers().get("X-Empty").unwrap(), "");
    }

    #[test]
    fn test_invalid_header_name_ignored() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("X-Valid", "value")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![
                ("X-Valid-New".to_string(), "new".to_string()),
                // Invalid header names should be silently ignored
                ("Invalid Header Name".to_string(), "value".to_string()),
            ],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(response.headers().get("X-Valid-New").unwrap(), "new");
        // Original header should still be there
        assert_eq!(response.headers().get("X-Valid").unwrap(), "value");
    }

    #[test]
    fn test_surrogate_key_header() {
        // Test h2o-specific header that's used for cache invalidation
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let rules = HeaderRules {
            set: vec![("Surrogate-Key".to_string(), "main api".to_string())],
            ..Default::default()
        };

        apply_response_headers(&mut response, &rules);

        assert_eq!(
            response.headers().get("Surrogate-Key").unwrap(),
            "main api"
        );
    }

    // =====================================================================
    // apply_expires tests
    // =====================================================================

    #[test]
    fn test_apply_expires_none() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "public")
            .body(Full::new(Bytes::new()))
            .unwrap();

        apply_expires(&mut response, None);

        // Should not modify anything
        assert_eq!(response.headers().get("Cache-Control").unwrap(), "public");
    }

    #[test]
    fn test_apply_expires_off() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "public")
            .header("Expires", "Thu, 01 Jan 2030 00:00:00 GMT")
            .body(Full::new(Bytes::new()))
            .unwrap();

        apply_expires(&mut response, Some(None));

        // Should remove cache headers
        assert!(response.headers().get("Cache-Control").is_none());
        assert!(response.headers().get("Expires").is_none());
    }

    #[test]
    fn test_apply_expires_zero() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        apply_expires(&mut response, Some(Some(0)));

        assert_eq!(
            response.headers().get("Cache-Control").unwrap(),
            "no-cache, no-store, must-revalidate"
        );
    }

    #[test]
    fn test_apply_expires_max_age() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap();

        apply_expires(&mut response, Some(Some(3600)));

        assert_eq!(
            response.headers().get("Cache-Control").unwrap(),
            "max-age=3600"
        );
    }

    #[test]
    fn test_apply_expires_overwrites_existing() {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("Cache-Control", "public")
            .body(Full::new(Bytes::new()))
            .unwrap();

        apply_expires(&mut response, Some(Some(86400)));

        // Should overwrite existing
        assert_eq!(
            response.headers().get("Cache-Control").unwrap(),
            "max-age=86400"
        );
    }
}
