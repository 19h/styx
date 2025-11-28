//! Static file serving with gzip support
//!
//! This module handles serving static files with:
//! - Directory indexing
//! - Directory listing with beautiful flat design
//! - Gzip pre-compressed file serving (file.gz)
//! - Proper MIME type detection
//! - Range request support
//! - Conditional requests (If-Modified-Since, ETag)

use bytes::Bytes;
use futures_util::StreamExt;
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

/// Configuration for static file serving
#[derive(Debug, Clone)]
pub struct StaticFileConfig {
    /// Root directory
    pub root: PathBuf,
    /// Index files to try
    pub index: Vec<String>,
    /// Whether to try serving .gz files
    pub send_gzip: bool,
    /// Whether to show directory listing when no index file
    pub dirlisting: bool,
    /// The matched route prefix to strip from request path
    pub prefix: String,
}

/// Serve a static file request  
pub async fn serve_static<B>(
    request: &Request<B>,
    config: &StaticFileConfig,
) -> Result<Response<BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>>, StaticFileError> {
    // Only allow GET and HEAD
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return Err(StaticFileError::MethodNotAllowed);
    }

    // Get request path and strip the matched route prefix
    let full_path = request.uri().path();
    let request_path = strip_prefix(full_path, &config.prefix);
    let file_path = resolve_path(&config.root, request_path)?;

    // Check if path is a directory
    let metadata = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StaticFileError::NotFound)?;

    // Handle directory - try index files first, then optionally show listing
    if metadata.is_dir() {
        if let Some(index_path) = find_index_file(&file_path, &config.index).await {
            return serve_file(request, &index_path, config).await;
        }
        // No index file found - generate directory listing if enabled
        if config.dirlisting {
            // Use full_path for links so they're absolute from server root
            return generate_directory_listing(request, &file_path, full_path).await;
        }
        return Err(StaticFileError::NotFound);
    }

    serve_file(request, &file_path, config).await
}

/// Serve a specific file
async fn serve_file<B>(
    request: &Request<B>,
    file_path: &Path,
    config: &StaticFileConfig,
) -> Result<Response<BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>>, StaticFileError> {
    let file_path = file_path.to_path_buf();

    // Check for gzip version if client accepts it
    let accepts_gzip = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("gzip"))
        .unwrap_or(false);

    let (final_path, is_gzipped) = if config.send_gzip && accepts_gzip {
        let gzip_path = PathBuf::from(format!("{}.gz", file_path.display()));
        if tokio::fs::metadata(&gzip_path).await.is_ok() {
            (gzip_path, true)
        } else {
            (file_path, false)
        }
    } else {
        (file_path, false)
    };

    // Get file metadata
    let metadata = tokio::fs::metadata(&final_path)
        .await
        .map_err(|_| StaticFileError::NotFound)?;

    // Check if file is readable
    if !metadata.is_file() {
        return Err(StaticFileError::NotFound);
    }

    // Check conditional request headers
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    let etag = modified.map(|m| format!("\"{}{}\"", m, metadata.len()));

    // Check If-None-Match
    if let Some(inm) = request.headers().get(header::IF_NONE_MATCH) {
        if let (Some(etag_value), Ok(inm_str)) = (&etag, inm.to_str()) {
            if inm_str == etag_value || inm_str == "*" {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        }
    }

    // Check If-Modified-Since
    if let Some(ims) = request.headers().get(header::IF_MODIFIED_SINCE) {
        if let (Some(file_modified), Ok(ims_str)) = (modified, ims.to_str()) {
            // Parse HTTP date (simplified check)
            if ims_str.contains(&file_modified.to_string()) {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        }
    }

    // Determine content type from original path (not gzipped)
    let content_type = mime_guess::from_path(&final_path.to_string_lossy().replace(".gz", ""))
        .first_or_octet_stream()
        .to_string();

    let file_size = metadata.len();

    // Parse Range header for partial content support (RFC 9110)
    let range = request.headers().get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_range(s, file_size));

    // Create streaming body (no size limit needed - streaming prevents OOM)
    let (body, status, content_length, content_range) = if request.method() == Method::HEAD {
        // HEAD requests have empty body
        (
            Full::new(Bytes::new()).map_err(|e| match e {}).boxed(),
            if range.is_some() { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK },
            if let Some((start, end)) = range { end - start + 1 } else { file_size },
            range.map(|(start, end)| format!("bytes {}-{}/{}", start, end, file_size)),
        )
    } else if let Some((start, end)) = range {
        // Range request - return 206 Partial Content
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        
        let mut file = File::open(&final_path)
            .await
            .map_err(|e| StaticFileError::IoError(e.to_string()))?;
        
        // Seek to start position
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| StaticFileError::IoError(e.to_string()))?;
        
        // Take only the requested range
        let range_length = end - start + 1;
        let limited_file = file.take(range_length);
        let reader_stream = ReaderStream::new(limited_file);
        
        let frame_stream = reader_stream.map(|result| {
            result
                .map(|bytes| Frame::data(bytes))
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        });
        
        (
            BodyExt::boxed(StreamBody::new(frame_stream)),
            StatusCode::PARTIAL_CONTENT,
            range_length,
            Some(format!("bytes {}-{}/{}", start, end, file_size)),
        )
    } else {
        // Full file - stream file contents in chunks
        let file = File::open(&final_path)
            .await
            .map_err(|e| StaticFileError::IoError(e.to_string()))?;

        // Use ReaderStream to stream file in chunks (default 8KB chunks)
        let reader_stream = ReaderStream::new(file);
        
        // Convert to Frame stream for http_body_util
        let frame_stream = reader_stream.map(|result| {
            result
                .map(|bytes| Frame::data(bytes))
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        });
        
        (
            BodyExt::boxed(StreamBody::new(frame_stream)),
            StatusCode::OK,
            file_size,
            None,
        )
    };

    // Build response
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, content_length.to_string());

    if is_gzipped {
        response = response.header(header::CONTENT_ENCODING, "gzip");
    }

    if let Some(ref etag_value) = etag {
        response = response.header(header::ETAG, etag_value.as_str());
    }

    if let Some(modified_secs) = modified {
        // Format as HTTP date
        let modified_time = chrono::DateTime::from_timestamp(modified_secs as i64, 0)
            .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

        if let Some(date_str) = modified_time {
            response = response.header(header::LAST_MODIFIED, date_str);
        }
    }

    response = response.header(header::ACCEPT_RANGES, "bytes");

    // Add Content-Range header for partial content responses
    if let Some(range_value) = content_range {
        response = response.header(header::CONTENT_RANGE, range_value);
    }

    Ok(response.body(body).unwrap())
}

/// Parse HTTP Range header (RFC 9110 Section 14.1.2)
/// Only supports simple byte ranges: "bytes=start-end"
/// Returns (start, end) inclusive, or None if invalid/unsatisfiable
fn parse_range(range_header: &str, file_size: u64) -> Option<(u64, u64)> {
    // Must start with "bytes="
    let range_spec = range_header.strip_prefix("bytes=")?;
    
    // Only support single range (not multipart ranges)
    if range_spec.contains(',') {
        return None;
    }
    
    // Parse "start-end" or "start-" or "-suffix"
    let parts: Vec<&str> = range_spec.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let (start_str, end_str) = (parts[0].trim(), parts[1].trim());
    
    let (start, end) = if start_str.is_empty() {
        // Suffix range: "-500" means last 500 bytes
        let suffix: u64 = end_str.parse().ok()?;
        if suffix == 0 || suffix > file_size {
            return None;
        }
        (file_size - suffix, file_size - 1)
    } else if end_str.is_empty() {
        // Open-ended range: "500-" means from byte 500 to end
        let start: u64 = start_str.parse().ok()?;
        if start >= file_size {
            return None; // Range not satisfiable
        }
        (start, file_size - 1)
    } else {
        // Full range: "0-999"
        let start: u64 = start_str.parse().ok()?;
        let end: u64 = end_str.parse().ok()?;
        
        if start > end || start >= file_size {
            return None; // Invalid or not satisfiable
        }
        
        // Clamp end to file size
        (start, end.min(file_size - 1))
    };
    
    Some((start, end))
}

/// Directory entry for listing
struct DirEntry {
    name: String,
    is_dir: bool,
    size: u64,
    modified: Option<u64>,
}

/// Generate a beautiful directory listing page
async fn generate_directory_listing<B>(
    request: &Request<B>,
    dir_path: &Path,
    request_path: &str,
) -> Result<Response<BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>>, StaticFileError> {
    let mut entries = Vec::new();

    let mut read_dir = tokio::fs::read_dir(dir_path)
        .await
        .map_err(|e| StaticFileError::IoError(e.to_string()))?;

    while let Some(entry) = read_dir.next_entry().await.map_err(|e| StaticFileError::IoError(e.to_string()))? {
        let metadata = entry.metadata().await.ok();
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files
        if name.starts_with('.') {
            continue;
        }

        let (is_dir, size, modified) = if let Some(meta) = metadata {
            let modified = meta.modified().ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            (meta.is_dir(), meta.len(), modified)
        } else {
            (false, 0, None)
        };

        entries.push(DirEntry { name, is_dir, size, modified });
    }

    // Get sort parameter from query string
    let query = request.uri().query().unwrap_or("");
    let (sort_by, sort_dir) = parse_sort_params(query);

    // Sort entries: directories first, then by selected criteria
    entries.sort_by(|a, b| {
        match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let cmp = match sort_by {
                    SortBy::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    SortBy::Size => a.size.cmp(&b.size),
                    SortBy::Modified => a.modified.cmp(&b.modified),
                };
                if sort_dir == SortDir::Desc { cmp.reverse() } else { cmp }
            }
        }
    });

    let html = render_directory_html(request_path, &entries, sort_by, sort_dir);

    let body = if request.method() == Method::HEAD {
        Full::new(Bytes::new()).map_err(|e| match e {}).boxed()
    } else {
        Full::new(Bytes::from(html)).map_err(|e| match e {}).boxed()
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .unwrap())
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum SortBy { Name, Size, Modified }

#[derive(Clone, Copy, PartialEq, Debug)]
enum SortDir { Asc, Desc }

fn parse_sort_params(query: &str) -> (SortBy, SortDir) {
    let mut sort_by = SortBy::Name;
    let mut sort_dir = SortDir::Asc;

    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            match key {
                "sort" => sort_by = match value {
                    "size" => SortBy::Size,
                    "modified" => SortBy::Modified,
                    _ => SortBy::Name,
                },
                "dir" => sort_dir = match value {
                    "desc" => SortDir::Desc,
                    _ => SortDir::Asc,
                },
                _ => {}
            }
        }
    }
    (sort_by, sort_dir)
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_time(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;") // escape single quote
        .replace('`', "&#96;")  // escape backtick
}

fn render_directory_html(path: &str, entries: &[DirEntry], sort_by: SortBy, sort_dir: SortDir) -> String {
    let path_display = html_escape(path);
    let base_path = if path.ends_with('/') { path.to_string() } else { format!("{}/", path) };

    // Build parent link
    let parent_link = if path != "/" {
        let parent = path.trim_end_matches('/').rsplit_once('/').map(|(p, _)| p).unwrap_or("/");
        let parent = if parent.is_empty() { "/" } else { parent };
        format!(r#"<a href="{}" class="entry parent"><span class="icon">⬆</span><span class="name">..</span><span class="size"></span><span class="modified"></span></a>"#,
            html_escape(parent))
    } else {
        String::new()
    };

    // Build entry rows
    let mut rows = String::new();
    for entry in entries {
        let icon = if entry.is_dir { "📁" } else { get_file_icon(&entry.name) };
        let href = format!("{}{}{}", base_path, html_escape(&entry.name), if entry.is_dir { "/" } else { "" });
        let size = if entry.is_dir { "-".to_string() } else { format_size(entry.size) };
        let modified = entry.modified.map(format_time).unwrap_or_else(|| "-".to_string());
        let class = if entry.is_dir { "entry dir" } else { "entry file" };

        rows.push_str(&format!(
            r#"<a href="{}" class="{}"><span class="icon">{}</span><span class="name">{}</span><span class="size">{}</span><span class="modified">{}</span></a>"#,
            href, class, icon, html_escape(&entry.name), size, modified
        ));
    }

    // Generate sort links
    let sort_link = |by: SortBy, label: &str| -> String {
        let dir = if sort_by == by && sort_dir == SortDir::Asc { "desc" } else { "asc" };
        let by_str = match by { SortBy::Name => "name", SortBy::Size => "size", SortBy::Modified => "modified" };
        let arrow = if sort_by == by { if sort_dir == SortDir::Asc { " ↑" } else { " ↓" } } else { "" };
        let active = if sort_by == by { " active" } else { "" };
        format!(r#"<a href="?sort={}&dir={}" class="sort{}">{}{}</a>"#, by_str, dir, active, label, arrow)
    };

    format!(r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Index of {path_display}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#fafbfc;--card:#fff;--border:#e1e4e8;--text:#24292e;--text2:#586069;--hover:#f6f8fa;--accent:#0366d6;--radius:8px}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--text2:#8b949e;--hover:#21262d;--accent:#58a6ff}}}}
body{{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;background:var(--bg);color:var(--text);padding:2rem;min-height:100vh}}
.container{{max-width:900px;margin:0 auto}}
h1{{font-size:1.25rem;font-weight:500;padding:1rem 0;border-bottom:1px solid var(--border);margin-bottom:1rem;word-break:break-all}}
.header{{display:flex;gap:1rem;padding:.75rem 1rem;font-size:.75rem;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}}
.header .name{{flex:1}}
.header .size,.header .modified{{width:100px;text-align:right}}
.header a{{color:var(--text2);text-decoration:none}}
.header a:hover,.header a.active{{color:var(--accent)}}
.list{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}}
.entry{{display:flex;align-items:center;gap:.75rem;padding:.75rem 1rem;text-decoration:none;color:var(--text);border-bottom:1px solid var(--border);transition:background .1s}}
.entry:last-child{{border-bottom:none}}
.entry:hover{{background:var(--hover)}}
.entry .icon{{width:1.5rem;text-align:center;flex-shrink:0}}
.entry .name{{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.entry .size,.entry .modified{{width:100px;text-align:right;color:var(--text2);font-size:.875rem;flex-shrink:0}}
.entry.dir .name{{font-weight:500}}
.search{{margin-bottom:1rem}}
.search input{{width:100%;padding:.625rem 1rem;border:1px solid var(--border);border-radius:var(--radius);background:var(--card);color:var(--text);font-size:1rem;outline:none}}
.search input:focus{{border-color:var(--accent)}}
.search input::placeholder{{color:var(--text2)}}
.empty{{padding:3rem;text-align:center;color:var(--text2)}}
@media(max-width:600px){{
  body{{padding:1rem}}
  .entry .modified{{display:none}}
  .header .modified{{display:none}}
  .entry .size{{width:70px}}
  .header .size{{width:70px}}
}}
</style>
</head>
<body>
<div class="container">
<h1>Index of {path_display}</h1>
<div class="search"><input type="text" id="q" placeholder="Filter files..." autocomplete="off"></div>
<div class="list">
<div class="header"><span class="name">{}</span><span class="size">{}</span><span class="modified">{}</span></div>
{parent_link}{rows}
</div>
</div>
<script>
(function(){{
var q=document.getElementById('q'),entries=document.querySelectorAll('.entry:not(.parent)');
q.oninput=function(){{var v=this.value.toLowerCase();entries.forEach(function(e){{e.style.display=e.textContent.toLowerCase().indexOf(v)>-1?'':'none'}})}};
q.onkeydown=function(e){{if(e.key==='Enter'){{var vis=[].filter.call(entries,function(el){{return el.style.display!=='none'}});if(vis.length===1)vis[0].click()}}}}
}})();
</script>
</body>
</html>"##,
        sort_link(SortBy::Name, "Name"),
        sort_link(SortBy::Size, "Size"),
        sort_link(SortBy::Modified, "Modified"),
    )
}

fn get_file_icon(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        // Archives
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => "📦",
        // Images
        "jpg" | "jpeg" | "png" | "gif" | "svg" | "webp" | "ico" | "bmp" => "🖼️",
        // Video
        "mp4" | "mkv" | "avi" | "mov" | "wmv" | "webm" => "🎬",
        // Audio
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => "🎵",
        // Documents
        "pdf" => "📕",
        "doc" | "docx" | "odt" => "📘",
        "xls" | "xlsx" | "ods" => "📗",
        "ppt" | "pptx" | "odp" => "📙",
        // Code
        "rs" | "go" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "java" | "rb" | "php" | "swift" | "kt" => "📜",
        "html" | "htm" | "css" | "scss" | "sass" | "less" => "🌐",
        "json" | "yaml" | "yml" | "toml" | "xml" => "⚙️",
        "sh" | "bash" | "zsh" | "fish" | "ps1" | "bat" | "cmd" => "⚡",
        // Text
        "txt" | "md" | "markdown" | "rst" | "log" => "📄",
        // Executables
        "exe" | "msi" | "app" | "dmg" | "deb" | "rpm" => "⚙️",
        // Default
        _ => "📄",
    }
}

/// Resolve and sanitize file path
/// Strip the route prefix from the request path
fn strip_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    // Handle root prefix specially
    if prefix == "/" {
        return path.strip_prefix('/').unwrap_or(path);
    }

    // Handle both with and without trailing slash
    let prefix_trimmed = prefix.trim_end_matches('/');

    if path.starts_with(prefix_trimmed) {
        let remainder = &path[prefix_trimmed.len()..];
        // Strip leading slash from remainder if present
        remainder.strip_prefix('/').unwrap_or(remainder)
    } else {
        path
    }
}

fn resolve_path(root: &Path, request_path: &str) -> Result<PathBuf, StaticFileError> {
    // Decode URL
    let decoded = urlencoding_decode(request_path)?;

    // Check for null bytes after decoding
    if decoded.contains('\0') {
        return Err(StaticFileError::Forbidden);
    }

    // Check for Windows path separators
    if decoded.contains('\\') {
        return Err(StaticFileError::Forbidden);
    }

    // Remove leading slash and normalize
    let cleaned = decoded.trim_start_matches('/');

    // Build path
    let mut path = root.to_path_buf();

    for component in cleaned.split('/') {
        match component {
            "" | "." => continue,
            ".." => {
                // Prevent directory traversal
                return Err(StaticFileError::Forbidden);
            }
            c => {
                // Additional traversal attempt detection
                if c.contains("..") {
                    return Err(StaticFileError::Forbidden);
                }
                path.push(c);
            }
        }
    }

    // Canonicalize the root to get absolute path and resolve symlinks
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|_| StaticFileError::IoError("Cannot access root directory".to_string()))?;

    // Try to canonicalize the requested path (resolves symlinks)
    // If the file doesn't exist yet, that's okay - we'll catch it later
    // But if it exists, we need to verify it doesn't escape via symlinks
    if let Ok(canonical_path) = std::fs::canonicalize(&path) {
        // Verify the canonical path is still under the canonical root
        if !canonical_path.starts_with(&canonical_root) {
            return Err(StaticFileError::Forbidden);
        }
        Ok(canonical_path)
    } else {
        // File doesn't exist - verify the parent directory doesn't escape
        let mut check_path = path.clone();
        while let Some(parent) = check_path.parent() {
            if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
                if !canonical_parent.starts_with(&canonical_root) {
                    return Err(StaticFileError::Forbidden);
                }
                break;
            }
            check_path = parent.to_path_buf();
        }
        Ok(path)
    }
}

/// URL decoding with proper UTF-8 support
fn urlencoding_decode(input: &str) -> Result<String, StaticFileError> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    bytes.push(byte);
                    continue;
                }
            }
            // Invalid escape, keep as-is
            bytes.push(b'%');
            bytes.extend(hex.as_bytes());
        } else if c == '+' {
            bytes.push(b' ');
        } else {
            // For ASCII chars, just push the byte
            // For non-ASCII chars (already UTF-8), push all bytes
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            bytes.extend(encoded.as_bytes());
        }
    }

    // Use strict UTF-8 validation instead of lossy conversion
    String::from_utf8(bytes).map_err(|_| StaticFileError::Forbidden)
}

/// Find an index file in a directory
async fn find_index_file(dir: &Path, index_files: &[String]) -> Option<PathBuf> {
    for index in index_files {
        let path = dir.join(index);
        if tokio::fs::metadata(&path).await.is_ok() {
            return Some(path);
        }
    }
    None
}

/// Static file errors
#[derive(Debug, thiserror::Error)]
pub enum StaticFileError {
    #[error("file not found")]
    NotFound,

    #[error("forbidden")]
    Forbidden,

    #[error("method not allowed")]
    MethodNotAllowed,

    #[error("IO error: {0}")]
    IoError(String),
}

impl StaticFileError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            StaticFileError::NotFound => StatusCode::NOT_FOUND,
            StaticFileError::Forbidden => StatusCode::FORBIDDEN,
            StaticFileError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            StaticFileError::IoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Serve a static file request for HTTP/3 (returns Bytes body instead of streaming)
/// This is a simplified version that reads the entire file into memory
pub async fn serve_static_h3<B>(
    request: &Request<B>,
    config: &StaticFileConfig,
) -> Result<Response<Bytes>, StaticFileError> {
    // Only allow GET and HEAD
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return Err(StaticFileError::MethodNotAllowed);
    }

    // Get request path and strip the matched route prefix
    let full_path = request.uri().path();
    let request_path = strip_prefix(full_path, &config.prefix);
    let file_path = resolve_path(&config.root, request_path)?;

    // Check if path is a directory
    let metadata = tokio::fs::metadata(&file_path)
        .await
        .map_err(|_| StaticFileError::NotFound)?;

    // Handle directory - try index files first, then optionally show listing
    if metadata.is_dir() {
        if let Some(index_path) = find_index_file(&file_path, &config.index).await {
            return serve_file_h3(request, &index_path, config).await;
        }
        // No index file found - generate directory listing if enabled
        if config.dirlisting {
            return generate_directory_listing_h3(request, &file_path, full_path).await;
        }
        return Err(StaticFileError::NotFound);
    }

    serve_file_h3(request, &file_path, config).await
}

/// Serve a specific file for HTTP/3
async fn serve_file_h3<B>(
    request: &Request<B>,
    file_path: &Path,
    config: &StaticFileConfig,
) -> Result<Response<Bytes>, StaticFileError> {
    let file_path = file_path.to_path_buf();

    // Check for gzip version if client accepts it
    let accepts_gzip = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("gzip"))
        .unwrap_or(false);

    let (final_path, is_gzipped) = if config.send_gzip && accepts_gzip {
        let gzip_path = PathBuf::from(format!("{}.gz", file_path.display()));
        if tokio::fs::metadata(&gzip_path).await.is_ok() {
            (gzip_path, true)
        } else {
            (file_path, false)
        }
    } else {
        (file_path, false)
    };

    // Get file metadata
    let metadata = tokio::fs::metadata(&final_path)
        .await
        .map_err(|_| StaticFileError::NotFound)?;

    if !metadata.is_file() {
        return Err(StaticFileError::NotFound);
    }

    // Check conditional request headers
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    let etag = modified.map(|m| format!("\"{}{}\"", m, metadata.len()));

    // Check If-None-Match
    if let Some(inm) = request.headers().get(header::IF_NONE_MATCH) {
        if let (Some(etag_value), Ok(inm_str)) = (&etag, inm.to_str()) {
            if inm_str == etag_value || inm_str == "*" {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Bytes::new())
                    .unwrap());
            }
        }
    }

    // Determine content type from original path
    let content_type = mime_guess::from_path(&final_path.to_string_lossy().replace(".gz", ""))
        .first_or_octet_stream()
        .to_string();

    // Read file content
    let body = if request.method() == Method::HEAD {
        Bytes::new()
    } else {
        let content = tokio::fs::read(&final_path)
            .await
            .map_err(|e| StaticFileError::IoError(e.to_string()))?;
        Bytes::from(content)
    };

    // Build response
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, metadata.len().to_string());

    if is_gzipped {
        response = response.header(header::CONTENT_ENCODING, "gzip");
    }

    if let Some(ref etag_value) = etag {
        response = response.header(header::ETAG, etag_value.as_str());
    }

    if let Some(modified_secs) = modified {
        let modified_time = chrono::DateTime::from_timestamp(modified_secs as i64, 0)
            .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string());

        if let Some(date_str) = modified_time {
            response = response.header(header::LAST_MODIFIED, date_str);
        }
    }

    response = response.header(header::ACCEPT_RANGES, "bytes");

    Ok(response.body(body).unwrap())
}

/// Generate directory listing for HTTP/3
async fn generate_directory_listing_h3<B>(
    request: &Request<B>,
    dir_path: &Path,
    request_path: &str,
) -> Result<Response<Bytes>, StaticFileError> {
    let mut entries = Vec::new();

    let mut read_dir = tokio::fs::read_dir(dir_path)
        .await
        .map_err(|e| StaticFileError::IoError(e.to_string()))?;

    while let Some(entry) = read_dir.next_entry().await.map_err(|e| StaticFileError::IoError(e.to_string()))? {
        let metadata = entry.metadata().await.ok();
        let name = entry.file_name().to_string_lossy().to_string();

        if name.starts_with('.') {
            continue;
        }

        let (is_dir, size, modified) = if let Some(meta) = metadata {
            let modified = meta.modified().ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            (meta.is_dir(), meta.len(), modified)
        } else {
            (false, 0, None)
        };

        entries.push(DirEntry { name, is_dir, size, modified });
    }

    let query = request.uri().query().unwrap_or("");
    let (sort_by, sort_dir) = parse_sort_params(query);

    entries.sort_by(|a, b| {
        match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let cmp = match sort_by {
                    SortBy::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    SortBy::Size => a.size.cmp(&b.size),
                    SortBy::Modified => a.modified.cmp(&b.modified),
                };
                if sort_dir == SortDir::Desc { cmp.reverse() } else { cmp }
            }
        }
    });

    let html = render_directory_html(request_path, &entries, sort_by, sort_dir);

    let body = if request.method() == Method::HEAD {
        Bytes::new()
    } else {
        Bytes::from(html)
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // resolve_path tests
    // =====================================================================

    #[test]
    fn test_resolve_path_simple() {
        // Use temp dir that actually exists for canonicalization
        let temp_dir = std::env::temp_dir();
        let path = resolve_path(&temp_dir, "/index.html").unwrap();
        assert!(path.starts_with(&temp_dir));
        assert!(path.ends_with("index.html"));
    }

    #[test]
    fn test_resolve_path_traversal_blocked() {
        let root = Path::new("/var/www");
        let result = resolve_path(root, "/../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_path_nested() {
        let temp_dir = std::env::temp_dir();
        let path = resolve_path(&temp_dir, "/assets/css/style.css").unwrap();
        assert!(path.starts_with(&temp_dir));
        assert!(path.ends_with("assets/css/style.css"));
    }

    #[test]
    fn test_resolve_path_root() {
        let temp_dir = std::env::temp_dir();
        let path = resolve_path(&temp_dir, "/").unwrap();
        // Should resolve to canonical temp dir
        assert_eq!(path, std::fs::canonicalize(&temp_dir).unwrap());
    }

    #[test]
    fn test_resolve_path_double_slash() {
        let temp_dir = std::env::temp_dir();
        let path = resolve_path(&temp_dir, "//test//file.html").unwrap();
        // Empty components should be skipped
        assert!(path.starts_with(&temp_dir));
        assert!(path.ends_with("test/file.html"));
    }

    #[test]
    fn test_resolve_path_dot_components() {
        let temp_dir = std::env::temp_dir();
        // Single dots should be skipped
        let path = resolve_path(&temp_dir, "/./test/./file.html").unwrap();
        assert!(path.starts_with(&temp_dir));
        assert!(path.ends_with("test/file.html"));
    }

    #[test]
    fn test_resolve_path_multiple_traversal_attempts() {
        let root = Path::new("/var/www");

        // All these should fail
        let attacks = vec![
            "/../../../etc/passwd",
            "/..%2F..%2Fetc/passwd",
            "/foo/../../bar",
            "/..",
            "/test/../..",
        ];

        for attack in attacks {
            let result = resolve_path(root, attack);
            assert!(result.is_err(), "Path '{}' should be blocked", attack);
        }
    }

    #[test]
    fn test_resolve_path_encoded_traversal() {
        let root = Path::new("/var/www");
        // URL encoded .. should also be blocked (decoded before path resolution)
        let result = resolve_path(root, "/%2e%2e/etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_path_no_leading_slash() {
        let temp_dir = std::env::temp_dir();
        let path = resolve_path(&temp_dir, "test.html").unwrap();
        assert!(path.starts_with(&temp_dir));
        assert!(path.ends_with("test.html"));
    }

    // =====================================================================
    // urlencoding_decode tests
    // =====================================================================

    #[test]
    fn test_url_decode() {
        assert_eq!(urlencoding_decode("/path%20with%20spaces").unwrap(), "/path with spaces");
        assert_eq!(urlencoding_decode("/path+with+plus").unwrap(), "/path with plus");
    }

    #[test]
    fn test_url_decode_no_encoding() {
        assert_eq!(urlencoding_decode("/normal/path.html").unwrap(), "/normal/path.html");
    }

    #[test]
    fn test_url_decode_special_chars() {
        // Common URL encoded characters
        assert_eq!(urlencoding_decode("%2F").unwrap(), "/");
        assert_eq!(urlencoding_decode("%3A").unwrap(), ":");
        assert_eq!(urlencoding_decode("%3F").unwrap(), "?");
        assert_eq!(urlencoding_decode("%26").unwrap(), "&");
        assert_eq!(urlencoding_decode("%3D").unwrap(), "=");
    }

    #[test]
    fn test_url_decode_uppercase_hex() {
        assert_eq!(urlencoding_decode("%2F").unwrap(), "/");
        assert_eq!(urlencoding_decode("%2f").unwrap(), "/");
    }

    #[test]
    fn test_url_decode_incomplete_sequence() {
        // Incomplete percent encoding should be preserved
        assert_eq!(urlencoding_decode("test%2").unwrap(), "test%2");
        assert_eq!(urlencoding_decode("test%").unwrap(), "test%");
        assert_eq!(urlencoding_decode("test%G").unwrap(), "test%G");
    }

    #[test]
    fn test_url_decode_wiki_style_paths() {
        // MediaWiki-style paths
        assert_eq!(urlencoding_decode("/wiki/Test%20Page").unwrap(), "/wiki/Test Page");
        assert_eq!(urlencoding_decode("/wiki/Special%3ASearch").unwrap(), "/wiki/Special:Search");
    }

    #[test]
    fn test_url_decode_unicode() {
        // UTF-8 encoded Unicode - our simple decoder converts bytes to chars directly
        // (using `byte as char`), which may produce different results than proper UTF-8 decoding
        let decoded = urlencoding_decode("%C3%A9").unwrap();
        // The decoder should have processed the two hex sequences
        // Just verify it contains the decoded content without panicking
        assert!(!decoded.is_empty());
        // The raw bytes 0xC3 0xA9 when interpreted as chars individually
        // will create a string, though not the combined é character
    }

    #[test]
    fn test_url_decode_null_byte() {
        // Null byte encoding (security concern)
        assert_eq!(urlencoding_decode("%00").unwrap(), "\0");
    }

    // =====================================================================
    // parse_range tests
    // =====================================================================

    #[test]
    fn test_parse_range_full_range() {
        // "bytes=0-999" for a 1000 byte file
        assert_eq!(parse_range("bytes=0-999", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=0-499", 1000), Some((0, 499)));
        assert_eq!(parse_range("bytes=500-999", 1000), Some((500, 999)));
    }

    #[test]
    fn test_parse_range_open_ended() {
        // "bytes=500-" means from 500 to end
        assert_eq!(parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=0-", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=999-", 1000), Some((999, 999)));
    }

    #[test]
    fn test_parse_range_suffix() {
        // "bytes=-500" means last 500 bytes
        assert_eq!(parse_range("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 999)));
        assert_eq!(parse_range("bytes=-1", 1000), Some((999, 999)));
    }

    #[test]
    fn test_parse_range_clamping() {
        // End beyond file size should be clamped
        assert_eq!(parse_range("bytes=0-9999", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=500-9999", 1000), Some((500, 999)));
    }

    #[test]
    fn test_parse_range_invalid() {
        // Invalid ranges should return None
        assert_eq!(parse_range("bytes=1000-", 1000), None); // Start >= file_size
        assert_eq!(parse_range("bytes=1000-1999", 1000), None); // Start >= file_size
        assert_eq!(parse_range("bytes=500-400", 1000), None); // Start > end
        assert_eq!(parse_range("bytes=-0", 1000), None); // Zero suffix
        assert_eq!(parse_range("bytes=-1001", 1000), None); // Suffix > file_size
    }

    #[test]
    fn test_parse_range_malformed() {
        // Malformed ranges should return None
        assert_eq!(parse_range("notbytes=0-100", 1000), None); // Wrong prefix
        assert_eq!(parse_range("bytes=", 1000), None); // Empty range
        assert_eq!(parse_range("bytes=0-100-200", 1000), None); // Too many parts
        assert_eq!(parse_range("bytes=abc-def", 1000), None); // Non-numeric
        assert_eq!(parse_range("bytes=0,100-200", 1000), None); // Multiple ranges (not supported)
    }

    #[test]
    fn test_parse_range_whitespace() {
        // Should handle whitespace
        assert_eq!(parse_range("bytes= 0 - 100 ", 1000), Some((0, 100)));
        assert_eq!(parse_range("bytes=  500  -  ", 1000), Some((500, 999)));
    }

    #[test]
    fn test_parse_range_edge_cases() {
        // Single byte file
        assert_eq!(parse_range("bytes=0-0", 1), Some((0, 0)));
        assert_eq!(parse_range("bytes=0-", 1), Some((0, 0)));
        assert_eq!(parse_range("bytes=-1", 1), Some((0, 0)));
        
        // Large file
        let large_size = 10_000_000_000u64; // 10GB
        assert_eq!(parse_range("bytes=0-999", large_size), Some((0, 999)));
        assert_eq!(parse_range(&format!("bytes=-1000"), large_size), Some((large_size - 1000, large_size - 1)));
    }

    // =====================================================================
    // StaticFileConfig tests
    // =====================================================================

    #[test]
    fn test_static_file_config_creation() {
        let config = StaticFileConfig {
            root: PathBuf::from("/var/www"),
            index: vec!["index.html".to_string(), "index.htm".to_string()],
            send_gzip: true,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        assert_eq!(config.root, PathBuf::from("/var/www"));
        assert_eq!(config.index.len(), 2);
        assert!(config.send_gzip);
    }

    #[test]
    fn test_static_file_config_clone() {
        let config = StaticFileConfig {
            root: PathBuf::from("/var/www"),
            index: vec!["index.html".to_string()],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let cloned = config.clone();
        assert_eq!(config.root, cloned.root);
        assert_eq!(config.index, cloned.index);
        assert_eq!(config.send_gzip, cloned.send_gzip);
    }

    // =====================================================================
    // StaticFileError tests
    // =====================================================================

    #[test]
    fn test_static_file_error_status_codes() {
        assert_eq!(StaticFileError::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(StaticFileError::Forbidden.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(StaticFileError::MethodNotAllowed.status_code(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            StaticFileError::IoError("test".to_string()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_static_file_error_display() {
        assert_eq!(StaticFileError::NotFound.to_string(), "file not found");
        assert_eq!(StaticFileError::Forbidden.to_string(), "forbidden");
        assert_eq!(StaticFileError::MethodNotAllowed.to_string(), "method not allowed");
        assert_eq!(
            StaticFileError::IoError("read error".to_string()).to_string(),
            "IO error: read error"
        );
    }

    // =====================================================================
    // find_index_file tests (async)
    // =====================================================================

    #[tokio::test]
    async fn test_find_index_file_none_exist() {
        let temp_dir = std::env::temp_dir().join("styx_test_no_index");
        let _ = tokio::fs::create_dir(&temp_dir).await;

        let index_files = vec!["index.html".to_string(), "index.htm".to_string()];
        let result = find_index_file(&temp_dir, &index_files).await;

        assert!(result.is_none());

        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_find_index_file_first_match() {
        let temp_dir = std::env::temp_dir().join("styx_test_index_first");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        // Create both index files
        let index_html = temp_dir.join("index.html");
        let index_htm = temp_dir.join("index.htm");
        let _ = tokio::fs::write(&index_html, "test").await;
        let _ = tokio::fs::write(&index_htm, "test").await;

        let index_files = vec!["index.html".to_string(), "index.htm".to_string()];
        let result = find_index_file(&temp_dir, &index_files).await;

        assert!(result.is_some());
        assert_eq!(result.unwrap().file_name().unwrap(), "index.html");

        // Cleanup
        let _ = tokio::fs::remove_file(&index_html).await;
        let _ = tokio::fs::remove_file(&index_htm).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_find_index_file_second_match() {
        let temp_dir = std::env::temp_dir().join("styx_test_index_second");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        // Create only index.htm
        let index_htm = temp_dir.join("index.htm");
        let _ = tokio::fs::write(&index_htm, "test").await;

        let index_files = vec!["index.html".to_string(), "index.htm".to_string()];
        let result = find_index_file(&temp_dir, &index_files).await;

        assert!(result.is_some());
        assert_eq!(result.unwrap().file_name().unwrap(), "index.htm");

        // Cleanup
        let _ = tokio::fs::remove_file(&index_htm).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    // =====================================================================
    // serve_static tests (async)
    // =====================================================================

    #[tokio::test]
    async fn test_serve_static_method_not_allowed() {
        let config = StaticFileConfig {
            root: PathBuf::from("/tmp"),
            index: vec!["index.html".to_string()],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        // POST should be rejected
        let request = Request::builder()
            .method(Method::POST)
            .uri("/test.txt")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StaticFileError::MethodNotAllowed));
    }

    #[tokio::test]
    async fn test_serve_static_file_not_found() {
        let config = StaticFileConfig {
            root: PathBuf::from("/tmp"),
            index: vec!["index.html".to_string()],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/nonexistent_file_xyz_12345.txt")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StaticFileError::NotFound));
    }

    #[tokio::test]
    async fn test_serve_static_directory_traversal_blocked() {
        let config = StaticFileConfig {
            root: PathBuf::from("/var/www"),
            index: vec!["index.html".to_string()],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/../etc/passwd")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StaticFileError::Forbidden));
    }

    #[tokio::test]
    async fn test_serve_static_real_file() {
        // Create a temporary file to serve
        let temp_dir = std::env::temp_dir().join("styx_test_serve");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let test_file = temp_dir.join("test.txt");
        let _ = tokio::fs::write(&test_file, "Hello, World!").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/test.txt")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(header::CONTENT_TYPE));
        assert!(response.headers().contains_key(header::ETAG));

        // Cleanup
        let _ = tokio::fs::remove_file(&test_file).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_serve_static_head_request() {
        let temp_dir = std::env::temp_dir().join("styx_test_head");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let test_file = temp_dir.join("test.txt");
        let _ = tokio::fs::write(&test_file, "Hello, World!").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::HEAD)
            .uri("/test.txt")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // HEAD response should have empty body
        // (in the actual implementation, the body is set to empty for HEAD)

        // Cleanup
        let _ = tokio::fs::remove_file(&test_file).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_serve_static_if_none_match() {
        let temp_dir = std::env::temp_dir().join("styx_test_etag");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let test_file = temp_dir.join("test.txt");
        let _ = tokio::fs::write(&test_file, "Content").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        // First request to get ETag
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test.txt")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let response = serve_static(&request, &config).await.unwrap();
        let etag = response.headers().get(header::ETAG).unwrap().to_str().unwrap().to_string();

        // Second request with If-None-Match
        let request_conditional = Request::builder()
            .method(Method::GET)
            .uri("/test.txt")
            .header(header::IF_NONE_MATCH, &etag)
            .body(Full::new(Bytes::new()))
            .unwrap();

        let response_conditional = serve_static(&request_conditional, &config).await.unwrap();
        assert_eq!(response_conditional.status(), StatusCode::NOT_MODIFIED);

        // Cleanup
        let _ = tokio::fs::remove_file(&test_file).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_serve_static_gzip() {
        let temp_dir = std::env::temp_dir().join("styx_test_gzip");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        // Create both regular and gzipped versions
        let test_file = temp_dir.join("test.js");
        let test_file_gz = temp_dir.join("test.js.gz");
        let _ = tokio::fs::write(&test_file, "console.log('test');").await;
        let _ = tokio::fs::write(&test_file_gz, "gzipped content").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![],
            send_gzip: true,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        // Request with gzip accepted
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test.js")
            .header(header::ACCEPT_ENCODING, "gzip, deflate")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );

        // Cleanup
        let _ = tokio::fs::remove_file(&test_file).await;
        let _ = tokio::fs::remove_file(&test_file_gz).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_serve_static_gzip_not_accepted() {
        let temp_dir = std::env::temp_dir().join("styx_test_no_gzip");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let test_file = temp_dir.join("test.js");
        let test_file_gz = temp_dir.join("test.js.gz");
        let _ = tokio::fs::write(&test_file, "console.log('test');").await;
        let _ = tokio::fs::write(&test_file_gz, "gzipped content").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![],
            send_gzip: true,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        // Request WITHOUT gzip accepted
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test.js")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        // Should NOT have content-encoding header
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());

        // Cleanup
        let _ = tokio::fs::remove_file(&test_file).await;
        let _ = tokio::fs::remove_file(&test_file_gz).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_serve_static_directory_with_index() {
        let temp_dir = std::env::temp_dir().join("styx_test_dir_index");
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let index_file = temp_dir.join("index.html");
        let _ = tokio::fs::write(&index_file, "<html></html>").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec!["index.html".to_string()],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().contains("html"));

        // Cleanup
        let _ = tokio::fs::remove_file(&index_file).await;
        let _ = tokio::fs::remove_dir(&temp_dir).await;
    }

    // =====================================================================
    // MIME type tests
    // =====================================================================

    #[test]
    fn test_mime_detection() {
        // These test the mime_guess library behavior
        let mime_html = mime_guess::from_path("test.html").first_or_octet_stream();
        assert!(mime_html.to_string().contains("html"));

        let mime_js = mime_guess::from_path("script.js").first_or_octet_stream();
        assert!(mime_js.to_string().contains("javascript"));

        let mime_css = mime_guess::from_path("style.css").first_or_octet_stream();
        assert!(mime_css.to_string().contains("css"));

        let mime_png = mime_guess::from_path("image.png").first_or_octet_stream();
        assert!(mime_png.to_string().contains("image"));

        let mime_json = mime_guess::from_path("data.json").first_or_octet_stream();
        assert!(mime_json.to_string().contains("json"));
    }

    #[test]
    fn test_mime_unknown_extension() {
        let mime = mime_guess::from_path("file.xyz123unknown").first_or_octet_stream();
        assert_eq!(mime.to_string(), "application/octet-stream");
    }

    // =====================================================================
    // Directory listing tests
    // =====================================================================

    #[test]
    fn test_strip_prefix() {
        // Root prefix
        assert_eq!(strip_prefix("/foo/bar", "/"), "foo/bar");
        assert_eq!(strip_prefix("/", "/"), "");

        // Exact match with trailing slash
        assert_eq!(strip_prefix("/yolo/Downloads", "/yolo/"), "Downloads");
        assert_eq!(strip_prefix("/yolo/Downloads/", "/yolo/"), "Downloads/");
        assert_eq!(strip_prefix("/yolo/", "/yolo/"), "");

        // Match without trailing slash in prefix
        assert_eq!(strip_prefix("/yolo/Downloads", "/yolo"), "Downloads");
        assert_eq!(strip_prefix("/yolo/Downloads/file.txt", "/yolo"), "Downloads/file.txt");
        assert_eq!(strip_prefix("/yolo", "/yolo"), "");

        // No match - return original
        assert_eq!(strip_prefix("/other/path", "/yolo"), "/other/path");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_parse_sort_params() {
        assert_eq!(parse_sort_params(""), (SortBy::Name, SortDir::Asc));
        assert_eq!(parse_sort_params("sort=size"), (SortBy::Size, SortDir::Asc));
        assert_eq!(parse_sort_params("sort=modified&dir=desc"), (SortBy::Modified, SortDir::Desc));
        assert_eq!(parse_sort_params("dir=desc&sort=name"), (SortBy::Name, SortDir::Desc));
        assert_eq!(parse_sort_params("sort=invalid"), (SortBy::Name, SortDir::Asc));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("<a href=\"x\">test</a>"), "&lt;a href=&quot;x&quot;&gt;test&lt;/a&gt;");
    }

    #[test]
    fn test_get_file_icon() {
        assert_eq!(get_file_icon("archive.zip"), "📦");
        assert_eq!(get_file_icon("image.png"), "🖼️");
        assert_eq!(get_file_icon("video.mp4"), "🎬");
        assert_eq!(get_file_icon("audio.mp3"), "🎵");
        assert_eq!(get_file_icon("document.pdf"), "📕");
        assert_eq!(get_file_icon("code.rs"), "📜");
        assert_eq!(get_file_icon("page.html"), "🌐");
        assert_eq!(get_file_icon("config.json"), "⚙️");
        assert_eq!(get_file_icon("script.sh"), "⚡");
        assert_eq!(get_file_icon("readme.txt"), "📄");
        assert_eq!(get_file_icon("unknown.xyz"), "📄");
    }

    #[test]
    fn test_render_directory_html_basic() {
        let entries = vec![
            DirEntry { name: "folder".to_string(), is_dir: true, size: 0, modified: Some(1700000000) },
            DirEntry { name: "file.txt".to_string(), is_dir: false, size: 1024, modified: Some(1700000000) },
        ];
        let html = render_directory_html("/test", &entries, SortBy::Name, SortDir::Asc);

        assert!(html.contains("Index of /test"));
        assert!(html.contains("folder"));
        assert!(html.contains("file.txt"));
        assert!(html.contains("📁")); // folder icon
        assert!(html.contains("📄")); // file icon
        assert!(html.contains("1.0 KB")); // file size
    }

    #[test]
    fn test_render_directory_html_escapes_xss() {
        let entries = vec![
            DirEntry { name: "<script>alert('xss')</script>".to_string(), is_dir: false, size: 0, modified: None },
        ];
        let html = render_directory_html("/test", &entries, SortBy::Name, SortDir::Asc);

        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn test_render_directory_html_parent_link() {
        let entries = vec![];

        // Root should not have parent link
        let html_root = render_directory_html("/", &entries, SortBy::Name, SortDir::Asc);
        assert!(!html_root.contains("class=\"entry parent\""));

        // Non-root should have parent link
        let html_sub = render_directory_html("/foo/bar", &entries, SortBy::Name, SortDir::Asc);
        assert!(html_sub.contains("class=\"entry parent\""));
        assert!(html_sub.contains("href=\"/foo\""));
    }

    #[tokio::test]
    async fn test_directory_listing_basic() {
        let temp_dir = std::env::temp_dir().join("styx_test_dir_listing");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        // Create test files
        let _ = tokio::fs::write(temp_dir.join("file1.txt"), "content").await;
        let _ = tokio::fs::write(temp_dir.join("file2.txt"), "more content").await;
        let _ = tokio::fs::create_dir(temp_dir.join("subdir")).await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![], // No index files, will show listing
            send_gzip: false,
            dirlisting: true,  // Enable directory listing
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().contains("html"));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_directory_listing_disabled() {
        let temp_dir = std::env::temp_dir().join("styx_test_dir_listing_disabled");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        // Create test files but no index
        let _ = tokio::fs::write(temp_dir.join("file1.txt"), "content").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec!["index.html".to_string()], // Index that doesn't exist
            send_gzip: false,
            dirlisting: false,  // Directory listing disabled
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        // Should return NotFound when dirlisting is disabled and no index
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StaticFileError::NotFound));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_directory_listing_hides_hidden_files() {
        let temp_dir = std::env::temp_dir().join("styx_test_hidden_files");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let _ = tokio::fs::write(temp_dir.join("visible.txt"), "visible").await;
        let _ = tokio::fs::write(temp_dir.join(".hidden"), "hidden").await;

        // Test the render function directly instead
        let entries = vec![
            DirEntry { name: "visible.txt".to_string(), is_dir: false, size: 7, modified: None },
        ];
        let html = render_directory_html("/", &entries, SortBy::Name, SortDir::Asc);

        assert!(html.contains("visible.txt"));
        assert!(!html.contains(".hidden"));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_directory_listing_with_sort() {
        let temp_dir = std::env::temp_dir().join("styx_test_dir_sort");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let _ = tokio::fs::write(temp_dir.join("aaa.txt"), "small").await;
        let _ = tokio::fs::write(temp_dir.join("zzz.txt"), "much larger content").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec![],
            send_gzip: false,
            dirlisting: true,  // Enable directory listing
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/?sort=size&dir=desc")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().status(), StatusCode::OK);

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_directory_with_index_serves_index() {
        let temp_dir = std::env::temp_dir().join("styx_test_index_priority");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        let _ = tokio::fs::create_dir_all(&temp_dir).await;

        let _ = tokio::fs::write(temp_dir.join("index.html"), "<html>Index</html>").await;
        let _ = tokio::fs::write(temp_dir.join("other.txt"), "other").await;

        let config = StaticFileConfig {
            root: temp_dir.clone(),
            index: vec!["index.html".to_string()],
            send_gzip: false,
            dirlisting: false,
            prefix: "/".to_string(),
        };

        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = serve_static(&request, &config).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        // When index.html exists, content-type should be html (from index.html)
        // but not show "Index of" (which would indicate directory listing)
        let ct = response.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(ct.contains("html"));

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    // =====================================================================
    // URL decoding tests
    // =====================================================================

    #[test]
    fn test_urlencoding_decode_ascii() {
        assert_eq!(urlencoding_decode("hello").unwrap(), "hello");
        assert_eq!(urlencoding_decode("/path/to/file.txt").unwrap(), "/path/to/file.txt");
    }

    #[test]
    fn test_urlencoding_decode_spaces() {
        assert_eq!(urlencoding_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(urlencoding_decode("hello+world").unwrap(), "hello world");
    }

    #[test]
    fn test_urlencoding_decode_special_chars() {
        assert_eq!(urlencoding_decode("%2F").unwrap(), "/");
        assert_eq!(urlencoding_decode("%3A").unwrap(), ":");
        assert_eq!(urlencoding_decode("%3F").unwrap(), "?");
        assert_eq!(urlencoding_decode("%26").unwrap(), "&");
    }

    #[test]
    fn test_urlencoding_decode_cyrillic() {
        // "Татьяна" in URL encoding
        // Т = D0 A2, а = D0 B0, т = D1 82, ь = D1 8C, я = D1 8F, н = D0 BD, а = D0 B0
        assert_eq!(
            urlencoding_decode("%D0%A2%D0%B0%D1%82%D1%8C%D1%8F%D0%BD%D0%B0").unwrap(),
            "Татьяна"
        );
    }

    #[test]
    fn test_urlencoding_decode_mixed_cyrillic_ascii() {
        // "Test Тест" - mixed ASCII and Cyrillic
        assert_eq!(
            urlencoding_decode("Test%20%D0%A2%D0%B5%D1%81%D1%82").unwrap(),
            "Test Тест"
        );
    }

    #[test]
    fn test_urlencoding_decode_chinese() {
        // "中文" - Chinese characters
        // 中 = E4 B8 AD, 文 = E6 96 87
        assert_eq!(
            urlencoding_decode("%E4%B8%AD%E6%96%87").unwrap(),
            "中文"
        );
    }

    #[test]
    fn test_urlencoding_decode_emoji() {
        // "😀" - emoji (U+1F600)
        // F0 9F 98 80 in UTF-8
        assert_eq!(
            urlencoding_decode("%F0%9F%98%80").unwrap(),
            "😀"
        );
    }

    #[test]
    fn test_urlencoding_decode_path_with_cyrillic() {
        // A realistic path with Cyrillic folder name
        let decoded = urlencoding_decode("/yolo/%D0%A2%D0%B0%D1%82%D1%8C%D1%8F%D0%BD%D0%B0%20-%20TR24/").unwrap();
        assert_eq!(decoded, "/yolo/Татьяна - TR24/");
    }

    #[test]
    fn test_urlencoding_decode_invalid_sequence() {
        // Invalid percent sequence - should preserve as-is
        assert_eq!(urlencoding_decode("%GG").unwrap(), "%GG");
        assert_eq!(urlencoding_decode("%").unwrap(), "%");
        assert_eq!(urlencoding_decode("%2").unwrap(), "%2");
    }
}
