//! styx - High-performance reverse proxy
//!
//! A drop-in replacement for h2o with compatible configuration format.

mod config;
mod http3;
mod middleware;
mod pool;
mod proxy;
mod routing;
mod server;
mod tcp_proxy;
mod tls;

use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

static MOTD: &str = r#"
      __   _               _   _     _
 .-. \  \ | /_____   ____.'_| \_'._.'_/
/ _ \_\ | | ______/ |___. '.   _> _ <_
|_\`.___/ |_\           '._| /_.' '._\
                  1.0
"#;

/// styx reverse proxy
#[derive(Parser, Debug)]
#[command(name = "styx")]
#[command(author, version, about = "High-performance reverse proxy", long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/styx/styx.yaml")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Enable JSON logging
    #[arg(long)]
    json_logs: bool,

    /// Test configuration and exit
    #[arg(short, long)]
    test: bool,

    /// Number of worker threads (0 = auto-detect)
    #[arg(short = 'w', long, default_value = "0")]
    workers: usize,

    /// Quick static file server mode: serve files from this directory
    #[arg(short = 's', long = "serve")]
    serve_dir: Option<PathBuf>,

    /// Port for quick static server (default: 8080)
    #[arg(short = 'p', long = "port", default_value = "8080")]
    port: u16,
}

fn main() -> anyhow::Result<()> {
    println!("{}", MOTD);

    let args = Args::parse();

    // Initialize TLS crypto provider (required for outbound HTTPS connections)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize logging
    init_logging(&args.log_level, args.json_logs)?;

    info!("styx reverse proxy v{}", env!("CARGO_PKG_VERSION"));

    // Quick static server mode
    if let Some(serve_dir) = args.serve_dir {
        return run_quick_static_server(serve_dir, args.port, args.workers);
    }

    // Load configuration
    info!("Loading configuration from {:?}", args.config);
    let config = config::Config::load(&args.config)?;

    // Resolve configuration
    let resolved = config.resolve()?;
    info!(
        "Loaded {} hosts, {} listeners",
        resolved.hosts.len(),
        resolved.listeners.len()
    );

    // Test mode
    if args.test {
        info!("Configuration test successful");
        return Ok(());
    }

    // Write PID file if configured
    if let Some(pid_path) = &resolved.pid_file {
        let pid = std::process::id();
        if let Err(e) = std::fs::write(pid_path, pid.to_string()) {
            error!("Failed to write PID file to {:?}: {}", pid_path, e);
            // Don't crash, just log error
        } else {
            info!("Wrote PID {} to {:?}", pid, pid_path);
        }
    }

    // Determine worker threads
    let workers = if args.workers == 0 {
        resolved.num_threads
    } else {
        args.workers
    };

    info!("Starting with {} worker threads", workers);

    // Build runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    // Run server
    runtime.block_on(async {
        // Start TCP proxies
        let mut tcp_handles = Vec::new();
        for tcp_listener in &resolved.tcp_listeners {
            match tcp_proxy::TcpProxy::new(tcp_listener) {
                Ok(tcp_proxy) => {
                    let handle = tokio::spawn(async move {
                        if let Err(e) = tcp_proxy.run().await {
                            error!("TCP proxy failed: {}", e);
                        }
                    });
                    tcp_handles.push(handle);
                }
                Err(e) => {
                    error!("Failed to create TCP proxy for {}: {}", tcp_listener.addr, e);
                }
            }
        }

        if !resolved.tcp_listeners.is_empty() {
            info!("Started {} TCP proxy listeners", resolved.tcp_listeners.len());
        }

        // Start HTTP server (only if there are HTTP hosts)
        let resolved_arc = std::sync::Arc::new(resolved);
        let server = server::Server::new((*resolved_arc).clone(), config.clone());

        // Start HTTP/3 server if enabled
        if resolved_arc.http3.enabled {
            let h3_config = resolved_arc.clone();
            let h3_router = server.router();
            let h3_proxy = server.proxy();

            let h3_server = std::sync::Arc::new(http3::Http3Server::new(
                h3_config,
                h3_router,
                h3_proxy,
            ));

            tokio::spawn(async move {
                if let Err(e) = h3_server.run().await {
                    error!("HTTP/3 server failed: {}", e);
                }
            });
        }

        // Handle shutdown signal
        let _server_clone = server.clone();
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!("Failed to listen for ctrl-c: {}", e);
                return;
            }
            info!("Received shutdown signal");
            // Graceful shutdown would go here
            std::process::exit(0);
        });

        server.run().await
    })?;

    Ok(())
}

fn init_logging(level: &str, json: bool) -> anyhow::Result<()> {
    let level = level.parse::<Level>().unwrap_or(Level::INFO);
    let filter = EnvFilter::new(format!("styx={},hyper=warn,rustls=warn", level));

    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_thread_ids(true))
            .init();
    }

    Ok(())
}

/// Quick static file server mode - lightweight server without config file
fn run_quick_static_server(dir: PathBuf, port: u16, workers: usize) -> anyhow::Result<()> {
    use bytes::Bytes;
    use http::{Request, Response};
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use server::static_files::{serve_static, StaticFileConfig, StaticFileError};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    // Resolve directory path
    let root = std::fs::canonicalize(&dir).map_err(|e| {
        anyhow::anyhow!("Cannot access directory '{}': {}", dir.display(), e)
    })?;

    info!("Quick static server mode");
    info!("Serving files from: {}", root.display());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Determine worker threads
    let workers = if workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    } else {
        workers
    };

    // Build runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on http://{}", addr);

        let static_config = StaticFileConfig {
            root,
            index: vec!["index.html".to_string(), "index.htm".to_string()],
            send_gzip: true,
            dirlisting: true,
            prefix: "/".to_string(),
        };
        let static_config = std::sync::Arc::new(static_config);

        // Handle shutdown signal
        tokio::spawn(async {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!("Failed to listen for ctrl-c: {}", e);
                return;
            }
            info!("Received shutdown signal");
            std::process::exit(0);
        });

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let config = std::sync::Arc::clone(&static_config);

            tokio::spawn(async move {
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let config = std::sync::Arc::clone(&config);
                    async move {
                        let response = match serve_static(&req, &config).await {
                            Ok(resp) => resp,
                            Err(e) => {
                                let status = e.status_code();
                                let body = match e {
                                    StaticFileError::NotFound => "404 Not Found",
                                    StaticFileError::Forbidden => "403 Forbidden",
                                    StaticFileError::MethodNotAllowed => "405 Method Not Allowed",
                                    StaticFileError::IoError(_) => "500 Internal Server Error",
                                };
                                Response::builder()
                                    .status(status)
                                    .header("content-type", "text/plain")
                                    .body(
                                        Full::new(Bytes::from(body))
                                            .map_err(|e| match e {})
                                            .boxed(),
                                    )
                                    .unwrap()
                            }
                        };
                        Ok::<_, Infallible>(response)
                    }
                });

                let io = TokioIo::new(stream);
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    if !e.to_string().contains("connection closed") {
                        error!("Connection error from {}: {}", remote_addr, e);
                    }
                }
            });
        }

        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}
