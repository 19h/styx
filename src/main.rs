//! styx - High-performance reverse proxy
//!
//! A drop-in replacement for h2o with compatible configuration format.

mod config;
mod middleware;
mod pool;
mod proxy;
mod routing;
mod server;
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
        let server = server::Server::new(resolved);

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
