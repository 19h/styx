# Build stage
FROM rust:1.91.1-bookworm as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY benches ./benches

# Build the application in release mode
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /build/target/release/styx /usr/local/bin/styx

# Copy the default configuration
COPY styx.yaml /app/styx.yaml

# Expose ports (80 and 443 based on config)
EXPOSE 80 443

# Run styx with the default config
CMD ["styx", "--config", "/app/styx.yaml"]
