FROM debian:bookworm-slim

# Install network tools and runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    socat \
    procps \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy pre-built binary (built on host, copied to tests/docker/ before build)
COPY tests/docker/udp-bcast-relay-rs /usr/local/bin/

# Copy test helper scripts
COPY tests/docker/setup_namespaces.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup_namespaces.sh /usr/local/bin/udp-bcast-relay-rs

# Keep container running
CMD ["tail", "-f", "/dev/null"]
