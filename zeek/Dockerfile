FROM zeek/zeek:latest

# Install additional Zeek packages for crypto analysis
RUN zkg install --force zeek/corelight/zeek-community-id || true

# Create directories
RUN mkdir -p /zeek/logs /zeek/scripts

# Copy local Zeek config
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY scripts/crypto-detection.zeek /zeek/scripts/crypto-detection.zeek

WORKDIR /zeek

# Default: run Zeek on interface (override in compose)
CMD ["zeek", "-i", "eth0", "local"]
