# Use the official Rust image.
FROM rust:slim-trixie AS builder

# Set the working directory in the container.
WORKDIR /workspace

# Install dependencies.
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    curl \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Node.JS 23.x via NodeSource
RUN bash -c 'curl -fsSL https://deb.nodesource.com/setup_23.x | bash -' && \
    apt-get install -y nodejs

# Copy source (build context is repo root, cargo fetches jetpack via git)
COPY . /workspace/dragonfly/

WORKDIR /workspace/dragonfly

RUN npm install

# Build the application.
RUN cargo build --release

# New container
FROM debian:trixie-slim AS runner

# Copy the binary from the builder container.
COPY --from=builder /workspace/dragonfly/target/release/dragonfly /usr/local/bin/dragonfly
# Copy static assets to /opt/dragonfly/
COPY --from=builder /workspace/dragonfly/crates/dragonfly-server/static /opt/dragonfly/static
# Copy templates to /opt/dragonfly/
COPY --from=builder /workspace/dragonfly/crates/dragonfly-server/templates /opt/dragonfly/templates

# Install Helm
RUN apt update && apt install -y curl git && curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
RUN rm -rf /var/lib/apt/lists/* && apt clean
# Expose the port that the application will run on.
EXPOSE 3000

# Set environment variable to indicate we're installed (running in Kubernetes)
ENV DRAGONFLY_INSTALLED=true

# Set the entrypoint for the container.
ENTRYPOINT ["dragonfly", "server"]
