# Run with
# docker build --platform linux/amd64 -f crates/dragonfly-agent/Dockerfile .
# for amd64 specific builds.

FROM rust:1.93-alpine AS builder

RUN apk add --no-cache \
    musl-dev \
    gcc \
    wget

ENV RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /usr/src/dragonfly
COPY . .
RUN cargo build --release -p dragonfly-agent

# Download iPXE kernel
RUN wget -O /usr/local/share/ipxe.lkrn https://boot.alpinelinux.org/alpine-ipxe/x86_64/ipxe.lkrn

FROM alpine:3.21
RUN apk add --no-cache \
    libgcc \
    kexec-tools

COPY --from=builder /usr/src/dragonfly/target/release/dragonfly-agent /usr/local/bin/
COPY --from=builder /usr/local/share/ipxe.lkrn /usr/local/share/ipxe.lkrn
CMD ["dragonfly-agent"]