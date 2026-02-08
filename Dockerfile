FROM debian:trixie-slim
ARG TARGETARCH
COPY dragonfly-${TARGETARCH} /usr/local/bin/dragonfly
COPY static/ /opt/dragonfly/static/
COPY templates/ /opt/dragonfly/templates/
COPY os-templates/ /opt/dragonfly/os-templates/
RUN apt-get update && apt-get install -y --no-install-recommends qemu-utils && rm -rf /var/lib/apt/lists/*
RUN chmod +x /usr/local/bin/dragonfly
VOLUME /var/lib/dragonfly
EXPOSE 3000 67/udp 69/udp
ENV DRAGONFLY_INSTALLED=true
ENTRYPOINT ["dragonfly", "serve"]
