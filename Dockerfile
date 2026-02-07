FROM debian:trixie-slim
ARG TARGETARCH
COPY dragonfly-${TARGETARCH} /usr/local/bin/dragonfly
COPY static/ /opt/dragonfly/static/
COPY templates/ /opt/dragonfly/templates/
RUN chmod +x /usr/local/bin/dragonfly \
    && apt-get update && apt-get install -y curl git \
    && curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 3000
ENV DRAGONFLY_INSTALLED=true
ENTRYPOINT ["dragonfly", "server"]
