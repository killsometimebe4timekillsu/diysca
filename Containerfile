# OCI image. Build with any OCI builder:
#   podman build -t diysca -f Containerfile .     |  buildah bud -t diysca .
#   (docker/nerdctl/kaniko/BuildKit work the same way)
FROM docker.io/library/python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY diysca ./diysca
RUN python -m venv /opt/diysca && /opt/diysca/bin/pip install --no-cache-dir ".[zstd]"
# For dynamic/vaulted inventories via the real ansible-inventory, add: && /opt/diysca/bin/pip install ansible-core

FROM docker.io/library/python:3.12-slim
LABEL org.opencontainers.image.title="diysca" \
      org.opencontainers.image.description="Poor man's DIY CVE scanner" \
      org.opencontainers.image.source="https://github.com/killsometimebe4timekillsu/diysca" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /opt/diysca /opt/diysca
RUN useradd --system --uid 10001 --home-dir /data diysca && install -d -o 10001 -g 10001 /data
ENV PATH=/opt/diysca/bin:$PATH DIYSCA_DATA_DIR=/data DIYSCA_CONFIG=/config/config.yml PYTHONUNBUFFERED=1
USER 10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')"
CMD ["diysca", "serve", "--port", "8080"]
