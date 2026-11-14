FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY diysca ./diysca
RUN pip install --no-cache-dir ".[zstd]"
# Uncomment to resolve dynamic/vaulted inventories with the real ansible-inventory:
# RUN pip install --no-cache-dir ansible-core
ENV DIYSCA_DATA_DIR=/data DIYSCA_CONFIG=/config/config.yml
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')"
CMD ["diysca", "serve", "--port", "8080"]
