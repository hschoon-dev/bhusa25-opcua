# ── asyncua-server/Dockerfile ─────────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir asyncua>=1.1.0 cryptography>=42.0.0

# Copy server source — certs/ is mounted as a volume at runtime,
# so we only copy the script itself from the build context.
COPY server.py ./

# PKI skeleton — actual files come from the bind-mount (./certs → /app/certs).
# These lines just ensure the directories exist if the mount is absent.
RUN mkdir -p certs/trusted certs/issuers

EXPOSE 4840

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; socket.create_connection(('localhost', 4840), 2)" \
    || exit 1

CMD ["python", "server.py"]