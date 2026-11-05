#!/bin/sh
set -e

# First-run initialisation: secrets, self-signed TLS certificate, database and default admin.
python -m app.bootstrap

# A single worker is required: the sync scheduler runs in-process.
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${BEACON_PORT:-8443}" \
  --ssl-keyfile "${BEACON_TLS_KEY:-/data/certs/key.pem}" \
  --ssl-certfile "${BEACON_TLS_CERT:-/data/certs/cert.pem}" \
  --no-server-header
