# ---- Stage 1: build the web UI ------------------------------------------------------------------
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: runtime ---------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BEACON_DATA_DIR=/data \
    BEACON_STATIC_DIR=/app/static \
    BEACON_PORT=8443
WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=ui /ui/dist ./static
COPY docker/entrypoint.sh /entrypoint.sh

RUN useradd --system --uid 10001 --home-dir /app beacon \
    && mkdir -p /data && chown -R beacon /data \
    && chmod +x /entrypoint.sh

USER beacon
VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import ssl,urllib.request; urllib.request.urlopen('https://127.0.0.1:8443/api/health', context=ssl._create_unverified_context(), timeout=4)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
