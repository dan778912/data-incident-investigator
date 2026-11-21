# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim AS web-builder

WORKDIR /build/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./

ARG VITE_API_MODE=live
ENV VITE_API_MODE=${VITE_API_MODE}

RUN npm run build


FROM python:3.13-slim AS python-builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv

RUN python -m venv "${VIRTUAL_ENV}"
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m pip install --upgrade pip \
    && python -m pip install .


FROM python:3.13-slim AS runtime

ENV APP_ENV=production \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000 \
    DATA_DIR=/app/data \
    FRONTEND_DIR=/app/web/dist \
    LANGGRAPH_STRICT_MSGPACK=true \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin app \
    && mkdir -p /app/data \
    && chown app:app /app/data

WORKDIR /app

COPY --from=python-builder /opt/venv /opt/venv
COPY --from=web-builder /build/web/dist /app/web/dist
COPY evals/ /app/evals/

USER app:app

EXPOSE 8000
VOLUME ["/app/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('APP_PORT', '8000') + '/api/health', timeout=2).read()"]

CMD ["dii-api"]
