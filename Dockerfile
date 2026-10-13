# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Copy dependency manifests
COPY pyproject.toml uv.lock ./

# Install virtualenv dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

# Copy application source code
COPY src/ ./src/
COPY proxy/ ./proxy/
COPY arena/ ./arena/
COPY README.md ./

# Install project itself into the baked virtualenv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

# Runtime image: hardened, read-only root, non-root user
FROM python:3.13-slim-bookworm AS runtime

WORKDIR /app

# Create unprivileged spanguard user and group
RUN groupadd -g 10001 spanguard && \
    useradd -u 10001 -g spanguard -d /app -s /usr/sbin/nologin spanguard && \
    mkdir -p /var/log/spanguard /tmp && \
    chown -R spanguard:spanguard /var/log/spanguard /tmp

# Copy baked virtualenv and application from builder
COPY --from=builder --chown=spanguard:spanguard /app/.venv /app/.venv
COPY --from=builder --chown=spanguard:spanguard /app/src /app/src
COPY --from=builder --chown=spanguard:spanguard /app/proxy /app/proxy
COPY --from=builder --chown=spanguard:spanguard /app/arena /app/arena
COPY --from=builder --chown=spanguard:spanguard /app/pyproject.toml /app/pyproject.toml

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:/app"
ENV PYTHONUNBUFFERED=1

USER spanguard

# Internal high port
EXPOSE 8443

# Directly invoke the ASGI server from the baked virtualenv — no runtime package sync
ENTRYPOINT ["/app/.venv/bin/uvicorn", "arena.app:app", "--host", "0.0.0.0", "--port", "8443"]
