# syntax=docker/dockerfile:1
FROM python:3.13-slim AS base

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set working directory
WORKDIR /app

# All dependencies ship manylinux wheels (snowflake-connector 5.x has no musl wheels, hence slim
# instead of alpine). wget is kept for the healthchecks here and in base-infra's docker-compose.
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget && \
    rm -rf /var/lib/apt/lists/*

# Stage 1: Install dependencies only
FROM base AS dependencies

# Copy dependency files
COPY pyproject.toml uv.lock* ./

# Install dependencies (cached layer)
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Stage 2: Final image
FROM base AS final

# Create a non-root user (owns /app; --chown below avoids duplicating layers with chown -R)
RUN useradd --create-home --uid 1000 appuser && \
    chown appuser:appuser /app

# Copy installed dependencies from previous stage
COPY --from=dependencies --chown=appuser:appuser /app/.venv /app/.venv

# Copy application code (changes frequently)
COPY --chown=appuser:appuser . .
COPY --chown=appuser:appuser --chmod=755 entrypoint.sh /app/entrypoint.sh

USER appuser

# Expose Streamlit port
EXPOSE 8501

# Configure Streamlit to listen on all interfaces
ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_PORT=8501
ENV STREAMLIT_SERVER_HEADLESS=true
ENV STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Build info for development footer
ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8501/_stcore/health || exit 1

# Run the application via entrypoint (generates container info, then starts Streamlit)
CMD ["/app/entrypoint.sh"]
