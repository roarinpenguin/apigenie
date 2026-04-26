FROM python:3.13-slim

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy project definition first for layer caching
COPY pyproject.toml .

# Install docker CLI (used by admin UI to stream container logs).
# docker.io ships only the daemon binaries on Debian and merely *recommends* docker-cli,
# which --no-install-recommends excludes. Install docker-cli directly.
RUN apt-get update -qq && apt-get install -y --no-install-recommends docker-cli && rm -rf /var/lib/apt/lists/*

# Install dependencies (no editable install needed for prod)
RUN uv pip install --system --no-cache fastapi uvicorn[standard] httpx kafka-python google-cloud-pubsub pydantic python-multipart

# Copy source
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
