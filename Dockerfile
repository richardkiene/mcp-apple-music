# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ ./src/

RUN pip install --no-cache-dir .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/mcp-apple-music /usr/local/bin/mcp-apple-music

# ── Configuration via environment variables ───────────────────────────────────
# Provide these at runtime instead of mounting a config.json:
#
#   APPLE_TEAM_ID              Your Apple Developer Team ID
#   APPLE_KEY_ID               Your MusicKit Key ID
#   APPLE_MUSIC_USER_TOKEN     Your Music User Token
#   APPLE_STOREFRONT           App Store storefront (default: us)
#
# Exactly ONE key source — setting both is a hard error:
#   APPLE_PRIVATE_KEY          Full content of your .p8 private key
#   APPLE_PRIVATE_KEY_OP_REF   1Password reference, e.g.
#                              op://Private/MusicKit/AuthKey.p8
#
# The 1Password path additionally needs the `op` CLI in the image and a
# OP_SERVICE_ACCOUNT_TOKEN at runtime (op reads that variable itself; this
# codebase needs no support for it). OP_CLI_PATH overrides where `op` lives.
#
ENV APPLE_TEAM_ID=""
ENV APPLE_KEY_ID=""
ENV APPLE_PRIVATE_KEY=""
ENV APPLE_PRIVATE_KEY_OP_REF=""
ENV APPLE_MUSIC_USER_TOKEN=""
ENV APPLE_STOREFRONT="us"

ENTRYPOINT ["mcp-apple-music"]
