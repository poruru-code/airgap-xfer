#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT/web/receiver-pwa"
CERT_DIR="$APP_DIR/certs"
HOSTS=("localhost" "127.0.0.1" "::1")

if [[ -n "${DEV_HOST:-}" ]]; then
  HOSTS+=("$DEV_HOST")
fi

if ! mise exec -- which mkcert >/dev/null 2>&1; then
  echo "mkcert not found in mise. Install with: mise install mkcert" >&2
  exit 1
fi

mkdir -p "$CERT_DIR"
mise exec -- mkcert -install
mise exec -- mkcert -cert-file "$CERT_DIR/localhost.pem" -key-file "$CERT_DIR/localhost-key.pem" "${HOSTS[@]}"

cd "$APP_DIR"
VITE_HTTPS=1 VITE_HTTPS_CERT_DIR="$CERT_DIR" mise exec -- bun run dev -- --host 0.0.0.0 --port "${PORT:-5173}"
