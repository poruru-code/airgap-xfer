#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/web/receiver-pwa/public/wasm/cimbar"
VERSION="${CIMBAR_VERSION:-v0.6.3}"
ARCHIVE_URL="https://github.com/sz3/libcimbar/releases/download/${VERSION}/cimbar.wasm.tar.gz"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$OUT_DIR"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found. Install curl first." >&2
  exit 1
fi

echo "Downloading libcimbar wasm bundle (${VERSION})..."
curl -L -o "$TMP_DIR/cimbar.wasm.tar.gz" "$ARCHIVE_URL"
tar -xzf "$TMP_DIR/cimbar.wasm.tar.gz" -C "$TMP_DIR"

WASM_JS="$(ls "$TMP_DIR"/cimbar_js.*.js 2>/dev/null | head -n 1)"
WASM_BIN="$(ls "$TMP_DIR"/cimbar_js.*.wasm 2>/dev/null | head -n 1)"

if [ -z "$WASM_JS" ] || [ -z "$WASM_BIN" ]; then
  echo "cimbar_js wasm assets not found in archive." >&2
  exit 1
fi

JS_NAME="$(basename "$WASM_JS")"
WASM_NAME="$(basename "$WASM_BIN")"

cp "$WASM_JS" "$OUT_DIR/$JS_NAME"
cp "$WASM_BIN" "$OUT_DIR/$WASM_NAME"

cat > "$OUT_DIR/cimbar_assets.json" <<EOF
{"js":"$JS_NAME","wasm":"$WASM_NAME","version":"$VERSION"}
EOF

printf "*\n" > "$OUT_DIR/.gitignore"
