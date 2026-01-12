#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="$ROOT/web/wasm/cimbar"
OUT_DIR="$ROOT/web/receiver-pwa/public/wasm/cimbar"
WASM_PACK_VERSION="0.12.1"
CARGO_BIN="${CARGO_HOME:-$HOME/.cargo}/bin"
WASM_PACK_BIN="$CARGO_BIN/wasm-pack"

if ! command -v mise >/dev/null 2>&1; then
  echo "mise not found. Install mise first." >&2
  exit 1
fi

if [ ! -x "$WASM_PACK_BIN" ]; then
  echo "wasm-pack not found in $CARGO_BIN. Installing via mise-managed cargo..." >&2
  mise exec -- cargo install wasm-pack --version "$WASM_PACK_VERSION" --locked
fi

mkdir -p "$OUT_DIR"

mise exec -- bash -lc "PATH=\"$CARGO_BIN:\$PATH\" \"$WASM_PACK_BIN\" build \"$CRATE_DIR\" --target web --out-dir \"$OUT_DIR\" --release"
