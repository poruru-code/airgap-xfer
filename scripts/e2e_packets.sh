#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
INPUT="$WORK/input.bin"
PSK="test-psk"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

dd if=/dev/urandom bs=1024 count=64 of="$INPUT" 2>/dev/null

mise exec -- cargo build -p xfer-cli

run_case() {
  local name="$1"
  local send_args="$2"
  local recv_args="$3"
  local outdir="$WORK/out-$name"
  local outfile="$WORK/output-$name.bin"
  mkdir -p "$outdir"
  "$ROOT/target/debug/xfer-cli" "$INPUT" --emit --emit-packets --out-dir "$outdir" $send_args
  "$ROOT/target/debug/xfer-recv" --debug "$outdir/debug.json" --packets "$outdir/packets.bin" --out "$outfile" $recv_args
  if cmp -s "$INPUT" "$outfile"; then
    echo "ok: e2e packets roundtrip ($name)"
  else
    echo "error: output mismatch ($name)" >&2
    exit 1
  fi
}

run_case "encrypted" "--psk $PSK" "--psk $PSK"
run_case "plain" "--no-encrypt" ""
