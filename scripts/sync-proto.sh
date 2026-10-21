#!/usr/bin/env bash
# Copy the shared protocol crate from the Vespera (panel) repository.
#
#   scripts/sync-proto.sh                 # from ../Vespera (sibling checkout)
#   scripts/sync-proto.sh /path/to/Vespera
#   scripts/sync-proto.sh --check         # exit 1 if the copy differs from GitHub main
set -euo pipefail

cd "$(dirname "$0")/.."
DEST=crates/vespera-proto

if [ "${1:-}" = "--check" ]; then
  URL="https://raw.githubusercontent.com/cidmex/Vespera/main/crates/vespera-proto/src/lib.rs"
  if curl -fsSL "$URL" | diff -q - "$DEST/src/lib.rs" >/dev/null; then
    echo "vespera-proto is in sync with cidmex/Vespera@main"
  else
    echo "vespera-proto differs from cidmex/Vespera@main" >&2
    exit 1
  fi
  exit 0
fi

SRC="${1:-../Vespera}/crates/vespera-proto"
[ -f "$SRC/src/lib.rs" ] || { echo "not found: $SRC" >&2; exit 1; }
rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SRC/." "$DEST/"
echo "synced $SRC -> $DEST"
