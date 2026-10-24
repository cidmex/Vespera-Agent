#!/usr/bin/env bash
# Copy the shared protocol crate from the Vespera (panel) repository.
#
#   scripts/sync-proto.sh                 # from ../Vespera (sibling checkout)
#   scripts/sync-proto.sh /path/to/Vespera
#
# The panel repository's CI warns when this copy drifts from its own.
set -euo pipefail

cd "$(dirname "$0")/.."
DEST=crates/vespera-proto

SRC="${1:-../Vespera}/crates/vespera-proto"
[ -f "$SRC/src/lib.rs" ] || { echo "not found: $SRC" >&2; exit 1; }
rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SRC/." "$DEST/"
echo "synced $SRC -> $DEST"
