#!/bin/bash
# Double-click to build ServerOS. All the work is in scripts/build-macos.sh —
# this wrapper exists only because macOS runs `.command` files on double-click.
cd "$(dirname "$0")" || exit 1
exec ./scripts/build-macos.sh
