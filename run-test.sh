#!/bin/sh

set -eu

top_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cd "$top_dir"

# Run tests via Meson
exec meson test -C builddir --verbose
