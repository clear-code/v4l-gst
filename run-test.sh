#!/bin/sh

set -eu

top_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$top_dir"

if [ ! -d builddir ]; then
    echo "builddir not found. Run ./scripts/build.sh first." >&2
    exit 1
fi

if ! meson test -C builddir --list 2>/dev/null | grep -q unit-tests; then
    echo "Unit tests are not configured in builddir (needs -Dtests=true)." >&2
    exit 1
fi

exec meson test -C builddir --verbose "$@"