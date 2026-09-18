#!/bin/sh

set -eu

top_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$top_dir"

if [ ! -d builddir ]; then
    echo "builddir not found. Run ./scripts/build.sh first." >&2
    exit 1
fi

if [ ! -f builddir/tests/test-utils.so ] || [ ! -f builddir/tests/test-gst-backend.so ]; then
    echo "Unit tests are not built in builddir (needs -Dtests=true)." >&2
    exit 1
fi

meson compile -C builddir test-utils test-gst-backend

if [ "${CUTTER:-}" ]; then
    cutter=$CUTTER
elif [ -x "$top_dir/_local/bin/cutter" ]; then
    cutter=$top_dir/_local/bin/cutter
else
    cutter=cutter
fi

cd builddir/tests
exec "$cutter" --notify=no "$@" .
