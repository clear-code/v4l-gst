#!/bin/sh

set -eu

top_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
builddir="$top_dir/builddir"

if [ ! -d "$builddir" ]; then
    echo "error: $builddir not found. Run ./scripts/build.sh first." >&2
    exit 1
fi

if [ "${CUTTER:-}" ]; then
	cutter=$CUTTER
elif [ -x "$top_dir/_local/bin/cutter" ]; then
	cutter=$top_dir/_local/bin/cutter
else
	cutter=cutter
fi

# Make sure the test modules are up to date.
meson compile -C "$builddir"

# Refuse to run when the test modules are not part of the current Meson build
# (e.g. configured with unit-tests=disabled), so a test run can never silently
# pass with zero tests or run stale modules.
for target in tests/libtest-utils.so tests/libtest-gst-backend.so; do
	if ! ninja -C "$builddir" -n "$target" >/dev/null 2>&1; then
		echo "error: $target is not part of the Meson build in $builddir." >&2
		echo "Rebuild with unit tests enabled (./scripts/build.sh)." >&2
		exit 1
	fi
done

cd "$builddir/tests"
exec "$cutter" --notify=no "$@" .
