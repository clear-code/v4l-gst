#!/bin/sh

set -eu

top_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "${CUTTER:-}" ]; then
	cutter=$CUTTER
elif [ -x "$top_dir/_local/bin/cutter" ]; then
	cutter=$top_dir/_local/bin/cutter
else
	cutter=cutter
fi

ninja -C "$top_dir/builddir"

cd "$top_dir/tests"
exec "$cutter" --notify=no "$@" .
