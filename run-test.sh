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

make -C "$top_dir/tests" test-utils.la test-gst-backend.la

cd "$top_dir/tests"
exec "$cutter" --notify=no "$@" .
