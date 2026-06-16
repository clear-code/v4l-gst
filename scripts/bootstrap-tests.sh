#!/bin/bash
set -eu
# Bootstrap and run tests for this repository. This script will:
# - ensure v4l-utils submodule is built into _install_root/usr (if needed)
# - ensure cutter is available (system or build submodule into _local)
# - configure (if needed), build (if needed) and run `make check`

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

V4L_DIR="$ROOT/v4l-utils/_install_root/usr"
if [ ! -d "$V4L_DIR" ]; then
    echo "v4l-utils install tree not found at: $V4L_DIR"
    echo "Attempting to initialise and build the v4l-utils submodule..."

    git submodule update --init --recursive v4l-utils
    if [ ! -d "$ROOT/v4l-utils" ]; then
        echo "v4l-utils submodule not present. Please add or init it manually." >&2
        exit 1
    fi

    cd "$ROOT/v4l-utils"
    if [ -f meson.build ] && command -v meson >/dev/null 2>&1; then
        BUILD_DIR=builddir
        if [ ! -d "$BUILD_DIR" ]; then
            meson setup "$BUILD_DIR" --prefix=/usr
        else
            meson setup --reconfigure "$BUILD_DIR" --prefix=/usr
        fi
        ninja -C "$BUILD_DIR" -j"$(nproc)"
        DESTDIR="$(pwd)/_install_root" ninja -C "$BUILD_DIR" install
    elif [ -f configure.ac ] || [ -f configure ]; then
        autoreconf -fi
        ./configure --prefix="$(pwd)/_install_root"
        make -j"$(nproc)"
        make install
    else
        echo "Unknown build system for v4l-utils; build it manually and ensure"
        echo "_install_root/usr exists." >&2
        exit 1
    fi

    cd "$ROOT"
    V4L_DIR="$ROOT/v4l-utils/_install_root/usr"
    if [ ! -d "$V4L_DIR" ]; then
        echo "v4l-utils install tree still not found at: $V4L_DIR" >&2
        exit 1
    fi
fi

# Cutter: prefer system cutter; otherwise use local installed copy or build
if command -v cutter >/dev/null 2>&1; then
    echo "cutter found in PATH; skipping cutter build"
elif [ -x "$ROOT/_local/bin/cutter" ]; then
    echo "Using existing local cutter at $ROOT/_local/bin/cutter"
    export PATH="$ROOT/_local/bin:$PATH"
    export PKG_CONFIG_PATH="$ROOT/_local/lib/pkgconfig:${PKG_CONFIG_PATH-}"
else
    echo "cutter not found — attempting to build from submodule..."
    git submodule update --init --recursive cutter || {
        echo "cutter submodule not present; please add or install cutter." >&2
        exit 1
    }

    cd "$ROOT/cutter"
    if [ -f meson.build ] && command -v meson >/dev/null 2>&1; then
        CBUILD=builddir
        if [ ! -d "$CBUILD" ]; then
            meson setup "$CBUILD" --prefix=/usr
        else
            meson setup --reconfigure "$CBUILD" --prefix=/usr
        fi
        ninja -C "$CBUILD" -j"$(nproc)"
        DESTDIR="$ROOT/_local" ninja -C "$CBUILD" install
    elif [ -f configure.ac ] || [ -f configure ]; then
        autoreconf -fi
        ./configure --prefix="$ROOT/_local"
        make -j"$(nproc)"
        make install
    else
        echo "Could not detect build system for cutter; install cutter manually." >&2
        exit 1
    fi

    cd "$ROOT"
    export PATH="$ROOT/_local/usr/bin:$ROOT/_local/bin:$PATH"
    export PKG_CONFIG_PATH="$ROOT/_local/usr/lib/pkgconfig:$ROOT/_local/lib/pkgconfig:${PKG_CONFIG_PATH-}"
fi

# Configure & build the project only when needed
if [ -f config.status ] && [ -f Makefile ]; then
    echo "config.status and Makefile exist; skipping autoreconf/configure"
else
    autoreconf -fi
    # Ensure the configure script can find headers/libs installed into the
    # v4l-utils local install tree.
    export PKG_CONFIG_PATH="$V4L_DIR/lib/pkgconfig:${PKG_CONFIG_PATH-}"
    ./configure --enable-unit-tests --with-libv4l-dir="$V4L_DIR"
fi

if make -q >/dev/null 2>&1; then
    echo "build up-to-date; skipping make"
else
    make -j"$(nproc)"
fi

make check
