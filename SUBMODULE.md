This repository can use a modified v4l-utils tree as a git submodule. The
following example shows how to build using that submodule on a development
PC.

1. Add and initialize the submodules

```sh
git submodule add -b scarthgap/v4l-utils-1.26.1 \
  https://github.com/clear-code/v4l-utils v4l-utils
git submodule add https://github.com/clear-code/cutter.git cutter
git submodule update --init --recursive
```

2. Build the project with Meson

```sh
./scripts/build.sh
```

The script builds `v4l-utils` with Meson and installs it locally under
`v4l-utils/_install_root`, builds the `cutter` submodule under `_local`
when Cutter is not available on the system, and then configures and builds
this project with Meson, passing `-Dlibv4l-dir` that points to the local
`v4l-utils` install.

Note: You will usually need `meson`, `ninja`, and development packages for
dependencies. On Debian/Ubuntu, for example, install something like:

```sh
sudo apt install meson ninja-build pkg-config libglib2.0-dev
```

Notes:
- If you omit `-Dlibv4l-dir`, Meson auto-detects a `v4l-utils` directory
  (the `_install_root/usr` install tree if present). If no local tree is
  found, the system `v4l-utils` is used, which is what Yocto builds rely on.
- Integrating this into Yocto requires adapting your existing recipes and
  is outside the scope of this document.
