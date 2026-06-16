This repository can use a modified v4l-utils tree as a git submodule. The
following example shows how to build using that submodule on a development
PC. The upstream `v4l-utils` in this branch uses Meson as its build system.

1. Add and initialize the submodule

```sh
git submodule add -b scarthgap/v4l-utils-1.26.1 \
	https://github.com/clear-code/v4l-utils v4l-utils
git submodule update --init --recursive
```

2. Build `v4l-utils` with Meson and install it locally under `_install`.

```sh
cd v4l-utils
meson setup builddir --prefix=$PWD/_install
meson compile -C builddir
meson install -C builddir
cd ..
```

Note: You will usually need `meson`, `ninja`, and development packages for
dependencies. On Debian/Ubuntu, for example, install something like:

```sh
sudo apt install meson ninja-build pkg-config libglib2.0-dev
```

3. Run `configure` at the project root and point it to the local install.

```sh
./configure --with-libv4l-dir=$PWD/v4l-utils/_install
make -j$(nproc)
```

Notes:
- If you omit `--with-libv4l-dir`, the build system will auto-detect a
	`v4l-utils` directory and add its include/lib paths. However, you must
	have built and installed `v4l-utils` beforehand.
- Integrating this into Yocto requires adapting your existing recipes and
	is outside the scope of this document.
