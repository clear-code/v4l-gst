# ── Unit tests (cutter) ────────────────────────────────────────
# cutter is a C unit test framework that loads shared modules containing
# test functions. It expects .so files with specific symbols.

cutter_dep = dependency('cutter', required: false)

if cutter_dep.found()
  message('Building unit tests with cutter')

  test_inc = include_directories(
    '..',
    '../lib/libv4l-gst',
  )

  # ── Static library for tests ─────────────────────────────────────
  # The plugin (shared module) uses -fvisibility=hidden, which hides all
  # symbols. cutter needs exported symbols, so we build a static library
  # without that flag and link the test modules against it.
  lib_sources = [
    '../lib/libv4l-gst/libv4l-gst.c',
    '../lib/libv4l-gst/gst-backend.c',
    '../lib/libv4l-gst/evfd-ctrl.c',
    '../lib/libv4l-gst/utils.c',
  ]

  lib_inc = include_directories(
    '..',
    '../lib/libv4l-gst',
    '../lib/include',
  )

  libv4l_gst_static = static_library(
    'libv4l-gst',
    lib_sources,
    include_directories: lib_inc,
    dependencies: common_deps,
    c_args: ['-D_GNU_SOURCE', '-DGST_USE_UNSTABLE_API'],
  )

  # ── test-utils shared module ────────────────────────────────────
  # Note: do NOT use -fvisibility=hidden for test modules; cutter needs
  # exported symbols to discover test suites.
  test_utils = shared_module(
    'test-utils',
    'test-utils.c',
    include_directories: test_inc,
    dependencies: common_deps + [cutter_dep],
    c_args: ['-D_GNU_SOURCE'],
    link_with: libv4l_gst_static,
    build_by_default: false,
  )

  # ── test-gst-backend shared module ──────────────────────────────
  test_gst_backend = shared_module(
    'test-gst-backend',
    'test-gst-backend.c',
    include_directories: test_inc,
    dependencies: common_deps + [cutter_dep],
    c_args: ['-D_GNU_SOURCE'],
    link_with: libv4l_gst_static,
    build_by_default: false,
  )

  # ── Register tests with meson test runner ───────────────────────
  # cutter loads the .so files directly; we use a wrapper script to invoke
  # cutter with the built modules.
  cutter_prog = find_program('cutter')

  test(
    'unit-tests',
    cutter_prog,
    args: [
      '--notify=no',
      test_utils.full_path(),
      test_gst_backend.full_path(),
    ],
    depends: [test_utils, test_gst_backend],
  )
else
  message('cutter not found — skipping unit tests')
endif
