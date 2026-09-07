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

  # ── test-utils shared module ────────────────────────────────────
  test_utils = shared_module(
    'test-utils',
    'test-utils.c',
    include_directories: test_inc,
    dependencies: common_deps + [cutter_dep],
    c_args: common_cargs,
    build_by_default: false,
  )

  # ── test-gst-backend shared module ──────────────────────────────
  test_gst_backend = shared_module(
    'test-gst-backend',
    'test-gst-backend.c',
    include_directories: test_inc,
    dependencies: common_deps + [cutter_dep],
    c_args: common_cargs,
    link_with: libv4l_gst,
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
