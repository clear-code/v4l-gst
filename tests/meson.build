# Unit tests using Cutter framework
# Each test is a shared module loaded by the `cutter` program.

test_inc = include_directories(
  '..',
  '../..',
  '../lib/libv4l-gst',
  '../lib/include',
)

# Common library sources shared with test binaries
_lib_utils_c = '../lib/libv4l-gst/utils.c'
_lib_srcs = files(
  '../lib/libv4l-gst/libv4l-gst.c',
  '../lib/libv4l-gst/gst-backend.c',
  '../lib/libv4l-gst/evfd-ctrl.c',
  '../lib/libv4l-gst/utils.c',
)

# ---------------------------------------------------------------------------
# test-utils.so
# ---------------------------------------------------------------------------
test_utils = shared_library(
  'test-utils',
  'test-utils.c',
  _lib_utils_c,
  include_directories: [inc_top, test_inc],
  dependencies: gst_deps + [libv4l2_dep, cutter_dep],
  c_args: ['-Wall', '-Wpointer-arith'],
  name_prefix: '',
  install: false,
)

# ---------------------------------------------------------------------------
# test-gst-backend.so
# ---------------------------------------------------------------------------
test_gst_backend = shared_library(
  'test-gst-backend',
  'test-gst-backend.c',
  _lib_srcs,
  include_directories: [inc_top, test_inc],
  dependencies: gst_deps + [libv4l2_dep, cutter_dep],
  c_args: ['-Wall', '-Wpointer-arith'],
  name_prefix: '',
  install: false,
)

# ---------------------------------------------------------------------------
# Test target
# ---------------------------------------------------------------------------
test(
  'unit-tests',
  cutter_prog,
  args: ['--notify=no', meson.current_build_dir()],
  env: environment(),
  workdir: meson.current_build_dir(),
)
