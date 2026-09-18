# libv4l-gst plugin shared library
# This is loaded by libv4l2 via dlopen, so it must be a module/shared library.

src_lib = files(
  'libv4l-gst.c',
  'gst-backend.c',   # gst-backend-testhooks.c is included at the end
  'evfd-ctrl.c',
  'utils.c',
)

inc_lib = include_directories('..', '../include')

_plugin_dir = get_option('libv4l2-plugin-dir')
if _plugin_dir == ''
  libv4l2_plugin_install_dir = get_option('libdir') / 'libv4l' / 'plugins'
else
  libv4l2_plugin_install_dir = _plugin_dir
endif

libv4l_gst = shared_library(
  'libv4l-gst',
  src_lib,
  include_directories: [inc_top, inc_lib],
  dependencies: gst_deps + [libv4l2_dep],
  c_args: ['-Wall', '-Wpointer-arith'],
  name_prefix: '',
  install: true,
  install_dir: libv4l2_plugin_install_dir,
)

# Install public header
install_headers(
  '../include/libv4l-gst-bufferpool.h',
  install_dir: get_option('includedir') / 'libv4l-gst',
)
