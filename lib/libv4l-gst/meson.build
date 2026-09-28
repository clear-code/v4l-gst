plugin_sources = [
  'libv4l-gst.c',
  'v4l-gst-core.c',
  'v4l-gst-pipeline.c',
  'v4l-gst-fmt.c',
  'v4l-gst-buf.c',
  'v4l-gst-ctrl.c',
  'v4l-gst-event.c',
  'evfd-ctrl.c',
  'utils.c',
]

# The target name is 'v4l-gst' so that the meson 1.3 shared_module
# lib prefix produces exactly 'libv4l-gst.so'.
libv4l_gst_plugin = shared_module('v4l-gst',
  plugin_sources,
  include_directories: [inc_buildroot, inc_libinclude],
  dependencies: gst_deps + [v4l_dep, threads_dep],
  # -export-dynamic is kept for compatibility with the previous build.
  link_args: ['-export-dynamic'],
  install: true,
  install_dir: get_option('libdir') / get_option('libv4l-subdir') / 'plugins',
)
