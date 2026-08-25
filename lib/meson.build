# ── libv4l-gst plugin (shared module) ───────────────────────────
lib_sources = [
  'libv4l-gst/libv4l-gst.c',
  'libv4l-gst/gst-backend.c',
  'libv4l-gst/evfd-ctrl.c',
  'libv4l-gst/utils.c',
]

lib_inc = include_directories(
  '..',
  'libv4l-gst',
  'include',
)

# The plugin is a shared module (.so) loaded by libv4l at runtime.
# It uses GST_PLUGIN_DEFINE to register with GStreamer's plugin system,
# so it must link against gstreamer libraries.
libv4l_gst = shared_module(
  'libv4l-gst',
  lib_sources,
  include_directories: lib_inc,
  dependencies: common_deps,
  c_args: common_cargs + ['-DGST_USE_UNSTABLE_API'],
  install_dir: plugin_install_dir,
  install: true,
)

# ── Install public headers ──────────────────────────────────────
install_headers(
  'include/libv4l-gst-bufferpool.h',
  subdir: 'libv4l-gst',
)
