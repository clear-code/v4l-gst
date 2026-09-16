project(
  'libv4l-gst',
  'c',
  version: '2.0.0',
  default_options: [
    'c_std=c99',
    'warning_level=2',
  ],
  meson_version: '>= 0.57.0',
)

cc = meson.get_compiler('c')

# Enable GNU extensions (needed for linux/videodev2.h struct __kernel_timespec)
add_project_arguments('-D_GNU_SOURCE', language: 'c')

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
enable_tests = get_option('tests')
enable_vidioc_debug = get_option('vidioc-debug')

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
gst_deps = [
  dependency('gstreamer-1.0'),
  dependency('gstreamer-video-1.0'),
  dependency('gstreamer-app-1.0'),
  dependency('gstreamer-allocators-1.0'),
]

# libv4l2: try a user-supplied directory first (PC builds with the v4l-utils
# submodule), fall back to pkg-config (Yocto / system install).
_libv4l_dir = get_option('libv4l-dir')
libv4l2_lib_dir = ''
if _libv4l_dir != ''
  # Use raw compile/link args to avoid Meson's source-tree path check
  # (v4l-utils _install_root is inside the source tree as a submodule)
  libv4l2_dep = declare_dependency(
    compile_args: ['-I' + _libv4l_dir / 'include'],
    link_args: ['-L' + _libv4l_dir / 'lib', '-lv4l2'],
  )
  libv4l2_lib_dir = _libv4l_dir / 'lib'
else
  libv4l2_dep = dependency('libv4l2', required: true)
endif

# Cutter (optional, for unit tests)
cutter_dep = dependency('cutter', required: false)
cutter_prog = find_program('cutter', required: false)

# ---------------------------------------------------------------------------
# config.h
# ---------------------------------------------------------------------------
conf_data = configuration_data()
conf_data.set('PACKAGE', meson.project_name())
conf_data.set('VERSION', meson.project_version())

if enable_vidioc_debug
  conf_data.set('ENABLE_DEBUG', 1)
  conf_data.set('ENABLE_VIDIOC_DEBUG', 1)
endif

if enable_tests == true
  conf_data.set('UNIT_TESTS', 1)
endif

configure_file(
  output: 'config.h',
  configuration: conf_data,
)

# Top-level include dir so that sources can #include "config.h"
inc_top = include_directories('.')

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
subdir('lib')

if enable_tests == true
  if cutter_dep.found() and cutter_prog.found()
    subdir('tests')
  else
    message('Cutter not found: unit tests disabled')
  endif
else
  message('Unit tests disabled (configure with -Dtests=true to enable)')
endif

