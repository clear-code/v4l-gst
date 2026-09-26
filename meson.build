project('libv4l-gst', 'c',
  version: '2.0.0',
  license: 'LGPL-2.1-or-later',
  meson_version: '>=0.63',
  default_options: [
    'warning_level=1',
  ])

cc = meson.get_compiler('c')

# warning_level=1 gives -Wall; -Wpointer-arith is kept from the previous build.
add_project_arguments('-Wpointer-arith', language: 'c')

gst_deps = [
  dependency('gstreamer-video-1.0', version: '>=1.4'),
  dependency('gstreamer-app-1.0'),
  dependency('gstreamer-allocators-1.0'),
]
threads_dep = dependency('threads')

# The plugin is loaded by libv4l (dlopen), so only the libv4l headers are
# needed at build time. libv4l implementation libraries are not linked.
fs = import('fs')
libv4l_dir = get_option('libv4l-dir')
if libv4l_dir == ''
  # PC development: prefer a locally built v4l-utils submodule tree.
  foreach candidate : [
    meson.current_source_dir() / 'v4l-utils' / '_install_root' / 'usr',
    meson.current_source_dir() / 'v4l-utils',
  ]
    if fs.is_file(candidate / 'include' / 'libv4l-plugin.h')
      libv4l_dir = candidate
      break
    endif
  endforeach
endif

v4l_dep = declare_dependency()
if libv4l_dir != ''
  v4l_inc_path = libv4l_dir / 'include'
  src_root = meson.project_source_root()
  if v4l_inc_path.startswith(src_root + '/')
    # Meson forbids absolute include paths inside the source tree;
    # use a path relative to the source root instead.
    v4l_inc_path = v4l_inc_path.replace(src_root + '/', '')
  endif
  v4l_dep = declare_dependency(
    include_directories: include_directories(v4l_inc_path))
  if not cc.has_header('libv4l-plugin.h', dependencies: v4l_dep)
    error('libv4l-plugin.h is needed (checked ' + (libv4l_dir / 'include') + ')')
  endif
else
  # Rely on the system v4l-utils, e.g. provided by the Yocto sysroot.
  if not cc.has_header('libv4l-plugin.h')
    error('libv4l-plugin.h is needed; install v4l-utils or pass -Dlibv4l-dir=DIR')
  endif
endif

plugin_srcdir = meson.current_source_dir() / 'lib' / 'libv4l-gst'
plugin_install_dir = get_option('libdir') / get_option('libv4l-subdir') / 'plugins'

inc_buildroot = include_directories('.')
inc_libinclude = include_directories('lib/include')
inc_plugin = include_directories('lib/libv4l-gst')

# config.h is referenced by the sources. Only the macros actually used by
# the current sources are generated:
# - _GNU_SOURCE (previously provided by AC_GNU_SOURCE)
# - LIBV4L2_PLUGIN_DIR (kept for compatibility)
# - ENABLE_DEBUG / ENABLE_VIDIOC_DEBUG (only with -Dvidioc-debug=true)
# NOTE: UNIT_TESTS is intentionally NOT defined here. It is defined only for
# the unit test modules (see tests/meson.build).
config = configuration_data()
config.set('_GNU_SOURCE', 1)
config.set_quoted('LIBV4L2_PLUGIN_DIR', plugin_install_dir)
if get_option('vidioc-debug')
  config.set('ENABLE_DEBUG', 1)
  config.set('ENABLE_VIDIOC_DEBUG', 1)
endif
configure_file(output: 'config.h', configuration: config)

subdir('lib')
subdir('tests')
