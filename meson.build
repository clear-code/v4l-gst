project(
  'libv4l-gst',
  'c',
  version: '2.0.0',
  default_options: [
    'warning_level=3',
    'buildtype=debugoptimized',
  ],
)

# ── Dependencies ────────────────────────────────────────────────
gst_dep      = dependency('gstreamer-1.0', version: '>= 1.4')
gst_video_dep = dependency('gstreamer-video-1.0', version: '>= 1.4')
gst_app_dep   = dependency('gstreamer-app-1.0')
gst_allocator_dep = dependency('gstreamer-allocators-1.0')

# libv4l can be found via pkg-config in two ways:
# 1. Custom v4l-utils builds provide 'libv4l.pc' (combined package)
# 2. System packages split into libv4l1, libv4l2, libv4lconvert

libv4l_dir = get_option('libv4l_dir')
if libv4l_dir != ''
  # Custom v4l-utils installation — prepend its pkgconfig path
  custom_pkg_path = libv4l_dir / 'lib' / 'pkgconfig'
  if not fs.exists(custom_pkg_path)
    custom_pkg_path = libv4l_dir / 'usr' / 'lib' / 'pkgconfig'
  endif
  PKG_CONFIG_PATH = custom_pkg_path + ':' + environment.get_variable('PKG_CONFIG_PATH')

  # Try combined libv4l.pc first (from patched v4l-utils)
  libv4l_dep = dependency('libv4l', required: false,
    method: 'pkg-config',
    variables: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
  )

  if not libv4l_dep.found()
    # Fall back to individual packages from custom build
    libv4l1_dep = dependency('libv4l1', required: true,
      method: 'pkg-config',
      variables: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    )
    libv4l2_dep = dependency('libv4l2', required: true,
      method: 'pkg-config',
      variables: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    )
    libv4lconvert_dep = dependency('libv4lconvert', required: false,
      method: 'pkg-config',
      variables: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    )
    libv4l_inc_dir = libv4l1_dep.get_variable('includedir')
    if libv4l2_dep.get_variable('includedir') != '' and \
       libv4l2_dep.get_variable('includedir') != libv4l_inc_dir
      libv4l_inc_dir += ':' + libv4l2_dep.get_variable('includedir')
    endif

    libv4l_dep = declare_dependency(
      include_directories: include_directories(libv4l_inc_dir),
      dependencies: [libv4l1_dep, libv4l2_dep] + (libv4lconvert_dep.found() ? [libv4lconvert_dep] : []),
    )
  endif

else
  # System installation — try combined libv4l.pc first
  libv4l_dep = dependency('libv4l', required: false)

  if not libv4l_dep.found()
    # Fall back to individual system packages
    libv4l1_dep = dependency('libv4l1', required: true)
    libv4l2_dep = dependency('libv4l2', required: true)
    libv4lconvert_dep = dependency('libv4lconvert', required: false)

    # Collect include directories from individual packages (deduplicated)
    inc_dirs = []
    foreach dep : [libv4l1_dep, libv4l2_dep] + (libv4lconvert_dep.found() ? [libv4lconvert_dep] : [])
      inc = dep.get_variable('includedir')
      if inc != '' and inc not in inc_dirs
        inc_dirs += inc
      endif
    endforeach

    libv4l_dep = declare_dependency(
      include_directories: include_directories(inc_dirs),
      dependencies: [libv4l1_dep, libv4l2_dep] + (libv4lconvert_dep.found() ? [libv4lconvert_dep] : []),
    )
  endif
endif

message('libv4l dependency found: ' + libv4l_dep.type_name())

# ── Compiler checks ─────────────────────────────────────────────
cc = meson.get_compiler('c')
have_visibility = cc.has_argument('-fvisibility=hidden')

# ── Configuration header ────────────────────────────────────────
config_h_data = configuration_data()
config_h_data.set10('ENABLE_DEBUG', true)
config_h_data.set10('ENABLE_VIDIOC_DEBUG', get_option('vidioc_debug'))
config_h_data.set10('UNIT_TESTS', get_option('unit_tests'))
config_h_data.set10('HAVE_VISIBILITY', have_visibility)

# Check if libv4l_dev_ops has mmap member (added in newer v4l-utils)
have_libv4l_mmap = cc.compiles(
  '#include <libv4l-plugin.h>\nstruct libv4l_dev_ops ops; void *p = NULL; ops.mmap = p;',
)
config_h_data.set10('HAVE_LIBV4L_MMAP', have_libv4l_mmap)

# Plugin install directory: ${libdir}/libv4l/plugins
plugin_install_dir = get_option('libdir') + '/' + get_option('libv4l2subdir') + '/plugins'
config_h_data.set('LIBV4L2_PLUGIN_DIR', plugin_install_dir)

configure_file(
  output: 'config.h',
  configuration: config_h_data,
)

# ── Common compile args ─────────────────────────────────────────
common_cargs = [
  '-D_GNU_SOURCE',
]
if have_visibility
  common_cargs += ['-fvisibility=hidden']
endif

common_deps = [gst_dep, gst_video_dep, gst_app_dep, gst_allocator_dep, libv4l_dep]

# ── Subdirectories ──────────────────────────────────────────────
subdir('lib')

if get_option('unit_tests')
  subdir('tests')
endif
