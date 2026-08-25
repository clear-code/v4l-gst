project(
  'libv4l-gst',
  'c',
  version: '2.0.0',
  default_options: [
    'warning_level=3',
    'buildtype=debugoptimized',
  ],
)

# Import filesystem module (Meson < 1.5 requires explicit import)
fs = import('fs')

# ── Dependencies ────────────────────────────────────────────────
gst_dep      = dependency('gstreamer-1.0', version: '>= 1.4')
gst_video_dep = dependency('gstreamer-video-1.0', version: '>= 1.4')
gst_app_dep   = dependency('gstreamer-app-1.0')
gst_allocator_dep = dependency('gstreamer-allocators-1.0')

# ── libv4l Dependency Resolution ────────────────────────────────
# Priority order:
#   1. User-specified -Dlibv4l_dir=DIR (custom v4l-utils build)
#   2. Auto-detected v4l-utils submodule in source tree
#   3. System packages (split libv4l1/libv4l2/libv4lconvert)

libv4l_dir = get_option('libv4l_dir')

# Auto-detect v4l-utils submodule if not explicitly specified
if libv4l_dir == ''
  v4l_utils_submodule = meson.source_root() / 'v4l-utils'
  if fs.exists(v4l_utils_submodule)
    libv4l_dir = v4l_utils_submodule
    message('Auto-detected v4l-utils submodule: ' + libv4l_dir)
  endif
endif

# Resolve pkg-config search paths for a given v4l-utils directory.
# Tries these locations in order:
#   - builddir/meson-uninstalled/     (unbuilt/uninstalled meson build)
#   - _install_root/usr/lib/*/pkgconfig/  (installed, arch-specific lib dir)
#   - _install_root/usr/lib/pkgconfig/    (installed, no arch-specific lib dir)
#   - lib/pkgconfig                     (custom builds without usr prefix)
v4l_pkg_paths = []

if libv4l_dir != ''
  # Meson uninstalled runtime (for building against unbuilt v4l-utils)
  meson_uninstalled = libv4l_dir / 'builddir' / 'meson-uninstalled'
  if fs.exists(meson_uninstalled)
    v4l_pkg_paths += [meson_uninstalled]
  endif

  # Installed to _install_root with arch-specific lib directory (e.g. x86_64-linux-gnu)
  install_arch_lib = libv4l_dir / '_install_root' / 'usr' / 'lib'
  if fs.exists(install_arch_lib) and v4l_pkg_paths.length() == 0
    foreach d : fs.glob(install_arch_lib, follow_symlinks: false)
      pkg_dir = d / 'pkgconfig'
      if fs.exists(pkg_dir)
        v4l_pkg_paths += [pkg_dir]
        break
      endif
    endforeach
  endif

  # Installed to _install_root without arch-specific lib directory
  install_lib_pkg = libv4l_dir / '_install_root' / 'usr' / 'lib' / 'pkgconfig'
  if v4l_pkg_paths.length() == 0 and fs.exists(install_lib_pkg)
    v4l_pkg_paths += [install_lib_pkg]
  endif

  # Custom build without usr prefix
  custom_lib_pkg = libv4l_dir / 'lib' / 'pkgconfig'
  if v4l_pkg_paths.length() == 0 and fs.exists(custom_lib_pkg)
    v4l_pkg_paths += [custom_lib_pkg]
  endif
endif

if v4l_pkg_paths.length() > 0
  # Build PKG_CONFIG_PATH from found paths
  PKG_CONFIG_PATH = ''
  foreach p : v4l_pkg_paths
    if PKG_CONFIG_PATH != ''
      PKG_CONFIG_PATH += ':'
    endif
    PKG_CONFIG_PATH += p
  endforeach

  # Append system PKG_CONFIG_PATH (use $() to avoid trailing newline from echo)
  _sys_pkg_path = run_command('sh', '-c', 'echo $PKG_CONFIG_PATH', check: false).stdout().strip()
  if _sys_pkg_path != ''
    PKG_CONFIG_PATH += ':' + _sys_pkg_path
  endif

  message('Using v4l-utils pkg-config paths: ' + PKG_CONFIG_PATH)

  # ── Query libv4l1 via pkg-config (required) ─────────────────────
  _q_cflags = run_command(
    'pkg-config', '--cflags', 'libv4l1',
    env: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    check: false,
  )
  if _q_cflags.returncode() != 0
    error('pkg-config --cflags libv4l1 failed (using PKG_CONFIG_PATH=' + PKG_CONFIG_PATH + ')')
  endif

  _q_libs = run_command(
    'pkg-config', '--libs', 'libv4l1',
    env: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    check: false,
  )
  if _q_libs.returncode() != 0
    error('pkg-config --libs libv4l1 failed')
  endif

  _q_cflags_arr = _q_cflags.stdout().strip().split()

  libv4l1_dep = declare_dependency(
    compile_args: _q_cflags_arr,
    link_args: _q_libs.stdout().strip().split(),
  )

  # ── Query libv4l2 via pkg-config (required) ─────────────────────
  _q_cflags = run_command(
    'pkg-config', '--cflags', 'libv4l2',
    env: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    check: false,
  )
  if _q_cflags.returncode() != 0
    error('pkg-config --cflags libv4l2 failed (using PKG_CONFIG_PATH=' + PKG_CONFIG_PATH + ')')
  endif

  _q_libs = run_command(
    'pkg-config', '--libs', 'libv4l2',
    env: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    check: false,
  )
  if _q_libs.returncode() != 0
    error('pkg-config --libs libv4l2 failed')
  endif

  _q_cflags_arr = _q_cflags.stdout().strip().split()

  libv4l2_dep = declare_dependency(
    compile_args: _q_cflags_arr,
    link_args: _q_libs.stdout().strip().split(),
  )

  # ── Query libv4lconvert via pkg-config (optional) ───────────────
  have_libv4lconvert = false
  _q_cflags = run_command(
    'pkg-config', '--cflags', 'libv4lconvert',
    env: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
    check: false,
  )

  if _q_cflags.returncode() == 0
    _q_libs = run_command(
      'pkg-config', '--libs', 'libv4lconvert',
      env: {'PKG_CONFIG_PATH': PKG_CONFIG_PATH},
      check: false,
    )

    if _q_libs.returncode() == 0
      _q_cflags_arr = _q_cflags.stdout().strip().split()

      libv4lconvert_dep = declare_dependency(
        compile_args: _q_cflags_arr,
        link_args: _q_libs.stdout().strip().split(),
      )
      have_libv4lconvert = true
    endif
  endif

  # Combine dependencies (include paths are in compile_args)
  libv4l_dep = declare_dependency(
    dependencies: [libv4l1_dep, libv4l2_dep] + (have_libv4lconvert ? [libv4lconvert_dep] : []),
  )

else
  # No pkg-config paths found — use system packages only
  if libv4l_dir != ''
    message('No pkg-config files in ' + libv4l_dir + '; falling back to system packages')
  else
    message('No v4l-utils directory specified or found; using system packages')
  endif

  libv4l1_dep = dependency('libv4l1', required: true)
  libv4l2_dep = dependency('libv4l2', required: true)
  libv4lconvert_dep = dependency('libv4lconvert', required: false)

  libv4l_dep = declare_dependency(
    dependencies: [libv4l1_dep, libv4l2_dep] + (libv4lconvert_dep.found() ? [libv4lconvert_dep] : []),
  )
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
