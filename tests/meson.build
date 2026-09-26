# Unit tests are built as Cutter test modules. UNIT_TESTS is defined only
# for these modules, never for the plugin itself.
# If the unit-tests feature is enabled and Cutter is not found, this fails.
cutter_dep = dependency('cutter', required: get_option('unit-tests'))

if cutter_dep.found()
  # cutter.pc carries the path to the cutter executable (cutter=${bindir}/cutter).
  cutter_path = cutter_dep.get_variable(pkgconfig: 'cutter')
  if cutter_path != '' and import('fs').is_file(cutter_path)
    cutter_prog = find_program(cutter_path)
  else
    cutter_prog = find_program('cutter')
  endif

  unit_test_c_args = ['-DUNIT_TESTS=1']

  test_utils = shared_module('test-utils',
    'test-utils.c',
    plugin_srcdir / 'utils.c',
    include_directories: [inc_buildroot, inc_libinclude, inc_plugin],
    dependencies: gst_deps + [v4l_dep, cutter_dep],
    c_args: unit_test_c_args,
  )

  test_gst_backend = shared_module('test-gst-backend',
    'test-gst-backend.c',
    plugin_srcdir / 'libv4l-gst.c',
    plugin_srcdir / 'gst-backend.c',
    plugin_srcdir / 'evfd-ctrl.c',
    plugin_srcdir / 'utils.c',
    include_directories: [inc_buildroot, inc_libinclude, inc_plugin],
    dependencies: gst_deps + [v4l_dep, cutter_dep],
    c_args: unit_test_c_args,
  )

  # Cutter loads the test modules from the working directory.
  # `meson test` builds all targets (including the test modules) first.
  test('unit-tests',
    cutter_prog,
    args: ['--notify=no', '.'],
    workdir: meson.current_build_dir(),
    timeout: 300,
  )
else
  if get_option('unit-tests').allowed()
    warning('Cutter not found; unit tests are disabled. ' +
      'Install cutter or build the cutter submodule via ./scripts/build.sh.')
  endif
endif
