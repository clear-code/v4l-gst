# -*- Autoconf -*-

# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([libv4l-gst],[2.0.0])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
	lib/Makefile
	lib/libv4l-gst/Makefile
	tests/Makefile
])

AC_GNU_SOURCE

AM_INIT_AUTOMAKE([1.9 subdir-objects no-dist-gzip dist-bzip2 -Wno-portability])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC_C99
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MKDIR_P

AC_CHECK_HEADER([libv4l-plugin.h], [], AC_MSG_ERROR([libv4l-plugin.h is needed]))
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES(GST, gstreamer-video-1.0 >= 1.4 gstreamer-app-1.0
		gstreamer-allocators-1.0)

# Unit tests using Cutter (auto/enable)
AC_ARG_ENABLE([unit-tests],
	AS_HELP_STRING([--enable-unit-tests], [Enable unit tests that use Cutter (default=auto)]),
	[],
	[enable_unit_tests=auto])

# Check for Cutter via pkg-config, allow overrides via CUTTER_CFLAGS/CUTTER_LIBS/CUTTER
m4_pattern_allow([^CUTTER_CFLAGS$])
m4_pattern_allow([^CUTTER_LIBS$])
m4_pattern_allow([^CUTTER$])
PKG_CHECK_MODULES([CUTTER], [cutter], [
	AC_PATH_PROG([CUTTER], [cutter])
	AS_IF([test "x$CUTTER" != "x"], [have_cutter=yes])
],[have_cutter=no])
AM_CONDITIONAL([HAVE_CUTTER], [test "x$have_cutter" = "xyes"])
if test "x$have_cutter" = "xyes"; then
	CUTTER_CFLAGS=$pkg_cv_CUTTER_CFLAGS
	CUTTER_LIBS=$pkg_cv_CUTTER_LIBS
	# Extract the first word of "cutter", so it can be a program name with args.
	set dummy cutter; ac_word=$2
	if test ${ac_cv_path_CUTTER+y}; then
	  ac_cv_path_CUTTER="$CUTTER"
	else
	  AC_PATH_PROG([CUTTER], [cutter])
	  ac_cv_path_CUTTER="$CUTTER"
	fi
	CUTTER=$ac_cv_path_CUTTER
	# Define UNIT_TESTS so test-only symbols are exposed to test sources
	AC_DEFINE([UNIT_TESTS], [1], [Define to enable unit test hooks])
else
	HAVE_CUTTER_FALSE='#'
	HAVE_CUTTER_TRUE=
fi
AC_SUBST([CUTTER])
AC_SUBST([CUTTER_CFLAGS])
AC_SUBST([CUTTER_LIBS])

if test "x$enable_unit_tests" = "xyes" && test "x$have_cutter" != "xyes"; then
	as_fn_error $? "Cutter is needed for --enable-unit-tests" "$LINENO" 5
fi

# Allow using a local (vendored / submodule) libv4l tree.
AC_ARG_WITH([libv4l-dir],
	[AS_HELP_STRING([--with-libv4l-dir=DIR], [use local libv4l from DIR])],
	[],
	[with_libv4l_dir="$withval"])

# Normalize user-provided path to absolute if needed
if test "x$with_libv4l_dir" != "x"; then
	case "$with_libv4l_dir" in
		/*) ;;
		*) with_libv4l_dir=`(cd "$with_libv4l_dir" && pwd)` ;;
	esac
fi

# If user provided a dir, use its include/lib. If a v4l-utils subdirectory
# exists, prefer that automatically.
EXTRA_CPPFLAGS=""
EXTRA_LDFLAGS=""
if test "x$with_libv4l_dir" != "x"; then
	EXTRA_CPPFLAGS="-I$with_libv4l_dir/include $EXTRA_CPPFLAGS"
	EXTRA_LDFLAGS="-L$with_libv4l_dir/lib $EXTRA_LDFLAGS"
else
	if test -d "$srcdir/v4l-utils"; then
		# Prefer headers from v4l-utils _install_root if present (contains libv4l-plugin.h)
		if test -d "$srcdir/v4l-utils/_install_root/usr/include" ; then
			EXTRA_CPPFLAGS="-I\$(top_srcdir)/v4l-utils/_install_root/usr/include $EXTRA_CPPFLAGS"
		else
			EXTRA_CPPFLAGS="-I\$(top_srcdir)/v4l-utils/include $EXTRA_CPPFLAGS"
		fi
		EXTRA_LDFLAGS="-L\$(top_srcdir)/v4l-utils/lib $EXTRA_LDFLAGS"
		# Normalize to an absolute path so subdir builds find it correctly
		tmp_libv4l_dir="$srcdir/v4l-utils"
		case "$tmp_libv4l_dir" in
			/*) with_libv4l_dir="$tmp_libv4l_dir" ;;
			*) with_libv4l_dir=`(cd "$tmp_libv4l_dir" && pwd)` ;;
		esac
	fi
fi
AC_SUBST([EXTRA_CPPFLAGS])
AC_SUBST([EXTRA_LDFLAGS])
AC_SUBST([with_libv4l_dir])

AC_ARG_WITH(libv4l2subdir,
        AS_HELP_STRING([--with-libv4l2subdir=DIR], [set libv4l2 library subdir (default=libv4l)]),
        [],
        [with_libv4l2subdir="libv4l"])

AC_SUBST([libv4l2plugindir], [$libdir/$with_libv4l2subdir/plugins])

AC_DEFINE_DIR([LIBV4L2_PLUGIN_DIR], [libv4l2plugindir], [libv4l2 plugin directory])

AC_ARG_ENABLE([vidioc-debug],
	[AS_HELP_STRING([--enable-vidioc-debug],
			[Enable/disable the specific features for debugging VIDIOC])],
	[],
	[enable_vidioc_debug=no]
)

if test "x${enable_vidioc_debug}" = "xyes"; then
	AC_DEFINE(ENABLE_DEBUG, 1,
		[Define if the specific debug output is enabled])
	AC_DEFINE(ENABLE_VIDIOC_DEBUG, 1,
		[Define if the specific debug operation to control VIDIOC features are enabled])
fi

CPPFLAGS="-I\$(top_srcdir)/lib/include -Wall -Wpointer-arith $EXTRA_CPPFLAGS $CPPFLAGS"
LDFLAGS="$EXTRA_LDFLAGS $LDFLAGS"

AC_OUTPUT
