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

# Allow using a local (vendored / submodule) libv4l tree.
AC_ARG_WITH([libv4l-dir],
	[AS_HELP_STRING([--with-libv4l-dir=DIR], [use local libv4l from DIR])],
	[],
	[with_libv4l_dir="$withval"])

# If user provided a dir, use its include/lib. If a v4l-utils subdirectory
# exists, prefer that automatically.
EXTRA_CPPFLAGS=""
EXTRA_LDFLAGS=""
if test "x$with_libv4l_dir" != "x"; then
	EXTRA_CPPFLAGS="-I$with_libv4l_dir/include $EXTRA_CPPFLAGS"
	EXTRA_LDFLAGS="-L$with_libv4l_dir/lib $EXTRA_LDFLAGS"
else
	if test -d "$srcdir/v4l-utils"; then
		EXTRA_CPPFLAGS="-I\$(top_srcdir)/v4l-utils/include $EXTRA_CPPFLAGS"
		EXTRA_LDFLAGS="-L\$(top_srcdir)/v4l-utils/lib $EXTRA_LDFLAGS"
		with_libv4l_dir="$srcdir/v4l-utils"
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
