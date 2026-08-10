AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/lib/libv4l-gst \
	-I$(top_srcdir)/lib/include \
	$(GST_CFLAGS)

AM_CFLAGS = -Wall -Wpointer-arith

if HAVE_CUTTER
AM_CPPFLAGS += $(CUTTER_CFLAGS)

TESTS = run-test-suite.sh
LOG_COMPILER = $(SHELL)
TESTS_ENVIRONMENT = CUTTER="$(CUTTER)"

check_LTLIBRARIES = test-utils.la
EXTRA_DIST = run-test-suite.sh

test_utils_la_SOURCES = \
	test-utils.c \
	$(top_srcdir)/lib/libv4l-gst/utils.c
test_utils_la_LIBADD = \
	$(GST_LIBS) \
	$(CUTTER_LIBS)
test_utils_la_LDFLAGS = -module -avoid-version -rpath $(abs_builddir) -L$(with_libv4l_dir)/lib

check_LTLIBRARIES += test-gst-backend.la

test_gst_backend_la_SOURCES = \
	test-gst-backend.c \
	$(top_srcdir)/lib/libv4l-gst/libv4l-gst.c \
	$(top_srcdir)/lib/libv4l-gst/gst-backend.c \
	$(top_srcdir)/lib/libv4l-gst/evfd-ctrl.c \
	$(top_srcdir)/lib/libv4l-gst/utils.c
test_gst_backend_la_LIBADD = \
	$(GST_LIBS) \
	$(CUTTER_LIBS)
test_gst_backend_la_LDFLAGS = -module -avoid-version -rpath $(abs_builddir) -L$(with_libv4l_dir)/lib
else
TESTS =
check_LTLIBRARIES =
endif
