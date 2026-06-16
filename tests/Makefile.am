AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/lib/libv4l-gst \
	-I$(top_srcdir)/lib/include \
	$(GST_CFLAGS)

AM_CFLAGS = -Wall -Wpointer-arith

if HAVE_CUTTER
AM_CPPFLAGS += $(CUTTER_CFLAGS)

TESTS = test-utils.la
LOG_COMPILER = $(CUTTER)

check_LTLIBRARIES = test-utils.la

test_utils_la_SOURCES = \
	test-utils.c \
	$(top_srcdir)/lib/libv4l-gst/utils.c
test_utils_la_LIBADD = \
	$(GST_LIBS) \
	$(CUTTER_LIBS)
test_utils_la_LDFLAGS = -module -avoid-version -rpath $(abs_builddir) -L$(with_libv4l_dir)/lib
else
TESTS =
check_LTLIBRARIES =
endif
