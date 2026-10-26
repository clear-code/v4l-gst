#include "v4l-gst-testhooks.h"
#include "v4l-gst.h"
#include <cutter.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <libv4l-plugin.h>
#include <sys/mman.h>
#include <unistd.h>

#include "utils.h"

static struct v4l_gst *backend;
extern const struct libv4l_dev_ops libv4l2_plugin;
static int backend_fd = -1;
static gchar *backend_fd_path;
static gchar *config_dir;
static gchar *config_path;
static gchar *old_xdg_config_dirs;
static gboolean had_xdg_config_dirs;

static GLogLevelFlags old_always_fatal;

struct querycap_result {
	int ret;
	guint32 device_caps;
	guint32 capabilities;
	gchar driver[sizeof(((struct v4l2_capability *)0)->driver)];
};

struct enum_fmt_result {
	int ret;
	int error_number;
	guint32 pixelformat;
	guint32 flags;
};

struct frame_size_result {
	int ret;
	int error_number;
	guint32 type;
	guint32 min_width;
	guint32 min_height;
	guint32 max_width;
	guint32 max_height;
	guint32 step_width;
	guint32 step_height;
};

struct pix_format_result {
	int ret;
	int error_number;
	guint32 pixelformat;
	guint32 width;
	guint32 height;
	guint32 num_planes;
	guint32 bytesperline;
	guint32 sizeimage;
};

static void
assert_equal_result_strings(const gchar *expected, const gchar *actual)
{
	cut_assert_equal_string(expected, actual,
				cut_message("%s", cut_take_diff(expected, actual)));
}

struct test_result_strings {
	GString *expected;
	GString *actual;
};

static void
test_result_strings_init(struct test_result_strings *result)
{
	result->expected = g_string_new(NULL);
	result->actual = g_string_new(NULL);
}

static void
test_result_strings_add_int(struct test_result_strings *result,
			    const gchar *name, gint64 expected, gint64 actual)
{
	g_string_append_printf(result->expected, "%s=%" G_GINT64_FORMAT "\n",
			       name, expected);
	g_string_append_printf(result->actual, "%s=%" G_GINT64_FORMAT "\n",
			       name, actual);
}

static void
test_result_strings_add_uint(struct test_result_strings *result,
			     const gchar *name, guint64 expected, guint64 actual)
{
	g_string_append_printf(result->expected, "%s=%" G_GUINT64_FORMAT "\n",
			       name, expected);
	g_string_append_printf(result->actual, "%s=%" G_GUINT64_FORMAT "\n",
			       name, actual);
}

static void
test_result_strings_assert(struct test_result_strings *result)
{
	assert_equal_result_strings(result->expected->str, result->actual->str);
	g_string_free(result->expected, TRUE);
	g_string_free(result->actual, TRUE);
}

static int
v4l_gst_ioctl(unsigned long int cmd, void *arg)
{
	return libv4l2_plugin.ioctl(backend, -1, cmd, arg);
}

void
cut_startup(void)
{
	/* Use identity only to satisfy pipeline configuration parsing.
	   Format-specific state that would normally come from real decoder
	   discovery is filled by prepare_format_backend_fixture(). */
	const gchar config[] =
		"[libv4l-gst]\n"
		"[H264]\n"
		"pipeline=identity\n";
	GError *error = NULL;

	config_dir = g_dir_make_tmp("v4l-gst-test-XXXXXX", &error);
	if (error)
		g_error("failed to create config directory: %s",
			error->message);

	config_path = g_build_filename(config_dir, "libv4l-gst.conf", NULL);
	if (!g_file_set_contents(config_path, config, -1, &error))
		g_error("failed to write config file: %s", error->message);

	had_xdg_config_dirs = g_getenv("XDG_CONFIG_DIRS") != NULL;
	old_xdg_config_dirs = g_strdup(g_getenv("XDG_CONFIG_DIRS"));
	g_setenv("XDG_CONFIG_DIRS", config_dir, TRUE);

	/* A critical during a test or teardown must fail the test process,
	   regardless of its GLib log domain. */
	old_always_fatal = g_log_set_always_fatal(G_LOG_LEVEL_CRITICAL);
}

void
setup(void)
{
	GError *error = NULL;

	backend_fd = g_file_open_tmp("v4l-gst-fd-XXXXXX", &backend_fd_path,
				     &error);
	cut_assert_null(error);

	backend = libv4l2_plugin.init(backend_fd);
	cut_assert_not_null(backend);
	prepare_format_backend_fixture(backend);
}

void
teardown(void)
{
	if (backend)
		libv4l2_plugin.close(backend);
	backend = NULL;

	if (backend_fd >= 0)
		close(backend_fd);
	backend_fd = -1;
	if (backend_fd_path)
		g_unlink(backend_fd_path);
	g_free(backend_fd_path);
	backend_fd_path = NULL;
}

void
cut_shutdown(void)
{
	if (had_xdg_config_dirs)
		g_setenv("XDG_CONFIG_DIRS", old_xdg_config_dirs, TRUE);
	else
		g_unsetenv("XDG_CONFIG_DIRS");
	g_free(old_xdg_config_dirs);
	old_xdg_config_dirs = NULL;
	if (config_path)
		g_unlink(config_path);
	g_free(config_path);
	config_path = NULL;
	if (config_dir)
		g_rmdir(config_dir);
	g_free(config_dir);
	config_dir = NULL;
	g_log_set_always_fatal(old_always_fatal);
}

void
test_create_pipeline_returns_nonnull(void)
{
	GstElement *p;

	gst_init(NULL, NULL);
	p = test_create_pipeline("identity");
	cut_assert_not_null(p);
	gst_element_set_state(p, GST_STATE_NULL);
	gst_object_unref(p);
}

static struct querycap_result
snapshot_querycap_result(int ret, struct v4l2_capability *cap)
{
	struct querycap_result result = {
		.ret = ret,
		.device_caps = cap->device_caps,
		.capabilities = cap->capabilities,
	};

	g_strlcpy(result.driver, (const gchar *)cap->driver,
		  sizeof(result.driver));

	return result;
}

static gchar *
querycap_result_to_string(const struct querycap_result *result)
{
	return g_strdup_printf("ret=%d\n"
			       "device_caps=0x%08x\n"
			       "capabilities=0x%08x\n"
			       "driver=%s\n",
			       result->ret,
			       result->device_caps,
			       result->capabilities,
			       result->driver);
}

void
test_querycap_advertises_m2m_mplane_streaming(void)
{
	struct v4l2_capability cap = { 0, };
	int ret;
	struct querycap_result expected = {
		.ret = 0,
		.device_caps = V4L2_CAP_VIDEO_M2M_MPLANE |
			       V4L2_CAP_VIDEO_CAPTURE_MPLANE |
			       V4L2_CAP_VIDEO_OUTPUT_MPLANE |
			       V4L2_CAP_EXT_PIX_FORMAT |
			       V4L2_CAP_STREAMING,
		.capabilities = V4L2_CAP_VIDEO_M2M_MPLANE |
				V4L2_CAP_VIDEO_CAPTURE_MPLANE |
				V4L2_CAP_VIDEO_OUTPUT_MPLANE |
				V4L2_CAP_EXT_PIX_FORMAT |
				V4L2_CAP_STREAMING |
				V4L2_CAP_DEVICE_CAPS,
		.driver = "libv4l-gst",
	};
	struct querycap_result actual;
	const gchar *expected_string =
		cut_take_string(querycap_result_to_string(&expected));
	const gchar *actual_string;

	ret = v4l_gst_ioctl(VIDIOC_QUERYCAP, &cap);
	actual = snapshot_querycap_result(ret, &cap);
	actual_string = cut_take_string(querycap_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

static struct enum_fmt_result
snapshot_enum_fmt_result(int ret, int error_number, struct v4l2_fmtdesc *desc)
{
	struct enum_fmt_result result = {
		.ret = ret,
		.error_number = error_number,
		.pixelformat = desc->pixelformat,
		.flags = desc->flags,
	};

	return result;
}

static gchar *
enum_fmt_result_to_string(const struct enum_fmt_result *result)
{
	gchar fourcc[5];

	fourcc_to_string(result->pixelformat, fourcc);

	return g_strdup_printf("ret=%d\n"
			       "errno=%d\n"
			       "pixelformat=%s (0x%08x)\n"
			       "flags=0x%08x\n",
			       result->ret,
			       result->error_number,
			       fourcc,
			       result->pixelformat,
			       result->flags);
}

void
test_enum_fmt_marks_output_as_compressed(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	desc.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_enum_fmt_marks_capture_as_raw(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.flags = 0,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_enum_fmt_rejects_output_index_after_configured_codec(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	desc.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	desc.index = 1;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_enum_fmt_capture_initial_is_nv12(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.flags = 0,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	desc.index = 1;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_enum_fmt_rejects_capture_index_after_fixture_format(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = -1,
		.error_number = EINVAL,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	desc.index = 2;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_enum_fmt_rejects_single_planar_type(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = -1,
		.error_number = EINVAL,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

static struct frame_size_result
snapshot_frame_size_result(int ret, int error_number,
			   struct v4l2_frmsizeenum *frame_size)
{
	struct frame_size_result result = {
		.ret = ret,
		.error_number = error_number,
		.type = frame_size->type,
		.min_width = frame_size->stepwise.min_width,
		.min_height = frame_size->stepwise.min_height,
		.max_width = frame_size->stepwise.max_width,
		.max_height = frame_size->stepwise.max_height,
		.step_width = frame_size->stepwise.step_width,
		.step_height = frame_size->stepwise.step_height,
	};

	return result;
}

static gchar *
frame_size_result_to_string(const struct frame_size_result *result)
{
	return g_strdup_printf("ret=%d\n"
			       "errno=%d\n"
			       "type=%u\n"
			       "min_width=%u\n"
			       "min_height=%u\n"
			       "max_width=%u\n"
			       "max_height=%u\n"
			       "step_width=%u\n"
			       "step_height=%u\n",
			       result->ret,
			       result->error_number,
			       result->type,
			       result->min_width,
			       result->min_height,
			       result->max_width,
			       result->max_height,
			       result->step_width,
			       result->step_height);
}

void
test_enum_framesizes_marks_encoded_format_as_continuous(void)
{
	struct v4l2_frmsizeenum frame_size = { 0, };
	int ret;
	struct frame_size_result expected = {
		.ret = 0,
		.error_number = 0,
		.type = V4L2_FRMSIZE_TYPE_CONTINUOUS,
		.min_width = 16,
		.min_height = 16,
		.max_width = 1920,
		.max_height = 1080,
		.step_width = 1,
		.step_height = 1,
	};
	struct frame_size_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	frame_size.pixel_format = V4L2_PIX_FMT_H264;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FRAMESIZES, &frame_size);
	actual = snapshot_frame_size_result(ret, errno, &frame_size);
	expected_string =
		cut_take_string(frame_size_result_to_string(&expected));
	actual_string = cut_take_string(frame_size_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_enum_framesizes_marks_nv12_as_even_sized_stepwise(void)
{
	struct v4l2_frmsizeenum frame_size = { 0, };
	int ret;
	struct frame_size_result expected = {
		.ret = 0,
		.error_number = 0,
		.type = V4L2_FRMSIZE_TYPE_STEPWISE,
		.min_width = 16,
		.min_height = 16,
		.max_width = 1920,
		.max_height = 1080,
		.step_width = 2,
		.step_height = 2,
	};
	struct frame_size_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	frame_size.pixel_format = V4L2_PIX_FMT_NV12;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FRAMESIZES, &frame_size);
	actual = snapshot_frame_size_result(ret, errno, &frame_size);
	expected_string =
		cut_take_string(frame_size_result_to_string(&expected));
	actual_string = cut_take_string(frame_size_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

static struct pix_format_result
snapshot_pix_format(int ret, int error_number, struct v4l2_format *format)
{
	struct v4l2_pix_format_mplane *pix = &format->fmt.pix_mp;
	struct pix_format_result result = {
		.ret = ret,
		.error_number = error_number,
		.pixelformat = pix->pixelformat,
		.width = pix->width,
		.height = pix->height,
		.num_planes = pix->num_planes,
		.bytesperline = pix->plane_fmt[0].bytesperline,
		.sizeimage = pix->plane_fmt[0].sizeimage,
	};

	return result;
}

static gchar *
pix_format_result_to_string(const struct pix_format_result *result)
{
	gchar fourcc[5];

	fourcc_to_string(result->pixelformat, fourcc);

	return g_strdup_printf("ret=%d\n"
			       "errno=%d\n"
			       "pixelformat=%s (0x%08x)\n"
			       "width=%u\n"
			       "height=%u\n"
			       "num_planes=%u\n"
			       "bytesperline=%u\n"
			       "sizeimage=%u\n",
			       result->ret,
			       result->error_number,
			       fourcc,
			       result->pixelformat,
			       result->width,
			       result->height,
			       result->num_planes,
			       result->bytesperline,
			       result->sizeimage);
}

void
test_try_fmt_output_accepts_configured_codec(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.width = 0,
		.height = 0,
		.num_planes = 1,
		.bytesperline = 0,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_H264;
	pix->width = 1920;
	pix->height = 1080;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_TRY_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_try_fmt_rejects_unsupported_output_codec(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_HEVC,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_HEVC;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_TRY_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_try_fmt_capture_accepts_fixture_raw_format(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.width = 640,
		.height = 480,
		.num_planes = 1,
		.bytesperline = 640,
		.sizeimage = 640 * 480 * 3 / 2,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_NV12;
	pix->width = 640;
	pix->height = 480;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = 640;
	pix->plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_TRY_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_try_fmt_capture_rejects_encoded_format(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_H264,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_TRY_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_try_fmt_rejects_single_planar_type(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_NV12,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_TRY_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_set_fmt_output_rejects_missing_sizeimage(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_H264,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_set_fmt_output_keeps_decoder_encoded_stream_contract(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.width = 0,
		.height = 0,
		.num_planes = 1,
		.sizeimage = 2048,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_H264;
	pix->plane_fmt[0].sizeimage = 2048;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_set_fmt_capture_accepts_fixture_raw_format(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_NV12;
	pix->width = 640;
	pix->height = 480;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = 640;
	pix->plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_set_fmt_capture_rejects_encoded_format(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_H264,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_set_fmt_rejects_single_planar_type(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_NV12,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_get_fmt_output_keeps_decoder_encoded_stream_contract(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.width = 0,
		.height = 0,
		.num_planes = 1,
		.sizeimage = 1024,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_get_fmt_capture_returns_acquired_fixture_format(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.width = 640,
		.height = 480,
		.num_planes = 1,
		.bytesperline = 640,
		.sizeimage = 640 * 480 * 3 / 2,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_get_fmt_rejects_single_planar_type(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

static const gchar *
role_to_string(enum v4l_gst_role role)
{
	switch (role) {
	case V4L_GST_ROLE_NONE:
		return "none";
	case V4L_GST_ROLE_DECODER:
		return "decoder";
	case V4L_GST_ROLE_ENCODER:
		return "encoder";
	}
	return "unknown";
}

static void
assert_role(enum v4l_gst_role expected)
{
	const gchar *expected_str = role_to_string(expected);
	const gchar *actual_str = role_to_string(get_backend_role(backend));

	cut_assert_equal_string(expected_str, actual_str,
				cut_message("expected role %s, got %s",
					    expected_str, actual_str));
}

void
test_role_is_decoder_with_decode_only_config(void)
{
	assert_role(V4L_GST_ROLE_DECODER);
}

void
test_role_is_encoder_with_encode_only_config(void)
{
	prepare_encode_only_role_backend_fixture(backend);

	assert_role(V4L_GST_ROLE_ENCODER);
}

void
test_encode_only_enum_fmt_output_is_raw(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.flags = 0,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	prepare_encode_only_role_backend_fixture(backend);

	desc.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_encode_only_enum_fmt_output_rejects_second_index(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	prepare_encode_only_role_backend_fixture(backend);

	desc.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	desc.index = 1;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_encode_only_enum_fmt_capture_is_compressed(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected = {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	struct enum_fmt_result actual;
	const gchar *expected_string =
		cut_take_string(enum_fmt_result_to_string(&expected));
	const gchar *actual_string;

	prepare_encode_only_role_backend_fixture(backend);

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_encode_only_set_fmt_output_keeps_raw_dimensions(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.width = 640,
		.height = 480,
		.num_planes = 1,
		.bytesperline = 640,
		.sizeimage = 640 * 480 * 3 / 2,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_encode_only_role_backend_fixture(backend);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_NV12;
	pix->width = 640;
	pix->height = 480;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = 640;
	pix->plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_encode_only_set_fmt_capture_accepts_codec(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.sizeimage = 1024,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_encode_only_role_backend_fixture(backend);

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = 1024;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_encode_only_get_fmt_output_keeps_raw_dimensions(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.width = 640,
		.height = 480,
		.num_planes = 1,
		.bytesperline = 640,
		.sizeimage = 640 * 480 * 3 / 2,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_encode_only_role_backend_fixture(backend);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_dual_role_stays_none_until_output_format(void)
{
	prepare_dual_role_backend_fixture(backend);

	assert_role(V4L_GST_ROLE_NONE);
}

void
test_dual_enum_fmt_output_lists_codec_then_raw(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected;
	struct enum_fmt_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_dual_role_backend_fixture(backend);

	desc.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	desc.index = 0;
	expected = (struct enum_fmt_result) {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	expected_string = cut_take_string(enum_fmt_result_to_string(&expected));
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));
	assert_equal_result_strings(expected_string, actual_string);

	desc.index = 1;
	expected = (struct enum_fmt_result) {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.flags = 0,
	};
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	expected_string = cut_take_string(enum_fmt_result_to_string(&expected));
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));
	assert_equal_result_strings(expected_string, actual_string);

	desc.index = 2;
	expected = (struct enum_fmt_result) {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	expected_string = cut_take_string(enum_fmt_result_to_string(&expected));
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));
	assert_equal_result_strings(expected_string, actual_string);
}

void
test_dual_enum_fmt_capture_lists_raw_then_codec(void)
{
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	struct enum_fmt_result expected;
	struct enum_fmt_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_dual_role_backend_fixture(backend);

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	desc.index = 0;
	expected = (struct enum_fmt_result) {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.flags = 0,
	};
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	expected_string = cut_take_string(enum_fmt_result_to_string(&expected));
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));
	assert_equal_result_strings(expected_string, actual_string);

	desc.index = 1;
	expected = (struct enum_fmt_result) {
		.ret = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.flags = V4L2_FMT_FLAG_COMPRESSED,
	};
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	expected_string = cut_take_string(enum_fmt_result_to_string(&expected));
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));
	assert_equal_result_strings(expected_string, actual_string);

	desc.index = 2;
	expected = (struct enum_fmt_result) {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_H264,
	};
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	actual = snapshot_enum_fmt_result(ret, errno, &desc);
	expected_string = cut_take_string(enum_fmt_result_to_string(&expected));
	actual_string = cut_take_string(enum_fmt_result_to_string(&actual));
	assert_equal_result_strings(expected_string, actual_string);
}

void
test_dual_set_fmt_output_codec_fixes_decoder_role(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_H264,
		.width = 0,
		.height = 0,
		.num_planes = 1,
		.sizeimage = 2048,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_dual_role_backend_fixture(backend);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_H264;
	pix->plane_fmt[0].sizeimage = 2048;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
	assert_role(V4L_GST_ROLE_DECODER);
}

void
test_dual_set_fmt_output_raw_fixes_encoder_role(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_pix_format_mplane *pix = &format.fmt.pix_mp;
	int ret;
	struct pix_format_result expected = {
		.ret = 0,
		.error_number = 0,
		.pixelformat = V4L2_PIX_FMT_NV12,
		.width = 640,
		.height = 480,
		.num_planes = 1,
		.bytesperline = 640,
		.sizeimage = 640 * 480 * 3 / 2,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_dual_role_backend_fixture(backend);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	pix->pixelformat = V4L2_PIX_FMT_NV12;
	pix->width = 640;
	pix->height = 480;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = 640;
	pix->plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
	assert_role(V4L_GST_ROLE_ENCODER);
}

void
test_dual_set_fmt_capture_rejected_before_role_fixed(void)
{
	struct v4l2_format format = { 0, };
	int ret;
	struct pix_format_result expected = {
		.ret = -1,
		.error_number = EINVAL,
		.pixelformat = V4L2_PIX_FMT_H264,
	};
	struct pix_format_result actual;
	const gchar *expected_string;
	const gchar *actual_string;

	prepare_dual_role_backend_fixture(backend);

	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	actual = snapshot_pix_format(ret, errno, &format);
	expected_string = cut_take_string(pix_format_result_to_string(&expected));
	actual_string = cut_take_string(pix_format_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
	assert_role(V4L_GST_ROLE_NONE);
}

static void
fill_nv12_frame(void *data, guint32 size)
{
	guint8 *p = data;
	const guint32 y_size = 640 * 480;
	guint32 i;

	for (i = 0; i < y_size && i < size; i++)
		p[i] = i & 0xff;
	for (i = y_size; i < size; i++)
		p[i] = 0x80;
}

static gboolean
contains_h264_start_code(const guint8 *data, gsize size)
{
	gsize i;

	for (i = 0; i + 4 <= size; i++) {
		if (data[i] == 0x00 && data[i + 1] == 0x00 &&
		    data[i + 2] == 0x00 && data[i + 3] == 0x01)
			return TRUE;
	}
	return FALSE;
}

/*
 * Produce a self-contained H264 annex-B byte stream by encoding a few
 * synthetic NV12 frames with x264enc. The stream starts with an inline
 * SPS/PPS/IDR (key-int-max=1, zerolatency) so that avdec_h264 can decode it
 * without an h264parse element. Returns a newly allocated buffer (free with
 * g_free()) or NULL on failure.
 */
static guint8 *
generate_h264_sample(guint32 n_frames, guint32 width, guint32 height,
		     gsize *out_len)
{
	gchar *desc;
	GstElement *pipeline;
	GstElement *sink;
	GstSample *sample;
	GstBuffer *buffer;
	GstMapInfo map;
	GByteArray *stream;

	*out_len = 0;

	desc = g_strdup_printf(
		"videotestsrc num-buffers=%u is-live=false "
		"! videoconvert ! video/x-raw,format=NV12,width=%u,height=%u,framerate=30/1 "
		"! x264enc tune=zerolatency speed-preset=ultrafast key-int-max=1 "
		"! appsink name=h264enc_sink", n_frames, width, height);
	pipeline = gst_parse_launch(desc, NULL);
	g_free(desc);
	if (!pipeline)
		return NULL;

	sink = gst_bin_get_by_name(GST_BIN(pipeline), "h264enc_sink");
	if (!sink) {
		gst_object_unref(pipeline);
		return NULL;
	}

	if (gst_element_set_state(pipeline, GST_STATE_PLAYING) ==
	    GST_STATE_CHANGE_FAILURE) {
		gst_object_unref(sink);
		gst_object_unref(pipeline);
		return NULL;
	}

	stream = g_byte_array_new();
	while ((sample = gst_app_sink_try_pull_sample(GST_APP_SINK(sink),
						       GST_CLOCK_TIME_NONE)) != NULL) {
		buffer = gst_sample_get_buffer(sample);
		if (buffer && gst_buffer_map(buffer, &map, GST_MAP_READ)) {
			g_byte_array_append(stream, map.data, map.size);
			gst_buffer_unmap(buffer, &map);
		}
		gst_sample_unref(sample);
	}

	gst_object_unref(sink);
	gst_element_set_state(pipeline, GST_STATE_NULL);
	gst_object_unref(pipeline);

	if (stream->len == 0) {
		g_byte_array_free(stream, TRUE);
		return NULL;
	}
	*out_len = stream->len;
	return g_byte_array_free(stream, FALSE);
}

void
test_x264enc_encoder_streaming_produces_h264(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	enum v4l2_buf_type type;
	const guint32 w = 640;
	const guint32 h = 480;
	const guint32 frame_size = 640 * 480 * 3 / 2;
	guint out_count, cap_count, i;
	int ret;

	if (!gst_element_factory_find("x264enc"))
		cut_pend("x264enc element is not available");

	prepare_pipeline_backend_fixture(backend, V4L_GST_ROLE_ENCODER,
					 "x264enc tune=zerolatency "
					 "speed-preset=ultrafast",
					 V4L2_PIX_FMT_H264, V4L2_PIX_FMT_NV12,
					 w, h, frame_size, 1024 * 1024);
	assert_role(V4L_GST_ROLE_ENCODER);

	/* Set the OUTPUT format to a raw NV12 frame. */
	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;
	format.fmt.pix_mp.width = w;
	format.fmt.pix_mp.height = h;
	format.fmt.pix_mp.num_planes = 1;
	format.fmt.pix_mp.plane_fmt[0].bytesperline = w;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = frame_size;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	cut_assert(ret == 0);

	/* Set the CAPTURE format to an H264 encoded stream. */
	memset(&format, 0, sizeof(format));
	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = 1024 * 1024;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	cut_assert(ret == 0);

	/* Request OUTPUT (raw) buffers. */
	memset(&req, 0, sizeof(req));
	req.count = INPUT_BUFFERING_CNT;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	out_count = req.count;
	cut_assert(out_count > 0);

	/* Fill each OUTPUT buffer with an NV12 frame and queue it. */
	for (i = 0; i < out_count; i++) {
		void *map;

		memset(&buf, 0, sizeof(buf));
		buf.index = i;
		buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.m.planes = planes;
		buf.length = 2;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
		cut_assert(ret == 0);

		map = libv4l2_plugin.mmap(backend, NULL,
					  buf.m.planes[0].length,
					  PROT_READ | PROT_WRITE,
					  MAP_SHARED, -1,
					  (int64_t) buf.m.planes[0].m.mem_offset);
		cut_assert_not_null(map);
		fill_nv12_frame(map, frame_size);
		buf.m.planes[0].bytesused = frame_size;

		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
		cut_assert(ret == 0);
	}

	/* Start the stream. */
	type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_STREAMON, &type);
	cut_assert(ret == 0);

	/* Request CAPTURE buffers; blocks until the first encoded frames are
	   available from the pipeline. */
	memset(&req, 0, sizeof(req));
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cap_count = req.count;
	cut_assert(cap_count > 0);

	/* Queue the CAPTURE buffers. */
	for (i = 0; i < cap_count; i++) {
		memset(&buf, 0, sizeof(buf));
		buf.index = i;
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.m.planes = planes;
		buf.length = 1;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
		cut_assert(ret == 0);
	}

	/* Dequeue CAPTURE buffers and verify they carry an H264 bitstream. */
	for (i = 0; i < cap_count; i++) {
		void *map;

		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.m.planes = planes;
		buf.length = 1;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_DQBUF, &buf);
		cut_assert(ret == 0);
		cut_assert(buf.m.planes[0].bytesused > 0);

		map = libv4l2_plugin.mmap(backend, NULL,
					  buf.m.planes[0].length,
					  PROT_READ, MAP_SHARED, -1,
					  (int64_t) buf.m.planes[0].m.mem_offset);
		cut_assert_not_null(map);
		cut_assert(contains_h264_start_code(
					(const guint8 *) map,
					buf.m.planes[0].bytesused));
	}

	/* Stop the stream. */
	type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_STREAMOFF, &type);
	cut_assert(ret == 0);
}

/*
 * Decode a self-contained H264 annex-B byte stream (produced by
 * generate_h264_sample()) with the real avdec_h264 pipeline and verify that
 * the CAPTURE side yields raw NV12 frames with monotonically non-decreasing
 * timestamps.  VIDIOC_DECODER_CMD with V4L2_DEC_CMD_STOP signals end of
 * stream so the decoder is exercised through its EOS/flush path and the
 * final CAPTURE buffer is returned with V4L2_BUF_FLAG_LAST.
 */
void
test_h264dec_decoder_streaming_produces_nv12(void)
{
	struct v4l2_format format = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	enum v4l2_buf_type type;
	const guint32 w = 320;
	const guint32 h = 240;
	const gsize frame_size = w * h * 3 / 2;
	/* The CAPTURE request below blocks until the decoder fills its output
	   buffer pool, so feed more frames than the pool can hold to guarantee
	   the pool is filled. key-int-max=1 keeps the stream compact. */
	const guint32 n_frames = 100;
	gsize stream_len = 0;
	guint8 *stream;
	guint out_count, cap_count, i;
	guint frame_count = 0;
	const guint max_frames = 1024;
	gboolean got_last = FALSE;
	gint64 last_sec = -1, last_usec = 0;
	int ret;

	/* The decode pipeline is "h264parse ! avdec_h264 ! videoconvert"
	   (per README, h264parse extracts the SPS/PPS into the codec_data caps
	   that avdec_h264 needs; videoconvert converts the decoder's I420
	   output to the NV12 CAPTURE format). All four elements are required. */
	if (!gst_element_factory_find("h264parse") ||
	    !gst_element_factory_find("avdec_h264") ||
	    !gst_element_factory_find("videoconvert") ||
	    !gst_element_factory_find("x264enc"))
		cut_pend("h264parse, avdec_h264, videoconvert or x264enc "
			 "element is not available");

	stream = generate_h264_sample(n_frames, w, h, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	prepare_pipeline_backend_fixture(backend, V4L_GST_ROLE_DECODER,
					 "h264parse ! avdec_h264 ! videoconvert",
					 V4L2_PIX_FMT_H264, V4L2_PIX_FMT_NV12,
					 w, h, frame_size, 4 * 1024 * 1024);
	assert_role(V4L_GST_ROLE_DECODER);

	/* Set the OUTPUT format to the H264 encoded stream. */
	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = 4 * 1024 * 1024;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	cut_assert(ret == 0);

	/* Set the CAPTURE format to a raw NV12 frame. */
	memset(&format, 0, sizeof(format));
	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;
	format.fmt.pix_mp.width = w;
	format.fmt.pix_mp.height = h;
	format.fmt.pix_mp.num_planes = 1;
	format.fmt.pix_mp.plane_fmt[0].bytesperline = w;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = frame_size;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	cut_assert(ret == 0);

	/* Request OUTPUT buffers; the whole stream is carried in the first
	   buffer.  End of stream is signalled with V4L2_DEC_CMD_STOP. */
	memset(&req, 0, sizeof(req));
	req.count = 1;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	out_count = req.count;
	cut_assert(out_count >= 1);

	/* Fill the first OUTPUT buffer with the whole H264 stream and queue it. */
	memset(&buf, 0, sizeof(buf));
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
	cut_assert(ret == 0);
	{
		void *map;

		map = libv4l2_plugin.mmap(backend, NULL,
					  buf.m.planes[0].length,
					  PROT_READ | PROT_WRITE,
					  MAP_SHARED, -1,
					  (int64_t) buf.m.planes[0].m.mem_offset);
		cut_assert_not_null(map);
		cut_assert(stream_len <= (gsize) buf.m.planes[0].length);
		memcpy(map, stream, stream_len);
		buf.m.planes[0].bytesused = (unsigned int) stream_len;
	}
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	cut_assert(ret == 0);

	/* Start the stream. */
	type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_STREAMON, &type);
	cut_assert(ret == 0);

	/* Request CAPTURE buffers; blocks until the decoder fills the output
	   buffer pool with decoded frames. */
	memset(&req, 0, sizeof(req));
	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cap_count = req.count;
	cut_assert(cap_count > 0);

	/* Signal end of stream now that the pipeline is running.  The decoder
	   flushes any buffered frames and the final CAPTURE buffer is marked
	   with V4L2_BUF_FLAG_LAST. */
	{
		struct v4l2_decoder_cmd decoder_cmd = { 0, };

		decoder_cmd.cmd = V4L2_DEC_CMD_STOP;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_DECODER_CMD, &decoder_cmd);
		cut_assert(ret == 0);
	}

	/* Queue the CAPTURE buffers. */
	for (i = 0; i < cap_count; i++) {
		memset(&buf, 0, sizeof(buf));
		buf.index = i;
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.m.planes = planes;
		buf.length = 2;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
		cut_assert(ret == 0);
	}

	/* Dequeue CAPTURE buffers until the decoder reports the final buffer.
	   Each dequeued buffer is queued again so the decoder can keep
	   flushing frames into the fixed CAPTURE buffer pool. */
	while (!got_last && frame_count < max_frames) {
		void *map;
		guint8 non_zero = 0;
		gsize j;

		memset(&buf, 0, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.m.planes = planes;
		buf.length = 2;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_DQBUF, &buf);
		if (ret != 0) {
			/* The last decoded buffer is held back until the
			   pipeline EOS is observed; retry until it is
			   released. */
			g_usleep(1000);
			continue;
		}
		cut_assert(buf.m.planes[0].bytesused > 0);

		map = libv4l2_plugin.mmap(backend, NULL,
					  buf.m.planes[0].length,
					  PROT_READ, MAP_SHARED, -1,
					  (int64_t) buf.m.planes[0].m.mem_offset);
		cut_assert_not_null(map);
		for (j = 0; j < 4096 && j < buf.m.planes[0].bytesused; j++)
			non_zero |= ((guint8 *) map)[j];
		munmap(map, buf.m.planes[0].length);
		cut_assert(non_zero != 0);

		cut_assert((buf.timestamp.tv_sec > last_sec) ||
			   (buf.timestamp.tv_sec == last_sec &&
			    buf.timestamp.tv_usec >= last_usec));
		last_sec = buf.timestamp.tv_sec;
		last_usec = buf.timestamp.tv_usec;

		frame_count++;
		if (buf.flags & V4L2_BUF_FLAG_LAST) {
			got_last = TRUE;
			break;
		}

		buf.flags = 0;
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
		cut_assert(ret == 0);
	}

	cut_assert(got_last);
	cut_assert(frame_count >= cap_count);

	/* Stop the stream. */
	type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_STREAMOFF, &type);
	cut_assert(ret == 0);

	g_free(stream);
}

/*
 * Shared setup for the shutdown tests: configure a real H264 decoder and
 * optionally queue an OUTPUT payload. start_h264dec_stream() also starts
 * streaming; a zero-length payload leaves all OUTPUT buffers dequeued.
 */
static void
prepare_h264dec_stream(const guint8 *stream, gsize stream_len)
{
	struct v4l2_format format = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	const guint32 w = 320;
	const guint32 h = 240;
	const gsize frame_size = w * h * 3 / 2;
	void *map;
	int ret;

	prepare_pipeline_backend_fixture(backend, V4L_GST_ROLE_DECODER,
					 "h264parse ! avdec_h264 ! videoconvert",
					 V4L2_PIX_FMT_H264, V4L2_PIX_FMT_NV12,
					 w, h, frame_size, 4 * 1024 * 1024);
	assert_role(V4L_GST_ROLE_DECODER);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = 4 * 1024 * 1024;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	cut_assert(ret == 0);

	memset(&format, 0, sizeof(format));
	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;
	format.fmt.pix_mp.width = w;
	format.fmt.pix_mp.height = h;
	format.fmt.pix_mp.num_planes = 1;
	format.fmt.pix_mp.plane_fmt[0].bytesperline = w;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = frame_size;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_S_FMT, &format);
	cut_assert(ret == 0);

	memset(&req, 0, sizeof(req));
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cut_assert(req.count >= 1);
	if (stream_len == 0)
		return;

	memset(&buf, 0, sizeof(buf));
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
	cut_assert(ret == 0);

	map = libv4l2_plugin.mmap(backend, NULL, buf.m.planes[0].length,
				  PROT_READ | PROT_WRITE, MAP_SHARED, -1,
				  (int64_t) buf.m.planes[0].m.mem_offset);
	cut_assert_not_null(map);
	cut_assert(stream_len <= (gsize) buf.m.planes[0].length);
	memcpy(map, stream, stream_len);
	buf.m.planes[0].bytesused = (unsigned int) stream_len;
	munmap(map, buf.m.planes[0].length);

	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	cut_assert(ret == 0);
}

static void
start_h264dec_stream(const guint8 *stream, gsize stream_len)
{
	enum v4l2_buf_type type;
	int ret;

	prepare_h264dec_stream(stream, stream_len);

	type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_STREAMON, &type);
	cut_assert(ret == 0);
}

static gboolean
h264dec_pipeline_available(void)
{
	return gst_element_factory_find("h264parse") != NULL &&
	       gst_element_factory_find("avdec_h264") != NULL &&
	       gst_element_factory_find("videoconvert") != NULL;
}

/*
 * Regression test for the shutdown deadlock: start decoding and close the
 * backend immediately after STREAMON without draining anything.  Before the
 * deinit lifecycle fix, close() freed shared state while the streaming
 * threads were still running, which hung or crashed the process.
 */
void
test_h264dec_close_immediately_after_streamon(void)
{
	guint8 *stream;
	gsize stream_len = 0;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	stream = generate_h264_sample(100, 320, 240, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	start_h264dec_stream(stream, stream_len);
	g_free(stream);

	/* Return immediately; teardown() closes the backend while the decoder
	   is still running.  The test passes if close() returns. */
}

struct dqbuf_thread_args {
	int ret;
	int err;
};

static gpointer
dqbuf_cap_until_shutdown(gpointer data)
{
	struct dqbuf_thread_args *args = data;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];

	buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;

	/* Keep dequeuing until the stream is torn down: a blocked DQBUF is
	   cancelled with EPERM, a later re-entry is rejected with EBUSY. */
	for (;;) {
		errno = 0;
		args->ret = v4l_gst_ioctl(VIDIOC_DQBUF, &buf);
		if (args->ret == 0)
			continue;
		args->err = errno;
		if (args->err == EPERM || args->err == EBUSY)
			break;
		g_usleep(1000);
	}

	return NULL;
}

/*
 * Close the backend while another thread is blocked in a blocking
 * VIDIOC_DQBUF on CAPTURE.  The blocked call must be cancelled by the
 * shutdown instead of hanging forever.
 */
void
test_h264dec_dqbuf_blocking_close_race(void)
{
	struct dqbuf_thread_args args = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	guint8 *stream;
	gsize stream_len = 0;
	GThread *thread;
	int ret;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	stream = generate_h264_sample(100, 320, 240, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	start_h264dec_stream(stream, stream_len);
	g_free(stream);

	memset(&req, 0, sizeof(req));
	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cut_assert(req.count > 0);

	args.ret = 0;
	thread = g_thread_new("dqbuf-cap", dqbuf_cap_until_shutdown, &args);
	g_usleep(200 * 1000);

	/* Close while the thread is inside VIDIOC_DQBUF. */
	libv4l2_plugin.close(backend);
	backend = NULL;

	g_thread_join(thread);
	cut_assert(args.ret == -1);
	cut_assert(args.err == EPERM || args.err == EBUSY);
}

static gpointer
reqbuf_cap_once(gpointer data)
{
	struct dqbuf_thread_args *args = data;
	struct v4l2_requestbuffers req = { 0, };

	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	args->ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	args->err = errno;

	return NULL;
}

/*
 * Close the backend while another thread is inside a VIDIOC_REQBUFS on
 * CAPTURE waiting for the first decoded buffer.  The payload carries no
 * valid H264 data, so that wait can only end when the shutdown cancels it;
 * it must not block until the initial-buffer timeout expires.
 */
void
test_h264dec_reqbuf_cap_close_race(void)
{
	struct dqbuf_thread_args args = { 0, };
	const guint8 garbage[] = { 0x00 };
	GThread *thread;
	gint64 close_time, joined_time;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	start_h264dec_stream(garbage, sizeof(garbage));

	args.ret = 0;
	thread = g_thread_new("reqbuf-cap", reqbuf_cap_once, &args);
	g_usleep(200 * 1000);

	close_time = g_get_monotonic_time();
	libv4l2_plugin.close(backend);
	backend = NULL;

	g_thread_join(thread);
	joined_time = g_get_monotonic_time();

	cut_assert(args.ret == -1);
	cut_assert(args.err == EINVAL);
	/* The wait must have been cancelled by the shutdown, not run to the
	   INITIAL_BUFFER_WAIT_TIMEOUT. */
	cut_assert(joined_time - close_time < 5 * G_TIME_SPAN_SECOND);
}

/*
 * Stop the pipeline with VIDIOC_REQBUF(count=0) while the client still
 * holds every dequeued CAPTURE buffer.  The decoder is then blocked
 * acquiring a CAPTURE buffer for the next frame, and before the
 * bounded-stop fix the state change to GST_STATE_NULL waited forever
 * for that streaming thread.
 */
void
test_h264dec_reqbuf_zero_while_holding_all_cap_buffers(void)
{
	struct v4l2_requestbuffers req = { 0, };
	guint8 *stream;
	gsize stream_len = 0;
	gint64 start_time;
	int ret;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	stream = generate_h264_sample(100, 320, 240, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	start_h264dec_stream(stream, stream_len);
	g_free(stream);

	memset(&req, 0, sizeof(req));
	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cut_assert(req.count > 0);

	/* Every CAPTURE buffer is in the DEQUEUED state held by the
	   client, so the decoder cannot produce more frames. */
	memset(&req, 0, sizeof(req));
	req.count = 0;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	start_time = g_get_monotonic_time();
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cut_assert(g_get_monotonic_time() - start_time <
		  5 * G_TIME_SPAN_SECOND);
}

/*
 * A stream shorter than the requested CAPTURE buffer count must not
 * stall VIDIOC_REQBUF until the collection timeout: the EOS event sent
 * by QBUF(bytesused=0) ends the stream, and VIDIOC_REQBUF is allowed to
 * return fewer buffers than requested.
 */
void
test_h264dec_reqbuf_cap_short_stream_with_eos(void)
{
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	guint8 *stream;
	gsize stream_len = 0;
	gint64 start_time;
	int ret;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	stream = generate_h264_sample(3, 320, 240, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	start_h264dec_stream(stream, stream_len);
	g_free(stream);

	/* QBUF with bytesused == 0 sends an EOS event to the pipeline. */
	memset(&buf, 0, sizeof(buf));
	buf.index = 1;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	buf.m.planes[0].bytesused = 0;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	cut_assert(ret == 0);

	memset(&req, 0, sizeof(req));
	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	start_time = g_get_monotonic_time();
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	cut_assert(ret == 0);
	cut_assert(req.count >= 1);
	cut_assert(req.count < 8);
	/* The wait must have ended at the EOS, not at the collection
	   timeout. */
	cut_assert(g_get_monotonic_time() - start_time <
		  5 * G_TIME_SPAN_SECOND);
}

/* EOS must return both OUTPUT buffers, not merely signal POLLIN while
 * retaining the empty buffer outside the pool. Nonblocking DQBUF makes
 * this regression fail instead of hanging the test process. */
void
test_h264dec_eos_returns_empty_output_buffer(void)
{
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES] = { 0, };
	guint8 *stream;
	gsize stream_len = 0;
	gboolean returned[2] = { FALSE, FALSE };
	gboolean got_eos;
	guint count = 0;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");
	stream = generate_h264_sample(3, 320, 240, &stream_len);
	cut_assert_not_null(stream);
	start_h264dec_stream(stream, stream_len);
	g_free(stream);

	buf.index = 1;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QBUF, &buf));

	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_REQBUFS, &req));
	g_mutex_lock(&backend->queue_mutex);
	got_eos = backend->eos_state == EOS_GOT;
	g_mutex_unlock(&backend->queue_mutex);
	cut_assert(got_eos);

	backend->is_non_blocking = TRUE;
	while (v4l_gst_ioctl(VIDIOC_DQBUF, &buf) == 0) {
		cut_assert(buf.index < 2);
		cut_assert(!returned[buf.index]);
		returned[buf.index] = TRUE;
		count++;
	}
	cut_assert_equal_int(EAGAIN, errno);
	cut_assert_equal_uint(2, count);
	cut_assert_equal_int(0, backend->out.returned_cnt);
}

/* Stage an operation paused between enter_operation() and dispatch, then
 * let shutdown stop the pipeline before resuming that admitted handler.
 * New plugin calls are also checked through the actual public wrapper. */
void
test_shutdown_rejects_pre_admitted_streamon_and_reqbuf_out(void)
{
	const guint8 garbage[] = { 0 };
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	struct v4l2_requestbuffers req = { 0, };
	int streamon_ret, streamon_errno, reqbuf_ret, reqbuf_errno;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");
	start_h264dec_stream(garbage, sizeof(garbage));
	cut_assert(v4l_gst_core_enter_operation(backend));
	cut_assert(v4l_gst_core_enter_operation(backend));
	g_atomic_int_set(&backend->shutting_down, 1);
	v4l_gst_core_set_pipeline_started(backend, FALSE);
	gst_buffer_pool_set_active(backend->out.pool, FALSE);
	gst_buffer_pool_set_active(backend->cap.pool, FALSE);
	cut_assert_equal_int(GST_STATE_CHANGE_SUCCESS,
		gst_element_set_state(backend->pipeline, GST_STATE_NULL));

	streamon_ret = v4l_gst_ioctl_streamon(backend, &type);
	streamon_errno = errno;
	v4l_gst_core_leave_operation(backend);
	req.count = 4;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	reqbuf_ret = v4l_gst_ioctl_reqbuf(backend, &req);
	reqbuf_errno = errno;
	v4l_gst_core_leave_operation(backend);

	cut_assert_equal_int(-1, streamon_ret);
	cut_assert_equal_int(EBUSY, streamon_errno);
	cut_assert_equal_int(-1, reqbuf_ret);
	cut_assert_equal_int(EBUSY, reqbuf_errno);
	cut_assert_equal_int(GST_STATE_NULL, GST_STATE_TARGET(backend->pipeline));
	cut_assert(!gst_buffer_pool_is_active(backend->out.pool));
	cut_assert_equal_int(0, g_atomic_int_get(&backend->inflight_ioctls));
	cut_assert_equal_int(-1, v4l_gst_ioctl(VIDIOC_STREAMON, &type));
	cut_assert_equal_int(EBUSY, errno);
	cut_assert(libv4l2_plugin.mmap(backend, NULL, 4096, PROT_READ,
		MAP_SHARED, -1, 0) == MAP_FAILED);
	cut_assert_equal_int(EBUSY, errno);
	cut_assert_equal_int(0, g_atomic_int_get(&backend->inflight_ioctls));
}

static void
mark_eos_buffer_freed(gpointer data, GstMiniObject *object)
{
	(void)object;
	*(gboolean *)data = TRUE;
}

/* Closing without another STREAMON or an EOS callback must release the
 * cached acquired reference. Also reject a second pending empty QBUF. */
void
test_h264dec_close_releases_pending_eos_buffer(void)
{
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES] = { 0, };
	gboolean freed = FALSE;

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");
	prepare_h264dec_stream(NULL, 0);
	buf.index = 1;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QBUF, &buf));
	cut_assert_equal_int(-1, v4l_gst_ioctl(VIDIOC_QBUF, &buf));
	cut_assert_equal_int(EINVAL, errno);
	buf.index = 2;
	cut_assert_equal_int(-1, v4l_gst_ioctl(VIDIOC_QBUF, &buf));
	cut_assert_equal_int(EBUSY, errno);
	gst_mini_object_weak_ref(GST_MINI_OBJECT(backend->out.buffers[1].gstbuf),
		mark_eos_buffer_freed, &freed);
	libv4l2_plugin.close(backend);
	backend = NULL;
	cut_assert(freed);
}

/* ------------------------------------------------------------------ */
/* Control ioctls: QUERYCTRL / QUERYMENU / G_CTRL / G_EXT_CTRLS        */
/* ------------------------------------------------------------------ */

/*
 * Re-point the decode pipeline at a different codec fourcc and re-derive
 * the role so that codec_pipeline_enabled() reflects the change. This lets
 * the control tests exercise both the "pipeline enabled" and "disabled"
 * branches without needing a real decoder for the alternate codec.
 */
static void
set_decode_pipeline_fourcc(const gchar *fourcc)
{
	g_hash_table_remove(backend->config.pipelines, "H264");
	g_hash_table_insert(backend->config.pipelines, g_strdup(fourcc),
			    g_strdup("identity"));
	v4l_gst_core_setup_role(backend);
}

/*
 * Allocate OUTPUT buffers without starting the pipeline. The default format
 * fixture creates a bare identity pipeline without a buffer pool, so the pool
 * is built by re-initialising the (reset) pipeline through S_FMT, exactly as
 * the streaming tests do, before REQBUFS can allocate from it. A real decoder
 * pipeline is used because the identity stub exposes no usable caps.
 */
static guint
prepare_out_buffers(guint count)
{
	struct v4l2_format format = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	const guint32 w = 320;
	const guint32 h = 240;
	const guint32 frame_size = w * h * 3 / 2;
	const guint32 stream_sizeimage = 64 * 1024;

	prepare_pipeline_backend_fixture(backend, V4L_GST_ROLE_DECODER,
					 "h264parse ! avdec_h264 ! videoconvert",
					 V4L2_PIX_FMT_H264, V4L2_PIX_FMT_NV12,
					 w, h, frame_size, stream_sizeimage);
	assert_role(V4L_GST_ROLE_DECODER);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = stream_sizeimage;
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_S_FMT, &format));

	req.count = count;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_REQBUFS, &req));
	cut_assert(req.count >= 1);
	return req.count;
}

void
test_queryctrl_h264_profile_decoder_role(void)
{
	struct test_result_strings result;
	struct v4l2_queryctrl qc = { 0, };
	int ret;
	test_result_strings_init(&result);

	assert_role(V4L_GST_ROLE_DECODER);
	qc.id = V4L2_CID_MPEG_VIDEO_H264_PROFILE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYCTRL, &qc);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_uint(&result, "minimum",
				     V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE,
				     qc.minimum);
	test_result_strings_add_uint(&result, "maximum",
				     V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10,
				     qc.maximum);
	test_result_strings_assert(&result);
}

void
test_queryctrl_h264_profile_rejected_when_pipeline_disabled(void)
{
	struct test_result_strings result;
	struct v4l2_queryctrl qc = { 0, };
	int ret;
	test_result_strings_init(&result);

	set_decode_pipeline_fourcc("HEVC");
	assert_role(V4L_GST_ROLE_DECODER);

	qc.id = V4L2_CID_MPEG_VIDEO_H264_PROFILE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYCTRL, &qc);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_queryctrl_hevc_profile_decoder_role(void)
{
	struct test_result_strings result;
	struct v4l2_queryctrl qc = { 0, };
	int ret;
	test_result_strings_init(&result);

	set_decode_pipeline_fourcc("HEVC");

	qc.id = V4L2_CID_MPEG_VIDEO_HEVC_PROFILE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYCTRL, &qc);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_uint(&result, "minimum",
				     V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN,
				     qc.minimum);
	test_result_strings_add_uint(&result, "maximum",
				     V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10,
				     qc.maximum);
	test_result_strings_assert(&result);
}

void
test_queryctrl_unknown_id_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_queryctrl qc = { 0, };
	int ret;
	test_result_strings_init(&result);

	qc.id = V4L2_CID_BRIGHTNESS;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYCTRL, &qc);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_querymenu_h264_profile_indexes(void)
{
	struct test_result_strings result;
	const guint32 valid[] = {
		V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE,
		V4L2_MPEG_VIDEO_H264_PROFILE_MAIN,
		V4L2_MPEG_VIDEO_H264_PROFILE_HIGH,
		V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10,
	};
	struct v4l2_querymenu qm = { 0, };
	guint i;
	int ret;
	test_result_strings_init(&result);

	for (i = 0; i < G_N_ELEMENTS(valid); i++) {
		qm.id = V4L2_CID_MPEG_VIDEO_H264_PROFILE;
		qm.index = valid[i];
		test_result_strings_add_uint(&result, "valid_index", valid[i],
					     qm.index);
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QUERYMENU, &qm);
		test_result_strings_add_int(&result, "valid_index_ret", 0, ret);
	}

	/* 1 (CONSTRAINED_BASELINE) is not a supported index. */
	qm.id = V4L2_CID_MPEG_VIDEO_H264_PROFILE;
	qm.index = 1;
	test_result_strings_add_uint(&result, "invalid_index", 1, qm.index);
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYMENU, &qm);
	test_result_strings_add_int(&result, "invalid_index_ret", -1, ret);
	test_result_strings_add_int(&result, "invalid_index_errno", EINVAL,
				     errno);
	test_result_strings_assert(&result);
}

void
test_querymenu_hevc_profile_indexes(void)
{
	struct test_result_strings result;
	const guint32 valid[] = {
		V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN,
		V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_STILL_PICTURE,
		V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10,
	};
	struct v4l2_querymenu qm = { 0, };
	guint i;
	int ret;
	test_result_strings_init(&result);

	for (i = 0; i < G_N_ELEMENTS(valid); i++) {
		qm.id = V4L2_CID_MPEG_VIDEO_HEVC_PROFILE;
		qm.index = valid[i];
		test_result_strings_add_uint(&result, "valid_index", valid[i],
					     qm.index);
		errno = 0;
		ret = v4l_gst_ioctl(VIDIOC_QUERYMENU, &qm);
		test_result_strings_add_int(&result, "valid_index_ret", 0, ret);
	}

	/* 3 is not a defined HEVC profile. */
	qm.id = V4L2_CID_MPEG_VIDEO_HEVC_PROFILE;
	qm.index = 3;
	test_result_strings_add_uint(&result, "invalid_index", 3, qm.index);
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYMENU, &qm);
	test_result_strings_add_int(&result, "invalid_index_ret", -1, ret);
	test_result_strings_add_int(&result, "invalid_index_errno", EINVAL,
				     errno);
	test_result_strings_assert(&result);
}

void
test_g_ctrl_min_buffers_default(void)
{
	struct test_result_strings result;
	struct v4l2_control ctrl = { 0, };
	int ret;
	test_result_strings_init(&result);

	ctrl.id = V4L2_CID_MIN_BUFFERS_FOR_CAPTURE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_CTRL, &ctrl);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_int(&result, "value", DEF_CAP_MIN_BUFFERS,
				     ctrl.value);
	test_result_strings_assert(&result);
}

void
test_g_ctrl_unknown_id_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_control ctrl = { 0, };
	int ret;
	test_result_strings_init(&result);

	ctrl.id = V4L2_CID_BRIGHTNESS;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_CTRL, &ctrl);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_g_ext_ctrls_returns_min_buffers(void)
{
	struct test_result_strings result;
	struct v4l2_ext_controls ext = { 0, };
	struct v4l2_ext_control ctrl = { 0, };
	int ret;
	test_result_strings_init(&result);

	ctrl.id = V4L2_CID_MIN_BUFFERS_FOR_CAPTURE;
	ext.count = 1;
	ext.controls = &ctrl;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_EXT_CTRLS, &ext);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_int(&result, "value", DEF_CAP_MIN_BUFFERS,
				     ctrl.value);
	test_result_strings_assert(&result);
}

void
test_g_ext_ctrls_rejects_unknown_id(void)
{
	struct test_result_strings result;
	struct v4l2_ext_controls ext = { 0, };
	struct v4l2_ext_control ctrl[2] = { { 0, }, { 0, } };
	int ret;
	test_result_strings_init(&result);

	ctrl[0].id = V4L2_CID_MIN_BUFFERS_FOR_CAPTURE;
	ctrl[1].id = V4L2_CID_BRIGHTNESS;
	ext.count = 2;
	ext.controls = ctrl;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_EXT_CTRLS, &ext);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

/* ------------------------------------------------------------------ */
/* Event ioctls: SUBSCRIBE_EVENT / DQEVENT / UNSUBSCRIBE_EVENT         */
/* ------------------------------------------------------------------ */

void
test_subscribe_event_source_change_accepted(void)
{
	struct v4l2_event_subscription sub = { 0, };
	int ret;

	sub.type = V4L2_EVENT_SOURCE_CHANGE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_SUBSCRIBE_EVENT, &sub);
	cut_assert_equal_int(0, ret);
}

void
test_subscribe_event_unsupported_type_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_event_subscription sub = { 0, };
	int ret;
	test_result_strings_init(&result);

	sub.type = V4L2_EVENT_EOS;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_SUBSCRIBE_EVENT, &sub);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", ENOTTY, errno);
	test_result_strings_assert(&result);
}

void
test_dqevent_returns_source_change_then_eagain(void)
{
	struct test_result_strings result;
	struct v4l2_event_subscription sub = { 0, };
	struct v4l2_event ev = { 0, };
	int ret;
	test_result_strings_init(&result);

	sub.type = V4L2_EVENT_SOURCE_CHANGE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_SUBSCRIBE_EVENT, &sub);
	test_result_strings_add_int(&result, "subscribe_ret", 0, ret);

	v4l_gst_core_push_source_change_event(backend);

	memset(&ev, 0, sizeof(ev));
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_DQEVENT, &ev);
	test_result_strings_add_int(&result, "first_dqevent_ret", 0, ret);
	test_result_strings_add_uint(&result, "event_type",
				     V4L2_EVENT_SOURCE_CHANGE, ev.type);
	test_result_strings_add_uint(&result, "sequence", 1, ev.sequence);
	test_result_strings_add_uint(&result, "pending", 0, ev.pending);

	/* The queue is now empty. */
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_DQEVENT, &ev);
	test_result_strings_add_int(&result, "empty_dqevent_ret", -1, ret);
	test_result_strings_add_int(&result, "empty_dqevent_errno", EAGAIN,
				     errno);
	test_result_strings_assert(&result);
}

void
test_dqevent_without_subscription_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_event_subscription sub = { 0, };
	struct v4l2_event ev = { 0, };
	int ret;
	test_result_strings_init(&result);

	/* A pending event exists but there is no subscription: it must
	 * not be delivered. */
	v4l_gst_core_push_source_change_event(backend);
	memset(&ev, 0, sizeof(ev));
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_DQEVENT, &ev);
	test_result_strings_add_int(&result, "unsubscribed_dqevent_ret", -1,
				     ret);
	test_result_strings_add_int(&result, "unsubscribed_dqevent_errno",
				     EINVAL, errno);

	/* Once subscribed, the pending event is delivered. */
	sub.type = V4L2_EVENT_SOURCE_CHANGE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_SUBSCRIBE_EVENT, &sub);
	test_result_strings_add_int(&result, "subscribe_ret", 0, ret);
	memset(&ev, 0, sizeof(ev));
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_DQEVENT, &ev);
	test_result_strings_add_int(&result, "subscribed_dqevent_ret", 0, ret);
	test_result_strings_add_uint(&result, "event_type",
				     V4L2_EVENT_SOURCE_CHANGE, ev.type);
	test_result_strings_assert(&result);
}

void
test_unsubscribe_event_all_clears_subscription(void)
{
	struct test_result_strings result;
	struct v4l2_event_subscription sub = { 0, };
	struct v4l2_event ev = { 0, };
	int ret;
	test_result_strings_init(&result);

	sub.type = V4L2_EVENT_SOURCE_CHANGE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_SUBSCRIBE_EVENT, &sub);
	test_result_strings_add_int(&result, "subscribe_ret", 0, ret);
	v4l_gst_core_push_source_change_event(backend);

	sub.type = V4L2_EVENT_ALL;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_UNSUBSCRIBE_EVENT, &sub);
	test_result_strings_add_int(&result, "unsubscribe_ret", 0, ret);

	/* No longer subscribed: the pending event is not delivered. */
	memset(&ev, 0, sizeof(ev));
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_DQEVENT, &ev);
	test_result_strings_add_int(&result, "dqevent_ret", -1, ret);
	test_result_strings_add_int(&result, "dqevent_errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

/* ------------------------------------------------------------------ */
/* mmap / EXPBUF / G_SELECTION                                         */
/* ------------------------------------------------------------------ */

void
test_mmap_out_buffer_roundtrip(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	void *map;
	guint8 *p;
	gsize length;
	guint i;
	gboolean ok;
	int ret;
	test_result_strings_init(&result);

	prepare_out_buffers(2);

	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
	cut_assert_equal_int(0, ret);
	length = buf.m.planes[0].length;
	cut_assert(length > 0);

	map = libv4l2_plugin.mmap(backend, NULL, length,
				  PROT_READ | PROT_WRITE, MAP_SHARED, -1,
				  (int64_t) buf.m.planes[0].m.mem_offset);
	cut_assert(map != MAP_FAILED);
	p = map;
	for (i = 0; i < length; i++)
		p[i] = (guint8) (i & 0xff);
	munmap(map, length);

	/* Remap read-only and verify the written pattern survives. */
	map = libv4l2_plugin.mmap(backend, NULL, length,
				  PROT_READ, MAP_SHARED, -1,
				  (int64_t) buf.m.planes[0].m.mem_offset);
	cut_assert(map != MAP_FAILED);
	ok = TRUE;
	for (i = 0; i < length; i++)
		if (((guint8 *) map)[i] != (guint8) (i & 0xff))
			ok = FALSE;
	test_result_strings_add_int(&result, "pattern_roundtrip", 1, ok);
	munmap(map, length);
	test_result_strings_assert(&result);
}

void
test_mmap_invalid_offset_returns_map_failed(void)
{
	void *map;

	prepare_out_buffers(2);

	/* An offset that matches no allocated buffer must fail. */
	map = libv4l2_plugin.mmap(backend, NULL, 4096, PROT_READ,
				  MAP_SHARED, -1, 12345);
	cut_assert(map == MAP_FAILED);
}

void
test_expbuf_rejects_output_buffer(void)
{
	struct test_result_strings result;
	struct v4l2_exportbuffer expbuf = { 0, };
	int ret;
	test_result_strings_init(&result);

	/* OUTPUT buffers cannot be exported as dmabuf. */
	expbuf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	expbuf.index = 0;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_EXPBUF, &expbuf);
	test_result_strings_add_int(&result, "output_ret", -1, ret);
	test_result_strings_add_int(&result, "output_errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_expbuf_rejects_capture_without_buffers(void)
{
	struct test_result_strings result;
	struct v4l2_exportbuffer expbuf = { 0, };
	int ret;
	test_result_strings_init(&result);

	/* With no CAPTURE buffers allocated, any index is out of range. */
	expbuf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_EXPBUF, &expbuf);
	test_result_strings_add_int(&result, "capture_ret", -1, ret);
	test_result_strings_add_int(&result, "capture_errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_g_selection_returns_capture_format(void)
{
	struct test_result_strings result;
	struct v4l2_selection sel = { 0, };
	int ret;
	test_result_strings_init(&result);

	sel.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	sel.target = V4L2_SEL_TGT_CROP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_SELECTION, &sel);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_uint(&result, "left", 0, sel.r.left);
	test_result_strings_add_uint(&result, "top", 0, sel.r.top);
	test_result_strings_add_uint(&result, "width", 640, sel.r.width);
	test_result_strings_add_uint(&result, "height", 480, sel.r.height);
	test_result_strings_assert(&result);
}

/* ------------------------------------------------------------------ */
/* Buffer state machine: QBUF / STREAMON / QUERYBUF error paths        */
/* ------------------------------------------------------------------ */

void
test_qbuf_out_before_reqbuf_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	int ret;
	test_result_strings_init(&result);

	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_qbuf_out_invalid_index_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	guint count;
	int ret;
	test_result_strings_init(&result);

	count = prepare_out_buffers(2);

	buf.index = count; /* one past the last valid index */
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

void
test_qbuf_out_duplicate_index_rejected(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	void *map;
	int ret;
	test_result_strings_init(&result);

	prepare_out_buffers(2);

	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
	cut_assert_equal_int(0, ret);

	map = libv4l2_plugin.mmap(backend, NULL, buf.m.planes[0].length,
				  PROT_READ | PROT_WRITE, MAP_SHARED, -1,
				  (int64_t) buf.m.planes[0].m.mem_offset);
	cut_assert(map != MAP_FAILED);
	memset(map, 0xa5, buf.m.planes[0].length);
	buf.m.planes[0].bytesused = buf.m.planes[0].length;
	munmap(map, buf.m.planes[0].length);

	/* The first queueing of a filled buffer succeeds. */
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	test_result_strings_add_int(&result, "first_qbuf_ret", 0, ret);

	/* Queueing the same index again must be rejected. */
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	test_result_strings_add_int(&result, "duplicate_qbuf_ret", -1, ret);
	test_result_strings_add_int(&result, "duplicate_qbuf_errno", EINVAL,
				     errno);
	test_result_strings_assert(&result);
}

struct streamon_result {
	int ret;
	int error_number;
};

static struct streamon_result
snapshot_streamon_result(int ret)
{
	struct streamon_result result = {
		.ret = ret,
		.error_number = errno,
	};

	return result;
}

static gchar *
streamon_result_to_string(const struct streamon_result *result)
{
	return g_strdup_printf("ret=%d\n"
			       "error_number=%d\n",
			       result->ret,
			       result->error_number);
}

/*
 * A VIDIOC_STREAMON on a device that is already streaming is a no-op that
 * returns 0 (V4L2 spec), which is distinct from a STREAMON rejected while the
 * plugin is shutting down (that returns EBUSY).  The started state is reached
 * by a real STREAMON after a decodable buffer has been enqueued, not by
 * flipping an internal flag.
 */
void
test_streamon_is_noop_when_pipeline_already_started(void)
{
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	guint8 *stream;
	gsize stream_len;
	void *map;
	int ret;
	struct streamon_result expected = {
		.ret = 0,
		.error_number = 0,
	};
	struct streamon_result actual;
	const gchar *expected_string =
		cut_take_string(streamon_result_to_string(&expected));
	const gchar *actual_string;

	if (!gst_element_factory_find("h264parse") ||
	    !gst_element_factory_find("avdec_h264") ||
	    !gst_element_factory_find("videoconvert") ||
	    !gst_element_factory_find("x264enc"))
		cut_pend("h264parse, avdec_h264, videoconvert or x264enc "
			 "element is not available");

	stream = generate_h264_sample(1, 320, 240, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	prepare_out_buffers(2);

	/* Enqueue one decodable OUTPUT buffer so STREAMON has data to start. */
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf));
	map = libv4l2_plugin.mmap(backend, NULL, buf.m.planes[0].length,
				  PROT_READ | PROT_WRITE, MAP_SHARED, -1,
				  (int64_t) buf.m.planes[0].m.mem_offset);
	cut_assert(map != MAP_FAILED);
	cut_assert(stream_len <= (gsize) buf.m.planes[0].length);
	memcpy(map, stream, stream_len);
	buf.m.planes[0].bytesused = (unsigned int) stream_len;
	munmap(map, buf.m.planes[0].length);
	g_free(stream);
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QBUF, &buf));

	/* Start the stream for real. */
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_STREAMON, &type));

	/* A repeat STREAMON on an already-started device is a no-op. */
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_STREAMON, &type);
	actual = snapshot_streamon_result(ret);
	actual_string = cut_take_string(streamon_result_to_string(&actual));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_querybuf_out_valid_index(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	int ret;
	test_result_strings_init(&result);

	prepare_out_buffers(2);

	/* A valid index returns the buffer's plane geometry. */
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
	test_result_strings_add_int(&result, "valid_ret", 0, ret);
	test_result_strings_add_uint(&result, "valid_index", 0, buf.index);
	test_result_strings_add_uint(&result, "valid_offset", 0,
				     buf.m.planes[0].m.mem_offset);
	test_result_strings_add_uint(&result, "valid_length_nonzero", 1,
				     buf.m.planes[0].length > 0);

	test_result_strings_assert(&result);
}

void
test_querybuf_out_invalid_index(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	guint count;
	int ret;
	test_result_strings_init(&result);

	count = prepare_out_buffers(2);
	buf.index = count;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf);
	test_result_strings_add_int(&result, "ret", -1, ret);
	test_result_strings_add_int(&result, "errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

/* ------------------------------------------------------------------ */
/* Config-driven behaviour: min_buffers / max dims / preferred format  */
/* ------------------------------------------------------------------ */

void
test_g_ctrl_min_buffers_reflects_config(void)
{
	struct test_result_strings result;
	struct v4l2_control ctrl = { 0, };
	int ret;
	test_result_strings_init(&result);

	backend->config.cap_min_buffers = 7;
	ctrl.id = V4L2_CID_MIN_BUFFERS_FOR_CAPTURE;
	ctrl.value = 0;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_G_CTRL, &ctrl);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_int(&result, "value", 7, ctrl.value);
	test_result_strings_assert(&result);
}

void
test_enum_framesizes_clamped_by_config_max_dimensions(void)
{
	struct test_result_strings result;
	struct v4l2_frmsizeenum frame_size = { 0, };
	int ret;
	test_result_strings_init(&result);

	backend->config.max_width = 320;
	backend->config.max_height = 240;

	frame_size.pixel_format = V4L2_PIX_FMT_NV12;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FRAMESIZES, &frame_size);
	test_result_strings_add_int(&result, "ret", 0, ret);
	test_result_strings_add_uint(&result, "type", V4L2_FRMSIZE_TYPE_STEPWISE,
				     frame_size.type);
	test_result_strings_add_uint(&result, "max_width", 320,
				     frame_size.stepwise.max_width);
	test_result_strings_add_uint(&result, "max_height", 240,
				     frame_size.stepwise.max_height);
	test_result_strings_assert(&result);
}

void
test_enum_fmt_capture_returns_preferred_format(void)
{
	struct test_result_strings result;
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	test_result_strings_init(&result);

	/* Re-derive the supported CAPTURE formats with a non-default
	 * preferred raw format. */
	backend->config.preferred_format = V4L2_PIX_FMT_NV21;
	v4l_gst_core_setup_role(backend);

	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	desc.index = 0;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	test_result_strings_add_int(&result, "preferred_ret", 0, ret);
	test_result_strings_add_uint(&result, "preferred_format",
				     V4L2_PIX_FMT_NV21, desc.pixelformat);
	test_result_strings_assert(&result);
}

void
test_enum_fmt_capture_rejects_index_after_preferred_format(void)
{
	struct test_result_strings result;
	struct v4l2_fmtdesc desc = { 0, };
	int ret;
	test_result_strings_init(&result);

	backend->config.preferred_format = V4L2_PIX_FMT_NV21;
	v4l_gst_core_setup_role(backend);
	desc.index = 1;
	desc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_ENUM_FMT, &desc);
	test_result_strings_add_int(&result, "next_index_ret", -1, ret);
	test_result_strings_add_int(&result, "next_index_errno", EINVAL, errno);
	test_result_strings_assert(&result);
}

/* ------------------------------------------------------------------ */
/* Buffer state / non-blocking / streaming-state P1 gaps               */
/* ------------------------------------------------------------------ */

/*
 * VIDIOC_QUERYBUF must expose the buffer's queueing state through the flags
 * field (V4L2_BUF_FLAG_QUEUED is valid here per the V4L2 spec), while
 * bytesused/timestamp are meaningless in this context and are only returned by
 * the corresponding DQBUF (see test_cap_buffer_return_roundtrip).
 */
void
test_querybuf_reports_queued_state_around_qbuf(void)
{
	struct test_result_strings result;
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	void *map;
	int ret;
	test_result_strings_init(&result);

	prepare_out_buffers(2);

	/* After REQBUFS the client owns the buffer, so it is not queued. */
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf));
	test_result_strings_add_uint(&result, "queued_after_reqbuf", 0,
				     (buf.flags & V4L2_BUF_FLAG_QUEUED) != 0);

	/* Fill and queue the buffer. */
	map = libv4l2_plugin.mmap(backend, NULL, buf.m.planes[0].length,
				  PROT_READ | PROT_WRITE, MAP_SHARED, -1,
				  (int64_t) buf.m.planes[0].m.mem_offset);
	cut_assert(map != MAP_FAILED);
	memset(map, 0xa5, buf.m.planes[0].length);
	buf.m.planes[0].bytesused = buf.m.planes[0].length;
	munmap(map, buf.m.planes[0].length);
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
	test_result_strings_add_int(&result, "qbuf_ret", 0, ret);

	/* QUERYBUF now reports the buffer as queued. */
	memset(&buf, 0, sizeof(buf));
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf));
	test_result_strings_add_uint(&result, "queued_after_qbuf", 1,
				     (buf.flags & V4L2_BUF_FLAG_QUEUED) != 0);

	test_result_strings_assert(&result);
}

static int
ioctl_on_backend(struct v4l_gst *priv, unsigned long int cmd, void *arg)
{
	return libv4l2_plugin.ioctl(priv, -1, cmd, arg);
}

/*
 * A backend opened on an O_NONBLOCK fd must be detected as non-blocking by
 * init() (via fcntl) and a VIDIOC_DQBUF on OUTPUT with no buffer the driver
 * can hand back must fail with EAGAIN immediately rather than block.
 */
void
test_dqbuf_out_empty_nonblocking_eagain(void)
{
	struct test_result_strings result;
	struct v4l_gst *nb = NULL;
	struct v4l2_format format = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	const guint32 w = 320;
	const guint32 h = 240;
	const gsize frame_size = w * h * 3 / 2;
	gchar *nb_path = NULL;
	int nb_fd = -1;
	int ret;
	gint64 start, elapsed_us;
	test_result_strings_init(&result);

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	/* A dedicated fd carrying O_NONBLOCK, independent of the blocking
	   backend created by setup(). */
	{
		GError *error = NULL;
		int flags;

		nb_fd = g_file_open_tmp("v4l-gst-nb-XXXXXX", &nb_path, &error);
		cut_assert_null(error);
		flags = fcntl(nb_fd, F_GETFL);
		cut_assert(flags >= 0);
		cut_assert_equal_int(0, fcntl(nb_fd, F_SETFL, flags | O_NONBLOCK));
	}

	nb = libv4l2_plugin.init(nb_fd);
	cut_assert_not_null(nb);
	test_result_strings_add_uint(&result, "nonblocking_detected", 1,
				     nb->is_non_blocking);

	prepare_pipeline_backend_fixture(nb, V4L_GST_ROLE_DECODER,
					 "h264parse ! avdec_h264 ! videoconvert",
					 V4L2_PIX_FMT_H264, V4L2_PIX_FMT_NV12,
					 w, h, frame_size, 4 * 1024 * 1024);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = 4 * 1024 * 1024;
	cut_assert_equal_int(0, ioctl_on_backend(nb, VIDIOC_S_FMT, &format));

	memset(&format, 0, sizeof(format));
	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;
	format.fmt.pix_mp.width = w;
	format.fmt.pix_mp.height = h;
	format.fmt.pix_mp.num_planes = 1;
	format.fmt.pix_mp.plane_fmt[0].bytesperline = w;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = frame_size;
	cut_assert_equal_int(0, ioctl_on_backend(nb, VIDIOC_S_FMT, &format));

	/* Allocate OUTPUT buffers; every one is acquired by the client, so the
	   pool holds nothing the driver can return. */
	req.count = 2;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	cut_assert_equal_int(0, ioctl_on_backend(nb, VIDIOC_REQBUFS, &req));
	cut_assert(req.count >= 1);

	/* Start streaming without queueing any OUTPUT buffer. */
	cut_assert_equal_int(0, ioctl_on_backend(nb, VIDIOC_STREAMON, &type));

	memset(&buf, 0, sizeof(buf));
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	errno = 0;
	start = g_get_monotonic_time();
	ret = ioctl_on_backend(nb, VIDIOC_DQBUF, &buf);
	elapsed_us = g_get_monotonic_time() - start;

	test_result_strings_add_int(&result, "dqbuf_ret", -1, ret);
	test_result_strings_add_int(&result, "dqbuf_errno", EAGAIN, errno);
	test_result_strings_add_uint(&result, "returned_without_blocking", 1,
				     elapsed_us < 1000000);

	/* Release the second backend before asserting so the fd/file are always
	   cleaned up. */
	libv4l2_plugin.close(nb);
	close(nb_fd);
	g_unlink(nb_path);
	g_free(nb_path);

	test_result_strings_assert(&result);
}

/*
 * VIDIOC_REQBUFS on OUTPUT with a non-zero count while the pipeline is already
 * streaming must be rejected with EBUSY (the buffers are in use by the running
 * stream).
 */
void
test_reqbuf_out_while_streaming_ebusy(void)
{
	struct test_result_strings result;
	struct v4l2_requestbuffers req = { 0, };
	const guint8 garbage[] = { 0 };
	int ret;
	test_result_strings_init(&result);

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");

	/* Reach the started state through a real STREAMON. */
	start_h264dec_stream(garbage, sizeof(garbage));

	req.count = 2;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	errno = 0;
	ret = v4l_gst_ioctl(VIDIOC_REQBUFS, &req);
	test_result_strings_add_int(&result, "reqbuf_ret", -1, ret);
	test_result_strings_add_int(&result, "reqbuf_errno", EBUSY, errno);
	test_result_strings_assert(&result);
}

/*
 * A CAPTURE buffer handed back by VIDIOC_DQBUF must be re-queueable and the
 * same index must be produced again by a later DQBUF, carrying the
 * API-guaranteed data (a non-zero bytesused and a non-decreasing timestamp).
 * The fixture feeds far more frames than the pool holds, so the re-queued
 * index is guaranteed to come back; the loop keeps re-queueing the other
 * buffers so they cannot mask the result, and only stops once the recorded
 * index reappears (or the final-buffer flag ends the stream).
 */
void
test_cap_buffer_return_roundtrip(void)
{
	struct test_result_strings result;
	struct v4l2_format format = { 0, };
	struct v4l2_requestbuffers req = { 0, };
	struct v4l2_buffer buf = { 0, };
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
	enum v4l2_buf_type type;
	const guint32 w = 320;
	const guint32 h = 240;
	const gsize frame_size = w * h * 3 / 2;
	const guint32 n_frames = 100;
	gsize stream_len = 0;
	guint8 *stream;
	guint cap_count, i;
	guint first_index = 0;
	struct timeval first_ts;
	int ret;
	test_result_strings_init(&result);

	if (!h264dec_pipeline_available())
		cut_pend("h264parse, avdec_h264 or videoconvert is not available");
	stream = generate_h264_sample(n_frames, w, h, &stream_len);
	if (!stream)
		cut_pend("failed to generate an h264 sample stream");

	prepare_pipeline_backend_fixture(backend, V4L_GST_ROLE_DECODER,
					 "h264parse ! avdec_h264 ! videoconvert",
					 V4L2_PIX_FMT_H264, V4L2_PIX_FMT_NV12,
					 w, h, frame_size, 4 * 1024 * 1024);
	assert_role(V4L_GST_ROLE_DECODER);

	format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_H264;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = 4 * 1024 * 1024;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_S_FMT, &format));

	memset(&format, 0, sizeof(format));
	format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	format.fmt.pix_mp.pixelformat = V4L2_PIX_FMT_NV12;
	format.fmt.pix_mp.width = w;
	format.fmt.pix_mp.height = h;
	format.fmt.pix_mp.num_planes = 1;
	format.fmt.pix_mp.plane_fmt[0].bytesperline = w;
	format.fmt.pix_mp.plane_fmt[0].sizeimage = frame_size;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_S_FMT, &format));

	memset(&req, 0, sizeof(req));
	req.count = 1;
	req.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_REQBUFS, &req));

	memset(&buf, 0, sizeof(buf));
	buf.index = 0;
	buf.type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	buf.memory = V4L2_MEMORY_MMAP;
	buf.m.planes = planes;
	buf.length = 1;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QUERYBUF, &buf));
	{
		void *map = libv4l2_plugin.mmap(backend, NULL,
						buf.m.planes[0].length,
						PROT_READ | PROT_WRITE, MAP_SHARED,
						-1,
						(int64_t) buf.m.planes[0].m.mem_offset);
		cut_assert(map != MAP_FAILED);
		cut_assert(stream_len <= (gsize) buf.m.planes[0].length);
		memcpy(map, stream, stream_len);
		buf.m.planes[0].bytesused = (unsigned int) stream_len;
		munmap(map, buf.m.planes[0].length);
	}
	g_free(stream);
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QBUF, &buf));

	type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_STREAMON, &type));

	memset(&req, 0, sizeof(req));
	req.count = 8;
	req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	req.memory = V4L2_MEMORY_MMAP;
	cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_REQBUFS, &req));
	cap_count = req.count;
	cut_assert(cap_count > 0);

	{
		struct v4l2_decoder_cmd decoder_cmd = { 0, };
		decoder_cmd.cmd = V4L2_DEC_CMD_STOP;
		cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_DECODER_CMD,
						      &decoder_cmd));
	}

	for (i = 0; i < cap_count; i++) {
		memset(&buf, 0, sizeof(buf));
		buf.index = i;
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
		buf.memory = V4L2_MEMORY_MMAP;
		buf.m.planes = planes;
		buf.length = 2;
		cut_assert_equal_int(0, v4l_gst_ioctl(VIDIOC_QBUF, &buf));
	}

	/* Dequeue CAPTURE buffers, re-queueing each one so the decoder keeps
	   cycling through the fixed pool. The first dequeued index is recorded;
	   the test then waits for that exact index to be handed back, which
	   only happens if the re-queued buffer is produced again. The DQBUF is
	   driven in non-blocking mode (as the EOS test does) so an empty queue
	   returns EAGAIN instead of blocking, letting the retry bound below
	   always terminate the wait. */
	{
		gboolean first_seen = FALSE;
		gboolean returned = FALSE;
		guint frames = 0;
		guint retries = 0;
		const guint max_frames = 1024;
		const guint max_retries = 1000;

		backend->is_non_blocking = TRUE;
		while (!returned && frames < max_frames) {
			memset(&buf, 0, sizeof(buf));
			buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
			buf.memory = V4L2_MEMORY_MMAP;
			buf.m.planes = planes;
			buf.length = 2;
			errno = 0;
			ret = v4l_gst_ioctl(VIDIOC_DQBUF, &buf);
			if (ret != 0) {
				if (++retries >= max_retries)
					break;
				g_usleep(1000);
				continue;
			}
			frames++;

			if (!first_seen) {
				first_index = buf.index;
				first_ts = buf.timestamp;
				first_seen = TRUE;
				test_result_strings_add_uint(&result,
					"first_index_in_range", 1,
					first_index < cap_count);
				test_result_strings_add_uint(&result,
					"first_bytesused_nonzero", 1,
					buf.m.planes[0].bytesused > 0);
			} else if (buf.index == first_index) {
				returned = TRUE;
				test_result_strings_add_uint(&result,
					"returned_bytesused_nonzero", 1,
					buf.m.planes[0].bytesused > 0);
				test_result_strings_add_uint(&result,
					"timestamp_monotonic", 1,
					(buf.timestamp.tv_sec > first_ts.tv_sec) ||
					(buf.timestamp.tv_sec == first_ts.tv_sec &&
					 buf.timestamp.tv_usec >= first_ts.tv_usec));
				break;
			}

			if (buf.flags & V4L2_BUF_FLAG_LAST)
				break;

			buf.flags = 0;
			errno = 0;
			ret = v4l_gst_ioctl(VIDIOC_QBUF, &buf);
			if (ret != 0)
				break;
		}

		backend->is_non_blocking = FALSE;

		test_result_strings_add_uint(&result, "requeued_index_returned",
					     1, returned);
	}

	test_result_strings_assert(&result);
}
