#include "v4l-gst-testhooks.h"
#include <cutter.h>
#include <errno.h>
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

	prepare_x264enc_backend_fixture(backend);
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
