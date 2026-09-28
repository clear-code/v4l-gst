#include "config.h"

#ifdef UNIT_TESTS

#include "v4l-gst-testhooks.h"
#include "v4l-gst-internal.h"

GstElement *
test_create_pipeline(const gchar *pipeline_str)
{
	return create_pipeline(pipeline_str);
}

static void
append_test_format(GArray *formats, guint fourcc, const gchar *description)
{
	struct fmt fmt = { 0, };

	fmt.fourcc = fourcc;
	g_strlcpy(fmt.desc, description, FMTDESC_NAME_LENGTH);
	g_array_append_val(formats, fmt);
}

void
prepare_format_backend_fixture(struct v4l_gst *priv)
{
	if (!priv)
		return;
	if (!priv->pipeline)
		priv->pipeline = create_pipeline("identity");
	append_test_format(priv->cap.supported_fmts, V4L2_PIX_FMT_NV12, "NV12");

	priv->out.fmt.pixelformat = V4L2_PIX_FMT_H264;
	priv->out.fmt.plane_fmt[0].sizeimage = 1024;
	priv->cap.fmt.pixelformat = V4L2_PIX_FMT_NV12;
	priv->cap.fmt.width = 640;
	priv->cap.fmt.height = 480;
	priv->cap.fmt.num_planes = 1;
	priv->cap.fmt.plane_fmt[0].bytesperline = 640;
	priv->cap.fmt.plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;
	g_atomic_int_set(&priv->cap.fmt_acquirable, 1);
	priv->out.cnt = INPUT_BUFFERING_CNT;
}

#endif
