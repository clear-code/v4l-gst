#include "gst-backend-testhooks.h"

#ifdef UNIT_TESTS

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
	append_test_format(priv->supported_cap_fmts, V4L2_PIX_FMT_NV12, "NV12");

	priv->out_fmt.pixelformat = V4L2_PIX_FMT_H264;
	priv->out_fmt.plane_fmt[0].sizeimage = 1024;
	priv->cap_fmt.pixelformat = V4L2_PIX_FMT_NV12;
}

#endif
