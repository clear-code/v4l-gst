#include "config.h"

#ifdef UNIT_TESTS

#include "v4l-gst-testhooks.h"
#include "v4l-gst-internal.h"

GstElement *
test_create_pipeline(const gchar *pipeline_str)
{
	return v4l_gst_core_create_pipeline(pipeline_str);
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
		priv->pipeline = v4l_gst_core_create_pipeline("identity");
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

/*
 * Reconfigure the backend of a decode-only config into an encoder-only role:
 * the decode pipeline is dropped, an encode pipeline is added and the role
 * is re-derived. The GStreamer pipeline itself is kept (already created as
 * "identity" by prepare_format_backend_fixture()).
 */
void
prepare_encode_only_role_backend_fixture(struct v4l_gst *priv)
{
	g_hash_table_remove(priv->config.pipelines, "H264");
	g_hash_table_insert(priv->config.encode_pipelines, g_strdup("H264"),
			    g_strdup("identity"));
	v4l_gst_core_setup_role(priv);

	priv->out.fmt.pixelformat = V4L2_PIX_FMT_NV12;
	priv->out.fmt.width = 640;
	priv->out.fmt.height = 480;
	priv->out.fmt.num_planes = 1;
	priv->out.fmt.plane_fmt[0].bytesperline = 640;
	priv->out.fmt.plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;
	priv->cap.fmt.pixelformat = V4L2_PIX_FMT_H264;
	priv->cap.fmt.plane_fmt[0].sizeimage = 1024;
	g_atomic_int_set(&priv->cap.fmt_acquirable, 1);
	priv->out.cnt = INPUT_BUFFERING_CNT;
}

/*
 * Reconfigure the backend of a decode-only config into the dual role: both
 * the decode and the encode pipeline are configured, so the role stays
 * V4L_GST_ROLE_NONE until the first OUTPUT format fixes it.
 */
void
prepare_dual_role_backend_fixture(struct v4l_gst *priv)
{
	g_hash_table_insert(priv->config.encode_pipelines, g_strdup("H264"),
			    g_strdup("identity"));
	v4l_gst_core_setup_role(priv);

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

/*
 * Reconfigure the backend into an encoder role backed by a real x264enc
 * GStreamer pipeline, so that OUTPUT raw frames are encoded to an H264
 * stream on CAPTURE. The "identity" placeholder pipeline created by
 * prepare_format_backend_fixture() is dropped so that the encoder pipeline
 * is created (via VIDIOC_S_FMT on CAPTURE) with a real encoder.
 */
void
prepare_x264enc_backend_fixture(struct v4l_gst *priv)
{
	if (priv->pipeline) {
		gst_object_unref(priv->pipeline);
		priv->pipeline = NULL;
	}

	g_hash_table_remove(priv->config.pipelines, "H264");
	/* Zero-latency tuning disables lookahead/bframes so that each input
	   frame produces an output frame immediately, which the CAPTURE
	   buffer flow depends on. */
	g_hash_table_insert(priv->config.encode_pipelines, g_strdup("H264"),
			    g_strdup("x264enc tune=zerolatency "
				     "speed-preset=ultrafast"));
	v4l_gst_core_setup_role(priv);

	priv->out.fmt.pixelformat = V4L2_PIX_FMT_NV12;
	priv->out.fmt.width = 640;
	priv->out.fmt.height = 480;
	priv->out.fmt.num_planes = 1;
	priv->out.fmt.plane_fmt[0].bytesperline = 640;
	priv->out.fmt.plane_fmt[0].sizeimage = 640 * 480 * 3 / 2;
	priv->cap.fmt.pixelformat = V4L2_PIX_FMT_H264;
	priv->cap.fmt.plane_fmt[0].sizeimage = 1024 * 1024;
	g_atomic_int_set(&priv->cap.fmt_acquirable, 1);
	priv->out.cnt = INPUT_BUFFERING_CNT;
}

enum v4l_gst_role
get_backend_role(struct v4l_gst *priv)
{
	return priv->role;
}

#endif
