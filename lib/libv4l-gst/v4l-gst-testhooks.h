#ifndef __V4L_GST_TESTHOOKS_H__
#define __V4L_GST_TESTHOOKS_H__

#include "config.h"

#ifdef UNIT_TESTS
#include <gst/gst.h>
#include <linux/videodev2.h>

#include "v4l-gst-internal.h"

struct v4l_gst;

GstElement *test_create_pipeline(const gchar *pipeline_str);
void prepare_format_backend_fixture(struct v4l_gst *priv);
void prepare_encode_only_role_backend_fixture(struct v4l_gst *priv);
void prepare_dual_role_backend_fixture(struct v4l_gst *priv);
enum v4l_gst_role get_backend_role(struct v4l_gst *priv);
#endif

#endif /* __V4L_GST_TESTHOOKS_H__ */
