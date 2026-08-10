#ifndef __GST_BACKEND_TEST_H__
#define __GST_BACKEND_TEST_H__

#include "config.h"

#ifdef UNIT_TESTS
#include <gst/gst.h>
#include <linux/videodev2.h>

struct v4l_gst;

GstElement *test_create_pipeline(const gchar *pipeline_str);
void prepare_format_backend_fixture(struct v4l_gst *priv);
#endif

#endif /* __GST_BACKEND_TEST_H__ */
