#ifndef __GST_BACKEND_TEST_H__
#define __GST_BACKEND_TEST_H__

#include "config.h"

#ifdef UNIT_TESTS
#include <gst/gst.h>
GstElement *test_create_pipeline(const gchar *pipeline_str);
#endif

#endif /* __GST_BACKEND_TEST_H__ */
