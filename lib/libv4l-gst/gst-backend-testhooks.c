#include "gst-backend-testhooks.h"

#ifdef UNIT_TESTS

GstElement *
test_create_pipeline(const gchar *pipeline_str)
{
    return create_pipeline(pipeline_str);
}

#endif
