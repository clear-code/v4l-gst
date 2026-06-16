#include "gst-backend-testhooks.h"
#include <cutter.h>

void
test_create_pipeline_returns_nonnull(void)
{
    gst_init(NULL, NULL);
    GstElement *p = test_create_pipeline("fakesrc");
    cut_assert_not_null(p);
    gst_element_set_state(p, GST_STATE_NULL);
    gst_object_unref(p);
}
