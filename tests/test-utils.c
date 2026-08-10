#include <cutter.h>

#include <linux/videodev2.h>
#include <string.h>

#include "utils.h"

struct mimetype_case {
	guint32 fourcc;
	const gchar *mimetype;
};

struct video_format_case {
	guint32 fourcc;
	GstVideoFormat gst_format;
};

static void
assert_equal_result_strings(const gchar *expected, const gchar *actual)
{
	cut_assert_equal_string(expected, actual,
				cut_message("%s", cut_take_diff(expected, actual)));
}

static gchar *
mimetype_cases_to_string(const struct mimetype_case *cases, gsize n_cases)
{
	GString *string = g_string_new(NULL);

	for (gsize i = 0; i < n_cases; i++) {
		gchar fourcc[5];

		fourcc_to_string(cases[i].fourcc, fourcc);
		g_string_append_printf(string, "%s=%s\n", fourcc,
				       cases[i].mimetype ? cases[i].mimetype : "(null)");
	}

	return g_string_free(string, FALSE);
}

static gchar *
video_format_cases_to_string(const struct video_format_case *cases,
			     gsize n_cases)
{
	GString *string = g_string_new(NULL);

	for (gsize i = 0; i < n_cases; i++) {
		gchar fourcc[5];
		const gchar *gst_format;

		fourcc_to_string(cases[i].fourcc, fourcc);
		if (cases[i].gst_format == GST_VIDEO_FORMAT_UNKNOWN)
			gst_format = "UNKNOWN";
		else
			gst_format = gst_video_format_to_string(cases[i].gst_format);
		g_string_append_printf(string, "%s=%s (%d)\n", fourcc,
				       gst_format, cases[i].gst_format);
	}

	return g_string_free(string, FALSE);
}

void
test_fourcc_from_string_returns_zero_for_invalid_input(void)
{
	gchar too_short[] = "H26";
	gchar too_long[] = "H264!";
	gchar empty[] = "";

	cut_assert_equal_uint(0, fourcc_from_string(NULL));
	cut_assert_equal_uint(0, fourcc_from_string(empty));
	cut_assert_equal_uint(0, fourcc_from_string(too_short));
	cut_assert_equal_uint(0, fourcc_from_string(too_long));
}

void
test_fourcc_string_roundtrip(void)
{
	gchar h264[] = "H264";
	gchar out[5];
	guint32 fourcc;

	fourcc = fourcc_from_string(h264);
	fourcc_to_string(fourcc, out);

	cut_assert_equal_uint(V4L2_PIX_FMT_H264, fourcc);
	cut_assert_equal_string("H264", out);
}

void
test_fourcc_to_mimetype_maps_encoder_codecs(void)
{
	const struct mimetype_case expected[] = {
		{ V4L2_PIX_FMT_H264, GST_VIDEO_CODEC_MIME_H264 },
		{ V4L2_PIX_FMT_HEVC, GST_VIDEO_CODEC_MIME_HEVC },
		{ V4L2_PIX_FMT_VP8, GST_VIDEO_CODEC_MIME_VP8 },
		{ V4L2_PIX_FMT_NV12, NULL },
	};
	struct mimetype_case actual[G_N_ELEMENTS(expected)];
	const gchar *expected_string;
	const gchar *actual_string;

	for (gsize i = 0; i < G_N_ELEMENTS(expected); i++) {
		actual[i].fourcc = expected[i].fourcc;
		actual[i].mimetype = fourcc_to_mimetype(expected[i].fourcc);
	}

	expected_string = cut_take_string(
		mimetype_cases_to_string(expected, G_N_ELEMENTS(expected)));
	actual_string = cut_take_string(
		mimetype_cases_to_string(actual, G_N_ELEMENTS(actual)));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_gst_video_format_mapping_covers_encoder_raw_formats(void)
{
	const struct video_format_case expected[] = {
		{ V4L2_PIX_FMT_NV12, GST_VIDEO_FORMAT_NV12 },
		{ V4L2_PIX_FMT_YUYV, GST_VIDEO_FORMAT_YUY2 },
		{ V4L2_PIX_FMT_RGB24, GST_VIDEO_FORMAT_RGB },
		{ V4L2_PIX_FMT_BGR24, GST_VIDEO_FORMAT_BGR },
		{ V4L2_PIX_FMT_NV16, GST_VIDEO_FORMAT_NV16 },
		{ V4L2_PIX_FMT_H264, GST_VIDEO_FORMAT_UNKNOWN },
	};
	struct video_format_case actual[G_N_ELEMENTS(expected)];
	const gchar *expected_string;
	const gchar *actual_string;

	for (gsize i = 0; i < G_N_ELEMENTS(expected); i++) {
		actual[i].fourcc = expected[i].fourcc;
		actual[i].gst_format =
			fourcc_to_gst_video_format(expected[i].fourcc);
	}

	expected_string = cut_take_string(
		video_format_cases_to_string(expected, G_N_ELEMENTS(expected)));
	actual_string = cut_take_string(
		video_format_cases_to_string(actual, G_N_ELEMENTS(actual)));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_gst_video_format_reverse_mapping_covers_encoder_raw_formats(void)
{
	const struct video_format_case expected[] = {
		{ V4L2_PIX_FMT_NV12, GST_VIDEO_FORMAT_NV12 },
		{ V4L2_PIX_FMT_YUYV, GST_VIDEO_FORMAT_YUY2 },
		{ V4L2_PIX_FMT_RGB24, GST_VIDEO_FORMAT_RGB },
		{ V4L2_PIX_FMT_BGR24, GST_VIDEO_FORMAT_BGR },
		{ V4L2_PIX_FMT_NV16, GST_VIDEO_FORMAT_NV16 },
		{ 0, GST_VIDEO_FORMAT_UNKNOWN },
	};
	struct video_format_case actual[G_N_ELEMENTS(expected)];
	const gchar *expected_string;
	const gchar *actual_string;

	for (gsize i = 0; i < G_N_ELEMENTS(expected); i++) {
		actual[i].fourcc =
			fourcc_from_gst_video_format(expected[i].gst_format);
		actual[i].gst_format = expected[i].gst_format;
	}

	expected_string = cut_take_string(
		video_format_cases_to_string(expected, G_N_ELEMENTS(expected)));
	actual_string = cut_take_string(
		video_format_cases_to_string(actual, G_N_ELEMENTS(actual)));

	assert_equal_result_strings(expected_string, actual_string);
}

void
test_v4l2_buffer_type_to_string(void)
{
	cut_assert_equal_string("VIDEO_CAPTURE_MPLANE",
				v4l2_buffer_type_to_string(
					V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE));
	cut_assert_equal_string("VIDEO_OUTPUT_MPLANE",
				v4l2_buffer_type_to_string(
					V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE));
	cut_assert_null(v4l2_buffer_type_to_string(0xffffffffu));
}

void
test_v4l2_event_type_to_string(void)
{
	cut_assert_equal_string("V4L2_EVENT_EOS",
				v4l2_event_type_to_string(V4L2_EVENT_EOS));
	cut_assert_equal_string("V4L2_EVENT_SOURCE_CHANGE",
				v4l2_event_type_to_string(
					V4L2_EVENT_SOURCE_CHANGE));
	cut_assert_null(v4l2_event_type_to_string(0xffffffffu));
}

void
test_crc32_calc(void)
{
	const gchar *sample = "123456789";

	cut_assert_equal_uint(0xcbf43926u,
			      crc32_calc(sample, strlen(sample)));
}

void
test_crc32_sampled_uses_large_regions_only(void)
{
	guint8 data[4096 * 3 + 1];

	for (guint i = 0; i < sizeof(data); i++)
		data[i] = (guint8)(i & 0xff);

	cut_assert_equal_uint(0, crc32_sampled(data, 4096));
	cut_assert_equal_uint(crc32_calc(data, 4096),
			      crc32_sampled(data, 4097));
	cut_assert_equal_uint(crc32_calc(data, 4096) ^
			      crc32_calc(data + 4096, 4096),
			      crc32_sampled(data, 4096 * 2 + 1));
}
