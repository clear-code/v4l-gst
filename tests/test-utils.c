#include <cutter.h>

#include <linux/videodev2.h>
#include <string.h>

#include "utils.h"

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
test_fourcc_to_mimetype(void)
{
	cut_assert_equal_string(GST_VIDEO_CODEC_MIME_H264,
				fourcc_to_mimetype(V4L2_PIX_FMT_H264));
	cut_assert_equal_string(GST_VIDEO_CODEC_MIME_HEVC,
				fourcc_to_mimetype(V4L2_PIX_FMT_HEVC));
	cut_assert_null(fourcc_to_mimetype(V4L2_PIX_FMT_NV12));
}

void
test_gst_video_format_mapping(void)
{
	cut_assert_equal_uint(V4L2_PIX_FMT_NV12,
			      fourcc_from_gst_video_format(GST_VIDEO_FORMAT_NV12));
	cut_assert_equal_int(GST_VIDEO_FORMAT_NV12,
			     fourcc_to_gst_video_format(V4L2_PIX_FMT_NV12));
	cut_assert_equal_uint(0,
			      fourcc_from_gst_video_format(GST_VIDEO_FORMAT_UNKNOWN));
	cut_assert_equal_int(GST_VIDEO_FORMAT_UNKNOWN,
			     fourcc_to_gst_video_format(V4L2_PIX_FMT_H264));
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
