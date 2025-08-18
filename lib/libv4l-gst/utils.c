/*
 * Copyright (C) 2015 Renesas Electronics Corporation
 * Copyright (C) 2024-2025 ClearCode Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA
 */
#include "utils.h"

#include <linux/videodev2.h>

struct v4l_gst_format_info {
	guint fourcc;
	GstVideoFormat format;
};

static const struct v4l_gst_format_info v4l_gst_video_format_table[] = {
	{ V4L2_PIX_FMT_GREY, GST_VIDEO_FORMAT_GRAY8 },
	{ V4L2_PIX_FMT_RGB565, GST_VIDEO_FORMAT_RGB16 },
	{ V4L2_PIX_FMT_RGB24, GST_VIDEO_FORMAT_RGB },
	{ V4L2_PIX_FMT_BGR24, GST_VIDEO_FORMAT_BGR },
	{ V4L2_PIX_FMT_ABGR32, GST_VIDEO_FORMAT_BGRA },
	{ V4L2_PIX_FMT_XBGR32, GST_VIDEO_FORMAT_BGRx },
	{ V4L2_PIX_FMT_ARGB32, GST_VIDEO_FORMAT_ARGB },
	{ V4L2_PIX_FMT_XRGB32, GST_VIDEO_FORMAT_xRGB },
	{ V4L2_PIX_FMT_NV12, GST_VIDEO_FORMAT_NV12 },
	{ V4L2_PIX_FMT_NV21 ,GST_VIDEO_FORMAT_NV21 },
	{ V4L2_PIX_FMT_NV16, GST_VIDEO_FORMAT_NV16 },
	{ V4L2_PIX_FMT_YVU410, GST_VIDEO_FORMAT_YVU9 },
	{ V4L2_PIX_FMT_YUV410, GST_VIDEO_FORMAT_YUV9 },
	{ V4L2_PIX_FMT_YUV420, GST_VIDEO_FORMAT_I420 },
	{ V4L2_PIX_FMT_YUYV, GST_VIDEO_FORMAT_YUY2 },
	{ V4L2_PIX_FMT_YVU420, GST_VIDEO_FORMAT_YV12 },
	{ V4L2_PIX_FMT_UYVY, GST_VIDEO_FORMAT_UYVY },
	{ V4L2_PIX_FMT_YUV411P, GST_VIDEO_FORMAT_Y41B },
	{ V4L2_PIX_FMT_YUV422P, GST_VIDEO_FORMAT_Y42B },
	{ V4L2_PIX_FMT_YVYU, GST_VIDEO_FORMAT_YVYU },
	{ V4L2_PIX_FMT_RGB32, GST_VIDEO_FORMAT_BGRA },
	{ V4L2_PIX_FMT_BGR32, GST_VIDEO_FORMAT_ARGB },
	{ V4L2_PIX_FMT_NV12MT, GST_VIDEO_FORMAT_NV12_64Z32 },
};

guint32
fourcc_from_gst_video_format(GstVideoFormat format)
{
	gint i;
	guint fourcc = 0;

	for (i = 0; i < G_N_ELEMENTS(v4l_gst_video_format_table); i++) {
		if (v4l_gst_video_format_table[i].format == format)
			fourcc = v4l_gst_video_format_table[i].fourcc;
	}

	return fourcc;
}

GstVideoFormat
fourcc_to_gst_video_format(guint32 fourcc)
{
	gint i;
	GstVideoFormat format = GST_VIDEO_FORMAT_UNKNOWN;

	for (i = 0; i < G_N_ELEMENTS(v4l_gst_video_format_table); i++) {
		if (v4l_gst_video_format_table[i].fourcc == fourcc)
			format = v4l_gst_video_format_table[i].format;
	}

	return format;
}

const gchar *
fourcc_to_mimetype(guint32 fourcc)
{
	switch(fourcc) {
	case V4L2_PIX_FMT_H264:
		return GST_VIDEO_CODEC_MIME_H264;
	case V4L2_PIX_FMT_VP8:
		return GST_VIDEO_CODEC_MIME_VP8;
	case V4L2_PIX_FMT_HEVC:
		return GST_VIDEO_CODEC_MIME_HEVC;
	default:
		return NULL;
	}
}

void
fourcc_to_string(guint32 fourcc, gchar out[5])
{
	guint32 fourcc_le = GUINT32_TO_LE(fourcc);
	out[0] = (gchar)((fourcc_le >> 0)  & 0xff);
	out[1] = (gchar)((fourcc_le >> 8)  & 0xff);
	out[2] = (gchar)((fourcc_le >> 16) & 0xff);
	out[3] = (gchar)((fourcc_le >> 24) & 0xff);
	out[4] = '\0';
}

const gchar*
v4l2_buffer_type_to_string(guint type)
{
	switch (type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		return "VIDEO_CAPTURE";
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		return "VIDEO_OUTPUT";
	case V4L2_BUF_TYPE_VIDEO_OVERLAY:
		return "VIDEO_OVERLAY";
	case V4L2_BUF_TYPE_VBI_CAPTURE:
		return "VBI_CAPTURE";
	case V4L2_BUF_TYPE_VBI_OUTPUT:
		return "VBI_OUTPUT";
	case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
		return "SLICED_VBI_CAPTURE";
	case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
		return "SLICED_VBI_OUTPUT";
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
		return "VIDEO_OUTPUT_OVERLAY";
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		return "VIDEO_CAPTURE_MPLANE";
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		return "VIDEO_OUTPUT_MPLANE";
	case V4L2_BUF_TYPE_SDR_CAPTURE:
		return "SDR_CAPTURE";
	case V4L2_BUF_TYPE_SDR_OUTPUT:
		return "SDR_OUTPUT";
	case V4L2_BUF_TYPE_META_CAPTURE:
		return "META_CAPTURE";
	case V4L2_BUF_TYPE_META_OUTPUT:
		return "META_OUTPUT";
	default:
		return NULL;
	}
}

const gchar*
v4l2_event_type_to_string(guint type)
{
	switch (type) {
	case V4L2_EVENT_ALL:
		return "V4L2_EVENT_ALL";
	case V4L2_EVENT_VSYNC:
		return "V4L2_EVENT_SYNC";
	case V4L2_EVENT_EOS:
		return "V4L2_EVENT_EOS";
	case V4L2_EVENT_CTRL:
		return "V4L2_EVENT_CTRL";
	case V4L2_EVENT_FRAME_SYNC:
		return "V4L2_EVENT_FRAME_SYNC";
	case V4L2_EVENT_SOURCE_CHANGE:
		return "V4L2_EVENT_SOURCE_CHANGE";
	case V4L2_EVENT_MOTION_DET:
		return "V4L2_EVENT_SOURCE_DET";
	case V4L2_EVENT_PRIVATE_START:
		return "V4L2_EVENT_PRIVATE_START";
	default:
		return NULL;
	}
}
