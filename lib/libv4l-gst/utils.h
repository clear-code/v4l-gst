/*
 * Copyright (C) 2015 Renesas Electronics Corporation
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

#ifndef __UTILS_H__
#define __UTILS_H__

#include <gst/video/video.h>

#define GST_VIDEO_CODEC_MIME_H264 "video/x-h264"
#define GST_VIDEO_CODEC_MIME_VP8  "video/x-vp8"

guint convert_video_format_gst_to_v4l2(GstVideoFormat fmt);
GstVideoFormat convert_video_format_v4l2_to_gst(guint fourcc);
const gchar* convert_codec_type_v4l2_to_gst(guint fourcc);
void fourcc_to_string(guint32 fourcc, gchar out[5]);
const gchar* buffer_type_to_string(guint type);
const gchar* event_type_to_string(guint type);

#endif /* __UTILS_H__ */
