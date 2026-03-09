/*
 * Copyright (C) 2015 Renesas Electronics Corporation
 * Copyright (C) 2024-2026 ClearCode Inc.
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
#define GST_VIDEO_CODEC_MIME_HEVC "video/x-h265"

typedef enum {
	FRAME_CHECK_NONE,
	FRAME_CHECK_LIGHT,
	FRAME_CHECK_FULL
} FrameCheckType;

guint32		fourcc_from_gst_video_format	(GstVideoFormat fmt);
GstVideoFormat	fourcc_to_gst_video_format	(guint32 fourcc);
const gchar*	fourcc_to_mimetype		(guint32 fourcc);
guint32		fourcc_from_string		(gchar *fourcc_str);
void		fourcc_to_string		(guint32 fourcc,
						 gchar out[5]);
const gchar*	v4l2_buffer_type_to_string	(guint type);
const gchar*	v4l2_event_type_to_string	(guint type);
void		dmabuf_sync_start		(int fd);
void		dmabuf_sync_end			(int fd);
guint32		crc32_calc			(const void *data,
						 size_t len);
guint32		crc32_sampled			(const guint8 *data,
						 size_t len);
guint32		frame_crc32			(GstBuffer *gstbuf,
						 FrameCheckType type);

#endif /* __UTILS_H__ */
