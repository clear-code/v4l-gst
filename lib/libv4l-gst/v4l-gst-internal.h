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

#ifndef __V4L_GST_INTERNAL_H__
#define __V4L_GST_INTERNAL_H__

#include <linux/videodev2.h>

#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <gst/video/video-info.h>

#include "evfd-ctrl.h"
#include "libv4l-gst-bufferpool.h"
#include "utils.h"

#define DEF_CAP_MIN_BUFFERS		2
#define INPUT_BUFFERING_CNT		16 // must be <= VIDEO_MAX_FRAME
#define INITIAL_BUFFER_WAIT_TIMEOUT	(10 * G_TIME_SPAN_SECOND)

#define FMTDESC_NAME_LENGTH		32  // The same size as defined in the V4L2 spec

enum buffer_state {
	V4L_GST_BUFFER_QUEUED,
	V4L_GST_BUFFER_DEQUEUED,
};

struct v4l_gst;

struct v4l_gst_buffer {
	GstBuffer *gstbuf;
	GstMapInfo info;
	GstMapFlags flags;
	struct v4l2_plane planes[GST_VIDEO_MAX_PLANES];
	struct v4l_gst *priv;
	enum buffer_state state;
	int plane0_fd; /* See reindex_buffers() */
};

struct fmt {
	guint fourcc;
	gchar desc[FMTDESC_NAME_LENGTH];
};

/*
 * Kind of media carried by the buffers of one M2M stream direction:
 *
 *  - V4L_GST_MEDIA_KIND_CODEC: compressed bitstream (H.264, HEVC, ...)
 *  - V4L_GST_MEDIA_KIND_RAW  : uncompressed video frames (NV12, ...)
 *
 * A decoder has OUTPUT = CODEC and CAPTURE = RAW,
 * an encoder has OUTPUT = RAW and CAPTURE = CODEC.
 */
enum v4l_gst_media_kind {
	V4L_GST_MEDIA_KIND_CODEC,
	V4L_GST_MEDIA_KIND_RAW,
};

/*
 * State of one M2M stream direction (OUTPUT or CAPTURE).
 */
struct v4l_gst_stream {
	enum v4l2_buf_type buf_type;
	enum v4l_gst_media_kind kind;

	struct v4l2_pix_format_mplane fmt;
	GArray *supported_fmts; /* struct fmt */

	GstBufferPool *pool;
	struct v4l_gst_buffer *buffers;
	gint buffers_num;
	GQueue *gstbufs_queue; /* GstBuffer */

	gint cnt;
	gint returned_cnt;

	/* Used by the RAW stream (decoder CAPTURE) to wait for the
	   requested number of buffers to be set in pad_probe_query() */
	GMutex reqbuf_mutex;
	GCond reqbuf_cond;
	gboolean cancel_reqbuf_wait;
	int fmt_acquirable;
};

typedef enum {
	EOS_NONE,
	EOS_WAITING_DECODE,
	EOS_GOT
} EOSState;

struct v4l_gst {
	int plugin_fd;
	gboolean is_non_blocking;
	struct event_state *event_state;

	GstElement *pipeline;
	GstElement *appsrc;
	GstElement *appsink;
	GstElement *decoder;
	GstPad *video_sink_pad;

	GstVideoInfo src_video_info;

	GstAppSinkCallbacks appsink_cb;
	gulong probe_id;
	gulong decoder_probe_id;

	void *pool_lib_handle;
	struct libv4l_gst_buffer_pool_ops *pool_ops;

	/*
	 *  out (OUTPUT) : Application --> v4l-gst
	 *  cap (CAPTURE): Application <-- v4l-gst
	 *
	 *  decoder: out.kind = CODEC (e.g. H.264), cap.kind = RAW (e.g. NV12)
	 *  encoder: out.kind = RAW (e.g. NV12),  cap.kind = CODEC (e.g. H.264)
	 */
	struct v4l_gst_stream out;
	struct v4l_gst_stream cap;

	int64_t mmap_offset;

	GMutex queue_mutex;
	GCond queue_cond;

	gboolean is_pipeline_started;

	GstBuffer *eos_gstbuf;
	EOSState eos_state;
	GstClockTime last_cap_pts;
	GstClockTime estimated_cap_duration;

	struct {
		gint cap_min_buffers;
		gint max_width;
		gint max_height;
		guint32 preferred_format;
		guint32 fixed_pipeline;
		GHashTable *pipelines; /* gchar *fourcc, gchar *pipeline */
		gchar *pool_lib_path;
		FrameCheckType frame_check;
	} config;

	struct {
		GMutex mutex;
		gint subscribed;
		guint32 sequence;
		GQueue *queue;
	} v4l2events;

	GMutex dev_lock;
};

#endif /* __V4L_GST_INTERNAL_H__ */
