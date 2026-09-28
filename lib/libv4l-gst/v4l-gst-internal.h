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

/* Debug categories (defined in v4l-gst-core.c) */
extern GstDebugCategory *v4l_gst_debug_category;
extern GstDebugCategory *v4l_gst_ioctl_debug_category;
extern GstDebugCategory *v4l_gst_buffer_debug_category;
#define GST_CAT_DEFAULT v4l_gst_debug_category

GQuark cap_buf_crc_quark(void);

/*
 * Functions shared between the v4l-gst-*.c translation units,
 * grouped by domain.
 */

/* core */
GstElement *v4l_gst_core_create_pipeline(const gchar *pipeline_str);
GstElement *v4l_gst_core_get_peer_element(GstElement *elem,
					  const gchar *pad_name);
gboolean v4l_gst_core_init_pipeline(struct v4l_gst *priv, guint32 fourcc);
void v4l_gst_core_push_source_change_event(struct v4l_gst *priv);
void v4l_gst_core_reset_cap_timestamp_state(struct v4l_gst *priv);
void v4l_gst_core_set_pipeline_started(struct v4l_gst *priv, gboolean started);

/* pipeline */
GstCaps *v4l_gst_pipeline_get_codec_caps_from_fourcc(guint fourcc);
gboolean v4l_gst_pipeline_get_raw_video_params(GstBufferPool *pool,
					       GstBuffer *gstbuf,
					       GstVideoInfo *info,
					       GstVideoMeta **meta);
void v4l_gst_pipeline_get_buffer_pool_params(GstBufferPool *pool,
					     GstCaps **caps,
					     guint *buf_size,
					     guint *min_buffers,
					     guint *max_buffers);
int v4l_gst_pipeline_flush(struct v4l_gst *priv);
gboolean v4l_gst_pipeline_set_out_format(struct v4l_gst *priv);
gboolean v4l_gst_pipeline_set_cap_format(struct v4l_gst *priv);
void v4l_gst_pipeline_set_buffer_pool_params(GstBufferPool *pool,
					     GstCaps *caps,
					     guint buf_size,
					     guint min_buffers,
					     guint max_buffers,
					     GstVideoAlignment *alignment);
gboolean v4l_gst_pipeline_setup_app_elements(struct v4l_gst *priv);
gulong v4l_gst_pipeline_setup_query_pad_probe(struct v4l_gst *priv);
int v4l_gst_pipeline_stop(struct v4l_gst *priv);

/* fmt */
void v4l_gst_fmt_init_decoded_frame_params(struct v4l2_pix_format_mplane *pix_fmt);

/* buf */
void v4l_gst_buf_release_out_buffer(struct v4l_gst *priv, GstBuffer *gstbuf);

#endif /* __V4L_GST_INTERNAL_H__ */
