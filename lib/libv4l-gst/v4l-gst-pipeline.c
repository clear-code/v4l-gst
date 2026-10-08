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

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gst/video/video.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <gst/allocators/gstdmabuf.h>

#include "libv4l-gst-bufferpool.h"

#include "v4l-gst.h"
#include "evfd-ctrl.h"
#include "debug.h"
#include "utils.h"
#include "v4l-gst-internal.h"

static void
get_cap_buffer_alignment(struct v4l_gst *priv, GstVideoAlignment *alignment)
{
	guint stride_align, i;

	/* In dma-buffer, ARM Mali requires strict allocation alignment for each
	   color format (NV12, NV21, YV12, IYUV, I420, IMC1, IMC2, IMC3, IMC4,
	   P210, P010 require 16-byte alignment. Others require 64-byte alignment)
	   refs:
	   https://github.com/renesas-rz/gst-plugins-bad/commit/728304b71301f909142bd2d29099a8fc370e5e25
	   https://github.com/renesas-rz/gst-plugins-bad/commit/79f3733bb085d07a78e996bf8d935ad31d43c7b1
	   https://github.com/renesas-rz/gst-plugins-bad/commit/e07995fa6e7c24868008826f177d9eaf9c1f88e1

	   GstVideoAlignment::stride_align is a bitmask, not an alignment value.
	   It must be specified as a bitmask of the form (2^n - 1).
	   gst_video_info_align_full() checks alignment using:

	     (stride & stride_align) == 0

	   e.g.)
	     16-byte alignment -> 15 (0b1111)
	     64-byte alignment -> 63 (0b111111) */
	switch (priv->cap.fmt.pixelformat) {
	case V4L2_PIX_FMT_NV12:
	case V4L2_PIX_FMT_NV21:
	case V4L2_PIX_FMT_YVU420:
	case V4L2_PIX_FMT_YUV420:
#ifdef V4L2_PIX_FMT_P010
	case V4L2_PIX_FMT_P010:
#endif
		stride_align = 15;
		break;
	default:
		stride_align = 63;
		break;
	}

	gst_video_alignment_reset(alignment);
	for (i = 0; i < priv->cap.fmt.num_planes; i++)
		alignment->stride_align[i] = stride_align;
}


void
v4l_gst_pipeline_set_buffer_pool_params(GstBufferPool *pool, GstCaps *caps, guint buf_size,
		       guint min_buffers, guint max_buffers,
		       GstVideoAlignment *alignment)
{
	GstStructure *config;

	config = gst_buffer_pool_get_config(pool);
	gst_buffer_pool_config_set_params(config, caps, buf_size, min_buffers,
					  max_buffers);
	if (alignment) {
		gst_buffer_pool_config_add_option
			(config, GST_BUFFER_POOL_OPTION_VIDEO_ALIGNMENT);
		gst_buffer_pool_config_set_video_alignment(config, alignment);
	}
	gst_buffer_pool_set_config(pool, config);
}


void
v4l_gst_pipeline_get_buffer_pool_params(GstBufferPool *pool, GstCaps **caps, guint *buf_size,
		       guint *min_buffers, guint *max_buffers)
{
	GstStructure *config;

	config = gst_buffer_pool_get_config(pool);
	gst_buffer_pool_config_get_params(config, caps, buf_size, min_buffers,
					  max_buffers);
	gst_structure_free(config);
}


static void
retrieve_cap_format_info(struct v4l_gst *priv, GstVideoInfo *info)
{
	gint fourcc;

	priv->cap.fmt.width = info->width;
	priv->cap.fmt.height = info->height;

	fourcc = fourcc_from_gst_video_format(info->finfo->format);
	if (priv->cap.fmt.pixelformat != 0 &&
	    priv->cap.fmt.pixelformat != fourcc) {
		GST_WARNING("Unexpected cap video format");
	}
	priv->cap.fmt.pixelformat = fourcc;

	priv->cap.fmt.num_planes = info->finfo->n_planes;
}


static gboolean
wait_for_cap_reqbuf_invocation(struct v4l_gst *priv)
{
	gboolean succeeded;
	gboolean timed_out = FALSE;
	gint64 end_time;

	g_mutex_lock(&priv->cap.reqbuf_mutex);
	end_time = g_get_monotonic_time() + INITIAL_BUFFER_WAIT_TIMEOUT;
	while (!priv->cap.cancel_reqbuf_wait && priv->cap.buffers_num <= 0) {
		if (!g_cond_wait_until(&priv->cap.reqbuf_cond,
				       &priv->cap.reqbuf_mutex,
				       end_time)) {
			timed_out = TRUE;
			break;
		}
	}
	succeeded = !priv->cap.cancel_reqbuf_wait && priv->cap.buffers_num > 0;
	g_mutex_unlock(&priv->cap.reqbuf_mutex);

	if (timed_out && !succeeded)
		GST_WARNING("Timed out waiting VIDIOC_REQBUFS on CAPTURE.");

	return succeeded;
}


static GstPadProbeReturn
pad_probe_query(GstPad *pad, GstPadProbeInfo *probe_info, gpointer user_data)
{
	struct v4l_gst *priv = user_data;
	GstQuery *query;
	GstCaps *caps;
	GstVideoInfo info;
	guint src_width = priv->src_video_info.width;
	guint src_height = priv->src_video_info.height;
	GstVideoAlignment alignment;

	query = GST_PAD_PROBE_INFO_QUERY (probe_info);
	if (GST_QUERY_TYPE (query) == GST_QUERY_ALLOCATION &&
	    GST_PAD_PROBE_INFO_TYPE (probe_info) & GST_PAD_PROBE_TYPE_PUSH) {
		GST_DEBUG("parse allocation query");
		gst_query_parse_allocation(query, &caps, NULL);
		if (!caps) {
			GST_ERROR("No caps in query");
			return GST_PAD_PROBE_OK;
		}

		if (priv->cap.kind == V4L_GST_MEDIA_KIND_CODEC) {
			/* Encoded stream on CAPTURE: the caps are codec caps
			   which do not carry an allocatable size, so use the
			   sizeimage specified via VIDIOC_S_FMT on CAPTURE. No
			   video meta or alignment is required for an encoded
			   stream. */
			guint buf_size = priv->cap.fmt.plane_fmt[0].sizeimage;

			g_atomic_int_set(&priv->cap.fmt_acquirable, 1);
			v4l_gst_core_push_source_change_event(priv);

			set_event(priv->event_state, POLLOUT);

			if (wait_for_cap_reqbuf_invocation(priv)) {
				v4l_gst_pipeline_set_buffer_pool_params(
						priv->cap.pool, caps,
						buf_size, 0,
						priv->cap.buffers_num, NULL);
				gst_query_add_allocation_pool(query,
						priv->cap.pool, buf_size,
						0, priv->cap.buffers_num);
			} else {
				GST_WARNING("Failed to wait VIDIOC_REQBUF.");
			}

			return GST_PAD_PROBE_OK;
		}

		if (!gst_video_info_from_caps(&info, caps)) {
			GST_ERROR("Failed to get video info");
			return GST_PAD_PROBE_OK;
		}

		if ((src_width  && src_width  != info.width) ||
		    (src_height && src_height != info.height)) {
			/* Sometimes decoder may send interim resolutions that
			   differ from the original one (typically 16x16
			   macroblock based one: e.g. 640x368 vs 640x360) before
			   sending the final resolution.
			   Skip such interim resolutions then wait for the original one.
			*/
			return GST_PAD_PROBE_OK;
		}

		retrieve_cap_format_info(priv, &info);
		get_cap_buffer_alignment(priv, &alignment);
		g_atomic_int_set(&priv->cap.fmt_acquirable, 1);
		v4l_gst_core_push_source_change_event(priv);

		set_event(priv->event_state, POLLOUT);

		/* Even if a min value is set here, omxvideodec will reset it
		   with an internally calculated value. It's at least 4 and
		   possible to become larger than max. When it's calculated as
		   larger than max, bufferpool will fail to allocate.
		   To ensure to avoid it, we set the smallest possible value 0
		   here.
		   ref: https://github.com/renesas-rcar/gst-omx/blob/37296f66e3392d8dcdcdae14b89b05dd7507dc39/omx/gstomxvideodec.c#L920

		   On RZ/G2, you can use `num-outbufs` property of omxvideodec
		   to override it.
		   e.g.)
		   `pipeline=h264parse ! omxh264dec no-reorder=true num-outbufs=7`
		*/
		if (wait_for_cap_reqbuf_invocation(priv)) {
			v4l_gst_pipeline_set_buffer_pool_params(priv->cap.pool, caps, info.size,
					       0, priv->cap.buffers_num,
					       &alignment);
			gst_query_add_allocation_pool(query, priv->cap.pool,
						      info.size,
						      0, priv->cap.buffers_num);
		} else {
			GST_WARNING("Failed to wait VIDIOC_REQBUF.");
		}
	}

	return GST_PAD_PROBE_OK;
}


static void
appsink_pad_unlinked_cb(GstPad *self, GstPad *peer, gpointer data)
{
	struct v4l_gst *priv = data;

	GST_DEBUG("clear probe_id");
	priv->probe_id = 0;

	g_signal_handlers_disconnect_by_func(self, appsink_pad_unlinked_cb, data);
}


static GstPadProbeReturn
decoder_sink_pad_probe(GstPad *pad, GstPadProbeInfo *probe_info, gpointer user_data)
{
	struct v4l_gst *priv = user_data;
	GstPadProbeType type = GST_PAD_PROBE_INFO_TYPE(probe_info);
	GstEvent *event;
	GstCaps *caps = NULL;

	if (!(type & GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM))
		return GST_PAD_PROBE_OK;

	event = GST_PAD_PROBE_INFO_EVENT(probe_info);
	if (GST_EVENT_TYPE(event) != GST_EVENT_CAPS)
		return GST_PAD_PROBE_OK;

	gst_event_parse_caps(event, &caps);
	if (!caps)
		return GST_PAD_PROBE_OK;

	if (!gst_video_info_from_caps(&priv->src_video_info, caps))
		return GST_PAD_PROBE_OK;

	GST_DEBUG("Source video info: %" GST_PTR_FORMAT, caps);

	return GST_PAD_PROBE_OK;
}


static void
decoder_pad_unlinked_cb(GstPad *self, GstPad *peer, gpointer data)
{
	struct v4l_gst *priv = data;

	GST_DEBUG("clear decoder_probe_id");
	priv->decoder_probe_id = 0;
	g_signal_handlers_disconnect_by_func(self, decoder_pad_unlinked_cb, data);
}


gulong
v4l_gst_pipeline_setup_query_pad_probe(struct v4l_gst *priv)
{
	gulong probe_id;

	g_signal_connect(G_OBJECT(priv->video_sink_pad), "unlinked",
			 G_CALLBACK(appsink_pad_unlinked_cb), priv);
	probe_id = gst_pad_add_probe(priv->video_sink_pad,
				     GST_PAD_PROBE_TYPE_QUERY_DOWNSTREAM,
				     pad_probe_query,
				     priv, NULL);

	return probe_id;
}


static GstBuffer *
pull_buffer_from_sample(GstAppSink *appsink)
{
	GstSample *sample;
	GstBuffer *gstbuf;

	sample = gst_app_sink_pull_sample(appsink);
	gstbuf = gst_sample_get_buffer(sample);
	gst_buffer_ref(gstbuf);
	gst_sample_unref(sample);

	return gstbuf;
}


static void
appsink_callback_eos(GstAppSink *appsink, gpointer user_data)
{
	struct v4l_gst *priv = user_data;
	if (priv->eos_gstbuf)
		v4l_gst_buf_release_out_buffer(priv, priv->eos_gstbuf);
	g_mutex_lock(&priv->queue_mutex);
	GST_DEBUG("EOS: Got from AppSink. Cached buffers: %u",
		  g_queue_get_length(priv->cap.gstbufs_queue));
	priv->eos_state = EOS_GOT;
	if (priv->cap.gstbufs_queue &&
	    !g_queue_is_empty(priv->cap.gstbufs_queue)) {
		set_event(priv->event_state, POLLOUT);
	}
	g_mutex_unlock(&priv->queue_mutex);
}


static GstFlowReturn
appsink_callback_new_sample(GstAppSink *appsink, gpointer user_data)
{
	struct v4l_gst *priv = user_data;
	GstBuffer *gstbuf;
	guint len;
	GQueue *queue;

	gstbuf = pull_buffer_from_sample(appsink);

	if (priv->cap.buffers && !gst_buffer_n_memory(gstbuf)) {
		/* Empty samples cannot be associated with a V4L2 CAPTURE
		   buffer or dmabuf fd, so do not expose them to clients. */
		GST_WARNING("Drop empty CAPTURE sample: gstbuf=%p, pts=%"
			    G_GUINT64_FORMAT ", duration=%" G_GUINT64_FORMAT,
			    gstbuf, (guint64) GST_BUFFER_PTS(gstbuf),
			    (guint64) GST_BUFFER_DURATION(gstbuf));
		gst_buffer_unref(gstbuf);
		return GST_FLOW_OK;
	}

	if (priv->config.frame_check && gst_buffer_n_memory(gstbuf)) {
		guint32 crc;

		crc = frame_crc32(gstbuf, priv->config.frame_check);
		gst_mini_object_set_qdata(GST_MINI_OBJECT(gstbuf),
					  cap_buf_crc_quark(),
					  GUINT_TO_POINTER(crc),
					  NULL);
		GST_CAT_DEBUG(v4l_gst_buffer_debug_category,
			      "pull buffer from appsink:"
			      " gstbuf=%p, pts=%lu, crc=%u",
			      gstbuf, GST_BUFFER_PTS(gstbuf) / 1000000, crc);
	} else {
		GST_CAT_DEBUG(v4l_gst_buffer_debug_category,
			      "pull buffer from appsink: gstbuf=%p, pts=%lu",
			      gstbuf, GST_BUFFER_PTS(gstbuf) / 1000000);
	}

	if (priv->cap.buffers)
		queue = priv->cap.gstbufs_queue;
	else
		queue = priv->out.gstbufs_queue;

	g_mutex_lock(&priv->queue_mutex);

	g_queue_push_tail(queue, gstbuf);
	len = g_queue_get_length(queue);

	if (len > 1 || priv->eos_state == EOS_GOT) {
		/* cache 1 buffer to detect EOS */
		if (len == 0 && priv->eos_state == EOS_GOT)
			GST_DEBUG("EOS: Flush last frame");
		g_cond_signal(&priv->queue_cond);
		set_event(priv->event_state, POLLOUT);
	} else if (!priv->cap.buffers) {
		g_cond_signal(&priv->queue_cond);
	}

	g_mutex_unlock(&priv->queue_mutex);

	return GST_FLOW_OK;
}


gboolean
v4l_gst_pipeline_setup_app_elements(struct v4l_gst *priv)
{
	/* Set the appsrc queue size to unlimited.
	   The amount of buffers is managed by the buffer pool. */
	gst_app_src_set_max_bytes(GST_APP_SRC(priv->appsrc), 0);

	/* Video frames are timestamped in time, not bytes. The appsrc
	   "format" property drives the segment format (gst_app_src_start
	   copies it into the base src), and do-timestamp assigns PTS/DTS
	   from the caps framerate since the wrapped buffers carry no PTS. */
	g_object_set(G_OBJECT(priv->appsrc), "format", GST_FORMAT_TIME,
		     "do-timestamp", TRUE, NULL);

	gst_base_sink_set_sync(GST_BASE_SINK(priv->appsink), FALSE);

	priv->appsink_cb.new_sample = appsink_callback_new_sample;
	priv->appsink_cb.eos = appsink_callback_eos;

	gst_app_sink_set_callbacks(GST_APP_SINK(priv->appsink),
				   &priv->appsink_cb, priv, NULL);

	if (priv->decoder) {
		GstPad *pad = gst_element_get_static_pad(priv->decoder, "sink");

		g_signal_connect(G_OBJECT(pad), "unlinked",
				 G_CALLBACK(decoder_pad_unlinked_cb), priv);
		priv->decoder_probe_id
			= gst_pad_add_probe(pad,
					    GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM,
					    decoder_sink_pad_probe,
					    priv, NULL);
		gst_object_unref(pad);
	}

	return TRUE;
}


gboolean
v4l_gst_pipeline_get_raw_video_params(GstBufferPool *pool, GstBuffer *gstbuf, GstVideoInfo *info,
		     GstVideoMeta **meta)
{
	gboolean ret;
	GstCaps *caps;
	GstVideoInfo vinfo;
	GstVideoMeta *vmeta;

	v4l_gst_pipeline_get_buffer_pool_params(pool, &caps, NULL, NULL, NULL);

	ret = gst_video_info_from_caps(&vinfo, caps);
	if (!ret || GST_VIDEO_INFO_FORMAT(&vinfo) == GST_VIDEO_FORMAT_ENCODED)
		return FALSE;

	vmeta = gst_buffer_get_video_meta(gstbuf);

	if (info)
		memcpy(info, &vinfo, sizeof(GstVideoInfo));
	if (meta)
		*meta = vmeta;

	return TRUE;
}


GstCaps *
v4l_gst_pipeline_get_codec_caps_from_fourcc(guint fourcc)
{
	const gchar *mime;

	mime = fourcc_to_mimetype(fourcc);
	if (!mime) {
		gchar fourcc_str[5];
		fourcc_to_string(fourcc, fourcc_str);
		GST_ERROR("Failed to convert from fourcc to mime string: %u (\"%s\")",
			  fourcc, fourcc_str);
		return NULL;
	}

	if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_H264) == 0 ||
	    g_strcmp0(mime, GST_VIDEO_CODEC_MIME_HEVC) == 0) {
		return gst_caps_new_simple(mime, "stream-format",
					   G_TYPE_STRING, "byte-stream", NULL);
	}

	return gst_caps_new_empty_simple(mime);
}


GstCaps *
v4l_gst_pipeline_get_raw_caps_from_fmt(struct v4l2_pix_format_mplane *fmt)
{
	GstVideoFormat gst_fmt;
	const gchar *fmt_str;

	gst_fmt = fourcc_to_gst_video_format(fmt->pixelformat);
	if (gst_fmt == GST_VIDEO_FORMAT_UNKNOWN) {
		gchar fourcc_str[5];
		fourcc_to_string(fmt->pixelformat, fourcc_str);
		GST_ERROR("Failed to convert from fourcc to gst video format: %s (0x%x)",
			  fourcc_str, fmt->pixelformat);
		return NULL;
	}

	fmt_str = gst_video_format_to_string(gst_fmt);

	/* Provide a framerate so the appsrc can auto-timestamp the
	   wrapped input buffers, which carry no PTS of their own. */
	return gst_caps_new_simple("video/x-raw",
				   "format", G_TYPE_STRING, fmt_str,
				   "width", G_TYPE_INT, (gint) fmt->width,
				   "height", G_TYPE_INT, (gint) fmt->height,
				   "framerate", GST_TYPE_FRACTION, 30, 1,
				   NULL);
}


int
v4l_gst_pipeline_flush(struct v4l_gst *priv)
{
	GstEvent *event;

	GST_DEBUG("flush start");

	gst_buffer_pool_set_flushing(priv->out.pool, TRUE);
	gst_buffer_pool_set_flushing(priv->cap.pool, TRUE);

	event = gst_event_new_flush_start();
	if (!gst_element_send_event(priv->pipeline, event)) {
		GST_ERROR("Failed to send a flush start event");
		errno = EINVAL;
		return -1;
	}

	GST_DEBUG("flush stop ...");

	event = gst_event_new_flush_stop(TRUE);
	if (!gst_element_send_event(priv->pipeline, event)) {
		GST_ERROR("Failed to send a flush stop event");
		errno = EINVAL;
		return -1;
	}

	gst_buffer_pool_set_flushing(priv->out.pool, FALSE);
	gst_buffer_pool_set_flushing(priv->cap.pool, FALSE);

	GST_DEBUG("flush end");

	return 0;
}


int
v4l_gst_pipeline_stop(struct v4l_gst *priv)
{
	GstStateChangeReturn state_ret;
	int ret = 0;
	gint i;

	GST_DEBUG("req->count == 0, stop the pipeline");

	v4l_gst_core_set_pipeline_started(priv, FALSE);

	state_ret = gst_element_set_state(priv->pipeline,
					  GST_STATE_NULL);
	while (state_ret == GST_STATE_CHANGE_ASYNC) {
		/* This API blocks up to the ASYNC state change completion. */
		g_mutex_unlock(&priv->dev_lock);
		state_ret = gst_element_get_state(priv->pipeline, NULL,
						  NULL,
						  GST_CLOCK_TIME_NONE);
		g_mutex_lock(&priv->dev_lock);
	}

	if (state_ret != GST_STATE_CHANGE_SUCCESS) {
		GST_ERROR("Failed to stop pipeline (ret:%s)",
			  gst_element_state_change_return_get_name(state_ret));
		errno = EINVAL;
		ret = -1;
		return ret;
	}

	g_atomic_int_set(&priv->cap.fmt_acquirable, 0);

	/* The appsrc queue is flushed when the pipeline goes to NULL, so the
	   OUTPUT caps must be re-pushed before the next first buffer. */
	priv->out_caps_set = FALSE;

	for (i = 0; i < priv->cap.buffers_num; i++) {
		if (priv->cap.buffers[i].state ==
		    V4L_GST_BUFFER_DEQUEUED) {
			gst_buffer_unref(priv->cap.buffers[i].gstbuf);
		}
	}

	g_queue_clear(priv->out.gstbufs_queue);
	g_queue_clear(priv->cap.gstbufs_queue);
	v4l_gst_core_reset_cap_timestamp_state(priv);

	v4l_gst_core_set_pipeline_started(priv, FALSE);

	if (priv->cap.buffers) {
		g_free(priv->cap.buffers);
		priv->cap.buffers = NULL;
	}
	priv->cap.buffers_num = 0;
	v4l_gst_fmt_init_decoded_frame_params(&priv->cap.fmt);

	return ret;
}


static gboolean
relink_elements_with_caps_filtered(GstElement *src_elem, GstElement *dest_elem,
				   GstCaps *caps)
{
	gst_element_unlink(src_elem, dest_elem);
	return gst_element_link_filtered(src_elem, dest_elem, caps);
}


gboolean
v4l_gst_pipeline_set_out_format(struct v4l_gst *priv)
{
	GstCaps *caps;

	if (priv->out.kind == V4L_GST_MEDIA_KIND_RAW)
		caps = v4l_gst_pipeline_get_raw_caps_from_fmt(&priv->out.fmt);
	else
		caps = v4l_gst_pipeline_get_codec_caps_from_fourcc(
				priv->out.fmt.pixelformat);
	if (!caps) {
		errno = EINVAL;
		return FALSE;
	}

	gst_app_src_set_caps(GST_APP_SRC(priv->appsrc), caps);
	gst_caps_unref(caps);

	return TRUE;
}


gboolean
v4l_gst_pipeline_set_cap_format(struct v4l_gst *priv)
{
	GstElement *peer_elem;
	GstCaps *caps;
	gboolean ret;

	if (priv->cap.kind == V4L_GST_MEDIA_KIND_CODEC) {
		caps = v4l_gst_pipeline_get_codec_caps_from_fourcc(
				priv->cap.fmt.pixelformat);
	} else {
		GstVideoFormat fmt;

		fmt = fourcc_to_gst_video_format(priv->cap.fmt.pixelformat);
		if (fmt == GST_VIDEO_FORMAT_UNKNOWN) {
			gchar fourcc_str[5];
			fourcc_to_string(priv->cap.fmt.pixelformat, fourcc_str);
			GST_ERROR("Invalid format on CAPTURE: %s (0x%x)",
				  fourcc_str, priv->cap.fmt.pixelformat);
			errno = EINVAL;
			return FALSE;
		}

		caps = gst_caps_new_simple("video/x-raw", "format",
					   G_TYPE_STRING,
					   gst_video_format_to_string(fmt),
					   NULL);
	}

	if (!caps) {
		errno = EINVAL;
		return FALSE;
	}

	peer_elem = v4l_gst_core_get_peer_element(priv->appsink, "sink");
	if (!relink_elements_with_caps_filtered(peer_elem, priv->appsink,
						caps)) {
		GST_ERROR("Failed to relink elements with "
			  "the CAPTURE setting (caps=%s)",
			  gst_caps_to_string(caps));
		errno = EINVAL;
		ret = FALSE;
		goto free_objects;
	}
	GST_DEBUG("appsink element is relinked");

	ret = TRUE;

 free_objects:
	gst_caps_unref(caps);
	gst_object_unref(peer_elem);

	return ret;
}



#if 0
static int
set_decoder_cmd_state(struct v4l_gst *priv, GstState state)
{
	int ret = 0;
	GstStateChangeReturn state_ret;
	g_mutex_lock(&priv->dev_lock);

	switch (state) {
	case GST_STATE_PAUSED:
		ret = gst_element_set_state(priv->pipeline, state);
		while (state_ret == GST_STATE_CHANGE_ASYNC) {
			/* This API blocks up to the ASYNC state change completion. */
			g_mutex_unlock(&priv->dev_lock);
			state_ret = gst_element_get_state(priv->pipeline, NULL,
							  NULL,
							  GST_CLOCK_TIME_NONE);
			g_mutex_lock(&priv->dev_lock);
		}

		if (state_ret != GST_STATE_CHANGE_SUCCESS) {
			GST_ERROR("Failed to stop pipeline (ret:%s)",
				  gst_element_state_change_return_get_name(state_ret));
			errno = EINVAL;
			ret = -1;
		}
		g_mutex_unlock(&priv->dev_lock);
	default:
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category,
			      "unsupported GstState to set %s",
			      gst_element_state_get_name(state));
		break;
	}
	return ret;
}


#endif
int
v4l_gst_ioctl_try_decoder_cmd(struct v4l_gst *priv,
		      struct v4l2_decoder_cmd *decoder_cmd)
{
	int ret = 0;

	switch (decoder_cmd->cmd) {
	case V4L2_DEC_CMD_START:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_dec_cmd: V4L2_DEC_CMD_START speed: %d format: %x",
			      decoder_cmd->start.speed, decoder_cmd->start.format);
		break;
	case V4L2_DEC_CMD_STOP:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_dec_cmd: V4L2_DEC_CMD_STOP pts: %llu",
			      decoder_cmd->stop.pts);
		break;
	case V4L2_DEC_CMD_PAUSE:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_dec_cmd: V4L2_DEC_CMD_PAUSE");
		break;
	case V4L2_DEC_CMD_RESUME:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_dec_cmd: V4L2_DEC_CMD_RESUME");
		break;
	case V4L2_DEC_CMD_FLUSH:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_dec_cmd: V4L2_DEC_CMD_FLUSH");
		break;
	default:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "unsupported v4l2_decoder_cmd cmd: 0x%x",
			      decoder_cmd->cmd);
		errno = EINVAL;
		ret = -1;
		break;
	}
	return ret;
}


int
v4l_gst_ioctl_decoder_cmd(struct v4l_gst *priv, struct v4l2_decoder_cmd *decoder_cmd)
{
	int ret = 0;

	g_mutex_lock(&priv->dev_lock);

	switch (decoder_cmd->cmd) {
	case V4L2_DEC_CMD_START:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_decoder_cmd: V4L2_DEC_CMD_START "
			      "speed: %d format: %x",
			      decoder_cmd->start.speed,
			      decoder_cmd->start.format);
		break;
	case V4L2_DEC_CMD_STOP:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_decoder_cmd: V4L2_DEC_CMD_STOP pts: %llu",
			      decoder_cmd->stop.pts);
		/* Clients send this command after queueing the last incoming
		   buffer. To detect the last decoded frame, we need to cache
		   an outgoing buffer and wait EOS event from the pipeline.
		   ref: https://www.kernel.org/doc/html/latest/userspace-api/media/v4l/dev-decoder.html#drain
		*/
		if (priv->eos_state == EOS_NONE) {
			GST_DEBUG("EOS: Send to AppSrc");
			priv->eos_state = EOS_WAITING_DECODE;
			gst_app_src_end_of_stream(GST_APP_SRC(priv->appsrc));
		}
		break;
	case V4L2_DEC_CMD_PAUSE:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_decoder_cmd: V4L2_DEC_CMD_PAUSE");
		break;
	case V4L2_DEC_CMD_RESUME:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_decoder_cmd: V4L2_DEC_CMD_RESUME");
		break;
	case V4L2_DEC_CMD_FLUSH:
		GST_CAT_DEBUG(v4l_gst_ioctl_debug_category,
			      "v4l2_decoder_cmd: V4L2_DEC_CMD_FLUSH");
		break;
	default:
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category,
			      "unsupported VIDIOC_DECODER_CMD "
			      "v4l2_decoder_cmd: cmd: 0x%x flags: 0x%x",
			      decoder_cmd->cmd, decoder_cmd->flags);
		errno = EINVAL;
		ret = -1;
		break;
	}

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}

