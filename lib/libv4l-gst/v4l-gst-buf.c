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

static inline void
release_out_buffer_unlocked(struct v4l_gst *priv, GstBuffer *gstbuf)
{
	GST_TRACE("unref buffer: %p", gstbuf);
	gst_buffer_unref(gstbuf);

	set_event(priv->event_state, POLLIN);

	priv->out.returned_cnt++;
}


void
v4l_gst_buf_release_out_buffer(struct v4l_gst *priv, GstBuffer *gstbuf)
{
	g_mutex_lock(&priv->queue_mutex);

	release_out_buffer_unlocked(priv, gstbuf);

	g_mutex_unlock(&priv->queue_mutex);
}


static gboolean
is_supported_memory_io(enum v4l2_memory memory)
{
	if (memory != V4L2_MEMORY_MMAP) {
		GST_ERROR("Only V4L2_MEMORY_MMAP is supported");
		errno = EINVAL;
		return FALSE;
	}

	return TRUE;
}


/* This check passes through the verification of the buffer index. */
static gboolean
check_no_index_v4l2_buffer(struct v4l2_buffer *v4l2buf,
			   struct v4l_gst_buffer *buffers, GstBufferPool *pool)
{
	GstVideoMeta *meta;
	guint n_planes;

	if (!is_supported_memory_io(v4l2buf->memory))
		return FALSE;

	if (!v4l2buf->m.planes) {
		GST_ERROR("This plugin supports only multi-planar "
			  "buffer type, but planes array is not set");
		errno = EINVAL;
		return FALSE;
	}

	if (!buffers) {
		GST_ERROR("Buffers list is not set");
		errno = EINVAL;
		return FALSE;
	}

	if (v4l_gst_pipeline_get_raw_video_params(pool, buffers[v4l2buf->index].gstbuf, NULL,
				 &meta))
		n_planes = meta->n_planes;
	else
		n_planes = 1;

	if (v4l2buf->length < n_planes || v4l2buf->length > VIDEO_MAX_PLANES) {
		GST_ERROR("Incorrect planes array length");
		errno = EINVAL;
		return FALSE;
	}

	return TRUE;
}


static gboolean
check_v4l2_buffer(struct v4l2_buffer *v4l2buf, struct v4l_gst_buffer *buffers,
		  gint buffers_num, GstBufferPool *pool)
{
	if (!check_no_index_v4l2_buffer(v4l2buf, buffers, pool))
		return FALSE;

	if (v4l2buf->index >= buffers_num) {
		GST_ERROR("buffer index is out of range");
		errno = EINVAL;
		return FALSE;
	}

	return TRUE;
}


static void
notify_unref(gpointer data)
{
	struct v4l_gst_buffer *buffer = data;

	v4l_gst_buf_release_out_buffer(buffer->priv, buffer->gstbuf);
}


static int
qbuf_ioctl_out(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	GstFlowReturn flow_ret;
	GstBuffer *wrapped_gstbuf;
	GstMapInfo info;
	struct v4l_gst_buffer *buffer;

	if (!check_v4l2_buffer(v4l2buf, priv->out.buffers, priv->out.buffers_num,
			       priv->out.pool))
		return -1;

	buffer = &priv->out.buffers[v4l2buf->index];

	if (v4l2buf->m.planes[0].bytesused == 0) {
		flow_ret = gst_app_src_end_of_stream(GST_APP_SRC(priv->appsrc));
		if (flow_ret != GST_FLOW_OK) {
			GST_ERROR("Failed to send an EOS event");
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("Send EOS event");

		gst_buffer_unmap(buffer->gstbuf, &buffer->info);
		memset(&buffer->info, 0, sizeof(buffer->info));

		buffer->state = V4L_GST_BUFFER_QUEUED;
		priv->eos_gstbuf = buffer->gstbuf;

		return 0;
	}

	if (buffer->state == V4L_GST_BUFFER_QUEUED) {
		GST_ERROR("Buffer %u is already queued", v4l2buf->index);
		errno = EINVAL;
		return -1;
	}

	GST_TRACE("queue index=%d buffer=%p", v4l2buf->index,
		  priv->out.buffers[v4l2buf->index].gstbuf);

	gst_buffer_unmap(buffer->gstbuf, &buffer->info);
	memset(&buffer->info, 0, sizeof(buffer->info));

	/* Rewrap an input buffer with the just size of bytesused
	   because it will be regarded as having data filled to the entire
	   buffer size internally in the GStreamer pipeline.
	   Also set the destructor (notify_unref()). */

	if (!gst_buffer_map(buffer->gstbuf, &info, GST_MAP_READ)) {
		GST_ERROR("Failed to map buffer (%p)", buffer->gstbuf);
		errno = EINVAL;
		return -1;
	}

	wrapped_gstbuf =
		gst_buffer_new_wrapped_full(GST_MEMORY_FLAG_READONLY, info.data,
					    v4l2buf->m.planes[0].bytesused, 0,
					    v4l2buf->m.planes[0].bytesused,
					    buffer, notify_unref);

	gst_buffer_unmap(buffer->gstbuf, &info);

	GST_BUFFER_PTS(wrapped_gstbuf) = GST_TIMEVAL_TO_TIME(v4l2buf->timestamp);
	GST_CAT_TRACE(v4l_gst_buffer_debug_category,
		      "QBUF OUT: gstbuf=%p, index=%d, pts=%lu",
		      wrapped_gstbuf, v4l2buf->index,
		      GST_BUFFER_PTS(wrapped_gstbuf) / 1000000);

	buffer->state = V4L_GST_BUFFER_QUEUED;

	flow_ret = gst_app_src_push_buffer(GST_APP_SRC(priv->appsrc),
					   wrapped_gstbuf);
	if (flow_ret != GST_FLOW_OK) {
		GST_ERROR("Failed to push a buffer to the pipeline on OUTPUT"
			  "(index=%d)", v4l2buf->index);
		errno = EINVAL;
		return -1;
	}

	if (priv->out.cnt < INPUT_BUFFERING_CNT)
		priv->out.cnt++;

	return 0;
}


static gboolean
push_to_cap_gstbufs_queue(struct v4l_gst *priv, GstBuffer *gstbuf)
{
	gboolean is_empty;
	gint index;

	index = g_queue_index(priv->out.gstbufs_queue, gstbuf);
	if (index < 0)
		return FALSE;

	g_mutex_lock(&priv->queue_mutex);

	is_empty = g_queue_is_empty(priv->cap.gstbufs_queue);
	g_queue_push_tail(priv->cap.gstbufs_queue, gstbuf);

	if (is_empty)
		g_cond_signal(&priv->queue_cond);

	g_mutex_unlock(&priv->queue_mutex);

	g_queue_pop_nth_link(priv->out.gstbufs_queue, index);

	return TRUE;
}


static int
qbuf_ioctl_cap(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	struct v4l_gst_buffer *buffer;

	if (!check_v4l2_buffer(v4l2buf, priv->cap.buffers, priv->cap.buffers_num,
			       priv->cap.pool))
		return -1;

	buffer = &priv->cap.buffers[v4l2buf->index];

	if (priv->config.frame_check && gst_buffer_n_memory(buffer->gstbuf)) {
		gpointer crc_p;
		guint32 crc, crc_dest;

		crc_p = gst_mini_object_get_qdata(GST_MINI_OBJECT(buffer->gstbuf),
						  cap_buf_crc_quark());
		crc = GPOINTER_TO_UINT(crc_p);
		crc_dest = frame_crc32(buffer->gstbuf,
				       priv->config.frame_check);
		GST_CAT_TRACE(v4l_gst_buffer_debug_category,
			      "QBUF CAP: gstbuf=%p, index=%d, pts=%lu, crc=%u",
			      buffer->gstbuf, v4l2buf->index,
			      GST_BUFFER_PTS(buffer->gstbuf) / 1000000, crc);
		if (crc && crc_dest != crc)
			GST_CAT_WARNING(v4l_gst_buffer_debug_category,
					"crc is changed!: src=%u, dest=%u",
					crc, crc_dest);
	} else {
		GST_CAT_TRACE(v4l_gst_buffer_debug_category,
			      "QBUF CAP: gstbuf=%p, index=%d, pts=%lu",
			      buffer->gstbuf, v4l2buf->index,
			      GST_BUFFER_PTS(buffer->gstbuf) / 1000000);
	}

	if (buffer->state == V4L_GST_BUFFER_QUEUED) {
		GST_ERROR("Buffer %u is already queued", v4l2buf->index);
		errno = EINVAL;
		return -1;
	}

	gst_buffer_unmap(buffer->gstbuf, &buffer->info);
	memset(&buffer->info, 0, sizeof(buffer->info));

	/* The buffers in req_gstbufs_queue, which are pushed by the REQBUF ioctl
	   on CAPTURE, have already contained decoded frames.
	   They should not back to the buffer pool and prepare to be
	   dequeued as they are. */
	if (g_queue_get_length(priv->out.gstbufs_queue) > 0) {
		GST_TRACE("push_to_cap_gstbufs_queue index=%d", v4l2buf->index);
		if (push_to_cap_gstbufs_queue(priv, buffer->gstbuf)) {
			buffer->state =V4L_GST_BUFFER_QUEUED;
			return 0;
		}
	}

	GST_TRACE("unref buffer: %p, index=%d", buffer->gstbuf, v4l2buf->index);
	buffer->state = V4L_GST_BUFFER_QUEUED;

	gst_buffer_unref(buffer->gstbuf);

	return 0;
}


int
v4l_gst_qbuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	int ret = -1;

	GST_TRACE("VIDIOC_QBUF: type: %s (0x%x) index: %d flags: 0x%x",
		  v4l2_buffer_type_to_string(v4l2buf->type), v4l2buf->type,
		  v4l2buf->index, v4l2buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = qbuf_ioctl_out(priv, v4l2buf);
	} else if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = qbuf_ioctl_cap(priv, v4l2buf);
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
	}

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}


static inline guint
calc_plane_size(GstVideoInfo *info, GstVideoMeta *meta, gint index)
{
	return meta->stride[index] * GST_VIDEO_INFO_COMP_HEIGHT(info, index);
}


static void
set_v4l2_buffer_plane_params(struct v4l_gst *priv,
			     struct v4l_gst_buffer *buffers, guint n_planes,
			     guint bytesused[], struct timeval *timestamp,
			     struct v4l2_buffer *v4l2buf)
{
	gint i;
	guint32 offset = 0;

	memcpy(v4l2buf->m.planes, buffers[v4l2buf->index].planes,
	       sizeof(struct v4l2_plane) * n_planes);

	for (i = 0; i < n_planes; i++) {
		if (bytesused)
			v4l2buf->m.planes[i].bytesused = bytesused[i];
		/* Use `data_offset` to notify offsets of multi-planes combined
		   in single dmabuf fd. Most applications will ignore this
		   field, so you'll need to modify such applications. */
		if (gst_buffer_n_memory(buffers[v4l2buf->index].gstbuf) == 1) {
			v4l2buf->m.planes[i].data_offset = offset;
			offset += v4l2buf->m.planes[i].length;
		}
	}

	if (timestamp) {
		v4l2buf->timestamp.tv_sec = timestamp->tv_sec;
		v4l2buf->timestamp.tv_usec = timestamp->tv_usec;
	} else {
		v4l2buf->timestamp.tv_sec = v4l2buf->timestamp.tv_usec = 0;
	}
}


static int
fill_v4l2_buffer(struct v4l_gst *priv, GstBufferPool *pool,
		 struct v4l_gst_buffer *buffers, gint buffers_num,
		 guint bytesused[], struct timeval *timestamp,
		 struct v4l2_buffer *v4l2buf)
{
	GstVideoMeta *meta = NULL;
	guint n_planes;

	v4l_gst_pipeline_get_raw_video_params(pool, buffers[v4l2buf->index].gstbuf, NULL, &meta);

	n_planes = (meta) ? meta->n_planes : 1;

	set_v4l2_buffer_plane_params(priv, buffers, n_planes, bytesused,
				     timestamp, v4l2buf);

	v4l2buf->flags = 0;
	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE &&
	    priv->eos_state == EOS_GOT &&
	    g_queue_is_empty(priv->cap.gstbufs_queue)) {
		GST_DEBUG("EOS: Set V4L2_BUF_FLAG_LAST");
		v4l2buf->flags |= V4L2_BUF_FLAG_LAST;
		priv->eos_state = EOS_NONE;
		clear_event(priv->event_state, POLLOUT);
	}

	/* set unused params */
	memset(&v4l2buf->timecode, 0, sizeof(v4l2buf->timecode));
	v4l2buf->sequence = 0;
	v4l2buf->field = V4L2_FIELD_NONE;

	v4l2buf->length = n_planes;

	return 0;
}


static guint
get_v4l2_buffer_index(struct v4l_gst_buffer *buffers, gint buffers_num,
		      GstBuffer *gstbuf)
{
	gint i;
	guint index = G_MAXUINT;

	for (i = 0; i < buffers_num; i++) {
		if (buffers[i].gstbuf == gstbuf) {
			index = i;
			break;
		}
	}

	return index;
}


static GstBuffer *
dequeue_blocking(struct v4l_gst *priv, GQueue *queue, GCond *cond)
{
	GstBuffer *gstbuf;

        gstbuf = g_queue_pop_head(queue);
	while (!gstbuf && priv->is_pipeline_started) {
		g_cond_wait(cond, &priv->queue_mutex);
		gstbuf = g_queue_pop_head(queue);
	}

	return gstbuf;
}


static GstBuffer *
dequeue_non_blocking(GQueue *queue)
{
	GstBuffer *gstbuf;

	gstbuf = g_queue_pop_head(queue);
	if (!gstbuf) {
		GST_TRACE("The buffer pool is empty in "
			  "the non-blocking mode, return EAGAIN");
		errno = EAGAIN;
	}

	return gstbuf;
}


static GstBuffer *
dequeue_cap_buffer(struct v4l_gst *priv)
{
	GQueue *queue = priv->cap.gstbufs_queue;
	GstBuffer *gstbuf = NULL;
	guint len;

	g_mutex_lock(&priv->queue_mutex);

	/* Cache 1 buffer to detect EOS */
	len = g_queue_get_length(queue);
	if (priv->eos_state != EOS_GOT && len == 1)
		goto unlock;

	if (priv->is_non_blocking)
		gstbuf = dequeue_non_blocking(queue);
	else
		gstbuf = dequeue_blocking(priv, queue, &priv->queue_cond);

	if (!gstbuf)
		goto unlock;

	/* Cache 1 buffer to detect EOS */
	len = g_queue_get_length(queue);
	if ((priv->eos_state != EOS_GOT && len == 1) || len == 0)
		clear_event(priv->event_state, POLLOUT);

 unlock:
	g_mutex_unlock(&priv->queue_mutex);

	return gstbuf;
}


static GstBuffer *
acquire_buffer_from_pool(struct v4l_gst *priv, GstBufferPool *pool)
{
	GstFlowReturn flow_ret;
	GstBuffer *gstbuf;
	GstBufferPoolAcquireParams params = { 0, };

	if (priv->is_non_blocking) {
		params.flags |= GST_BUFFER_POOL_ACQUIRE_FLAG_DONTWAIT;
	} else
		g_mutex_unlock(&priv->queue_mutex);

	flow_ret = gst_buffer_pool_acquire_buffer(pool, &gstbuf, &params);
	if (!priv->is_non_blocking)
		g_mutex_lock(&priv->queue_mutex);

	if (priv->is_non_blocking && flow_ret == GST_FLOW_EOS) {
		GST_TRACE("The buffer pool is empty in "
			  "the non-blocking mode, return EAGAIN");
		errno = EAGAIN;
		return NULL;
	} else if (flow_ret != GST_FLOW_OK) {
		GST_ERROR("gst_buffer_pool_acquire_buffer failed");
		errno = EINVAL;
		return NULL;
	}

	return gstbuf;
}



/* gst-omx may reassociate GstBuffers and dmabuf-fds without closing them after
   flushing. Since clients will associate a dmabuf-fd with a v4l2_buffer's
   index, we need to update GstBuffer-index association after flushing to avoid
   misalign with clients. */
static void
reindex_buffers(struct v4l_gst *priv)
{
	int i, j;
	gchar fd_str[8], error_fds[128] = {0};
	gchar opened_fds[128] = {0}, initial_fds[128] = {0};

	for (i = 0; i < priv->cap.buffers_num; ++i) {
		struct v4l_gst_buffer *buf1 = &priv->cap.buffers[i];
		GstMemory *mem;
		int fd;

		g_snprintf(fd_str, sizeof(fd_str), "%d:%d,",
			   i, buf1->plane0_fd);
		g_strlcat(initial_fds, fd_str, sizeof(initial_fds));

		if (!buf1->plane0_fd)
			continue;
		if (buf1->state == V4L_GST_BUFFER_DEQUEUED)
			continue;
		if (!gst_buffer_n_memory(buf1->gstbuf))
			continue;

		mem = gst_buffer_peek_memory(buf1->gstbuf, 0);
		if (!gst_is_dmabuf_memory(mem))
			continue;

		fd = gst_dmabuf_memory_get_fd(mem);

		g_snprintf(fd_str, sizeof(fd_str), "%d:%d,", i, fd);
		g_strlcat(opened_fds, fd_str, sizeof(opened_fds));

		if (buf1->plane0_fd == fd)
			continue;

		for (j = 0; j < priv->cap.buffers_num; ++j) {
			struct v4l_gst_buffer *buf2 = &priv->cap.buffers[j];
			GstBuffer *gstbuf = buf1->gstbuf;

			if (i == j)
				continue;
			if (buf2->plane0_fd != fd)
				continue;
			if (buf2->state == V4L_GST_BUFFER_DEQUEUED)
				continue;

			buf1->gstbuf = buf2->gstbuf;
			buf2->gstbuf = gstbuf;
			i--;
			break;
		}
		if (j >= priv->cap.buffers_num) {
			g_snprintf(fd_str, sizeof(fd_str), "%d:%d,", i, fd);
			g_strlcat(error_fds, fd_str, sizeof(error_fds));
		}
	}

	if (*error_fds) {
		GST_WARNING("Failed to reindex dmabuf fd!");
		GST_DEBUG("failed fds: %s / opened_fds: %s / initial_fds: %s",
			  error_fds, opened_fds, initial_fds);
	}
}


static int
dqbuf_ioctl_out(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	GstBuffer *gstbuf;
	guint index;

	if (!priv->is_pipeline_started) {
		GST_ERROR("The pipeline does not start yet.");
		errno = EINVAL;
		return -1;
	}

	if (!check_no_index_v4l2_buffer(v4l2buf, priv->out.buffers,
					priv->out.pool))
		return -1;

	g_mutex_lock(&priv->queue_mutex);

	gstbuf = acquire_buffer_from_pool(priv, priv->out.pool);
	if (!gstbuf) {
		g_mutex_unlock(&priv->queue_mutex);
		return -1;
	}

	priv->out.returned_cnt--;

	if (priv->out.returned_cnt == 0) {
		clear_event(priv->event_state, POLLIN);
	}


	g_mutex_unlock(&priv->queue_mutex);

	index = get_v4l2_buffer_index(priv->out.buffers,
				      priv->out.buffers_num, gstbuf);
	if (index >= priv->out.buffers_num) {
		GST_ERROR("Failed to get a valid buffer index "
			  "on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	v4l2buf->index = index;
	priv->out.buffers[v4l2buf->index].state = V4L_GST_BUFFER_DEQUEUED;

	GST_CAT_TRACE(v4l_gst_buffer_debug_category,
		      "DQBUF OUT: gstbuf=%p, index=%d",
		      gstbuf, index);

	return fill_v4l2_buffer(priv, priv->out.pool,
				priv->out.buffers, priv->out.buffers_num,
				NULL, NULL, v4l2buf);
}


static gboolean
get_valid_cap_pts(struct v4l_gst *priv, GstBuffer *gstbuf,
		  GstClockTime *pts)
{
	GstClockTime buffer_pts = GST_BUFFER_PTS(gstbuf);
	GstClockTime buffer_duration = GST_BUFFER_DURATION(gstbuf);

	if (GST_CLOCK_TIME_IS_VALID(buffer_pts)) {
		if (GST_CLOCK_TIME_IS_VALID(priv->last_cap_pts) &&
		    buffer_pts > priv->last_cap_pts) {
			priv->estimated_cap_duration =
				buffer_pts - priv->last_cap_pts;
		} else if (!GST_CLOCK_TIME_IS_VALID(priv->estimated_cap_duration) &&
			   GST_CLOCK_TIME_IS_VALID(buffer_duration) &&
			   buffer_duration > 0) {
			priv->estimated_cap_duration = buffer_duration;
		}

		priv->last_cap_pts = buffer_pts;
		*pts = buffer_pts;
		return TRUE;
	}

	if (GST_CLOCK_TIME_IS_VALID(priv->last_cap_pts) &&
	    GST_CLOCK_TIME_IS_VALID(priv->estimated_cap_duration) &&
	    G_MAXUINT64 - priv->last_cap_pts >= priv->estimated_cap_duration) {
		/* Some decoders may output the last CAPTURE buffer without a
		   valid PTS. Do not expose GST_CLOCK_TIME_NONE as a V4L2
		   timestamp because clients can interpret it as a huge future
		   timestamp and wait indefinitely for playback end. */
		*pts = priv->last_cap_pts + priv->estimated_cap_duration;
		GST_WARNING("CAPTURE buffer has invalid PTS; using estimated PTS "
			    "(last=%" G_GUINT64_FORMAT ", duration=%"
			    G_GUINT64_FORMAT ", estimated=%" G_GUINT64_FORMAT ")",
			    (guint64) priv->last_cap_pts,
			    (guint64) priv->estimated_cap_duration,
			    (guint64) *pts);
		priv->last_cap_pts = *pts;
		return TRUE;
	}

	GST_WARNING("CAPTURE buffer has invalid PTS and no estimate is available");
	return FALSE;
}


static int
dqbuf_ioctl_cap(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	GstBuffer *gstbuf;
	guint index;
	struct timeval timestamp;
	struct timeval *timestamp_ptr = NULL;
	GstClockTime pts = GST_CLOCK_TIME_NONE;
	guint bytesused[GST_VIDEO_MAX_PLANES];
	gint i;

	if (!check_no_index_v4l2_buffer(v4l2buf, priv->cap.buffers,
					priv->cap.pool))
		return -1;

	gstbuf = dequeue_cap_buffer(priv);
	if (!gstbuf)
		return -1;

	reindex_buffers(priv);

	index = get_v4l2_buffer_index(priv->cap.buffers,
				      priv->cap.buffers_num, gstbuf);
	if (index >= priv->cap.buffers_num) {
		GST_ERROR("Failed to get a valid buffer index "
			  "on CAPTURE");
		errno = EINVAL;
		gst_buffer_unref(gstbuf);
		return -1;
	}

	v4l2buf->index = index;

	for (i = 0; i < priv->cap.fmt.num_planes; i++)
		bytesused[i] = priv->cap.fmt.plane_fmt[i].sizeimage;

	if (priv->cap.buffers[index].state == V4L_GST_BUFFER_DEQUEUED) {
		/* It might occur when a buffer is unexpectedly queued
		   after streamoff_ioctl_out(). In this case reference count of
		   the buffer should already have been incremented, need to
		   revert it here. */
		GST_WARNING("Already dequeued buffer %u is dequeued again", index);
		gst_buffer_unref(priv->cap.buffers[index].gstbuf);
	}
	priv->cap.buffers[v4l2buf->index].state = V4L_GST_BUFFER_DEQUEUED;

	if (get_valid_cap_pts(priv, gstbuf, &pts)) {
		GST_TIME_TO_TIMEVAL(pts, timestamp);
		timestamp_ptr = &timestamp;
	}
	GST_CAT_TRACE(v4l_gst_buffer_debug_category,
		      "DQBUF CAP: gstbuf=%p, index=%d, pts=%lu, raw_pts=%lu",
		      gstbuf, index, pts / 1000000,
		      GST_BUFFER_PTS(gstbuf) / 1000000);

	return fill_v4l2_buffer(priv, priv->cap.pool,
				priv->cap.buffers, priv->cap.buffers_num,
				bytesused, timestamp_ptr, v4l2buf);
}


int
v4l_gst_dqbuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	int ret = -1;

	GST_TRACE("VIDIOC_DQBUF: type: %s (0x%x) index: %d flags: 0x%x",
		  v4l2_buffer_type_to_string(v4l2buf->type), v4l2buf->type,
		  v4l2buf->index, v4l2buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = dqbuf_ioctl_out(priv, v4l2buf);
	} else if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = dqbuf_ioctl_cap(priv, v4l2buf);
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
	}

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}


int
v4l_gst_querybuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	struct v4l_gst_buffer *buffers;
	gint buffers_num;
	GstBufferPool *pool;
	int ret;

	GST_TRACE("VIDIOC_QUERYBUF: type: %s (0x%x) index: %d flags: 0x%x",
		  v4l2_buffer_type_to_string(v4l2buf->type), v4l2buf->type,
		  v4l2buf->index, v4l2buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		buffers = priv->out.buffers;
		buffers_num = priv->out.buffers_num;
		pool = priv->out.pool;
	} else if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		buffers = priv->cap.buffers;
		buffers_num = priv->cap.buffers_num;
		pool = priv->cap.pool;
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		g_mutex_unlock(&priv->dev_lock);
		return -1;
	}

	if (!check_v4l2_buffer(v4l2buf, buffers, buffers_num, pool)) {
		g_mutex_unlock(&priv->dev_lock);
		return -1;
	}

	ret = fill_v4l2_buffer(priv, pool, buffers, buffers_num,
			       NULL, NULL, v4l2buf);

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}



#define PAGE_ALIGN(off, align) ((off + align - 1) & ~(align - 1))
static gsize
set_mem_offset(struct v4l_gst_buffer *buffer, GstBufferPool *pool, gsize offset)
{
	GstVideoInfo info;
	GstVideoMeta *meta;
	static long page_size = -1;
	gint i;

	if (page_size < 0)
		page_size = sysconf(_SC_PAGESIZE);

	if (!v4l_gst_pipeline_get_raw_video_params(pool, buffer->gstbuf, &info, &meta)) {
		/* deal with this as a single plane */
		buffer->planes[0].m.mem_offset = offset;
		return PAGE_ALIGN(gst_buffer_get_size(buffer->gstbuf),
				  page_size) + offset;
	}

	if (meta) {
		for (i = 0; i < meta->n_planes; i++) {
			buffer->planes[i].m.mem_offset = offset;
			offset += PAGE_ALIGN(calc_plane_size(&info, meta, i),
					     page_size);
		}
	}

	return offset;
}


static guint
alloc_buffers_from_pool(struct v4l_gst *priv, GstBufferPool *pool,
			struct v4l_gst_buffer **buffers)
{
	GstBufferPoolAcquireParams params = { 0, };
	GstFlowReturn flow_ret;
	guint actual_max_buffers;
	struct v4l_gst_buffer *bufs_list;
	gint i;

	if (!gst_buffer_pool_set_active(pool, TRUE)) {
		GST_ERROR("Failed to activate buffer pool on OUTPUT");
		errno = EINVAL;
		return 0 ;
	}

	/* The buffer pool parameters can not be changed after activation,
	   so it is good time to confirm the number of buffers actually set to
	   the buffer pool. */
	v4l_gst_pipeline_get_buffer_pool_params(pool, NULL, NULL, NULL, &actual_max_buffers);
	if (actual_max_buffers == 0) {
		GST_ERROR("Cannot handle the unlimited amount of buffers");
		errno = EINVAL;
		goto inactivate_pool;
	}

	bufs_list = g_new0(struct v4l_gst_buffer, actual_max_buffers);

	for (i = 0; i < actual_max_buffers; i++) {
		flow_ret = gst_buffer_pool_acquire_buffer(pool,
							  &bufs_list[i].gstbuf,
							  &params);
		if (flow_ret != GST_FLOW_OK) {
			GST_ERROR("Failed to acquire a buffer on OUTPUT");
			errno = ENOMEM;
			goto free_bufs_list;
		}

		bufs_list[i].priv = priv;
		bufs_list[i].state = V4L_GST_BUFFER_DEQUEUED;

		GST_DEBUG("out gst_buffer[%d] : %p", i, bufs_list[i].gstbuf);
	}

	*buffers = bufs_list;

	GST_DEBUG("The number of buffers actually set to the buffer pool is %d",
		  actual_max_buffers);

	return actual_max_buffers;

	/* error cases */
 free_bufs_list:
	for (i = 0; i < actual_max_buffers; i++) {
		if (bufs_list[i].gstbuf)
			gst_buffer_unref(bufs_list[i].gstbuf);
	}
	g_free(bufs_list);
 inactivate_pool:
	gst_buffer_pool_set_active(pool, FALSE);

	return 0;
}


static GstFlowReturn
force_dqbuf_from_pool(GstBufferPool *pool, struct v4l_gst_buffer *buffers,
		      gint buffers_num, gboolean map)
{
	GstFlowReturn flow_ret;
	GstBufferPoolAcquireParams params = { 0, };
	GstBuffer *gstbuf;
	guint index;

	params.flags = GST_BUFFER_POOL_ACQUIRE_FLAG_DONTWAIT;

	/* force to make buffers available to the V4L2 caller side */
	flow_ret = gst_buffer_pool_acquire_buffer(pool, &gstbuf, &params);
	if (flow_ret != GST_FLOW_OK)
		return flow_ret;

	index = get_v4l2_buffer_index(buffers, buffers_num, gstbuf);
	if (index >= buffers_num) {
		GST_ERROR("Failed to get a valid buffer index");
		errno = EINVAL;
		return GST_FLOW_ERROR;
	}

	buffers[index].state = V4L_GST_BUFFER_DEQUEUED;

	if (!map)
		return GST_FLOW_OK;

	if (!gst_buffer_map(gstbuf, &buffers[index].info,
			    buffers[index].flags)) {
		GST_ERROR("Failed to map buffer (%p)", gstbuf);
		errno = EINVAL;
		return GST_FLOW_ERROR;
	}
	return GST_FLOW_OK;
}


static int
force_out_dqbuf(struct v4l_gst *priv)
{
	g_mutex_lock(&priv->queue_mutex);

	while (force_dqbuf_from_pool(priv->out.pool, priv->out.buffers,
				     priv->out.buffers_num, TRUE) == GST_FLOW_OK) {
		priv->out.returned_cnt--;
	}

	clear_event(priv->event_state, POLLIN);

	g_mutex_unlock(&priv->queue_mutex);

	GST_DEBUG("returned_out_buffers_num : %d", priv->out.returned_cnt);

	return 0;
}


static int
force_cap_dqbuf(struct v4l_gst *priv)
{
	GstBuffer *gstbuf;
	guint index;

	do {
		g_mutex_lock(&priv->queue_mutex);
		gstbuf = dequeue_non_blocking(priv->cap.gstbufs_queue);
		/* This function may set errno but not need to expose it to
		   clients in this case */
		errno = 0;
		g_mutex_unlock(&priv->queue_mutex);

		if (!gstbuf)
			break;

		index = get_v4l2_buffer_index(priv->cap.buffers,
					      priv->cap.buffers_num, gstbuf);
		if (index >= priv->cap.buffers_num) {
			GST_ERROR("Failed to get a valid buffer index "
				  "on CAPTURE");
			errno = EINVAL;
			return -1;
		}

		priv->cap.buffers[index].state = V4L_GST_BUFFER_DEQUEUED;
		GST_DEBUG("CAPTURE buffer %u is forcedly dequeued", index);
	} while (gstbuf);

	clear_event(priv->event_state, POLLOUT);

	for (index = 0; index < priv->cap.buffers_num; index++) {
		if (priv->cap.buffers[index].state == V4L_GST_BUFFER_DEQUEUED)
			continue;
		gst_buffer_ref(priv->cap.buffers[index].gstbuf);
		priv->cap.buffers[index].state = V4L_GST_BUFFER_DEQUEUED;
	}

	return 0;
}


static int
streamoff_ioctl_out(struct v4l_gst *priv, gboolean steal_ref)
{
	int ret;

	GST_CAT_DEBUG(v4l_gst_buffer_debug_category,
		      "STREAMOFF OUT begin: dequeue all OUT & CAP buffers ...");

	v4l_gst_core_set_pipeline_started(priv, FALSE);

	GST_OBJECT_LOCK(priv->pipeline);
	if (GST_STATE(priv->pipeline) == GST_STATE_NULL) {
		/* No need to flush the pipeline after it has been
		   the NULL state. */
		GST_OBJECT_UNLOCK(priv->pipeline);
		goto flush_buffer_queues;
	}
	GST_OBJECT_UNLOCK(priv->pipeline);


	ret = v4l_gst_pipeline_flush(priv);

	if (ret < 0)
		return ret;

 flush_buffer_queues:
	/* Vacate the buffers queues to make them available in the next time */
	ret = force_out_dqbuf(priv);
	if (ret < 0)
		return ret;

	ret = force_cap_dqbuf(priv);
	if (ret < 0)
		return ret;

	/* The reference counted up below will be unreffed when calling
	   the streamon ioctl. This prevents from returning all the buffers
	   of the OUTPUT bufferpool and freeing them by inactivating
	   the bufferpool for flushing. */
	if (steal_ref)
		gst_buffer_ref(priv->out.buffers[0].gstbuf);

	/* wake up blocking of the OUTPUT buffer acquisition */
	if (!gst_buffer_pool_set_active(priv->out.pool, FALSE)) {
		GST_ERROR("Failed to inactivate buffer pool on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	/* wake up blocking of the CAPTURE buffer acquisition */
	v4l_gst_core_set_pipeline_started(priv, FALSE);

	GST_CAT_DEBUG(v4l_gst_buffer_debug_category, "STREAMOFF OUT end");

	return 0;
}


static int
reqbuf_ioctl_out(struct v4l_gst *priv,
		 struct v4l2_requestbuffers *req)
{
	GstCaps *caps;
	guint adjusted_count;
	guint allocated_num;
	int ret;
	guint i;

	if (!is_supported_memory_io(req->memory))
		return -1;

	g_mutex_lock(&priv->dev_lock);

	if (req->count == 0) {
		GST_DEBUG("req->count == 0");

		/* The following function flushes both the OUTPUT and CAPTURE
		   buffer types because the GStreamer can only flush the whole
		   of the pipeline, so the buffers of both the buffer types
		   need to be requeued after this operation.
		*/
		ret = streamoff_ioctl_out(priv, FALSE);
		if (ret < 0)
			goto unlock;

		/* Force to return dequeued buffers to the buffer pool. */
		for (i = 0; i < priv->out.buffers_num; i++) {
			if (priv->out.buffers[i].state ==
			    V4L_GST_BUFFER_DEQUEUED) {
				gst_buffer_unref(priv->out.buffers[i].gstbuf);
			}
		}

		if (priv->out.buffers) {
			g_free(priv->out.buffers);
			priv->out.buffers = NULL;
		}

		ret = 0;
		goto unlock;
	}

	if (priv->is_pipeline_started) {
		GST_ERROR("The pipeline is already running");
		errno = EBUSY;
		ret = -1;
		goto unlock;
	}

	if (gst_buffer_pool_is_active(priv->out.pool)) {
		if (!gst_buffer_pool_set_active(priv->out.pool, FALSE)) {
			GST_ERROR("Failed to inactivate buffer pool");
			errno = EBUSY;
			ret = -1;
			goto unlock;
		}
	}

	caps = v4l_gst_pipeline_get_codec_caps_from_fourcc(priv->out.fmt.pixelformat);
	if (!caps) {
		errno = EINVAL;
		ret = -1;
		goto unlock;
	}

	adjusted_count = MAX(req->count, INPUT_BUFFERING_CNT);
	adjusted_count = MIN(adjusted_count, VIDEO_MAX_FRAME);

	v4l_gst_pipeline_set_buffer_pool_params(priv->out.pool, caps,
			       priv->out.fmt.plane_fmt[0].sizeimage,
			       adjusted_count, adjusted_count, NULL);

	allocated_num = alloc_buffers_from_pool(priv, priv->out.pool,
						&priv->out.buffers);
	if (allocated_num == 0) {
		gst_caps_unref(caps);
		ret = -1;
		goto unlock;
	}

	for (i = 0; i < allocated_num; i++) {
		/* Set identifiers for associating a GstBuffer with
		   a V4L2 buffer in the V4L2 caller side. */
		priv->mmap_offset =
			set_mem_offset(&priv->out.buffers[i],
				       priv->out.pool,
				       priv->mmap_offset);

		priv->out.buffers[i].planes[0].length =
			gst_buffer_get_size(priv->out.buffers[i].gstbuf);
	}

	req->count = priv->out.buffers_num = allocated_num;

	GST_DEBUG("buffers count=%d", req->count);

	priv->out.returned_cnt = 0;

	ret = 0;

 unlock:
	g_mutex_unlock(&priv->dev_lock);

	return ret;
}


static GstBuffer *
peek_first_cap_buffer(struct v4l_gst *priv)
{
	GstBuffer *gstbuf = NULL;
	gboolean timed_out = FALSE;
	gint64 end_time;

	g_mutex_lock(&priv->queue_mutex);
	gstbuf = g_queue_peek_head(priv->out.gstbufs_queue);
	end_time = g_get_monotonic_time() + INITIAL_BUFFER_WAIT_TIMEOUT;
	while (!gstbuf && priv->is_pipeline_started) {
		if (!g_cond_wait_until(&priv->queue_cond,
				       &priv->queue_mutex,
				       end_time)) {
			timed_out = TRUE;
			break;
		}
		gstbuf = g_queue_peek_head(priv->out.gstbufs_queue);
	}
	g_mutex_unlock(&priv->queue_mutex);

	if (timed_out && !gstbuf)
		GST_WARNING("Timed out waiting the first CAPTURE buffer.");

	return gstbuf;
}


static gboolean
wait_for_all_bufs_collected(struct v4l_gst *priv,
			    guint max_buffers)
{
	GQueue *queue = priv->out.gstbufs_queue;
	gboolean succeeded;
	gboolean timed_out = FALSE;
	gint64 end_time;

	g_mutex_lock(&priv->queue_mutex);
	end_time = g_get_monotonic_time() + INITIAL_BUFFER_WAIT_TIMEOUT;
	while (g_queue_get_length(queue) < max_buffers &&
	       priv->is_pipeline_started) {
		if (!g_cond_wait_until(&priv->queue_cond,
				       &priv->queue_mutex,
				       end_time)) {
			timed_out = TRUE;
			break;
		}
	}
	succeeded = g_queue_get_length(queue) >= max_buffers;
	g_mutex_unlock(&priv->queue_mutex);

	if (timed_out && !succeeded)
		GST_WARNING("Timed out waiting CAPTURE buffers.");

	return succeeded;
}


static gboolean
retrieve_cap_frame_info(GstBufferPool *pool, GstBuffer *gstbuf,
			struct v4l2_pix_format_mplane *cap_fmt)
{
	GstVideoInfo info;
	GstVideoMeta *meta;
	gint i;

	if (!v4l_gst_pipeline_get_raw_video_params(pool, gstbuf, &info, &meta)) {
		GST_ERROR("Failed to get video meta data");
		return FALSE;
	}

	for (i = 0; i < meta->n_planes; i++) {
		cap_fmt->plane_fmt[i].sizeimage =
			calc_plane_size(&info, meta, i);
		cap_fmt->plane_fmt[i].bytesperline = meta->stride[i];
	}

	return TRUE;
}


static guint
create_cap_buffers_list(struct v4l_gst *priv)
{
	GstBuffer *first_gstbuf;
	guint actual_max_buffers;
	gint i, j;
	gboolean succeeded;

	if (priv->cap.buffers)
		/* Cannot realloc the buffers without stopping the pipeline,
		   so return the same number of the buffers so far. */
		return priv->cap.buffers_num;

	g_mutex_unlock(&priv->dev_lock);

	first_gstbuf = peek_first_cap_buffer(priv);

	g_mutex_lock(&priv->dev_lock);

	if (!first_gstbuf) {
		GST_ERROR("Failed to wait for the first CAPTURE buffer.");
		errno = EINVAL;
		return 0;
	}

	if (!first_gstbuf->pool) {
		GST_ERROR("Cannot handle buffers not belonging to "
			  "a bufferpool");
		errno = EINVAL;
		return 0;
	}

	if (priv->cap.pool != first_gstbuf->pool) {
		GST_DEBUG("The buffer pool we prepared is not used by "
			  "the pipeline, so replace it with the pool that is "
			  "actually used");
		gst_object_unref(priv->cap.pool);
		priv->cap.pool = gst_object_ref(first_gstbuf->pool);
	}

	/* Confirm the number of buffers actually set to the buffer pool. */
	v4l_gst_pipeline_get_buffer_pool_params(priv->cap.pool, NULL, NULL, NULL,
			       &actual_max_buffers);
	if (actual_max_buffers == 0) {
		GST_ERROR("Cannot handle the unlimited amount of buffers");
		errno = EINVAL;
		return 0;
	}

	if (!retrieve_cap_frame_info(priv->cap.pool, first_gstbuf,
				     &priv->cap.fmt)) {
		GST_ERROR("Failed to retrieve frame info on CAPTURE");
		errno = EINVAL;
		return 0;
	}

	/* We wait for buffers from appsink to be collected for
	   the maximum number of the buffer pool. */
	g_mutex_unlock(&priv->dev_lock);
	succeeded = wait_for_all_bufs_collected(priv, actual_max_buffers);
	g_mutex_lock(&priv->dev_lock);

	if (!succeeded) {
		GST_ERROR("Failed to collect buffers for CAPTURE.");
		errno = EINVAL;
		return 0;
	}

	priv->cap.buffers = g_new0(struct v4l_gst_buffer, actual_max_buffers);

	for (i = 0; i < actual_max_buffers; i++) {
		priv->cap.buffers[i].gstbuf =
			g_queue_peek_nth(priv->out.gstbufs_queue, i);

		/* Set identifiers for associating a GstBuffer with
		   a V4L2 buffer in the V4L2 caller side. */
		priv->mmap_offset = set_mem_offset(&priv->cap.buffers[i],
						   priv->cap.pool,
						   priv->mmap_offset);

		priv->cap.buffers[i].state = V4L_GST_BUFFER_DEQUEUED;

		/* assume that decoded image data has been filled to
		   the entire plane size, because the GStreamer buffer
		   information does not provides how much valid data size
		   a GstBuffer has. */
		for (j = 0; j < priv->cap.fmt.num_planes; j++) {
			priv->cap.buffers[i].planes[j].length =
				priv->cap.fmt.plane_fmt[j].sizeimage;
		}

		GST_DEBUG("cap gst_buffer[%d] : %p", i,
			  priv->cap.buffers[i].gstbuf);
	}

	GST_DEBUG("The number of buffers actually set to the buffer pool is %d",
		  actual_max_buffers);

	return actual_max_buffers;
}


static int
reqbuf_ioctl_cap(struct v4l_gst *priv,
		 struct v4l2_requestbuffers *req)
{
	int ret = -1;

	if (!is_supported_memory_io(req->memory))
		return ret;

	g_mutex_lock(&priv->dev_lock);

	if (req->count == 0) {
		ret = v4l_gst_pipeline_stop(priv);
		goto unlock;
	}

	if (!priv->is_pipeline_started) {
		GST_ERROR("Need to start the pipeline for the buffer request "
			  "on CAPTURE");
		errno = EINVAL;
		goto unlock;
	}

	g_mutex_lock(&priv->cap.reqbuf_mutex);
	priv->cap.buffers_num = MIN(req->count, VIDEO_MAX_FRAME);
	g_cond_signal(&priv->cap.reqbuf_cond);
	g_mutex_unlock(&priv->cap.reqbuf_mutex);

	req->count = priv->cap.buffers_num = create_cap_buffers_list(priv);
	if (req->count == 0)
		goto unlock;

	GST_DEBUG("buffers count=%d", req->count);

	ret = 0;

 unlock:
	g_mutex_unlock(&priv->dev_lock);

	return ret;
}


int
v4l_gst_reqbuf_ioctl(struct v4l_gst *priv, struct v4l2_requestbuffers *req)
{
	int ret;

	GST_DEBUG("VIDIOC_REQBUF: type: %s (0x%x) count: %d memory: 0x%x",
		  v4l2_buffer_type_to_string(req->type), req->type,
		  req->count, req->memory);

	if (req->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = reqbuf_ioctl_out(priv, req);
	} else if (req->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = reqbuf_ioctl_cap(priv, req);
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}


static int
streamon_ioctl_out(struct v4l_gst *priv)
{
	GstState state;

	if (priv->is_pipeline_started) {
		GST_ERROR("The pipeline is already running");
		errno = EBUSY;
		return -1;
	}

	GST_OBJECT_LOCK(priv->pipeline);
	state = GST_STATE(priv->pipeline);
	GST_OBJECT_UNLOCK(priv->pipeline);

	g_mutex_lock(&priv->dev_lock);

	if (state == GST_STATE_NULL) {
		if (!v4l_gst_pipeline_set_out_format(priv))
			return -1;
		if (!v4l_gst_pipeline_set_cap_format(priv))
			return -1;
	}

	if (!gst_buffer_pool_is_active(priv->out.pool)) {
		if (!gst_buffer_pool_set_active(priv->out.pool, TRUE)) {
			GST_ERROR("Failed to activate buffer pool");
			errno = EINVAL;
			return -1;
		}

		/* Restore the extra reference counted up in the streamoff */
		gst_buffer_unref(priv->out.buffers[0].gstbuf);
	}

	priv->eos_state = EOS_NONE;
	v4l_gst_core_reset_cap_timestamp_state(priv);

	v4l_gst_core_set_pipeline_started(priv, TRUE);

	gst_element_set_state(priv->pipeline, GST_STATE_PLAYING);

	g_mutex_unlock(&priv->dev_lock);

	GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS(GST_BIN(priv->pipeline),
					  GST_DEBUG_GRAPH_SHOW_ALL,
					  "v4l-gst.streamon.snapshot");

	return 0;
}


int
v4l_gst_streamon_ioctl(struct v4l_gst *priv, enum v4l2_buf_type *type)
{
	int ret;

	GST_DEBUG("VIDIOC_STREAMON: type: %s (0x%x)",
		  v4l2_buffer_type_to_string(*type), *type);

	if (*type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = streamon_ioctl_out(priv);
	} else if (*type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		/* no processing */
		ret = 0;
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}


int
v4l_gst_streamoff_ioctl(struct v4l_gst *priv, enum v4l2_buf_type *type)
{
	int ret;

	GST_DEBUG("VIDIOC_STREAMOFF: type: %s (0x%x)",
		  v4l2_buffer_type_to_string(*type), *type);

	GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS(GST_BIN(priv->pipeline),
					  GST_DEBUG_GRAPH_SHOW_ALL,
					  "v4l-gst.streamoff.snapshot");

	if (*type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		g_mutex_lock(&priv->dev_lock);
		ret = streamoff_ioctl_out(priv, TRUE);
		g_mutex_unlock(&priv->dev_lock);
	} else if (*type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		/* no processing */
		ret = 0;
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}


static int
find_out_buffer_by_offset(struct v4l_gst *priv, int64_t offset)
{
	gint index = -1;
	gint i;

	for (i = 0; i < priv->out.buffers_num; i++) {
		if (priv->out.buffers[i].planes[0].m.mem_offset == offset) {
			index = i;
			break;
		}
	}

	return index;
}


static void *
map_out_buffer(struct v4l_gst *priv, int index, int prot)
{
	GstMapInfo info;
	void *data;
	GstMapFlags map_flags;

	map_flags = (prot & PROT_READ) ? GST_MAP_READ : 0;
	map_flags |= (prot & PROT_WRITE) ? GST_MAP_WRITE : 0;

	if (!gst_buffer_map(priv->out.buffers[index].gstbuf, &info,
			    map_flags)) {
		GST_ERROR("Failed to map buffer (%p)",
			  priv->out.buffers[index].gstbuf);
		errno = EINVAL;
		return MAP_FAILED;
	}

	data = info.data;

	gst_buffer_unmap(priv->out.buffers[index].gstbuf, &info);

	priv->out.buffers[index].flags = map_flags;

	return data;
}


static int
find_cap_buffer_by_offset(struct v4l_gst *priv,
			  int64_t offset, int *index, int *plane)
{
	gint i, j;

	for (i = 0; i < priv->cap.buffers_num; i++) {
		for (j = 0; j < priv->cap.fmt.num_planes; j++) {
			if (priv->cap.buffers[i].planes[j].m.mem_offset ==
			    offset) {
				*index = i;
				*plane = j;
				return 0;
			}
		}
	}

	return -1;
}


static void *
map_cap_buffer(struct v4l_gst *priv, int index, int plane,
	       int prot)
{
	GstVideoMeta *meta;
	GstMapInfo info;
	void *data;
	GstMapFlags map_flags;

	map_flags = (prot & PROT_READ) ? GST_MAP_READ : 0;
	map_flags |= (prot & PROT_WRITE) ? GST_MAP_WRITE : 0;

	if (!gst_buffer_map(priv->cap.buffers[index].gstbuf, &info,
			    map_flags)) {
		GST_ERROR("Failed to map buffer (%p)",
			  priv->cap.buffers[index].gstbuf);
		errno = EINVAL;
		return MAP_FAILED;
	}

	if (!v4l_gst_pipeline_get_raw_video_params(priv->cap.pool,
				  priv->cap.buffers[index].gstbuf,
				  NULL, &meta)) {
		GST_ERROR("Failed to get video meta data");
		errno = EINVAL;
		gst_buffer_unmap(priv->cap.buffers[index].gstbuf,
				 &priv->cap.buffers[index].info);
		return MAP_FAILED;
	}

	data = info.data + meta->offset[plane];

	gst_buffer_unmap(priv->cap.buffers[index].gstbuf, &info);

	priv->cap.buffers[index].flags = map_flags;

	return data;
}


void *
v4l_gst_mmap(struct v4l_gst *priv, void *start, size_t length,
		 int prot, int flags, int fd, int64_t offset)
{
	int index;
	int plane;
	void *map = MAP_FAILED;
	int ret;

	/* unused */
	(void)start;
	(void)flags;
	(void)fd;

	/* The GStreamer memory mapping internally maps
	   the whole allocated size of a buffer, so the mapping length
	   does not need to be specified. */
	(void)length;

	g_mutex_lock(&priv->dev_lock);

	index = find_out_buffer_by_offset(priv, offset);
	if (index >= 0) {
		map = map_out_buffer(priv, index, prot);
		goto unlock;
	}

	ret = find_cap_buffer_by_offset(priv, offset, &index, &plane);
	if (ret == 0) {
		map = map_cap_buffer(priv, index, plane, prot);
		goto unlock;
	}

 unlock:
	g_mutex_unlock(&priv->dev_lock);

	GST_DEBUG("Final map = %p", map);

	return map;
}


int
v4l_gst_expbuf_ioctl(struct v4l_gst *priv, struct v4l2_exportbuffer *expbuf)
{
	struct v4l_gst_buffer *buffer;
	guint mem_index = 0;
	GstMemory *mem = NULL;

	GST_TRACE("VIDIOC_EXPBUF: type: 0x%x index: %d flags: 0x%x",
		  expbuf->type, expbuf->index, expbuf->flags);

	if (expbuf->type != V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE &&
	    expbuf->type != V4L2_BUF_TYPE_PRIVATE) {
		GST_ERROR("Can only export capture buffers as dmabuf");
		errno = EINVAL;
		return -1;
	}

	if (expbuf->index >= priv->cap.buffers_num) {
		GST_ERROR("Buffer index is out of range!: %d/%d",
			  expbuf->index, priv->cap.buffers_num);
		errno = EINVAL;
		return -1;
	}

	if (expbuf->plane >= priv->cap.fmt.num_planes) {
		GST_ERROR("Plane index is out of range!: %d/%d",
			  expbuf->plane, priv->cap.fmt.num_planes);
		errno = EINVAL;
		return -1;
	}

	buffer = &priv->cap.buffers[expbuf->index];

	if (expbuf->plane < gst_buffer_n_memory(buffer->gstbuf))
		mem_index = expbuf->plane;

	mem = gst_buffer_peek_memory(buffer->gstbuf, mem_index);
	if (!mem || !gst_is_dmabuf_memory(mem)) {
		GST_ERROR("Failed to get dmabuf memory.");
		errno = EINVAL;
		return -1;
	}

	switch(expbuf->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		expbuf->fd = dup(gst_dmabuf_memory_get_fd(mem));
		if (expbuf->plane == 0) {
			/* See reindex_buffers() */
			buffer->plane0_fd = gst_dmabuf_memory_get_fd(mem);
		}
		break;
       case V4L2_BUF_TYPE_PRIVATE:
	       /* For backward compatibility, will be removed.
		  See also set_v4l2_buffer_plane_params(). */
	       expbuf->reserved[0] = 0;
	       if (gst_buffer_n_memory(buffer->gstbuf) == 1) {
		       guint i;
		       for (i = 0; i < expbuf->plane; i++)
			       expbuf->reserved[0] += buffer->planes[i].length;
	       }
	       break;
	default:
		GST_ERROR("Can only export capture buffers as dmabuf");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

