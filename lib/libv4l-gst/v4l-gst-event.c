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

int
v4l_gst_ioctl_subscribe_event(struct v4l_gst *priv,
		      struct v4l2_event_subscription *subscription)
{
	int retval = -1;

	errno = EINVAL;
	g_return_val_if_fail(priv, retval);
	g_return_val_if_fail(subscription, retval);

	g_mutex_lock(&priv->dev_lock);

	GST_DEBUG("VIDIOC_SUBSCRIBE_EVENT: type: %s (0x%x) id: %d flags: 0x%x",
		  v4l2_event_type_to_string(subscription->type), subscription->type,
		  subscription->id, subscription->flags);

	switch (subscription->type) {
	case V4L2_EVENT_SOURCE_CHANGE:
		/* Chromium supports only this type of v4l2events. */
		priv->v4l2events.subscribed |= (1 << V4L2_EVENT_SOURCE_CHANGE);
		errno = 0;
		retval = 0;
		break;
	default:
		GST_ERROR("unsupported V4L2_EVENT type: %s (type: 0x%x)",
			  v4l2_event_type_to_string(subscription->type),
			  subscription->type);
		errno = ENOTTY;
		break;
	}

	g_mutex_unlock(&priv->dev_lock);

	return retval;
}


int
v4l_gst_ioctl_dqevent(struct v4l_gst *priv, struct v4l2_event *ev)
{
	int retval = -1;

	GST_TRACE("VIDIOC_DQEVENT");

	errno = EINVAL;
	g_return_val_if_fail(ev, retval);
	g_return_val_if_fail(priv, retval);

	g_mutex_lock(&priv->dev_lock);
	g_mutex_lock(&priv->v4l2events.mutex);

	if (!priv->v4l2events.queue || priv->v4l2events.queue->length == 0) {
		errno = EAGAIN;
		goto unlock;
	}

	if (priv->v4l2events.subscribed & (1 << V4L2_EVENT_SOURCE_CHANGE)) {
		struct v4l2_event *next
			= g_queue_pop_head(priv->v4l2events.queue);
		if (!next) {
			GST_WARNING("Failed to pop a v4l2_event.");
			errno = EINVAL;
			goto unlock;
		}
		*ev = *next;
		ev->pending = priv->v4l2events.queue->length;
		g_free(next);
		errno = 0;
		retval = 0;
		GST_DEBUG("Dequeue SOURCE_CHANGE: pending %u, sequence: %u",
			  ev->pending, ev->sequence);
	}

 unlock:
	g_mutex_unlock(&priv->v4l2events.mutex);
	g_mutex_unlock(&priv->dev_lock);

	return retval;
}


int
v4l_gst_ioctl_unsubscribe_event(struct v4l_gst *priv,
			struct v4l2_event_subscription *subscription)
{
	int retval = 0;

	GST_INFO("VIDIOC_UNSUBSCRIBE_EVENT: type: 0x%x id: 0x%x flags: 0x%x",
		 subscription->type, subscription->id, subscription->flags);

	g_mutex_lock(&priv->dev_lock);

	errno = 0;

	switch (subscription->type) {
	case V4L2_EVENT_ALL:
		/* V4L2_EVENT_ALL is valid only for unsubscribe:
		   https://www.kernel.org/doc/html/v4.9/media/uapi/v4l/vidioc-dqevent.html#id2
		*/
		priv->v4l2events.subscribed = 0;
		break;
	case V4L2_EVENT_SOURCE_CHANGE:
		priv->v4l2events.subscribed &= ~(1 << V4L2_EVENT_SOURCE_CHANGE);
		break;
	default:
		GST_ERROR("unsupported V4L2_EVENT type: %s (type: 0x%x)",
			  v4l2_event_type_to_string(subscription->type),
			  subscription->type);
		errno = ENOTTY;
		retval = -1;
		break;
	}

	g_mutex_unlock(&priv->dev_lock);

	return retval;
}

