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

#include <config.h>

#include "libv4l-plugin.h"

#include "gst-backend.h"
#include "debug.h"

#if HAVE_VISIBILITY
#define PLUGIN_PUBLIC __attribute__ ((visibility("default")))
#else
#define PLUGIN_PUBLIC
#endif

static void *plugin_init(int fd)
{
#ifdef ENABLE_VIDIOC_DEBUG
	char *vidioc_features = getenv(ENV_DISABLE_VIDIOC_FEATURES);

	if (vidioc_features) {
		DBG_LOG("DISABLE_VIDIOC_FEATURES: %s\n", vidioc_features);
	}
	fprintf(stderr, "DISABLE_VIDIOC_FEATURES: %s\n", vidioc_features);
#endif
	return gst_backend_init(fd);
}

static void plugin_close(void *dev_ops_priv)
{
	struct v4l_gst *priv = dev_ops_priv;

	if (!priv)
		return;

	gst_backend_deinit(priv);
}

static int plugin_ioctl(void *dev_ops_priv, int fd,
			unsigned long int cmd, void *arg)
{
	struct v4l_gst *priv = dev_ops_priv;
	int ret = -1;

	(void)fd; /* unused */

	switch (cmd) {
	case VIDIOC_QUERYCAP:
		ret = querycap_ioctl(priv, arg);
		break;
	case VIDIOC_S_FMT:
		ret = set_fmt_ioctl(priv, arg);
		break;
	case VIDIOC_G_FMT:
		ret = get_fmt_ioctl(priv, arg);
		break;
	case VIDIOC_ENUM_FMT:
		ret = enum_fmt_ioctl(priv, arg);
		break;
	case VIDIOC_G_CTRL:
		ret = get_ctrl_ioctl(priv, arg);
		break;
	case VIDIOC_G_EXT_CTRLS:
		ret = get_ext_ctrl_ioctl(priv, arg);
		break;
	case VIDIOC_QBUF:
		ret = qbuf_ioctl(priv, arg);
		break;
	case VIDIOC_DQBUF:
		ret = dqbuf_ioctl(priv, arg);
		break;
	case VIDIOC_QUERYBUF:
		ret = querybuf_ioctl(priv, arg);
		break;
	case VIDIOC_REQBUFS:
		ret = reqbuf_ioctl(priv, arg);
		break;
	case VIDIOC_STREAMON:
		ret = streamon_ioctl(priv, arg);
		break;
	case VIDIOC_STREAMOFF:
		ret = streamoff_ioctl(priv, arg);
		break;
	case VIDIOC_SUBSCRIBE_EVENT:
		ret = subscribe_event_ioctl(priv, arg);
		break;
	case VIDIOC_DQEVENT:
		ret = dqevent_ioctl(priv, arg);
		break;
	case VIDIOC_EXPBUF:
		ret = expbuf_ioctl(priv, arg);
		break;
	case VIDIOC_ENUM_FRAMESIZES :
		ret = enum_framesizes_ioctl(priv, arg);
		break;
	case VIDIOC_G_SELECTION :
		ret = g_selection_ioctl(priv, arg);
		break;
	case VIDIOC_QUERYCTRL:
		ret = queryctrl_ioctl(priv, arg);
		break;
	case VIDIOC_QUERYMENU:
		ret = querymenu_ioctl(priv, arg);
		break;
	case VIDIOC_G_CROP:
		ret = g_crop_ioctl(priv, arg);
		break;
	case VIDIOC_TRY_FMT:
		ret = try_fmt_ioctl(priv, arg);
		break;
	case VIDIOC_UNSUBSCRIBE_EVENT:
		ret = unsubscribe_event_ioctl(priv, arg);
		break;
	case VIDIOC_DECODER_CMD:
		ret = decoder_cmd_ioctl(priv, arg);
		break;
	case VIDIOC_TRY_DECODER_CMD:
		ret = try_decoder_cmd_ioctl(priv, arg);
		break;
	default:
		DBG_LOG("unknown ioctl: %lu\n", cmd);
		errno = ENOTTY;
		break;
	}

	return ret;
}

static void *
plugin_mmap(void *dev_ops_priv, void *start, size_t length, int prot,
	    int flags, int fd, int64_t offset)
{
	struct v4l_gst *priv = dev_ops_priv;
	return gst_backend_mmap(priv, start, length, prot, flags, fd,
				offset);
}

PLUGIN_PUBLIC const struct libv4l_dev_ops libv4l2_plugin = {
	.init = &plugin_init,
	.close = &plugin_close,
	.ioctl = &plugin_ioctl,
	.mmap = &plugin_mmap,
};
