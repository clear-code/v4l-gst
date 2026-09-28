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
get_ctrl_ioctl(struct v4l_gst *priv, struct v4l2_control *ctrl)
{
	int ret;

	GST_DEBUG("VIDIOC_G_CTRL: id: 0x%x value: 0x%x", ctrl->id, ctrl->value);

	switch (ctrl->id) {
	case V4L2_CID_MIN_BUFFERS_FOR_CAPTURE:
		ctrl->value = priv->config.cap_min_buffers;
		ret = 0;
		break;
	default:
		GST_ERROR("Invalid control id");
		errno = EINVAL;
		ret = -1;
		break;
	}

	return ret;
}


int
get_ext_ctrl_ioctl(struct v4l_gst *priv, struct v4l2_ext_controls *ext_ctrls)
{
	unsigned int i;

#ifdef ENABLE_VIDIOC_DEBUG
	char *vidioc_features = getenv(ENV_DISABLE_VIDIOC_FEATURES);
	if (vidioc_features && strstr(vidioc_features, "VIDIOC_G_EXT_CTRLS")) {
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category, "unsupported VIDIOC_G_EXT_CTRLS");
		errno = ENOTTY;
		return 0;
	}
#endif

	GST_DEBUG("VIDIOC_G_EXT_CTRLS: count: %d", ext_ctrls->count);

	for (i = 0; i < ext_ctrls->count; i++) {
		struct v4l2_ext_control *ext_ctrl = &ext_ctrls->controls[i];
		if (ext_ctrl->id == V4L2_CID_MIN_BUFFERS_FOR_CAPTURE) {
			ext_ctrl->value = priv->config.cap_min_buffers;
			continue;
		}
		errno = EINVAL;
		return -1;
	}

	return 0;
}


/* See https://github.com/JeffyCN/libv4l-rkmpp/blob/master/src/libv4l-rkmpp-dec.c#L740-L776 */
int
queryctrl_ioctl(struct v4l_gst *priv, struct v4l2_queryctrl *query_ctrl)
{
	gchar fourcc_str[5];

#ifdef ENABLE_VIDIOC_DEBUG
	char *vidioc_features = getenv(ENV_DISABLE_VIDIOC_FEATURES);
	if (vidioc_features && strstr(vidioc_features, "VIDIOC_QUERYCTRL")) {
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category,
			      "unsupported VIDIOC_QUERYCTRL: id: 0x%x",
			      query_ctrl->id);
		errno = ENOTTY;
		return 0;
	}
#endif

	GST_INFO("unsupported VIDIOC_QUERYCTRL id: 0x%x", query_ctrl->id);

	switch (query_ctrl->id) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		fourcc_to_string(V4L2_PIX_FMT_H264, fourcc_str);
		if (g_hash_table_lookup(priv->config.pipelines, fourcc_str)) {
			query_ctrl->minimum = V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE;
			query_ctrl->maximum = V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10;
		} else {
			GST_ERROR("disabled H264 profile for query_ctrl id: %x", query_ctrl->id);
			errno = EINVAL;
			return -1;
		}
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		fourcc_to_string(V4L2_PIX_FMT_HEVC, fourcc_str);
		if (g_hash_table_lookup(priv->config.pipelines, fourcc_str)) {
			query_ctrl->minimum = V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN;
			query_ctrl->maximum = V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10;
		} else {
			GST_ERROR("disabled H265/HEVC profile for unsupported query_ctrl id: %x", query_ctrl->id);
			errno = EINVAL;
			return -1;
		}
		break;
#if 0 // No AV1, VP8, VP9 definition
	case V4L2_CID_MPEG_VIDEO_AV1_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_AV1_PROFILE_MAIN;
		query_ctrl->maximum = query_ctrl->minimum;
		break;
	case V4L2_CID_MPEG_VIDEO_VP8_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_VP8_PROFILE_0;
		query_ctrl->maximum = query_ctrl->minimum;
		break;
	case V4L2_CID_MPEG_VIDEO_VP9_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_VP9_PROFILE_0;
		query_ctrl->maximum = V4L2_MPEG_VIDEO_VP9_PROFILE_2;
		break;
#endif
		/* TODO: fill info for other supported ctrls */
	default:
		GST_ERROR("unsupported query_ctrl id: %x", query_ctrl->id);
		errno = EINVAL;
		return -1;
	}
	return 0;
}


/* See https://github.com/JeffyCN/libv4l-rkmpp/blob/master/src/libv4l-rkmpp-dec.c#L778-L842 */
int
querymenu_ioctl(struct v4l_gst *priv, struct v4l2_querymenu *query_menu)
{

#ifdef ENABLE_VIDIOC_DEBUG
	char *vidioc_features = getenv(ENV_DISABLE_VIDIOC_FEATURES);
	if (vidioc_features && strstr(vidioc_features, "VIDIOC_QUERYMENU")) {
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category,
			      "unsupported VIDIOC_QUERYMENU query_menu id: 0x%x",
			      query_menu->id);
		errno = ENOTTY;
		return 0;
	}
#endif

	GST_DEBUG("VIDIOC_QUERYMENU query_menu id: %x", query_menu->id);
	GST_DEBUG("query_menu index: %x", query_menu->index);

	switch (query_menu->id) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE:
		case V4L2_MPEG_VIDEO_H264_PROFILE_MAIN:
		case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH:
		case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10:
			break;
		default:
			GST_INFO("unsupported H264 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_H264_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN:
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_STILL_PICTURE:
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10:
			break;
		default:
			GST_INFO("unsupported HEVC profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_HEVC_PROFILE index: %x", query_menu->index);
		break;
#if 0 // omit non-supported AV1, VP8, VP9
	case V4L2_CID_MPEG_VIDEO_AV1_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_AV1_PROFILE_MAIN) {
			GST_INFO("unsupported VP8 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_AV1_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_VP8_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_VP8_PROFILE_0) {
			GST_INFO("unsupported VP8 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_VP8_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_VP9_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_VP9_PROFILE_0:
		case V4L2_MPEG_VIDEO_VP9_PROFILE_2:
			break;
		default:
			GST_INFO("unsupported VP9 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_VP9_PROFILE index: %x", query_menu->index);
		break;
#endif
	default:
		GST_ERROR("unsupported menu: %x", query_menu->id);
		errno = EINVAL;
		return -1;
	}
	return 0;
}

