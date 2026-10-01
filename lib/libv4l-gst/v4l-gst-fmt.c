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
v4l_gst_querycap_ioctl(struct v4l_gst *priv, struct v4l2_capability *cap)
{
	GST_DEBUG("VIDIOC_QUERYCAP");

	cap->device_caps =
		V4L2_CAP_VIDEO_M2M_MPLANE |
		V4L2_CAP_VIDEO_CAPTURE_MPLANE |
		V4L2_CAP_VIDEO_OUTPUT_MPLANE |
		V4L2_CAP_EXT_PIX_FORMAT |
		V4L2_CAP_STREAMING;

	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	g_strlcpy((gchar *)cap->driver, "libv4l-gst", sizeof(cap->driver));
	g_strlcpy((gchar *)cap->card, "gst-dummy", sizeof(cap->card));
	g_strlcpy((gchar *)cap->bus_info, "user-vst-gst-000", sizeof(cap->bus_info));
	memset(cap->reserved, 0, sizeof(cap->reserved));

	return 0;
}


static gboolean
is_pix_fmt_supported(struct fmt *fmts, gint fmts_num, guint fourcc)
{
	gint i;
	gboolean ret = FALSE;

	for (i = 0; i < fmts_num; i++) {
		if (fmts[i].fourcc == fourcc) {
			ret = TRUE;
			break;
		}
	}

	return ret;
}


static void
set_params_as_encoded_stream(struct v4l2_pix_format_mplane *pix_fmt)
{
	/* We set the following parameters assuming that encoded streams are
	   received on the output buffer type. The values are almost
	   meaningless. */
	pix_fmt->width = 0;
	pix_fmt->height = 0;
	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;
	pix_fmt->plane_fmt[0].bytesperline = 0;
	pix_fmt->num_planes = 1;
}


static int
set_fmt_ioctl_out(struct v4l_gst *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;
	gchar fourcc_str[5];
	GArray *cap_fmts = priv->cap.supported_fmts;

	pix_fmt = &fmt->fmt.pix_mp;
	fourcc_to_string(pix_fmt->pixelformat, fourcc_str);

	if (!is_pix_fmt_supported((struct fmt*)priv->out.supported_fmts->data,
				  priv->out.supported_fmts->len,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on OUTPUT: %s (0x%x)",
			  fourcc_str, pix_fmt->pixelformat);
		errno = EINVAL;
		return -1;
	}

	if (pix_fmt->plane_fmt[0].sizeimage == 0) {
		GST_ERROR("sizeimage field is not specified on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	if (priv->role == V4L_GST_ROLE_NONE) {
		/* Fix the role from the media kind of the OUTPUT format:
		   a codec selects the decoder, a raw format selects the
		   encoder. The format is guaranteed to be supported by
		   the check above. */
		if (g_hash_table_lookup(priv->config.pipelines,
					fourcc_str)) {
			priv->role = V4L_GST_ROLE_DECODER;
			priv->out.kind = V4L_GST_MEDIA_KIND_CODEC;
			priv->cap.kind = V4L_GST_MEDIA_KIND_RAW;
		} else {
			priv->role = V4L_GST_ROLE_ENCODER;
			priv->out.kind = V4L_GST_MEDIA_KIND_RAW;
			priv->cap.kind = V4L_GST_MEDIA_KIND_CODEC;
		}
		GST_INFO("role fixed from OUTPUT format %s: %s",
			 fourcc_str,
			 priv->role == V4L_GST_ROLE_DECODER ?
			 "decoder" : "encoder");
	}

	if (priv->role == V4L_GST_ROLE_ENCODER) {
		/* The OUTPUT format does not select the GStreamer pipeline.
		   The encoder pipeline is created when the CAPTURE codec
		   format is set. */
	} else if (priv->pipeline) {
		if (priv->out.fmt.pixelformat == pix_fmt->pixelformat) {
			GST_INFO("Same pixelformat with current: %s",
				 fourcc_str);
		} else {
			gchar current[5];

			fourcc_to_string(priv->out.fmt.pixelformat, current);
			GST_ERROR("Different pixelformat with current: "
				  "pixelformat:%s, current: %s",
				  fourcc_str, current);
			errno = EINVAL;
			return -1;
		}
	} else {
		gboolean succeeded = v4l_gst_core_init_pipeline(priv, pix_fmt->pixelformat);
		if (!succeeded)
			goto error;
	}

	priv->out.fmt = *pix_fmt;

	if (priv->role != V4L_GST_ROLE_ENCODER)
		set_params_as_encoded_stream(pix_fmt);

	if (!priv->cap.fmt.pixelformat && cap_fmts->len > 0)
		priv->cap.fmt.pixelformat
			= ((struct fmt*)cap_fmts->data)[0].fourcc;

	return 0;

 error:
	return -1;
}


void
v4l_gst_fmt_init_decoded_frame_params(struct v4l2_pix_format_mplane *pix_fmt)
{
	/* The following parameters will be determined after
	   the video decoding starts. */
	pix_fmt->width = 0;
	pix_fmt->height = 0;
	pix_fmt->num_planes = 0;
	memset(pix_fmt->plane_fmt, 0, sizeof(pix_fmt->plane_fmt));
}


static int
set_fmt_ioctl_cap(struct v4l_gst *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;

	pix_fmt = &fmt->fmt.pix_mp;

	if (priv->role == V4L_GST_ROLE_NONE) {
		GST_ERROR("The role is not fixed yet; set the OUTPUT format "
			  "first");
		errno = EINVAL;
		return -1;
	}

	if (!is_pix_fmt_supported((struct fmt*)priv->cap.supported_fmts->data,
				  priv->cap.supported_fmts->len,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on CAPTURE");
		errno = EINVAL;
		return -1;
	}

	if (priv->role == V4L_GST_ROLE_ENCODER &&
	    pix_fmt->plane_fmt[0].sizeimage == 0) {
		GST_ERROR("sizeimage field is not specified on CAPTURE");
		errno = EINVAL;
		return -1;
	}

	if (priv->role == V4L_GST_ROLE_ENCODER && !priv->pipeline) {
		if (!v4l_gst_core_init_pipeline(priv, pix_fmt->pixelformat))
			return -1;
	}

	GST_OBJECT_LOCK(priv->pipeline);
	if (priv->role == V4L_GST_ROLE_ENCODER) {
		/* Encoded stream on CAPTURE: the stream size is given by the
		   caller via sizeimage, so store it and mark the format as an
		   encoded stream. */
		if (GST_STATE(priv->pipeline) == GST_STATE_NULL) {
			set_params_as_encoded_stream(&priv->cap.fmt);
			priv->cap.fmt.pixelformat = pix_fmt->pixelformat;
			priv->cap.fmt.plane_fmt[0].sizeimage =
				pix_fmt->plane_fmt[0].sizeimage;
		} else if (priv->cap.fmt.pixelformat !=
			   pix_fmt->pixelformat) {
			gchar fourcc_str[5];
			fourcc_to_string(pix_fmt->pixelformat, fourcc_str);
			GST_ERROR("Changing pixel format during playing isn't "
				  "supported: pixelformat: %s (0x%x)",
				  fourcc_str, pix_fmt->pixelformat);
			errno = EBUSY;
			GST_OBJECT_UNLOCK(priv->pipeline);
			return -1;
		}
	} else if (GST_STATE(priv->pipeline) == GST_STATE_NULL) {
		priv->cap.fmt.pixelformat = pix_fmt->pixelformat;
		v4l_gst_fmt_init_decoded_frame_params(pix_fmt);
	} else if (priv->cap.fmt.width != pix_fmt->width ||
		   priv->cap.fmt.height != pix_fmt->height ||
		   priv->cap.fmt.pixelformat != pix_fmt->pixelformat) {
		/* TODO: Should check the pix_fmt more strictly. */
		gchar fourcc_str[5];
		fourcc_to_string(pix_fmt->pixelformat, fourcc_str);
		GST_ERROR("Changing pixel format during playing isn't supported: "
			  "width: %u, height: %u, pixelformat: %s (0x%x)",
			  pix_fmt->width, pix_fmt->height,
			  fourcc_str, pix_fmt->pixelformat);
		errno = EBUSY;
		GST_OBJECT_UNLOCK(priv->pipeline);
		return -1;
	}
	GST_OBJECT_UNLOCK(priv->pipeline);

	/* set unsupported parameters */
	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;

	return 0;
}


int
v4l_gst_set_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *fmt)
{
	int ret;

	GST_DEBUG("VIDIOC_S_FMT: type: %s (0x%x)",
		  v4l2_buffer_type_to_string(fmt->type), fmt->type);

	g_mutex_lock(&priv->dev_lock);

	if (fmt->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = set_fmt_ioctl_out(priv, fmt);
	} else if (fmt->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = set_fmt_ioctl_cap(priv, fmt);
	} else {
		GST_ERROR("Invalid buffer type");
		errno = EINVAL;
		ret = -1;
	}

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}


static int
get_fmt_ioctl_cap(struct v4l_gst *priv,
		  struct v4l2_pix_format_mplane *pix_fmt)
{
	gint i;
	gchar fourcc_str[5];

	if (!g_atomic_int_get(&priv->cap.fmt_acquirable) ||
	    priv->out.cnt < INPUT_BUFFERING_CNT) {
		errno = EINVAL;
		return -1;
	}

	GST_DEBUG("cap format is acquirable. out_cnt = %d",priv->out.cnt);

	pix_fmt->width = priv->cap.fmt.width;
	pix_fmt->height = priv->cap.fmt.height;
	pix_fmt->pixelformat = priv->cap.fmt.pixelformat;
	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;
	pix_fmt->num_planes = priv->cap.fmt.num_planes;

	fourcc_to_string(pix_fmt->pixelformat, fourcc_str);
	GST_DEBUG("width:%d height:%d, format: %s (0x%x) num_planes=%d",
		  pix_fmt->width, pix_fmt->height,
		  fourcc_str, pix_fmt->pixelformat,
		  pix_fmt->num_planes);

	if (priv->cap.fmt.plane_fmt[0].sizeimage > 0) {
		for (i = 0; i < pix_fmt->num_planes; i++) {
			pix_fmt->plane_fmt[i].sizeimage =
				priv->cap.fmt.plane_fmt[i].sizeimage;
			pix_fmt->plane_fmt[i].bytesperline =
				priv->cap.fmt.plane_fmt[i].bytesperline;
		}
		pix_fmt->num_planes = priv->cap.fmt.num_planes;
	} else {
		memset(pix_fmt->plane_fmt, 0, sizeof(pix_fmt->plane_fmt));
	}

	return 0;
}


int
v4l_gst_get_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;
	int ret;

	GST_DEBUG("VIDIOC_G_FMT: type: %s (0x%x)",
		  v4l2_buffer_type_to_string(fmt->type), fmt->type);

	pix_fmt = &fmt->fmt.pix_mp;

	if (fmt->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		g_mutex_lock(&priv->dev_lock);
		*pix_fmt = priv->out.fmt;
		g_mutex_unlock(&priv->dev_lock);
		if (priv->role != V4L_GST_ROLE_ENCODER)
			set_params_as_encoded_stream(pix_fmt);
		ret = 0;
	} else if (fmt->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = get_fmt_ioctl_cap(priv, pix_fmt);
	} else {
		GST_ERROR("Invalid buffer type");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}


int
v4l_gst_enum_fmt_ioctl(struct v4l_gst *priv, struct v4l2_fmtdesc *desc)
{
	struct fmt *fmts;
	gint fmts_num;
	gchar fourcc_str[5];

	GST_DEBUG("VIDIOC_ENUM_FMT: type: %s (0x%x) index: %d",
		  v4l2_buffer_type_to_string(desc->type), desc->type, desc->index);

	if (desc->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		fmts = (struct fmt*)priv->out.supported_fmts->data;
		fmts_num = priv->out.supported_fmts->len;
		desc->flags = V4L2_FMT_FLAG_COMPRESSED;
	} else if (desc->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		fmts = (struct fmt*)priv->cap.supported_fmts->data;
		fmts_num = priv->cap.supported_fmts->len;
		desc->flags = 0;
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		return -1;
	}

	if (fmts_num <= desc->index) {
		GST_DEBUG("  Index %u is out of range", desc->index);
		errno = EINVAL;
		return -1;
	}

	desc->pixelformat = fmts[desc->index].fourcc;
	g_strlcpy((gchar *)desc->description, fmts[desc->index].desc,
		  sizeof(desc->description));
	memset(desc->reserved, 0, sizeof(desc->reserved));
	fourcc_to_string(desc->pixelformat, fourcc_str);

	/* Flag each entry by its media kind: codec entries are compressed. */
	if (desc->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE)
		desc->flags = g_hash_table_lookup(priv->config.pipelines,
						  fourcc_str) ?
			V4L2_FMT_FLAG_COMPRESSED : 0;
	else
		desc->flags = g_hash_table_lookup(priv->config.encode_pipelines,
						  fourcc_str) ?
			V4L2_FMT_FLAG_COMPRESSED : 0;

	GST_DEBUG("  description: %s pixelformat: %s (0x%x)",
		  desc->description, fourcc_str, desc->pixelformat);

	return 0;
}


int
v4l_gst_enum_framesizes_ioctl(struct v4l_gst *priv, struct v4l2_frmsizeenum *argp)
{
	gchar fourcc_str[5];

	fourcc_to_string(argp->pixel_format, fourcc_str);
	GST_DEBUG("VIDIOC_ENUM_FRAMESIZES:"
		  " index: %d pixel_format: %s (0x%x)",
		  argp->index, fourcc_str, argp->pixel_format);

	switch (argp->pixel_format) {
	case V4L2_PIX_FMT_GREY:
	case V4L2_PIX_FMT_RGB565:
	case V4L2_PIX_FMT_RGB24:
	case V4L2_PIX_FMT_BGR24:
	case V4L2_PIX_FMT_ABGR32:
	case V4L2_PIX_FMT_XBGR32:
	case V4L2_PIX_FMT_ARGB32:
	case V4L2_PIX_FMT_XRGB32:
	case V4L2_PIX_FMT_RGB32:
	case V4L2_PIX_FMT_BGR32:
	case V4L2_PIX_FMT_H264:
	case V4L2_PIX_FMT_HEVC:
		argp->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;
		argp->stepwise.step_width = 1;
		argp->stepwise.step_height = 1;
		break;
	case V4L2_PIX_FMT_NV12:
	case V4L2_PIX_FMT_NV21:
	case V4L2_PIX_FMT_YUV420:
	case V4L2_PIX_FMT_YVU420:
	case V4L2_PIX_FMT_NV12MT:
		argp->type = V4L2_FRMSIZE_TYPE_STEPWISE;
		argp->stepwise.step_width = 2;
		argp->stepwise.step_height = 2;
		break;
	case V4L2_PIX_FMT_NV16:
	case V4L2_PIX_FMT_YUYV:
	case V4L2_PIX_FMT_UYVY:
	case V4L2_PIX_FMT_YVYU:
	case V4L2_PIX_FMT_YUV422P:
		argp->type = V4L2_FRMSIZE_TYPE_STEPWISE;
		argp->stepwise.step_width = 2;
		argp->stepwise.step_height = 1;
		break;
	case V4L2_PIX_FMT_YVU410:
	case V4L2_PIX_FMT_YUV410:
		argp->type = V4L2_FRMSIZE_TYPE_STEPWISE;
		argp->stepwise.step_width = 4;
		argp->stepwise.step_height = 4;
		break;
	case V4L2_PIX_FMT_YUV411P:
		argp->type = V4L2_FRMSIZE_TYPE_STEPWISE;
		argp->stepwise.step_width = 4;
		argp->stepwise.step_height = 1;
		break;
	}
	argp->stepwise.min_width = 16;
	argp->stepwise.min_height = 16;
	argp->stepwise.max_width = priv->config.max_width ?
		priv->config.max_width : 1920;
	argp->stepwise.max_height = priv->config.max_height ?
		priv->config.max_height : 1080;

	return 0;
}


int
v4l_gst_g_selection_ioctl(struct v4l_gst *priv, struct v4l2_selection *selection)
{
#ifdef ENABLE_VIDIOC_DEBUG
	char *vidioc_features = getenv(ENV_DISABLE_VIDIOC_FEATURES);
	if (vidioc_features && strstr(vidioc_features, "VIDIOC_G_SELECTION")) {
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category,
			      "unsupported VIDIOC_G_SELECTION");
		errno = ENOTTY;
		return 0;
	}
#endif
	GST_DEBUG("VIDIOC_G_SELECTION: type: 0x%x target: 0x%x flags: 0x%x",
		  selection->type, selection->target, selection->flags);

	selection->r.top = selection->r.left = 0;
	selection->r.width = priv->cap.fmt.width;
	selection->r.height = priv->cap.fmt.height;

	return 0;
}


static int
try_fmt_ioctl_out(struct v4l_gst *priv, struct v4l2_format *format)
{
	struct v4l2_pix_format_mplane *pix_fmt = &format->fmt.pix_mp;
	gchar fourcc_str[5];

	fourcc_to_string(pix_fmt->pixelformat, fourcc_str);

	if (!is_pix_fmt_supported((struct fmt*)priv->out.supported_fmts->data,
				  priv->out.supported_fmts->len,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on OUTPUT: %s (0x%x)",
			  fourcc_str, pix_fmt->pixelformat);

		errno = EINVAL;
		return -1;
	}

	if (priv->pipeline &&
	    priv->out.fmt.pixelformat != pix_fmt->pixelformat) {
		gchar current[5];

		fourcc_to_string(priv->out.fmt.pixelformat, current);
		GST_ERROR("Different pixelformat with current: "
			  "pixelformat:%s, current: %s",
			  fourcc_str, current);

		errno = EINVAL;
		return -1;
	}

	if (priv->role != V4L_GST_ROLE_ENCODER)
		set_params_as_encoded_stream(pix_fmt);

	return 0;
}


static int
try_fmt_ioctl_cap(struct v4l_gst *priv, struct v4l2_format *format)
{
	struct v4l2_pix_format_mplane *pix_fmt = &format->fmt.pix_mp;

	if (!is_pix_fmt_supported((struct fmt*)priv->cap.supported_fmts->data,
				  priv->cap.supported_fmts->len,
				  pix_fmt->pixelformat)) {
		gchar fourcc_str[5];

		fourcc_to_string(pix_fmt->pixelformat, fourcc_str);
		GST_ERROR("Unsupported pixelformat on CAPTURE");

		errno = EINVAL;
		return -1;
	}

	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;

	return 0;
}


int
v4l_gst_try_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *format)
{
	int ret;
	gchar fourcc_str[5];

	fourcc_to_string(format->fmt.pix_mp.pixelformat, fourcc_str);
	GST_DEBUG("VIDIOC_TRY_FMT: type: 0x%x, pixelformat: %s (0x%x)",
		  format->type, fourcc_str, format->fmt.pix_mp.pixelformat);

	g_mutex_lock(&priv->dev_lock);

	if (format->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = try_fmt_ioctl_out(priv, format);
	} else if (format->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = try_fmt_ioctl_cap(priv, format);
	} else {
		GST_ERROR("Invalid buffer type");
		errno = EINVAL;
		ret = -1;
	}

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}


int
v4l_gst_g_crop_ioctl(struct v4l_gst *priv, struct v4l2_crop *crop)
{
	const gchar *buf_type;
#ifdef ENABLE_VIDIOC_DEBUG
	char *vidioc_features = getenv(ENV_DISABLE_VIDIOC_FEATURES);
	if (vidioc_features && strstr(vidioc_features, "VIDIOC_G_CROP")) {
		GST_CAT_ERROR(v4l_gst_ioctl_debug_category,
			      "unsupported VIDIOC_G_EXT_CTRLS v4l2_crop type: 0x%x",
			      crop->type);
		errno = ENOTTY;
		return 0;
	}
#endif

	GST_INFO("unsupported VIDIOC_G_CROP v4l2_crop type: 0x%x", crop->type);

	buf_type = v4l2_buffer_type_to_string(crop->type);
	if (buf_type) {
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_%s", buf_type);
	} else {
		GST_DEBUG("unsupported v4l2_crop type: 0x%x", crop->type);
	}
	GST_DEBUG("v4l2_crop rect: left:%d top:%d width: %u height: %u",
		  crop->c.left, crop->c.top, crop->c.width, crop->c.height);

	return 0;
}

