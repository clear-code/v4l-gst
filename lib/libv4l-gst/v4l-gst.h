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

#ifndef __V4L_GST_H__
#define __V4L_GST_H__

#include <linux/videodev2.h>

struct v4l_gst;

/*
 * Public backend API, grouped by domain. Each domain is implemented in
 * v4l-gst-<domain>.c; cross-TU helpers are declared in
 * v4l-gst-internal.h.
 */

/* core: backend lifecycle */
struct v4l_gst *v4l_gst_init(int fd);
void v4l_gst_deinit(struct v4l_gst *priv);

/* pipeline: decoder command */
int v4l_gst_try_decoder_cmd_ioctl(struct v4l_gst *priv,
					   struct v4l2_decoder_cmd *decoder_cmd);
int v4l_gst_decoder_cmd_ioctl(struct v4l_gst *priv,
				       struct v4l2_decoder_cmd *decoder_cmd);

/* fmt: format */
int v4l_gst_querycap_ioctl(struct v4l_gst *priv,
			       struct v4l2_capability *cap);
int v4l_gst_set_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *fmt);
int v4l_gst_get_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *fmt);
int v4l_gst_enum_fmt_ioctl(struct v4l_gst *priv, struct v4l2_fmtdesc *desc);
int v4l_gst_enum_framesizes_ioctl(struct v4l_gst *priv,
				      struct v4l2_frmsizeenum *argp);
int v4l_gst_g_selection_ioctl(struct v4l_gst *priv,
				  struct v4l2_selection *selection);
int v4l_gst_g_crop_ioctl(struct v4l_gst *priv, struct v4l2_crop *crop);
int v4l_gst_try_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *format);

/* buf: buffer */
int v4l_gst_qbuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *buf);
int v4l_gst_dqbuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *buf);
int v4l_gst_querybuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *buf);
int v4l_gst_reqbuf_ioctl(struct v4l_gst *priv,
			     struct v4l2_requestbuffers *req);
int v4l_gst_streamon_ioctl(struct v4l_gst *priv, enum v4l2_buf_type *type);
int v4l_gst_streamoff_ioctl(struct v4l_gst *priv,
				enum v4l2_buf_type *type);
int v4l_gst_expbuf_ioctl(struct v4l_gst *priv,
			     struct v4l2_exportbuffer *buf);
void *v4l_gst_mmap(struct v4l_gst *priv, void *start, size_t length,
		       int prot, int flags, int fd, int64_t offset);

/* ctrl: control */
int v4l_gst_get_ctrl_ioctl(struct v4l_gst *priv,
				struct v4l2_control *ctrl);
int v4l_gst_get_ext_ctrl_ioctl(struct v4l_gst *priv,
				    struct v4l2_ext_controls *ext_ctrls);
int v4l_gst_queryctrl_ioctl(struct v4l_gst *priv,
				 struct v4l2_queryctrl *query_ctrl);
int v4l_gst_querymenu_ioctl(struct v4l_gst *priv,
				 struct v4l2_querymenu *query_menu);

/* event: event */
int v4l_gst_subscribe_event_ioctl(struct v4l_gst *priv,
					struct v4l2_event_subscription *sub);
int v4l_gst_dqevent_ioctl(struct v4l_gst *priv, struct v4l2_event *ev);
int v4l_gst_unsubscribe_event_ioctl(struct v4l_gst *priv,
					  struct v4l2_event_subscription *subscription);

#define ENV_DISABLE_VIDIOC_FEATURES "DISABLE_VIDIOC_FEATURES"

#endif /* __V4L_GST_H__ */
