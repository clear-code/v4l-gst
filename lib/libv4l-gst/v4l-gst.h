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
struct v4l_gst *  v4l_gst_init			   (int fd);
void		  v4l_gst_deinit		   (struct v4l_gst *priv);

/* pipeline: decoder command */
int		  v4l_gst_ioctl_try_decoder_cmd	   (struct v4l_gst *priv,
						    struct v4l2_decoder_cmd *decoder_cmd);
int		  v4l_gst_ioctl_decoder_cmd	   (struct v4l_gst *priv,
						    struct v4l2_decoder_cmd *decoder_cmd);

/* fmt: format */
int		  v4l_gst_ioctl_querycap	   (struct v4l_gst *priv,
						    struct v4l2_capability *cap);
int		  v4l_gst_ioctl_set_fmt		   (struct v4l_gst *priv,
						    struct v4l2_format *fmt);
int		  v4l_gst_ioctl_get_fmt		   (struct v4l_gst *priv,
						    struct v4l2_format *fmt);
int		  v4l_gst_ioctl_enum_fmt	   (struct v4l_gst *priv,
						    struct v4l2_fmtdesc *desc);
int		  v4l_gst_ioctl_enum_framesizes	   (struct v4l_gst *priv,
						    struct v4l2_frmsizeenum *argp);
int		  v4l_gst_ioctl_g_selection	   (struct v4l_gst *priv,
						    struct v4l2_selection *selection);
int		  v4l_gst_ioctl_g_crop		   (struct v4l_gst *priv,
						    struct v4l2_crop *crop);
int		  v4l_gst_ioctl_try_fmt		   (struct v4l_gst *priv,
						    struct v4l2_format *format);

/* buf: buffer */
int		  v4l_gst_ioctl_qbuf		   (struct v4l_gst *priv,
						    struct v4l2_buffer *buf);
int		  v4l_gst_ioctl_dqbuf		   (struct v4l_gst *priv,
						    struct v4l2_buffer *buf);
int		  v4l_gst_ioctl_querybuf	   (struct v4l_gst *priv,
						    struct v4l2_buffer *buf);
int		  v4l_gst_ioctl_reqbuf		   (struct v4l_gst *priv,
						    struct v4l2_requestbuffers *req);
int		  v4l_gst_ioctl_streamon	   (struct v4l_gst *priv,
						    enum v4l2_buf_type *type);
int		  v4l_gst_ioctl_streamoff	   (struct v4l_gst *priv,
						    enum v4l2_buf_type *type);
int		  v4l_gst_ioctl_expbuf		   (struct v4l_gst *priv,
						    struct v4l2_exportbuffer *buf);
void *		  v4l_gst_mmap			   (struct v4l_gst *priv,
						    void *start,
						    size_t length,
						    int prot,
						    int flags,
						    int fd,
						    int64_t offset);

/* ctrl: control */
int		  v4l_gst_ioctl_get_ctrl	   (struct v4l_gst *priv,
						    struct v4l2_control *ctrl);
int		  v4l_gst_ioctl_get_ext_ctrl	   (struct v4l_gst *priv,
						    struct v4l2_ext_controls *ext_ctrls);
int		  v4l_gst_ioctl_queryctrl	   (struct v4l_gst *priv,
						    struct v4l2_queryctrl *query_ctrl);
int		  v4l_gst_ioctl_querymenu	   (struct v4l_gst *priv,
						    struct v4l2_querymenu *query_menu);

/* event: event */
int		  v4l_gst_ioctl_subscribe_event	   (struct v4l_gst *priv,
						    struct v4l2_event_subscription *sub);
int		  v4l_gst_ioctl_dqevent		   (struct v4l_gst *priv,
						    struct v4l2_event *ev);
int		  v4l_gst_ioctl_unsubscribe_event  (struct v4l_gst *priv,
						    struct v4l2_event_subscription *subscription);

#define ENV_DISABLE_VIDIOC_FEATURES "DISABLE_VIDIOC_FEATURES"

#endif /* __V4L_GST_H__ */
