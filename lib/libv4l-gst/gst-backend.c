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

#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libv4l-gst-bufferpool.h"

#include "gst-backend.h"
#include "evfd-ctrl.h"
#include "debug.h"

GST_DEBUG_CATEGORY_STATIC(v4l_gst_debug_category);
#define GST_CAT_DEFAULT v4l_gst_debug_category

#define DEF_CAP_MIN_BUFFERS		2
#define INPUT_BUFFERING_CNT		16 // must be <= than VIDEO_MAX_FRAME

#define FMTDESC_NAME_LENGTH		32  //The same size as defined int the V4L2 spec

enum buffer_state {
	V4L_GST_BUFFER_QUEUED,
	V4L_GST_BUFFER_DEQUEUED,
};

struct v4l_gst_buffer {
	GstBuffer *buffer;
	GstMapInfo info;
	GstMapFlags flags;

	struct v4l2_plane planes[GST_VIDEO_MAX_PLANES];

	struct gst_backend_priv *priv;

	enum buffer_state state;
};

struct fmts {
        guint fmt;
        gchar fmt_char[FMTDESC_NAME_LENGTH];
};

struct gst_backend_priv {
	struct v4l_gst_priv *dev_ops_priv;

	GstElement *pipeline;
	GstElement *appsrc;
	GstElement *appsink;

	GstAppSinkCallbacks appsink_cb;

	void *pool_lib_handle;
	struct libv4l_gst_buffer_pool_ops *pool_ops;

	struct fmts *out_fmts;
	gint out_fmts_num;
	struct fmts *cap_fmts;
	gint cap_fmts_num;

	guint out_fourcc;
	gsize out_buf_size;
	struct v4l2_pix_format_mplane cap_pix_fmt;

	gint cap_min_buffers;

	GstBufferPool *src_pool;
	GstBufferPool *sink_pool;

	struct v4l_gst_buffer *out_buffers;
	gint out_buffers_num;
	struct v4l_gst_buffer *cap_buffers;
	gint cap_buffers_num;

	int64_t mmap_offset;

	GQueue *reqbufs_queue;

	GQueue *cap_buffers_queue;
	GMutex queue_mutex;
	GCond queue_cond;

	gint returned_out_buffers_num;

	gulong probe_id;

	GMutex cap_reqbuf_mutex;
	GCond cap_reqbuf_cond;

	int is_cap_fmt_acquirable;

	gboolean is_pipeline_started;

	GMutex dev_lock;

	GstBuffer *eos_buffer;

	gint max_width;
	gint max_height;

        gint out_cnt;
};

struct v4l_gst_format_info {
	guint fourcc;
	GstVideoFormat format;
};

static const gchar* const GST_VIDEO_CODEC_MIME_H264	= "video/x-h264";
static const gchar* const GST_VIDEO_CODEC_MIME_VP8	= "video/x-vp8";

static const struct v4l_gst_format_info v4l_gst_vid_fmt_tbl[] = {
	{ V4L2_PIX_FMT_GREY, GST_VIDEO_FORMAT_GRAY8 },
	{ V4L2_PIX_FMT_RGB565, GST_VIDEO_FORMAT_RGB16 },
	{ V4L2_PIX_FMT_RGB24, GST_VIDEO_FORMAT_RGB },
	{ V4L2_PIX_FMT_BGR24, GST_VIDEO_FORMAT_BGR },
	{ V4L2_PIX_FMT_ABGR32, GST_VIDEO_FORMAT_BGRA },
	{ V4L2_PIX_FMT_XBGR32, GST_VIDEO_FORMAT_BGRx },
	{ V4L2_PIX_FMT_ARGB32, GST_VIDEO_FORMAT_ARGB },
	{ V4L2_PIX_FMT_XRGB32, GST_VIDEO_FORMAT_xRGB },
	{ V4L2_PIX_FMT_NV12, GST_VIDEO_FORMAT_NV12 },
	{ V4L2_PIX_FMT_NV21 ,GST_VIDEO_FORMAT_NV21 },
	{ V4L2_PIX_FMT_NV16, GST_VIDEO_FORMAT_NV16 },
	{ V4L2_PIX_FMT_YVU410, GST_VIDEO_FORMAT_YVU9 },
	{ V4L2_PIX_FMT_YUV410, GST_VIDEO_FORMAT_YUV9 },
	{ V4L2_PIX_FMT_YUV420, GST_VIDEO_FORMAT_I420 },
	{ V4L2_PIX_FMT_YUYV, GST_VIDEO_FORMAT_YUY2 },
	{ V4L2_PIX_FMT_YVU420, GST_VIDEO_FORMAT_YV12 },
	{ V4L2_PIX_FMT_UYVY, GST_VIDEO_FORMAT_UYVY },
	{ V4L2_PIX_FMT_YUV411P, GST_VIDEO_FORMAT_Y41B },
	{ V4L2_PIX_FMT_YUV422P, GST_VIDEO_FORMAT_Y42B },
	{ V4L2_PIX_FMT_YVYU, GST_VIDEO_FORMAT_YVYU },
	{ V4L2_PIX_FMT_RGB32, GST_VIDEO_FORMAT_BGRA },
	{ V4L2_PIX_FMT_BGR32, GST_VIDEO_FORMAT_ARGB },
	{ V4L2_PIX_FMT_NV12MT, GST_VIDEO_FORMAT_NV12_64Z32 },
};

static gboolean
parse_conf_settings(gchar **pipeline_str, gchar **pool_lib_path,
		    gint *min_buffers, gint *max_width, gint *max_height)
{
	const gchar *const *sys_conf_dirs;
	GKeyFile *conf_key;
	const gchar *conf_name = "libv4l-gst.conf";
	GError *err = NULL;
	gchar **groups;
	gsize n_groups;
	gboolean ret = FALSE;
	gint i;

	sys_conf_dirs = g_get_system_config_dirs();

	conf_key = g_key_file_new();
	if (!g_key_file_load_from_dirs(conf_key, conf_name,
				       (const gchar **) sys_conf_dirs, NULL,
				       G_KEY_FILE_NONE, &err)) {
		GST_ERROR("Failed to load %s "
			  "from the xdg system config directory retrieved from "
			  "XDG_CONFIG_DIRS (%s)", conf_name, err->message);
		g_error_free(err);
		goto free_key_file;
	}

	groups = g_key_file_get_groups(conf_key, &n_groups);
	for (i = 0; i < n_groups; i++) {
		if (g_strcmp0(groups[i], "libv4l-gst") != 0)
			/* search next group */
			continue;

		GST_DEBUG("libv4l-gst configuration file is found");

		err = NULL;
		*pipeline_str = g_key_file_get_string(conf_key, groups[i],
						      "pipeline", &err);
		if (!*pipeline_str) {
			GST_ERROR("GStreamer pipeline is not specified");
			g_error_free(err);
			goto free_groups;
		}

		GST_DEBUG("parsed pipeline : %s", *pipeline_str);

		/* No need to check if the external bufferpool library is set,
		   because it is not mandatory for this plugin. */
		*pool_lib_path = g_key_file_get_string(conf_key, groups[i],
						       "bufferpool-library",
						       NULL);

		GST_DEBUG("external buffer pool library : %s",
			  *pool_lib_path ? *pool_lib_path : "none");

		*min_buffers = g_key_file_get_integer(conf_key, groups[i],
						      "min-buffers", NULL);
		if (*min_buffers == 0)
			*min_buffers = DEF_CAP_MIN_BUFFERS;

		GST_DEBUG("minimum number of buffers on CAPTURE "
			  "for the GStreamer pipeline to work : %d",
			  *min_buffers);

                *max_width = g_key_file_get_integer(conf_key, groups[i],
                                                      "max-width", NULL);
                *max_height = g_key_file_get_integer(conf_key, groups[i],
                                                      "max-height", NULL);
		break;
	}

	ret = TRUE;

free_groups:
	g_strfreev(groups);
free_key_file:
	g_key_file_free(conf_key);

	return ret;
}

static GstElement *
create_pipeline(gchar *pipeline_str)
{
	gchar *launch_str;
	GstElement *pipeline;
	GError *err = NULL;

	launch_str = g_strdup_printf("appsrc ! %s ! appsink sync=false",
				     pipeline_str);

	GST_DEBUG("gst_parse_launch: %s", launch_str);

	pipeline = gst_parse_launch(launch_str, &err);
	g_free(launch_str);

	if (err) {
		GST_ERROR("Couldn't construct pipeline: %s",
			  err->message);
		g_error_free(err);
		return NULL;
	}

	return pipeline;
}

static gboolean
get_app_elements(GstElement *pipeline, GstElement **appsrc,
		 GstElement **appsink)
{
	GstIterator *it;
	gboolean done = FALSE;
	GValue data = { 0, };
	GstElement *elem;
	GstElement *src_elem, *sink_elem;
	GstElementFactory *factory;
	const gchar *elem_name;

	src_elem = sink_elem = NULL;

	it = gst_bin_iterate_elements(GST_BIN(pipeline));
	while (!done) {
		switch (gst_iterator_next(it, &data)) {
		case GST_ITERATOR_OK:
			elem = g_value_get_object(&data);

			factory = gst_element_get_factory(elem);
			elem_name =
				gst_element_factory_get_metadata(factory,
						GST_ELEMENT_METADATA_LONGNAME);
			if (g_strcmp0(elem_name, "AppSrc") == 0)
				src_elem = elem;
			else if (g_strcmp0(elem_name, "AppSink") == 0)
				sink_elem = elem;

			g_value_reset(&data);
			break;
		case GST_ITERATOR_DONE:
		default:
			done = TRUE;
			break;
		}
	}

	g_value_unset(&data);
	gst_iterator_free(it);

	if (!src_elem || !sink_elem) {
		GST_ERROR("Failed to get app elements from the pipeline");
		return FALSE;
	}

	*appsrc = src_elem;
	*appsink = sink_elem;

	GST_DEBUG("appsrc and appsink elements are found in the pipeline");

	return TRUE;
}

static void
get_buffer_pool_ops(gchar *pool_lib_path, void **pool_lib_handle,
		    struct libv4l_gst_buffer_pool_ops **pool_ops)
{
	void *handle;
	gchar *err;
	struct libv4l_gst_buffer_pool_ops *ops;

	/* This dynamic linking will keep loaded even after the plugin has been
	   closed in order to prevent from the duplicate class registration of
	   the buffer pool due to the static variable that indicates if
	   the class has already been registered being deleted when the dynamic
	   library is unloaded. */
	handle = dlopen(pool_lib_path, RTLD_LAZY);
	if (!handle) {
		GST_ERROR("dlopen failed (%s)", dlerror());
		return;
	}

	dlerror(); /* Clear any existing error */

	ops = dlsym(handle, "libv4l_gst_bufferpool");
	err = dlerror();
	if (err) {
		GST_ERROR("dlsym failed (%s)", err);
		dlclose(handle);
		return;
	}

	*pool_lib_handle = handle;
	*pool_ops = ops;

	GST_DEBUG("buffer pool ops is set");
}

static guint
convert_video_format_gst_to_v4l2(GstVideoFormat fmt)
{
	gint i;
	guint fourcc = 0;

	for (i = 0; i < G_N_ELEMENTS(v4l_gst_vid_fmt_tbl); i++) {
		if (v4l_gst_vid_fmt_tbl[i].format == fmt)
			fourcc = v4l_gst_vid_fmt_tbl[i].fourcc;
	}

	return fourcc;
}

static GstVideoFormat
convert_video_format_v4l2_to_gst(guint fourcc)
{
	gint i;
	GstVideoFormat fmt = GST_VIDEO_FORMAT_UNKNOWN;

	for (i = 0; i < G_N_ELEMENTS(v4l_gst_vid_fmt_tbl); i++) {
		if (v4l_gst_vid_fmt_tbl[i].fourcc == fourcc)
			fmt = v4l_gst_vid_fmt_tbl[i].format;
	}

	return fmt;
}

static const gchar *
convert_codec_type_v4l2_to_gst(guint fourcc)
{
	const gchar *mime;

	if (fourcc == V4L2_PIX_FMT_H264)
		mime = GST_VIDEO_CODEC_MIME_H264;
	else if (fourcc == V4L2_PIX_FMT_VP8)
		mime = GST_VIDEO_CODEC_MIME_VP8;
	else
		mime = NULL;

	return mime;
}

static GstPad *
get_peer_pad(GstElement *elem, const gchar *pad_name)
{
	GstPad *pad;
	GstPad *peer_pad;

	pad = gst_element_get_static_pad(elem, pad_name);
	peer_pad = gst_pad_get_peer(pad);
	gst_object_unref(pad);

	return peer_pad;
}

static GstElement *
get_peer_element(GstElement *elem, const gchar *pad_name)
{
	GstPad *peer_pad;
	GstElement *peer_elem;

	peer_pad = get_peer_pad(elem, pad_name);
	peer_elem = gst_pad_get_parent_element(peer_pad);
	gst_object_unref(peer_pad);

	return peer_elem;
}

static GstCaps *
get_peer_pad_template_caps(GstElement *elem, const gchar *pad_name)
{
	GstPad *peer_pad;
	GstCaps *caps;

	peer_pad = get_peer_pad(elem, pad_name);
	caps = GST_PAD_TEMPLATE_CAPS(GST_PAD_PAD_TEMPLATE(peer_pad));
	gst_caps_ref(caps);
	gst_object_unref(peer_pad);

	return caps;
}

static gboolean
get_supported_video_format_out(GstElement *appsrc, struct fmts **out_fmts,
			       gint *out_fmts_num)
{
	GstCaps *caps;
	GstStructure *structure;
	const gchar *mime;
	guint fourcc;

	caps = get_peer_pad_template_caps(appsrc, "src");

	if (gst_caps_is_any(caps)) {
		/* H.264 and VP8 codecs are supported in this plugin.
		   We treat all the codecs when GST_CAPS_ANY is set as
		   a template caps. */
		*out_fmts_num = 2;
		*out_fmts = g_new0(struct fmts, *out_fmts_num);

		(*out_fmts)[0].fmt = V4L2_PIX_FMT_H264;
		(*out_fmts)[1].fmt = V4L2_PIX_FMT_VP8;
		g_strlcpy((*out_fmts)[0].fmt_char, "V4L2_PIX_FMT_H264", FMTDESC_NAME_LENGTH);
		g_strlcpy((*out_fmts)[1].fmt_char, "V4L2_PIX_FMT_VP8", FMTDESC_NAME_LENGTH);

		GST_DEBUG("out supported codecs : h264, vp8");
	} else {
		structure = gst_caps_get_structure(caps, 0);
		mime = gst_structure_get_name(structure);

		if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_H264) == 0) {
			fourcc = V4L2_PIX_FMT_H264;
		} else if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_VP8) == 0) {
			fourcc = V4L2_PIX_FMT_VP8;
		} else {
			GST_ERROR("Unsupported codec : %s", mime);
			gst_caps_unref(caps);
			return FALSE;
		}

		GST_DEBUG("out supported codec : %s", mime);

		*out_fmts_num = 1;
		*out_fmts = g_new0(struct fmts, *out_fmts_num);

		(*out_fmts)[0].fmt = fourcc;
		if(fourcc == V4L2_PIX_FMT_H264)
			g_strlcpy((*out_fmts)[0].fmt_char, "V4L2_PIX_FMT_H264", FMTDESC_NAME_LENGTH);
		else
			g_strlcpy((*out_fmts)[0].fmt_char, "V4L2_PIX_FMT_VP8", FMTDESC_NAME_LENGTH);
	}

	gst_caps_unref(caps);

	return TRUE;
}

static gboolean
get_supported_video_format_cap(GstElement *appsink, struct fmts **cap_fmts,
			       gint *cap_fmts_num)
{
	GstCaps *caps;
	GstStructure *structure;
	guint structs;
	const GValue *val, *list_val;
	const gchar *fmt_str;
	GstVideoFormat fmt;
	guint fourcc;
	gint list_size;
	gint fmts_num;
	guint i, j;
	struct fmts *color_fmts = NULL;

	caps = get_peer_pad_template_caps(appsink, "sink");

	/* We treat GST_CAPS_ANY as all video formats support. */
	if (gst_caps_is_any(caps)) {
		gst_caps_unref(caps);
		caps = gst_caps_from_string
				("video/x-raw, format=" GST_VIDEO_FORMATS_ALL);
	}

	structs = gst_caps_get_size(caps);
	list_size = 2; // Add space for legacy RGB formats if available */
	fmts_num = 0;

	for (j = 0; j < structs; j++) {
	        gint num_cap_formats;
		structure = gst_caps_get_structure(caps, j);
		val = gst_structure_get_value(structure, "format");
		if (!val)
			continue;

		num_cap_formats = gst_value_list_get_size(val);
		list_size += num_cap_formats;
		color_fmts = g_renew(struct fmts, color_fmts, list_size);

		for (i = 0; i < num_cap_formats; i++) {
			list_val = gst_value_list_get_value(val, i);
			fmt_str = g_value_get_string(list_val);

			fmt = gst_video_format_from_string(fmt_str);
			if (fmt == GST_VIDEO_FORMAT_UNKNOWN) {
				GST_ERROR("Unknown video format : %s", fmt_str);
				continue;
			}

			fourcc = convert_video_format_gst_to_v4l2(fmt);
			if (fourcc == 0) {
				GST_DEBUG("Failed to convert video format "
					  "from gst to v4l2 : %s", fmt_str);
				continue;
			}

			GST_DEBUG("cap supported video format : %s", fmt_str);

			color_fmts[fmts_num].fmt = fourcc;
			g_strlcpy(color_fmts[fmts_num++].fmt_char, fmt_str,
				FMTDESC_NAME_LENGTH);

			/* Add legacy RGB formats */
			if (fourcc == V4L2_PIX_FMT_ARGB32) {
				color_fmts[fmts_num].fmt = V4L2_PIX_FMT_RGB32;
				g_strlcpy(color_fmts[fmts_num++].fmt_char,
					fmt_str, FMTDESC_NAME_LENGTH);
			} else if (fourcc == V4L2_PIX_FMT_ABGR32) {
				color_fmts[fmts_num].fmt = V4L2_PIX_FMT_BGR32;
				g_strlcpy(color_fmts[fmts_num++].fmt_char,
					fmt_str, FMTDESC_NAME_LENGTH);
			}
		}
	}

	gst_caps_unref(caps);

	if (fmts_num == 0) {
		GST_ERROR("Failed to get video formats from caps");
		return FALSE;
	}

	*cap_fmts_num = fmts_num;
	*cap_fmts = color_fmts;

	GST_DEBUG("The total number of cap supported video format : %d",
		  *cap_fmts_num);


	return TRUE;
}

static void
create_buffer_pool(struct libv4l_gst_buffer_pool_ops *pool_ops,
		   GstBufferPool **src_pool, GstBufferPool **sink_pool)
{
	if (pool_ops) {
		if (pool_ops->add_external_src_buffer_pool)
			*src_pool = pool_ops->add_external_src_buffer_pool();

		if (pool_ops->add_external_sink_buffer_pool)
			*sink_pool = pool_ops->add_external_sink_buffer_pool();
	}

	/* fallback to the default buffer pool */
	if (!*src_pool)
		*src_pool = gst_buffer_pool_new();
	if (!*sink_pool)
		*sink_pool = gst_buffer_pool_new();
}

static void
set_buffer_pool_params(GstBufferPool *pool, GstCaps *caps, guint buf_size,
		       guint min_buffers, guint max_buffers)
{
	GstStructure *config;

	config = gst_buffer_pool_get_config(pool);
	gst_buffer_pool_config_set_params(config, caps, buf_size, min_buffers,
					  max_buffers);
	gst_buffer_pool_set_config(pool, config);
}

static void
get_buffer_pool_params(GstBufferPool *pool, GstCaps **caps, guint *buf_size,
		       guint *min_buffers, guint *max_buffers)
{
	GstStructure *config;

	config = gst_buffer_pool_get_config(pool);
	gst_buffer_pool_config_get_params(config, caps, buf_size, min_buffers,
					  max_buffers);
	gst_structure_free(config);
}

static void
retrieve_cap_format_info(struct gst_backend_priv *priv, GstVideoInfo *info)
{
	gint fourcc;

	priv->cap_pix_fmt.width = info->width;
	priv->cap_pix_fmt.height = info->height;

	fourcc = convert_video_format_gst_to_v4l2(info->finfo->format);
	if (priv->cap_pix_fmt.pixelformat != 0 &&
	    priv->cap_pix_fmt.pixelformat != fourcc) {
		GST_WARNING("Unexpected cap video format");
	}
	priv->cap_pix_fmt.pixelformat = fourcc;

	priv->cap_pix_fmt.num_planes = info->finfo->n_planes;
}

static void
wait_for_cap_reqbuf_invocation(struct gst_backend_priv *priv)
{
	g_mutex_lock(&priv->cap_reqbuf_mutex);
	while (priv->cap_buffers_num <= 0)
		g_cond_wait(&priv->cap_reqbuf_cond, &priv->cap_reqbuf_mutex);
	g_mutex_unlock(&priv->cap_reqbuf_mutex);
}

static inline void
release_out_buffer_unlocked(struct gst_backend_priv *priv, GstBuffer *buffer)
{
	GST_TRACE("unref buffer: %p", buffer);
	gst_buffer_unref(buffer);

	set_event(priv->dev_ops_priv->event_state, POLLIN);

	priv->returned_out_buffers_num++;
}

static inline void
release_out_buffer(struct gst_backend_priv *priv, GstBuffer *buffer)
{
	g_mutex_lock(&priv->queue_mutex);

	release_out_buffer_unlocked(priv, buffer);

	g_mutex_unlock(&priv->queue_mutex);
}

static GstPadProbeReturn
pad_probe_query(GstPad *pad, GstPadProbeInfo *probe_info, gpointer user_data)
{
	struct gst_backend_priv *priv = user_data;
	GstQuery *query;
	GstCaps *caps;
	GstVideoInfo info;

	query = GST_PAD_PROBE_INFO_QUERY (probe_info);
	if (GST_QUERY_TYPE (query) == GST_QUERY_ALLOCATION &&
	    GST_PAD_PROBE_INFO_TYPE (probe_info) & GST_PAD_PROBE_TYPE_PUSH) {
		GST_DEBUG("parse allocation query");
		gst_query_parse_allocation(query, &caps, NULL);
		if (!caps) {
			GST_ERROR("No caps in query");
			return GST_PAD_PROBE_OK;
		}

		if (!gst_video_info_from_caps(&info, caps)) {
			GST_ERROR("Failed to get video info");
			return GST_PAD_PROBE_OK;
		}

		/* Workaround: gst-omx arouses caps negotiations toward
		   downstream twice.
		   The first of them always has the QCIF resolution
		   and we skip it to receive the only second query that
		   has the actual video parameters. */
		if (info.width == 176 && info.height == 144)
			return GST_PAD_PROBE_OK;

		retrieve_cap_format_info(priv, &info);

		g_atomic_int_set(&priv->is_cap_fmt_acquirable, 1);

	        set_event(priv->dev_ops_priv->event_state, POLLOUT);
		wait_for_cap_reqbuf_invocation(priv);

		set_buffer_pool_params(priv->sink_pool, caps, info.size,
				       priv->cap_buffers_num - 4, /* XXX */
				       priv->cap_buffers_num);

		gst_query_add_allocation_pool(query, priv->sink_pool,
					      info.size,
					      priv->cap_buffers_num - 4, /* XXX */
					      priv->cap_buffers_num);
	}

	return GST_PAD_PROBE_OK;
}

static gulong
setup_query_pad_probe(struct gst_backend_priv *priv)
{
	GstPad *peer_pad;
	gulong probe_id;

	peer_pad = get_peer_pad(priv->appsink, "sink");
	probe_id = gst_pad_add_probe(peer_pad,
				     GST_PAD_PROBE_TYPE_QUERY_DOWNSTREAM,
				     (GstPadProbeCallback) pad_probe_query,
				     priv, NULL);
	gst_object_unref(peer_pad);

	return probe_id;
}

static GstBuffer *
pull_buffer_from_sample(GstAppSink *appsink)
{
	GstSample *sample;
	GstBuffer *buffer;

	sample = gst_app_sink_pull_sample(appsink);
	buffer = gst_sample_get_buffer(sample);
	gst_buffer_ref(buffer);
	gst_sample_unref(sample);

	return buffer;
}

void
appsink_callback_eos(GstAppSink *appsink, gpointer user_data)
{
	struct gst_backend_priv *priv = user_data;
	if (priv->eos_buffer)
		release_out_buffer(priv, priv->eos_buffer);
	GST_DEBUG("Got EOS event");
}

static GstFlowReturn
appsink_callback_new_sample(GstAppSink *appsink, gpointer user_data)
{
	struct gst_backend_priv *priv = user_data;
	GstBuffer *buffer;
	gboolean is_empty;
	GQueue *queue;

	buffer = pull_buffer_from_sample(appsink);

	GST_TRACE("pull buffer: %p", buffer);

	if (priv->cap_buffers)
		queue = priv->cap_buffers_queue;
	else
		queue = priv->reqbufs_queue;

	g_mutex_lock(&priv->queue_mutex);

	is_empty = g_queue_is_empty(queue);
	g_queue_push_tail(queue, buffer);

	if (is_empty) {
		g_cond_signal(&priv->queue_cond);
		set_event(priv->dev_ops_priv->event_state, POLLOUT);
	} else if (!priv->cap_buffers) {
		g_cond_signal(&priv->queue_cond);
	}

	g_mutex_unlock(&priv->queue_mutex);

	return GST_FLOW_OK;
}

static gboolean
init_app_elements(struct gst_backend_priv *priv)
{
	struct fmts *out_fmts;
	gint out_fmts_num;
	struct fmts *cap_fmts;
	gint cap_fmts_num;

	/* Get appsrc and appsink elements respectively from the pipeline */
	if (!get_app_elements(priv->pipeline, &priv->appsrc, &priv->appsink))
		return FALSE;

	/* Set the appsrc queue size to unlimited.
	   The amount of buffers is managed by the buffer pool. */
	gst_app_src_set_max_bytes(GST_APP_SRC(priv->appsrc), 0);

	priv->appsink_cb.new_sample = appsink_callback_new_sample;
	priv->appsink_cb.eos = appsink_callback_eos;

	gst_app_sink_set_callbacks(GST_APP_SINK(priv->appsink),
				   &priv->appsink_cb, priv, NULL);

	/* For queuing buffers received from appsink */
	priv->cap_buffers_queue = g_queue_new();
	priv->reqbufs_queue = g_queue_new();
	g_mutex_init(&priv->queue_mutex);
	g_cond_init(&priv->queue_cond);

	if (!get_supported_video_format_out(priv->appsrc, &out_fmts,
					    &out_fmts_num))
		return FALSE;
	if (!get_supported_video_format_cap(priv->appsink, &cap_fmts,
					    &cap_fmts_num)) {
		g_free(out_fmts);
		return FALSE;
	}
	priv->out_fmts = out_fmts;
	priv->out_fmts_num = out_fmts_num;
	priv->cap_fmts = cap_fmts;
	priv->cap_fmts_num = cap_fmts_num;

	return TRUE;
}

static gboolean
init_buffer_pool(struct gst_backend_priv *priv, gchar *pool_lib_path)
{
	/* Get the external buffer pool when it is specified in
	   the configuration file */
	if (pool_lib_path) {
		get_buffer_pool_ops(pool_lib_path,
				    &priv->pool_lib_handle, &priv->pool_ops);
	}

	create_buffer_pool(priv->pool_ops, &priv->src_pool, &priv->sink_pool);

	/* To hook allocation queries */
	priv->probe_id = setup_query_pad_probe(priv);
	if (priv->probe_id == 0) {
		GST_ERROR("Failed to setup query pad probe");
		goto free_pool;
	}

	/* To wait for the requested number of buffers on CAPTURE
	   to be set in pad_probe_query() */
	g_mutex_init(&priv->cap_reqbuf_mutex);
	g_cond_init(&priv->cap_reqbuf_cond);

	return TRUE;

	/* error cases */
free_pool:
	gst_object_unref(priv->src_pool);
	gst_object_unref(priv->sink_pool);

	return FALSE;
}

int
gst_backend_init(struct v4l_gst_priv *dev_ops_priv)
{
	struct gst_backend_priv *priv;
	gchar *pipeline_str = NULL;
	gchar *pool_lib_path = NULL;

	priv = calloc(1, sizeof(*priv));
	if (!priv) {
		perror("Couldn't allocate memory for gst-backend");
		return -1;
	}

	priv->dev_ops_priv = dev_ops_priv;

	gst_init(NULL, NULL);
        GST_DEBUG_CATEGORY_INIT(v4l_gst_debug_category, "v4l-gst", 0, "debug category for v4l-gst application");

	if (!parse_conf_settings(&pipeline_str, &pool_lib_path,
				 &priv->cap_min_buffers,
				 &priv->max_width,
				 &priv->max_height))
		goto free_priv;

	priv->pipeline = create_pipeline(pipeline_str);
	g_free(pipeline_str);

	if (!priv->pipeline)
		goto free_pool_path;

	/* Initialization regarding appsrc and appsink elements */
	if (!init_app_elements(priv))
		goto free_pipeline;

	if (!init_buffer_pool(priv, pool_lib_path))
		goto free_app_elems_init_objs;
	g_free(pool_lib_path);

	g_mutex_init(&priv->dev_lock);

	dev_ops_priv->gst_priv = priv;

	return 0;

	/* error cases */
free_app_elems_init_objs:
	g_queue_free(priv->cap_buffers_queue);
	g_queue_free(priv->reqbufs_queue);
	g_mutex_clear(&priv->queue_mutex);
	g_cond_clear(&priv->queue_cond);

	g_free(priv->out_fmts);
	g_free(priv->cap_fmts);
free_pipeline:
	gst_object_unref(priv->pipeline);
free_pool_path:
	g_free(pool_lib_path);
free_priv:
	g_free(priv);

	return -1;
}

static void
remove_query_pad_probe(GstElement *appsink, gulong probe_id)
{
	GstPad *peer_pad;

	peer_pad = get_peer_pad(appsink, "sink");
	gst_pad_remove_probe(peer_pad, probe_id);
	gst_object_unref(peer_pad);
}

void
gst_backend_deinit(struct v4l_gst_priv *dev_ops_priv)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;

	g_mutex_clear(&priv->dev_lock);

	remove_query_pad_probe(priv->appsink, priv->probe_id);

	if (priv->out_buffers)
		g_free(priv->out_buffers);

	if (priv->cap_buffers)
		g_free(priv->cap_buffers);

	gst_object_unref(priv->src_pool);
	gst_object_unref(priv->sink_pool);

	g_free(priv->out_fmts);
	g_free(priv->cap_fmts);

	g_queue_free(priv->cap_buffers_queue);
	g_queue_free(priv->reqbufs_queue);
	g_mutex_clear(&priv->queue_mutex);
	g_cond_clear(&priv->queue_cond);

	g_mutex_clear(&priv->cap_reqbuf_mutex);
	g_cond_clear(&priv->cap_reqbuf_cond);

	gst_object_unref(priv->pipeline);
}

int
querycap_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_capability *cap)
{
#if 0
	GST_DEBUG("VIDIOC_QUERYCAP(querycap_ioctl) driver: %s card: %s bus_info: %s version: %s\n", cap->driver, cap->card, cap->bus_info, cap->version);
#else
	GST_DEBUG("VIDIOC_QUERYCAP(querycap_ioctl)\n");
#endif
	cap->device_caps = V4L2_CAP_VIDEO_M2M_MPLANE
#ifdef ENABLE_CHROMIUM_COMPAT
			| V4L2_CAP_VIDEO_CAPTURE_MPLANE
			| V4L2_CAP_VIDEO_OUTPUT_MPLANE
#endif
			| V4L2_CAP_EXT_PIX_FORMAT
			| V4L2_CAP_STREAMING;

	cap->capabilities = cap->device_caps | V4L2_CAP_DEVICE_CAPS;

	g_strlcpy((gchar *)cap->driver, "libv4l-gst", sizeof(cap->driver));
	g_strlcpy((gchar *)cap->card, "gst-dummy", sizeof(cap->card));
	g_strlcpy((gchar *)cap->bus_info, "user-vst-gst-000", sizeof(cap->bus_info));
	memset(cap->reserved, 0, sizeof(cap->reserved));

	return 0;
}

static gboolean
is_pix_fmt_supported(struct fmts *fmts, gint fmts_num, guint fourcc)
{
	gint i;
	gboolean ret = FALSE;

	for (i = 0; i < fmts_num; i++) {
		if (fmts[i].fmt == fourcc) {
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
set_fmt_ioctl_out(struct gst_backend_priv *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;

	pix_fmt = &fmt->fmt.pix_mp;

	if (!is_pix_fmt_supported(priv->out_fmts, priv->out_fmts_num,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	if (pix_fmt->plane_fmt[0].sizeimage == 0) {
		GST_ERROR("sizeimage field is not specified on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	priv->out_fourcc = pix_fmt->pixelformat;
	priv->out_buf_size = pix_fmt->plane_fmt[0].sizeimage;

	set_params_as_encoded_stream(pix_fmt);

	return 0;
}

static void
init_decoded_frame_params(struct v4l2_pix_format_mplane *pix_fmt)
{
	/* The following parameters will be determined after
	   the video decoding starts. */
	pix_fmt->width = 0;
	pix_fmt->height = 0;
	pix_fmt->num_planes = 0;
	memset(pix_fmt->plane_fmt, 0, sizeof(pix_fmt->plane_fmt));
}

static int
set_fmt_ioctl_cap(struct gst_backend_priv *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;

	pix_fmt = &fmt->fmt.pix_mp;

	if (!is_pix_fmt_supported(priv->cap_fmts, priv->cap_fmts_num,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on CAPTURE");
		errno = EINVAL;
		return -1;
	}

	priv->cap_pix_fmt.pixelformat = pix_fmt->pixelformat;

	init_decoded_frame_params(pix_fmt);

	/* set unsupported parameters */
	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;

	return 0;
}

int
set_fmt_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_format *fmt)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_S_FMT:set_fmt_ioctl: type: 0x%x\n", fmt->type);

	g_mutex_lock(&priv->dev_lock);

	GST_OBJECT_LOCK(priv->pipeline);
	if (GST_STATE(priv->pipeline) != GST_STATE_NULL) {
		GST_ERROR("The pipeline is already running");
		errno = EBUSY;
		GST_OBJECT_UNLOCK(priv->pipeline);
		g_mutex_unlock(&priv->dev_lock);
		return -1;
	}
	GST_OBJECT_UNLOCK(priv->pipeline);

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
get_fmt_ioctl_cap(struct gst_backend_priv *priv,
		  struct v4l2_pix_format_mplane *pix_fmt)
{
	gint i;

	if (!g_atomic_int_get(&priv->is_cap_fmt_acquirable) ||
        	    priv->out_cnt < INPUT_BUFFERING_CNT) {
		errno = EINVAL;
		return -1;
	}

	GST_DEBUG("cap format is acquirable. out_cnt = %d",priv->out_cnt);

	pix_fmt->width = priv->cap_pix_fmt.width;
	pix_fmt->height = priv->cap_pix_fmt.height;
	pix_fmt->pixelformat = priv->cap_pix_fmt.pixelformat;
	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;
	pix_fmt->num_planes = priv->cap_pix_fmt.num_planes;

	GST_DEBUG("width:%d height:%d num_plnaes=%d",
		  pix_fmt->width, pix_fmt->height, pix_fmt->num_planes);

	if (priv->cap_pix_fmt.plane_fmt[0].sizeimage > 0) {
		for (i = 0; i < pix_fmt->num_planes; i++) {
			pix_fmt->plane_fmt[i].sizeimage =
					priv->
					cap_pix_fmt.plane_fmt[i].sizeimage;
			pix_fmt->plane_fmt[i].bytesperline =
					priv->
					cap_pix_fmt.plane_fmt[i].bytesperline;
		}
		pix_fmt->num_planes = priv->cap_pix_fmt.num_planes;
	} else {
		memset(pix_fmt->plane_fmt, 0, sizeof(pix_fmt->plane_fmt));
	}

	return 0;
}

int
get_fmt_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_format *fmt)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	struct v4l2_pix_format_mplane *pix_fmt;
	int ret;

	GST_DEBUG("VIDIOC_G_FMT:get_fmt_ioctl: type: 0x%x\n", fmt->type);

	pix_fmt = &fmt->fmt.pix_mp;

	if (fmt->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		g_mutex_lock(&priv->dev_lock);
		pix_fmt->pixelformat = priv->out_fourcc;
		pix_fmt->plane_fmt[0].sizeimage = priv->out_buf_size;
		g_mutex_unlock(&priv->dev_lock);
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
enum_fmt_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_fmtdesc *desc)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	struct fmts *fmts;
	gint fmts_num;

	GST_DEBUG("VIDIOC_ENUM_FMT:enum_fmt_ioctl: type: 0x%x index: %d flags:0x%x description: %s pixelformat: 0x%x\n",
		  desc->type, desc->index, desc->flags, desc->description, desc->pixelformat);

	if (!priv->out_fmts || !priv->cap_fmts) {
		GST_ERROR("Supported formats lists are not prepared");
		errno = EINVAL;
		return -1;
	}

	if (desc->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		fmts = priv->out_fmts;
		fmts_num = priv->out_fmts_num;
		desc->flags = V4L2_FMT_FLAG_COMPRESSED;
	} else if (desc->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		fmts = priv->cap_fmts;
		fmts_num = priv->cap_fmts_num;
		desc->flags = 0;
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		return -1;
	}

	if (fmts_num <= desc->index) {
		errno = EINVAL;
		return -1;
	}

	desc->pixelformat = fmts[desc->index].fmt;
	g_strlcpy((gchar *)desc->description, fmts[desc->index].fmt_char,
		   sizeof(desc->description));
	memset(desc->reserved, 0, sizeof(desc->reserved));

	return 0;
}
int
enum_framesizes_ioctl (struct v4l_gst_priv *dev_ops_priv, struct v4l2_frmsizeenum *argp) {
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;

	GST_DEBUG("VIDIOC_ENUM_FRAMESIZES:enum_framesizes_ioctl: type: 0x%x index: %d pixel_format: 0x%x\n", argp->type, argp->index, argp->pixel_format);

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
	argp->stepwise.max_width = priv->max_width ?
		priv->max_width : 1920;
	argp->stepwise.max_height = priv->max_height ?
		priv->max_height : 1088;

	return 0;
}

int
get_ctrl_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_control *ctrl)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_G_CTRL:get_ctrl_ioctl: id: 0x%x value: 0x%x\n", ctrl->id, ctrl->value);

	switch (ctrl->id) {
	case V4L2_CID_MIN_BUFFERS_FOR_CAPTURE:
		ctrl->value = priv->cap_min_buffers;
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
get_ext_ctrl_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_ext_controls *ext_ctrls)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	unsigned int i;

	GST_DEBUG("VIDIOC_G_EXT_CTRLS:get_ext_ctrl_ioctl: count: %d\n", ext_ctrls->count);

	for (i = 0; i < ext_ctrls->count; i++) {
		struct v4l2_ext_control *ext_ctrl = &ext_ctrls->controls[i];
		if (ext_ctrl->id == V4L2_CID_MIN_BUFFERS_FOR_CAPTURE) {
			ext_ctrl->value = priv->cap_min_buffers;
			continue;
		}
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static gboolean
is_supported_memory_io(enum v4l2_memory memory)
{
	if (memory != V4L2_MEMORY_MMAP) {
		errno = EINVAL;
		return FALSE;
	}

	return TRUE;
}

static gboolean
get_raw_video_params(GstBufferPool *pool, GstBuffer *buffer, GstVideoInfo *info,
		     GstVideoMeta **meta)
{
	gboolean ret;
	GstCaps *caps;
	GstVideoInfo vinfo;
	GstVideoMeta *vmeta;

	get_buffer_pool_params(pool, &caps, NULL, NULL, NULL);

	ret = gst_video_info_from_caps(&vinfo, caps);
	if (!ret || GST_VIDEO_INFO_FORMAT(&vinfo) == GST_VIDEO_FORMAT_ENCODED)
		return FALSE;

	vmeta = gst_buffer_get_video_meta(buffer);
	if (!vmeta)
		return FALSE;

	if (info)
		memcpy(info, &vinfo, sizeof(GstVideoInfo));
	if (meta)
		*meta = vmeta;

	return TRUE;
}

/* This check passes through the verification of the buffer index. */
static gboolean
check_no_index_v4l2_buffer(struct v4l2_buffer *buf,
			   struct v4l_gst_buffer *buffers, GstBufferPool *pool)
{
	GstVideoMeta *meta;
	guint n_planes;

	if (!is_supported_memory_io(buf->memory))
		return FALSE;

	if (!buf->m.planes) {
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

	if (get_raw_video_params(pool, buffers[buf->index].buffer, NULL,
				 &meta))
		n_planes = meta->n_planes;
	else
		n_planes = 1;

	if (buf->length < n_planes || buf->length > VIDEO_MAX_PLANES) {
		GST_ERROR("Incorrect planes array length");
		errno = EINVAL;
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_v4l2_buffer(struct v4l2_buffer *buf, struct v4l_gst_buffer *buffers,
		  gint buffers_num, GstBufferPool *pool)
{
	if (!check_no_index_v4l2_buffer(buf, buffers, pool))
		return FALSE;

	if (buf->index >= buffers_num) {
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
	struct gst_backend_priv *priv;

	priv = buffer->priv;

	release_out_buffer(priv, buffer->buffer);
}

static int
qbuf_ioctl_out(struct gst_backend_priv *priv, struct v4l2_buffer *buf)
{
	GstFlowReturn flow_ret;
	GstBuffer *wrapped_buffer;
	GstMapInfo info;
	struct v4l_gst_buffer *buffer;

	if (!check_v4l2_buffer(buf, priv->out_buffers, priv->out_buffers_num,
			       priv->src_pool))
		return -1;

	buffer = &priv->out_buffers[buf->index];

	if (buf->m.planes[0].bytesused == 0) {
		flow_ret = gst_app_src_end_of_stream(GST_APP_SRC(priv->appsrc));
		if (flow_ret != GST_FLOW_OK) {
			GST_ERROR("Failed to send an EOS event");
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("Send EOS event");

		gst_buffer_unmap(buffer->buffer, &buffer->info);
		memset(&buffer->info, 0, sizeof(buffer->info));

		buffer->state = V4L_GST_BUFFER_QUEUED;
		priv->eos_buffer = buffer->buffer;

		return 0;
	}

	if (buffer->state == V4L_GST_BUFFER_QUEUED) {
		GST_ERROR("Invalid buffer state");
		errno = EINVAL;
		return -1;
	}

	GST_TRACE("queue index=%d buffer=%p", buf->index,
		  priv->out_buffers[buf->index].buffer);

	gst_buffer_unmap(buffer->buffer, &buffer->info);
	memset(&buffer->info, 0, sizeof(buffer->info));

	/* Rewrap an input buffer with the just size of bytesused
	   because it will be regarded as having data filled to the entire
	   buffer size internally in the GStreame pipeline.
	   Also set the destructor (notify_unref()). */

	if (!gst_buffer_map(buffer->buffer, &info, GST_MAP_READ)) {
		GST_ERROR("Failed to map buffer (%p)", buffer->buffer);
		errno = EINVAL;
		return -1;
	}

	wrapped_buffer = gst_buffer_new_wrapped_full(
					GST_MEMORY_FLAG_READONLY, info.data,
					buf->m.planes[0].bytesused, 0,
					buf->m.planes[0].bytesused,
					buffer, notify_unref);

	gst_buffer_unmap(buffer->buffer, &info);

	GST_TRACE("buffer rewrap ts=%ld", buf->timestamp.tv_sec);
	GST_BUFFER_PTS(wrapped_buffer) = GST_TIMEVAL_TO_TIME(buf->timestamp);

	buffer->state = V4L_GST_BUFFER_QUEUED;

	flow_ret = gst_app_src_push_buffer(
			GST_APP_SRC(priv->appsrc), wrapped_buffer);
	if (flow_ret != GST_FLOW_OK) {
		GST_ERROR("Failed to push a buffer to the pipeline on OUTPUT"
			  "(index=%d)", buf->index);
		errno = EINVAL;
		return -1;
	}

        if (priv->out_cnt < INPUT_BUFFERING_CNT)
            priv->out_cnt++;

	return 0;
}

static gboolean
push_to_cap_buffers_queue(struct gst_backend_priv *priv, GstBuffer *buffer)
{
	gboolean is_empty;
	gint index;

	index = g_queue_index(priv->reqbufs_queue, buffer);
	if (index < 0)
		return FALSE;

	g_mutex_lock(&priv->queue_mutex);

	is_empty = g_queue_is_empty(priv->cap_buffers_queue);
	g_queue_push_tail(priv->cap_buffers_queue, buffer);

	if (is_empty)
		g_cond_signal(&priv->queue_cond);

	g_mutex_unlock(&priv->queue_mutex);

	g_queue_pop_nth_link(priv->reqbufs_queue, index);

	return TRUE;
}

static int
qbuf_ioctl_cap(struct gst_backend_priv *priv, struct v4l2_buffer *buf)
{
	struct v4l_gst_buffer *buffer;

	if (!check_v4l2_buffer(buf, priv->cap_buffers, priv->cap_buffers_num,
			       priv->sink_pool))
		return -1;

	buffer = &priv->cap_buffers[buf->index];

	if (buffer->state == V4L_GST_BUFFER_QUEUED) {
		GST_ERROR("Invalid buffer state");
		errno = EINVAL;
		return -1;
	}

	gst_buffer_unmap(buffer->buffer, &buffer->info);
	memset(&buffer->info, 0, sizeof(buffer->info));

	/* The buffers in reqbufs_queue, which are pushed by the REQBUF ioctl
	   on CAPTURE, have already contained decoded frames.
	   They should not back to the buffer pool and prepare to be
	   dequeued as they are. */
	if (g_queue_get_length(priv->reqbufs_queue) > 0) {
		GST_TRACE("push_to_cap_buffers_queue index=%d", buf->index);
		if (push_to_cap_buffers_queue(priv, buffer->buffer)) {
			buffer->state =V4L_GST_BUFFER_QUEUED;
			return 0;
		}
	}

	GST_TRACE("unref buffer: %p, index=%d", buffer->buffer, buf->index);
	buffer->state = V4L_GST_BUFFER_QUEUED;

	gst_buffer_unref(buffer->buffer);

	return 0;
}

int
qbuf_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_buffer *buf)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_QBUF:qbuf_ioctl: type: 0x%x index: %d flags: 0x%x\n", buf->type, buf->index, buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = qbuf_ioctl_out(priv, buf);
		if (ret < 0) {
			g_mutex_unlock(&priv->dev_lock);
			return ret;
		}
	} else if (buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = qbuf_ioctl_cap(priv, buf);
		if (ret < 0) {
			g_mutex_unlock(&priv->dev_lock);
			return 0;
		}
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		g_mutex_unlock(&priv->dev_lock);
		return -1;
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
set_v4l2_buffer_plane_params(struct gst_backend_priv *priv,
			     struct v4l_gst_buffer *buffers, guint n_planes,
			     guint bytesused[], struct timeval *timestamp,
			     struct v4l2_buffer *buf)
{
	gint i;

	memcpy(buf->m.planes, buffers[buf->index].planes,
	       sizeof(struct v4l2_plane) * n_planes);

	if (bytesused) {
		for (i = 0; i < n_planes; i++)
			buf->m.planes[i].bytesused = bytesused[i];
	}

	if (timestamp) {
		buf->timestamp.tv_sec = timestamp->tv_sec;
		buf->timestamp.tv_usec = timestamp->tv_usec;
	} else {
		buf->timestamp.tv_sec = buf->timestamp.tv_usec = 0;
	}
}

static int
fill_v4l2_buffer(struct gst_backend_priv *priv, GstBufferPool *pool,
		 struct v4l_gst_buffer *buffers, gint buffers_num,
		 guint bytesused[], struct timeval *timestamp,
		 struct v4l2_buffer *buf)
{
	GstVideoMeta *meta = NULL;
	guint n_planes;

	get_raw_video_params(pool, buffers[buf->index].buffer, NULL, &meta);

	n_planes = (meta) ? meta->n_planes : 1;

	set_v4l2_buffer_plane_params(priv, buffers, n_planes, bytesused,
				     timestamp, buf);

	/* set unused params */
	memset(&buf->timecode, 0, sizeof(buf->timecode));
	buf->sequence = 0;
	buf->flags = 0;
	buf->field = V4L2_FIELD_NONE;

	buf->length = n_planes;

	return 0;
}

static guint
get_v4l2_buffer_index(struct v4l_gst_buffer *buffers, gint buffers_num,
		      GstBuffer *buffer)
{
	gint i;
	guint index = G_MAXUINT;

	for (i = 0; i < buffers_num; i++) {
		if (buffers[i].buffer == buffer) {
			index = i;
			break;
		}
	}

	return index;
}

static GstBuffer *
dequeue_blocking(struct gst_backend_priv *priv, GQueue *queue, GCond *cond)
{
	GstBuffer *buffer;

	buffer = g_queue_pop_head(queue);
	while (!buffer && priv->is_pipeline_started) {
		g_cond_wait(cond, &priv->queue_mutex);
		buffer = g_queue_pop_head(queue);
	}

	return buffer;
}

static GstBuffer *
dequeue_non_blocking(GQueue *queue)
{
	GstBuffer *buffer;

	buffer = g_queue_pop_head(queue);
	if (!buffer) {
		GST_DEBUG("The buffer pool is empty in "
			  "the non-blocking mode, return EAGAIN");
		errno = EAGAIN;
	}

	return buffer;
}

static GstBuffer *
dequeue_buffer(struct gst_backend_priv *priv, GQueue *queue, GCond *cond,
		int type)
{
	GstBuffer *buffer = NULL;

	g_mutex_lock(&priv->queue_mutex);

	if (priv->dev_ops_priv->is_non_blocking)
		buffer = dequeue_non_blocking(queue);
	else
		buffer = dequeue_blocking(priv, queue, cond);

	if (buffer) {
		if (type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE &&
		    priv->returned_out_buffers_num == 0) {
			clear_event(priv->dev_ops_priv->event_state, POLLIN);
		} else if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE &&
			   g_queue_is_empty(priv->cap_buffers_queue)) {
			clear_event(priv->dev_ops_priv->event_state, POLLOUT);
		}
	}

	g_mutex_unlock(&priv->queue_mutex);

	return buffer;
}

static GstBuffer *
acquire_buffer_from_pool(struct gst_backend_priv *priv, GstBufferPool *pool)
{
	GstFlowReturn flow_ret;
	GstBuffer *buffer;
	GstBufferPoolAcquireParams params = { 0, };

	if (priv->dev_ops_priv->is_non_blocking) {
		params.flags |= GST_BUFFER_POOL_ACQUIRE_FLAG_DONTWAIT;
	} else
		g_mutex_unlock(&priv->queue_mutex);

	flow_ret = gst_buffer_pool_acquire_buffer(pool, &buffer, &params);
	if (!priv->dev_ops_priv->is_non_blocking)
		g_mutex_lock(&priv->queue_mutex);

	if (priv->dev_ops_priv->is_non_blocking && flow_ret == GST_FLOW_EOS) {
		GST_TRACE("The buffer pool is empty in "
			  "the non-blocking mode, return EAGAIN");
		errno = EAGAIN;
		return NULL;
	} else if (flow_ret != GST_FLOW_OK) {
		GST_ERROR("gst_buffer_pool_acquire_buffer failed");
		errno = EINVAL;
		return NULL;
	}

	return buffer;
}

static int
dqbuf_ioctl_out(struct gst_backend_priv *priv, struct v4l2_buffer *buf)
{
	GstBuffer *buffer;
	guint index;

	if (!priv->is_pipeline_started) {
		GST_ERROR("The pipeline does not start yet.");
		errno = EINVAL;
		return -1;
	}

	if (!check_no_index_v4l2_buffer(buf, priv->out_buffers,
					priv->src_pool))
		return -1;

	g_mutex_lock(&priv->queue_mutex);

	buffer = acquire_buffer_from_pool(priv, priv->src_pool);
	if (!buffer) {
		g_mutex_unlock(&priv->queue_mutex);
		return -1;
	}

	priv->returned_out_buffers_num--;

	if (priv->returned_out_buffers_num == 0)
		clear_event(priv->dev_ops_priv->event_state, POLLIN);

	g_mutex_unlock(&priv->queue_mutex);

	index = get_v4l2_buffer_index(priv->out_buffers,
				      priv->out_buffers_num, buffer);
	if (index >= priv->out_buffers_num) {
		GST_ERROR("Failed to get a valid buffer index "
			  "on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	buf->index = index;
	priv->out_buffers[buf->index].state = V4L_GST_BUFFER_DEQUEUED;

	GST_TRACE("success dequeue buffer index=%d buffer=%p", index, buffer);

	return fill_v4l2_buffer(priv, priv->src_pool,
				priv->out_buffers, priv->out_buffers_num,
				NULL, NULL, buf);
}

static int
dqbuf_ioctl_cap(struct gst_backend_priv *priv, struct v4l2_buffer *buf)
{
	GstBuffer *buffer;
	guint index;
	struct timeval timestamp;
	guint bytesused[GST_VIDEO_MAX_PLANES];
	gint i;

	if (!check_no_index_v4l2_buffer(buf, priv->cap_buffers,
					priv->sink_pool))
		return -1;

	buffer = dequeue_buffer(priv, priv->cap_buffers_queue,
				&priv->queue_cond, buf->type);
	if (!buffer)
		return -1;

	index = get_v4l2_buffer_index(priv->cap_buffers,
				      priv->cap_buffers_num, buffer);
	if (index >= priv->cap_buffers_num) {
		GST_ERROR("Failed to get a valid buffer index "
			  "on CAPTURE");
		errno = EINVAL;
		gst_buffer_unref(buffer);
		return -1;
	}

	buf->index = index;

	for (i = 0; i < priv->cap_pix_fmt.num_planes; i++)
		bytesused[i] = priv->cap_pix_fmt.plane_fmt[i].sizeimage;

	GST_TIME_TO_TIMEVAL(GST_BUFFER_PTS(buffer), timestamp);

	priv->cap_buffers[buf->index].state = V4L_GST_BUFFER_DEQUEUED;

	GST_TRACE("success dequeue buffer index=%d buffer=%p ts=%ld",
		  index, buffer, timestamp.tv_sec);

	return fill_v4l2_buffer(priv, priv->sink_pool,
				priv->cap_buffers, priv->cap_buffers_num,
				bytesused, &timestamp, buf);
}

int
dqbuf_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_buffer *buf)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_QQBUF:dqbuf_ioctl: type: 0x%x index: %d flags: 0x%x\n", buf->type, buf->index, buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = dqbuf_ioctl_out(priv, buf);
		if (ret < 0) {
			g_mutex_unlock(&priv->dev_lock);
			return ret;
		}

	} else if (buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = dqbuf_ioctl_cap(priv, buf);
		if (ret < 0) {
			g_mutex_unlock(&priv->dev_lock);
			return ret;
		}

	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		g_mutex_unlock(&priv->dev_lock);
		return -1;
	}

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}

int
querybuf_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_buffer *buf)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	struct v4l_gst_buffer *buffers;
	gint buffers_num;
	GstBufferPool *pool;
	int ret;

	GST_DEBUG("VIDIOC_QUERYBUF:querybuf_ioctl: type: 0x%x index: %d flags: 0x%x\n", buf->type, buf->index, buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		buffers = priv->out_buffers;
		buffers_num = priv->out_buffers_num;
		pool = priv->src_pool;
	} else if (buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		buffers = priv->cap_buffers;
		buffers_num = priv->cap_buffers_num;
		pool = priv->sink_pool;
	} else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		g_mutex_unlock(&priv->dev_lock);
		return -1;
	}

	if (!check_v4l2_buffer(buf, buffers, buffers_num, pool)) {
		g_mutex_unlock(&priv->dev_lock);
		return -1;
	}

	ret = fill_v4l2_buffer(priv, pool, buffers, buffers_num,
			       NULL, NULL, buf);

	g_mutex_unlock(&priv->dev_lock);

	return ret;
}

static GstCaps *
get_codec_caps_from_fourcc(guint fourcc)
{
	const gchar *mime;

	mime = convert_codec_type_v4l2_to_gst(fourcc);
	if (!mime) {
		GST_ERROR("Failed to convert from fourcc to mime string");
		return NULL;
	}

	if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_H264) == 0) {
		return gst_caps_new_simple(mime, "stream-format",
					   G_TYPE_STRING, "byte-stream", NULL);
	}

	return gst_caps_new_empty_simple(mime);
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

	if (!get_raw_video_params(pool, buffer->buffer, &info, &meta)) {
		/* deal with this as a single plane */
		buffer->planes[0].m.mem_offset = offset;
		return PAGE_ALIGN(gst_buffer_get_size(buffer->buffer),
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
alloc_buffers_from_pool(struct gst_backend_priv *priv, GstBufferPool *pool,
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
	get_buffer_pool_params(pool, NULL, NULL, NULL, &actual_max_buffers);
	if (actual_max_buffers == 0) {
		GST_ERROR("Cannot handle the unlimited amount of buffers");
		errno = EINVAL;
		goto inactivate_pool;
	}

	bufs_list = g_new0(struct v4l_gst_buffer, actual_max_buffers);

	for (i = 0; i < actual_max_buffers; i++) {
		flow_ret = gst_buffer_pool_acquire_buffer(pool,
							  &bufs_list[i].buffer,
							  &params);
		if (flow_ret != GST_FLOW_OK) {
			GST_ERROR("Failed to acquire a buffer on OUTPUT");
			errno = ENOMEM;
			goto free_bufs_list;
		}

		bufs_list[i].priv = priv;
		bufs_list[i].state = V4L_GST_BUFFER_DEQUEUED;

		GST_DEBUG("out gst_buffer[%d] : %p", i, bufs_list[i].buffer);
	}

	*buffers = bufs_list;

	GST_DEBUG("The number of buffers actually set to the buffer pool is %d",
		  actual_max_buffers);

	return actual_max_buffers;

	/* error cases */
free_bufs_list:
	for (i = 0; i < actual_max_buffers; i++) {
		if (bufs_list[i].buffer)
			gst_buffer_unref(bufs_list[i].buffer);
	}
	g_free(bufs_list);
inactivate_pool:
	gst_buffer_pool_set_active(pool, FALSE);

	return 0;
}

static GstFlowReturn
force_dqbuf_from_pool(GstBufferPool *pool, struct v4l_gst_buffer *buffers,
		      gint buffers_num, gboolean map, GstBuffer **prev_buffer)
{
	GstFlowReturn flow_ret;
	GstBufferPoolAcquireParams params = { 0, };
	GstBuffer *buffer;
	guint index;

	params.flags = GST_BUFFER_POOL_ACQUIRE_FLAG_DONTWAIT;

	/* force to make buffers available to the V4L2 caller side */
	flow_ret = gst_buffer_pool_acquire_buffer(pool, &buffer, &params);
	if (flow_ret != GST_FLOW_OK)
		return flow_ret;
	if (prev_buffer) {
		/* omxbufferpool always returns same address when the buffer is
		   dmabuf
		   https://github.com/GStreamer/gst-omx/blob/4a35d4ee81fe707845ae33f2a5ac701ad01c3e4d/omx/gstomxbufferpool.c#L591-L625
		*/
		if (*prev_buffer && buffer == *prev_buffer)
			return GST_FLOW_ERROR;
		*prev_buffer = buffer;
	}

	index = get_v4l2_buffer_index(buffers, buffers_num, buffer);
	if (index >= buffers_num) {
		GST_ERROR("Failed to get a valid buffer index");
		errno = EINVAL;
		return GST_FLOW_ERROR;
	}

	buffers[index].state = V4L_GST_BUFFER_DEQUEUED;

	if (!map)
		return GST_FLOW_OK;

	if (!gst_buffer_map(buffer, &buffers[index].info,
			    buffers[index].flags)) {
		GST_ERROR("Failed to map buffer (%p)", buffer);
		errno = EINVAL;
		return GST_FLOW_ERROR;
	}
	return GST_FLOW_OK;
}

static int
force_out_dqbuf(struct gst_backend_priv *priv)
{
	g_mutex_lock(&priv->queue_mutex);

	while (force_dqbuf_from_pool(priv->src_pool, priv->out_buffers,
			   priv->out_buffers_num, true, NULL) == GST_FLOW_OK) {
		priv->returned_out_buffers_num--;
	}

	clear_event(priv->dev_ops_priv->event_state, POLLIN);

	g_mutex_unlock(&priv->queue_mutex);

	GST_DEBUG("returned_out_buffers_num : %d", priv->returned_out_buffers_num);

	return 0;
}

static int
force_cap_dqbuf(struct gst_backend_priv *priv)
{
	GstBuffer *buffer;
	guint index;
	GstFlowReturn flow_ret;

	g_mutex_lock(&priv->queue_mutex);

	buffer = dequeue_non_blocking(priv->cap_buffers_queue);
	while (buffer) {
		index = get_v4l2_buffer_index(priv->cap_buffers,
					      priv->cap_buffers_num, buffer);
		if (index >= priv->cap_buffers_num) {
			GST_ERROR("Failed to get a valid buffer index "
				  "on CAPTURE");
			g_mutex_unlock(&priv->queue_mutex);
			errno = EINVAL;
			return -1;
		}

		priv->cap_buffers[index].state = V4L_GST_BUFFER_DEQUEUED;

		buffer = dequeue_non_blocking(priv->cap_buffers_queue);
	}

	clear_event(priv->dev_ops_priv->event_state, POLLOUT);

	g_mutex_unlock(&priv->queue_mutex);

	buffer = NULL;
	do {
		flow_ret = force_dqbuf_from_pool(priv->sink_pool,
						 priv->cap_buffers,
						 priv->cap_buffers_num,
						 false,
						 &buffer);
	} while (flow_ret == GST_FLOW_OK);

	return 0;
}

static int
flush_pipeline(struct gst_backend_priv *priv)
{
	GstEvent *event;

	GST_DEBUG("flush start");

	gst_buffer_pool_set_flushing(priv->src_pool, true);
	gst_buffer_pool_set_flushing(priv->sink_pool, true);

	event = gst_event_new_flush_start();
	if (!gst_element_send_event(priv->pipeline, event)) {
		GST_ERROR("Failed to send a flush start event");
		errno = EINVAL;
		return -1;
	}

	event = gst_event_new_flush_stop(TRUE);
	if (!gst_element_send_event(priv->pipeline, event)) {
		GST_ERROR("Failed to send a flush stop event");
		errno = EINVAL;
		return -1;
	}

	gst_buffer_pool_set_flushing(priv->src_pool, false);
	gst_buffer_pool_set_flushing(priv->sink_pool, false);

	GST_DEBUG("flush end");

	return 0;
}

static int
streamoff_ioctl_out(struct gst_backend_priv *priv, gboolean steal_ref)
{
	int ret;

	GST_OBJECT_LOCK(priv->pipeline);
	if (GST_STATE(priv->pipeline) == GST_STATE_NULL) {
		/* No need to flush the pipeline after it has been
		   the NULL state. */
		GST_OBJECT_UNLOCK(priv->pipeline);
		goto flush_buffer_queues;
	}
	GST_OBJECT_UNLOCK(priv->pipeline);


	ret = flush_pipeline(priv);

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
		gst_buffer_ref(priv->out_buffers[0].buffer);

	/* wake up blocking of the OUTPUT buffers acquistion */
	if (!gst_buffer_pool_set_active(priv->src_pool, FALSE)) {
		GST_ERROR("Failed to inactivate buffer pool on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	/* wake up blocking of the CAPTURE buffers acquistion */
	g_mutex_lock(&priv->queue_mutex);
	priv->is_pipeline_started = FALSE;
	g_cond_broadcast(&priv->queue_cond);
	g_mutex_unlock(&priv->queue_mutex);

	return 0;
}

static int
reqbuf_ioctl_out(struct gst_backend_priv *priv,
		 struct v4l2_requestbuffers *req)
{
	GstCaps *caps;
	guint adjusted_count;
	guint allocated_num;
	int ret;
	guint i;

	if (!is_supported_memory_io(req->memory)) {
		GST_ERROR("Only V4L2_MEMORY_MMAP is supported");
		return -1;
	}

	g_mutex_lock(&priv->dev_lock);

	if (req->count == 0) {
		/* The following function flushes both the OUTPUT and CAPTURE
		   buffer types because the GStreamer can only flush the whole
		   of the pipeline, so the buffers of both the buffer types
		   need to be requeued after this operation.
		*/
		ret = streamoff_ioctl_out(priv, FALSE);
		if (ret < 0)
			goto unlock;

		/* Force to return dequeued buffers to the buffer pool. */
		for (i = 0; i < priv->out_buffers_num; i++) {
			if (priv->out_buffers[i].state ==
			    V4L_GST_BUFFER_DEQUEUED) {
				gst_buffer_unref(priv->out_buffers[i].buffer);
			}
		}

		if (priv->out_buffers) {
			g_free(priv->out_buffers);
			priv->out_buffers = NULL;
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

	if (gst_buffer_pool_is_active(priv->src_pool)) {
		if (!gst_buffer_pool_set_active(priv->src_pool, FALSE)) {
			GST_ERROR("Failed to inactivate buffer pool");
			errno = EBUSY;
			ret = -1;
			goto unlock;
		}
	}

	caps = get_codec_caps_from_fourcc(priv->out_fourcc);
	if (!caps) {
		errno = EINVAL;
		ret = -1;
		goto unlock;
	}

	adjusted_count = MAX(req->count, INPUT_BUFFERING_CNT);
	adjusted_count = MIN(adjusted_count, VIDEO_MAX_FRAME);

	set_buffer_pool_params(priv->src_pool, caps,
			       priv->out_buf_size, adjusted_count,
			       adjusted_count);

	allocated_num = alloc_buffers_from_pool(priv, priv->src_pool,
						&priv->out_buffers);
	if (allocated_num == 0) {
		gst_caps_unref(caps);
		ret = -1;
		goto unlock;
	}

	for (i = 0; i < allocated_num; i++) {
		/* Set identifiers for associating a GstBuffer with
		   a V4L2 buffer in the V4L2 caller side. */
		priv->mmap_offset =
			set_mem_offset(&priv->out_buffers[i],
			priv->src_pool,
			priv->mmap_offset);

		priv->out_buffers[i].planes[0].length =
				gst_buffer_get_size(priv->out_buffers[i].buffer);
	}

	req->count = priv->out_buffers_num = allocated_num;

	GST_DEBUG("buffers count=%d", req->count);

	priv->returned_out_buffers_num = 0;

	ret = 0;

unlock:
	g_mutex_unlock(&priv->dev_lock);

	return ret;
}

static GstBuffer *
peek_first_cap_buffer(struct gst_backend_priv *priv)
{
	GstBuffer *buffer;

	g_mutex_lock(&priv->queue_mutex);
	buffer = g_queue_peek_head(priv->reqbufs_queue);
	while (!buffer) {
		g_cond_wait(&priv->queue_cond, &priv->queue_mutex);
		buffer = g_queue_peek_head(priv->reqbufs_queue);
	}
	g_mutex_unlock(&priv->queue_mutex);

	return buffer;
}

static void
wait_for_all_bufs_collected(struct gst_backend_priv *priv,
			    guint max_buffers)
{
	g_mutex_lock(&priv->queue_mutex);
	while (g_queue_get_length(priv->reqbufs_queue) <
	       max_buffers)
		g_cond_wait(&priv->queue_cond, &priv->queue_mutex);
	g_mutex_unlock(&priv->queue_mutex);
}

static gboolean
retrieve_cap_frame_info(GstBufferPool *pool, GstBuffer *buffer,
			struct v4l2_pix_format_mplane *cap_pix_fmt)
{
	GstVideoInfo info;
	GstVideoMeta *meta;
	gint i;

	if (!get_raw_video_params(pool, buffer, &info, &meta)) {
		GST_ERROR("Failed to get video meta data");
		return FALSE;
	}

	for (i = 0; i < meta->n_planes; i++) {
		cap_pix_fmt->plane_fmt[i].sizeimage =
				calc_plane_size(&info, meta, i);
		cap_pix_fmt->plane_fmt[i].bytesperline = meta->stride[i];
	}

	return TRUE;
}

static guint
create_cap_buffers_list(struct gst_backend_priv *priv)
{
	GstBuffer *first_buffer;
	guint actual_max_buffers;
	gint i, j;

	if (priv->cap_buffers)
		/* Cannot realloc the buffers without stopping the pipeline,
		   so return the same number of the buffers so far. */
		return priv->cap_buffers_num;

	g_mutex_unlock(&priv->dev_lock);

	first_buffer = peek_first_cap_buffer(priv);

	g_mutex_lock(&priv->dev_lock);

	if (!first_buffer->pool) {
		GST_ERROR("Cannot handle buffers not belonging to "
			  "a bufferpool");
		errno = EINVAL;
		return 0;
	}

	if (priv->sink_pool != first_buffer->pool) {
		GST_DEBUG("The buffer pool we prepared is not used by "
			  "the pipeline, so replace it with the pool that is "
			  "actually used");
		gst_object_unref(priv->sink_pool);
		priv->sink_pool = gst_object_ref(first_buffer->pool);
	}

	/* Confirm the number of buffers actually set to the buffer pool. */
	get_buffer_pool_params(priv->sink_pool, NULL, NULL, NULL,
			       &actual_max_buffers);
	if (actual_max_buffers == 0) {
		GST_ERROR("Cannot handle the unlimited amount of buffers");
		errno = EINVAL;
		return 0;
	}

	if (!retrieve_cap_frame_info(priv->sink_pool, first_buffer,
				     &priv->cap_pix_fmt)) {
		GST_ERROR("Failed to retrieve frame info on CAPTURE");
		errno = EINVAL;
		return 0;
	}

	g_mutex_unlock(&priv->dev_lock);

	/* We wait for buffers from appsink to be collected for
	   the maximum number of the buffer pool. */
	wait_for_all_bufs_collected(priv, actual_max_buffers);

	g_mutex_lock(&priv->dev_lock);

	priv->cap_buffers = g_new0(struct v4l_gst_buffer, actual_max_buffers);

	for (i = 0; i < actual_max_buffers; i++) {
		priv->cap_buffers[i].buffer =
				g_queue_peek_nth(priv->reqbufs_queue, i);

		/* Set identifiers for associating a GstBuffer with
		   a V4L2 buffer in the V4L2 caller side. */
		priv->mmap_offset =
				set_mem_offset(&priv->cap_buffers[i],
				priv->sink_pool,
				priv->mmap_offset);

		priv->cap_buffers[i].state = V4L_GST_BUFFER_DEQUEUED;

		/* assume that decoded image data has been filled to
		   the entire plane size, because the GStreamer buffer
		   information does not provides how much valid data size
		   a GstBuffer has. */
		for (j = 0; j < priv->cap_pix_fmt.num_planes; j++) {
			priv->cap_buffers[i].planes[j].length =
					priv->cap_pix_fmt.plane_fmt[j].sizeimage;
		}

		GST_DEBUG("cap gst_buffer[%d] : %p", i,
			  priv->cap_buffers[i].buffer);
	}

	GST_DEBUG("The number of buffers actually set to the buffer pool is %d",
		  actual_max_buffers);

	return actual_max_buffers;
}

static int
reqbuf_ioctl_cap(struct gst_backend_priv *priv,
		 struct v4l2_requestbuffers *req)
{
	guint buffers_num;
	GstStateChangeReturn state_ret;
	int ret;
	gint i;

	if (!is_supported_memory_io(req->memory)) {
		GST_ERROR("Only V4L2_MEMORY_MMAP is supported");
		return -1;
	}

	g_mutex_lock(&priv->dev_lock);

	if (req->count == 0) {
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
			goto unlock;
		}

		g_atomic_int_set(&priv->is_cap_fmt_acquirable, 0);

		for (i = 0; i < priv->cap_buffers_num; i++) {
			if (priv->cap_buffers[i].state ==
			    V4L_GST_BUFFER_DEQUEUED) {
				gst_buffer_unref(priv->cap_buffers[i].buffer);
			}
		}

		g_queue_clear(priv->reqbufs_queue);
		g_queue_clear(priv->cap_buffers_queue);

		g_mutex_lock(&priv->queue_mutex);
		priv->is_pipeline_started = FALSE;
		g_cond_broadcast(&priv->queue_cond);
		g_mutex_unlock(&priv->queue_mutex);

		if (priv->cap_buffers) {
			g_free(priv->cap_buffers);
			priv->cap_buffers = NULL;
		}
		init_decoded_frame_params(&priv->cap_pix_fmt);

		ret = 0;
		goto unlock;
	}

	if (!priv->is_pipeline_started) {
		GST_ERROR("Need to start the pipeline for the buffer request "
			  "on CAPTURE");
		errno = EINVAL;
		ret = -1;
		goto unlock;
	}

	g_mutex_lock(&priv->cap_reqbuf_mutex);
	priv->cap_buffers_num = MIN(req->count, VIDEO_MAX_FRAME);

	g_cond_signal(&priv->cap_reqbuf_cond);
	g_mutex_unlock(&priv->cap_reqbuf_mutex);

	buffers_num = create_cap_buffers_list(priv);
	if (buffers_num == 0) {
		ret = -1;
		goto unlock;
	}

	req->count = priv->cap_buffers_num = buffers_num;

	GST_DEBUG("buffers count=%d", req->count);

	ret = 0;

unlock:
	g_mutex_unlock(&priv->dev_lock);

	return ret;
}

int
reqbuf_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_requestbuffers *req)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_REQBUF:reqbuf_ioctl: type: 0x%x count: %d memory: 0x%x\n", req->type, req->count, req->memory);

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

static gboolean
relink_elements_with_caps_filtered(GstElement *src_elem, GstElement *dest_elem,
				   GstCaps *caps)
{
	gst_element_unlink(src_elem, dest_elem);
	return gst_element_link_filtered(src_elem, dest_elem, caps);
}

static gboolean
set_out_format_to_pipeline(struct gst_backend_priv *priv)
{
	GstCaps *caps;

	caps = get_codec_caps_from_fourcc(priv->out_fourcc);
	if (!caps) {
		errno = EINVAL;
		return FALSE;
	}

	gst_app_src_set_caps(GST_APP_SRC(priv->appsrc), caps);
	gst_caps_unref(caps);

	return TRUE;
}

static gboolean
set_cap_format_to_pipeline(struct gst_backend_priv *priv)
{
	GstElement *peer_elem;
	GstCaps *caps;
	GstVideoFormat fmt;
	gboolean ret;

	fmt = convert_video_format_v4l2_to_gst(priv->
					       cap_pix_fmt.pixelformat);
	if (fmt == GST_VIDEO_FORMAT_UNKNOWN) {
		GST_ERROR("Invalid format on CAPTURE");
		errno = EINVAL;
		return FALSE;
	}

	caps = gst_caps_new_simple("video/x-raw", "format", G_TYPE_STRING,
				   gst_video_format_to_string(fmt), NULL);

	peer_elem = get_peer_element(priv->appsink, "sink");
	if (!relink_elements_with_caps_filtered(peer_elem, priv->appsink,
						caps)) {
		GST_ERROR("Failed to relink elements with "
			  "the CAPTURE setting (caps=%s)",
			  gst_caps_to_string(caps));
		errno = EINVAL;
		ret = FALSE;
		goto free_objects;
	}

	ret = TRUE;

free_objects:
	gst_caps_unref(caps);
	gst_object_unref(peer_elem);

	return ret;
}

static int
streamon_ioctl_out(struct gst_backend_priv *priv)
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
		if (!set_out_format_to_pipeline(priv))
			return -1;
		if (!set_cap_format_to_pipeline(priv))
			return -1;
	}

	if (!gst_buffer_pool_is_active(priv->src_pool)) {
		if (!gst_buffer_pool_set_active(priv->src_pool, TRUE)) {
			GST_ERROR("Failed to activate buffer pool");
			errno = EINVAL;
			return -1;
		}

		/* Restore the extra reference counted up in the streamoff */
		gst_buffer_unref(priv->out_buffers[0].buffer);
	}

	gst_element_set_state(priv->pipeline, GST_STATE_PLAYING);

	priv->is_pipeline_started = TRUE;

	g_mutex_unlock(&priv->dev_lock);

	return 0;
}

int
streamon_ioctl(struct v4l_gst_priv *dev_ops_priv, enum v4l2_buf_type *type)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_STREAMON:streamon_ioctl: type: 0x%x\n", *type);

	if (*type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		GST_DEBUG("streamon on OUTPUT");
		ret = streamon_ioctl_out(priv);
	} else if (*type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE)
		/* no processing */
		ret = 0;
	else {
		GST_ERROR("Invalid buf type");
		errno = EINVAL;
		ret = -1;
	}

	return ret;
}

int
streamoff_ioctl(struct v4l_gst_priv *dev_ops_priv, enum v4l2_buf_type *type)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	int ret;

	GST_DEBUG("VIDIOC_STREAMOFF:streamoff_ioctl: type: 0x%x\n", *type);

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

int
subscribe_event_ioctl(struct v4l_gst_priv *dev_ops_priv,
		      struct v4l2_event_subscription *sub)
{
	GST_DEBUG("VIDIOC_SUBSCRIBE_EVENT:subscribe_event_ioctl: type: 0x%x id: %d flags: 0x%x\n", sub->type, sub->id, sub->flags);

	return 0;
}

int
dqevent_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_event *ev)
{
	/* TODO: Add the implementation for subscribed event notifications.
		 Always return failure until the feature has been supported. */
	GST_DEBUG("VIDIOC_DQEVENT:dqevent_ioctl: id: %d sequence: %d pending: %d\n", ev->id, ev->sequence, ev->pending);

	return -1;
}

static int
find_out_buffer_by_offset(struct v4l_gst_priv *dev_ops_priv, int64_t offset)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	gint index = -1;
	gint i;

	for (i = 0; i < priv->out_buffers_num; i++) {
		if (priv->out_buffers[i].planes[0].m.mem_offset == offset) {
			index = i;
			break;
		}
	}

	return index;
}

static void *
map_out_buffer(struct v4l_gst_priv *dev_ops_priv, int index, int prot)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	GstMapInfo info;
	void *data;
	GstMapFlags map_flags;

	map_flags = (prot & PROT_READ) ? GST_MAP_READ : 0;
	map_flags |= (prot & PROT_WRITE) ? GST_MAP_WRITE : 0;

	if (!gst_buffer_map(priv->out_buffers[index].buffer, &info,
			    map_flags)) {
		GST_ERROR("Failed to map buffer (%p)",
			  priv->out_buffers[index].buffer);
		errno = EINVAL;
		return MAP_FAILED;
	}

	data = info.data;

	gst_buffer_unmap(priv->out_buffers[index].buffer, &info);

	priv->out_buffers[index].flags = map_flags;

	return data;
}

static int
find_cap_buffer_by_offset(struct v4l_gst_priv *dev_ops_priv, int64_t offset,
			  int *index, int *plane)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	gint i, j;

	for (i = 0; i < priv->cap_buffers_num; i++) {
		for (j = 0; j < priv->cap_pix_fmt.num_planes; j++) {
			if (priv->cap_buffers[i].planes[j].m.mem_offset ==
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
map_cap_buffer(struct v4l_gst_priv *dev_ops_priv, int index, int plane,
	       int prot)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	GstVideoMeta *meta;
	GstMapInfo info;
	void *data;
	GstMapFlags map_flags;

	map_flags = (prot & PROT_READ) ? GST_MAP_READ : 0;
	map_flags |= (prot & PROT_WRITE) ? GST_MAP_WRITE : 0;

	if (!gst_buffer_map(priv->cap_buffers[index].buffer, &info,
			    map_flags)) {
		GST_ERROR("Failed to map buffer (%p)",
			  priv->cap_buffers[index].buffer);
		errno = EINVAL;
		return MAP_FAILED;
	}

	if (!get_raw_video_params(priv->sink_pool,
				  priv->cap_buffers[index].buffer,
				  NULL, &meta)) {
		GST_ERROR("Failed to get video meta data");
		errno = EINVAL;
		gst_buffer_unmap(priv->cap_buffers[index].buffer,
				 &priv->cap_buffers[index].info);
		return MAP_FAILED;
	}

	data = info.data + meta->offset[plane];

	gst_buffer_unmap(priv->cap_buffers[index].buffer, &info);

	priv->cap_buffers[index].flags = map_flags;

	return data;
}

void *
gst_backend_mmap(struct v4l_gst_priv *dev_ops_priv, void *start, size_t length,
		 int prot, int flags, int fd, int64_t offset)
{
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
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

	index = find_out_buffer_by_offset(dev_ops_priv, offset);
	if (index >= 0) {
		map = map_out_buffer(dev_ops_priv, index, prot);
		goto unlock;
	}

	ret = find_cap_buffer_by_offset(dev_ops_priv, offset, &index, &plane);
	if (ret == 0) {
		map = map_cap_buffer(dev_ops_priv, index, plane, prot);
		goto unlock;
	}

unlock:
	g_mutex_unlock(&priv->dev_lock);

	GST_DEBUG("Final map = %p", map);

	return map;
}

int expbuf_ioctl(struct v4l_gst_priv *dev_ops_priv,
		 struct v4l2_exportbuffer *expbuf) {
	struct v4l_gst_buffer *buffer;
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;
	guint i = 0;
	GstMemory *mem = NULL;

	GST_DEBUG("VIDIOC_EXPBUF:expbuf_ioctl: type: 0x%x index: %d flags: 0x%x\n", expbuf->type, expbuf->index, expbuf->flags);

	if ((expbuf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
	    (expbuf->type == V4L2_BUF_TYPE_PRIVATE)) {
		buffer = &priv->cap_buffers[expbuf->index];
		if (expbuf->plane < gst_buffer_n_memory(buffer->buffer)) {
			i = expbuf->plane;
		}

		mem = gst_buffer_peek_memory(buffer->buffer, i);
		if (!gst_is_dmabuf_memory(mem)) {
			GST_ERROR("Failed to get dambuf emmory.");
			return -1;
		}
	}

	if (mem == NULL) {
		GST_ERROR("Invalid type.");
		errno = EINVAL;
		return -1;
	}

	switch(expbuf->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		expbuf->fd = dup(gst_dmabuf_memory_get_fd (mem));
		break;
	case V4L2_BUF_TYPE_PRIVATE:
		expbuf->reserved[0] = mem->offset;
		break;
	default:
		GST_ERROR("Can only export capture buffers as dmebuf");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int g_selection_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_selection *selection) {
	struct gst_backend_priv *priv = dev_ops_priv->gst_priv;

	GST_DEBUG("VIDIOC_G_SELECTION:g_selection_ioctl: type: 0x%x target: 0x%x flags: 0x%x\n", selection->type, selection->target, selection->flags);

	selection->r.top = selection->r.left = 0;
	selection->r.width = priv->cap_pix_fmt.width;
	selection->r.height = priv->cap_pix_fmt.height;

	return 0;
}

/* See https://github.com/JeffyCN/libv4l-rkmpp/blob/master/src/libv4l-rkmpp-dec.c#L740-L776 */
int queryctrl_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_queryctrl *query_ctrl) {

	switch (query_ctrl->id) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE;
		query_ctrl->maximum = V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10;
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		query_ctrl->minimum = V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN;
		query_ctrl->maximum = V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10;
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
int querymenu_ioctl(struct v4l_gst_priv *dev_ops_priv, struct v4l2_querymenu *query_menu) {

	GST_ERROR("unsupported query_menu id: %x", query_menu->id);
	GST_ERROR("unsupported query_menu index: %x", query_menu->index);

	switch (query_menu->id) {
	case V4L2_CID_MPEG_VIDEO_H264_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE:
		case V4L2_MPEG_VIDEO_H264_PROFILE_MAIN:
		case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH:
		case V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10:
			break;
		default:
			GST_ERROR("unsupported H264 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_ERROR("V4L2_CID_MPEG_VIDEO_H264_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN:
		case V4L2_MPEG_VIDEO_HEVC_PROFILE_MAIN_10:
			break;
		default:
			GST_ERROR("unsupported HEVC profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_ERROR("V4L2_CID_MPEG_VIDEO_HEVC_PROFILE index: %x", query_menu->index);
		break;
#if 0 // omit non-supported AV1, VP8, VP9
	case V4L2_CID_MPEG_VIDEO_AV1_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_AV1_PROFILE_MAIN) {
			GST_ERROR("unsupported VP8 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_ERROR("V4L2_CID_MPEG_VIDEO_AV1_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_VP8_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_VP8_PROFILE_0) {
			GST_ERROR("unsupported VP8 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_ERROR("V4L2_CID_MPEG_VIDEO_VP8_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_VP9_PROFILE:
		switch (query_menu->index) {
		case V4L2_MPEG_VIDEO_VP9_PROFILE_0:
		case V4L2_MPEG_VIDEO_VP9_PROFILE_2:
			break;
		default:
			GST_ERROR("unsupported VP9 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_ERROR("V4L2_CID_MPEG_VIDEO_VP9_PROFILE index: %x", query_menu->index);
		break;
#endif
	default:
		GST_ERROR("unsupported menu: %x", query_menu->id);
		errno = EINVAL;
		return -1;
	}
	return 0;
}

/* See https://github.com/JeffyCN/libv4l-rkmpp/blob/master/src/libv4l-rkmpp.c#L297-L361 */
int try_fmt_ioctl(struct v4l_gst_priv *ctx, struct v4l2_format *format)
{
	GST_DEBUG("v4l2_format type: %x", format->type);

	return 0;
}

int g_crop_ioctl(struct v4l_gst_priv *ctx, struct v4l2_crop *crop)
{
	GST_DEBUG("v4l2_crop type: 0x%x", crop->type);

	switch (crop->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VIDEO_CAPTURE");
		break;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VIDEO_OUTPUT");
		break;
	case V4L2_BUF_TYPE_VIDEO_OVERLAY:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VIDEO_OVERLAY");
		break;
	case V4L2_BUF_TYPE_VBI_CAPTURE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VBI_CAPTURE");
		break;
	case V4L2_BUF_TYPE_VBI_OUTPUT:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VBI_OUTPUT");
		break;
	case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_SLICED_VBI_CAPTURE");
		break;
	case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_SLICED_VBI_OUTPUT");
		break;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY");
		break;
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE");
		break;
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE");
		break;
	case V4L2_BUF_TYPE_SDR_CAPTURE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_SDR_CAPTURE");
		break;
	case V4L2_BUF_TYPE_SDR_OUTPUT:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_SDR_OUTPUT");
		break;
	case V4L2_BUF_TYPE_META_CAPTURE:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_META_CAPTURE");
		break;
	case V4L2_BUF_TYPE_META_OUTPUT:
		GST_DEBUG("v4l2_crop type: V4L2_BUF_TYPE_META_OUTPUT");
		break;
	default:
		GST_DEBUG("unsupported v4l2_crop type: 0x%x", crop->type);
		break;
	}
	GST_DEBUG("v4l2_crop rect: left:%d top:%d width: %u height: %u",
		crop->c.left, crop->c.top, crop->c.width, crop->c.height);

	return 0;
}

int try_decoder_cmd_ioctl(struct v4l_gst_priv *ctx, struct v4l2_decoder_cmd *decoder_cmd)
{

	GST_DEBUG("v4l2_decoder_cmd: cmd: 0x%x flags: 0x%x", decoder_cmd->cmd, decoder_cmd->flags);
	switch (decoder_cmd->cmd) {
	case V4L2_DEC_CMD_START:
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_START");
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_START speed: %d format: %x", decoder_cmd->start.speed, decoder_cmd->start.format);
		break;
	case V4L2_DEC_CMD_STOP:
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_STOP");
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_STOP pts: %llu", decoder_cmd->stop.pts);
		break;
	case V4L2_DEC_CMD_PAUSE:
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_PAUSE");
		break;
	case V4L2_DEC_CMD_RESUME:
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_RESUME");
		break;
	case V4L2_DEC_CMD_FLUSH:
		GST_DEBUG("v4l2_dec_cmd: V4L2_DEC_CMD_FLUSH");
		break;
	default:
		GST_DEBUG("unsupported v4l2_decoder_cmd cmd: 0x%x", decoder_cmd->cmd);
		break;
	}
	return 0;
}
