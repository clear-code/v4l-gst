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

#include "gst-backend.h"
#include "evfd-ctrl.h"
#include "debug.h"
#include "utils.h"

GST_DEBUG_CATEGORY_STATIC(v4l_gst_debug_category);
#define GST_CAT_DEFAULT v4l_gst_debug_category

GST_DEBUG_CATEGORY_STATIC(v4l_gst_ioctl_debug_category);

#define DEF_CAP_MIN_BUFFERS		2
#define INPUT_BUFFERING_CNT		16 // must be <= than VIDEO_MAX_FRAME

#define FMTDESC_NAME_LENGTH		32  //The same size as defined int the V4L2 spec

enum buffer_state {
	V4L_GST_BUFFER_QUEUED,
	V4L_GST_BUFFER_DEQUEUED,
};

struct v4l_gst_buffer {
	GstBuffer *gstbuf;
	GstMapInfo info;
	GstMapFlags flags;
	struct v4l2_plane planes[GST_VIDEO_MAX_PLANES];
	struct v4l_gst *priv;
	enum buffer_state state;
};

struct fmt {
	guint fourcc;
	gchar desc[FMTDESC_NAME_LENGTH];
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

	GstVideoInfo src_video_info;

	GstAppSinkCallbacks appsink_cb;
	gulong probe_id;
	gulong decoder_probe_id;

	void *pool_lib_handle;
	struct libv4l_gst_buffer_pool_ops *pool_ops;

	/*
	 *  out (OUTPUT) : Application --> v4l-gst  Encoded data like H.264
	 *  cap (CAPTURE): Application <-- v4l-gst  Decoded data like NV12
	 */
	GArray *supported_out_fmts; /* struct fmt */
	GArray *supported_cap_fmts; /* struct fmt */
	struct v4l2_pix_format_mplane out_fmt;
	struct v4l2_pix_format_mplane cap_fmt;

	GstBufferPool *src_pool;  /* for OUTPUT  */
	GstBufferPool *sink_pool; /* for CAPTURE */

	struct v4l_gst_buffer *out_buffers;
	gint out_buffers_num;
	struct v4l_gst_buffer *cap_buffers;
	gint cap_buffers_num;

	int64_t mmap_offset;

	GQueue *req_gstbufs_queue; /* GstBuffer */
	GQueue *cap_gstbufs_queue; /* GstBuffer */
	GMutex queue_mutex;
	GCond queue_cond;

	gint returned_out_buffers_num;

	/* To wait for the requested number of buffers on CAPTURE
	   to be set in pad_probe_query() */
	GMutex cap_reqbuf_mutex;
	GCond cap_reqbuf_cond;
	int is_cap_fmt_acquirable;
	gint out_cnt;

	gboolean is_pipeline_started;

	GstBuffer *eos_gstbuf;
	EOSState eos_state;

	struct {
		gint cap_min_buffers;
		gint max_width;
		gint max_height;
		guint32 preferred_format;
		gchar *h264_pipeline;
		gchar *hevc_pipeline;
		gchar *pool_lib_path;
	} config;

	struct {
		GMutex mutex;
		gint subscribed;
		guint32 sequence;
		GQueue *queue;
	} v4l2events;

	GMutex dev_lock;
};

static gboolean
parse_config_file(struct v4l_gst *priv)
{
	const gchar *const *sys_conf_dirs;
	GKeyFile *conf_key;
	const gchar *conf_name = "libv4l-gst.conf";
	const gchar *libv4l_gst_group = "libv4l-gst";
	GError *err = NULL;
	gchar **groups;
	gsize n_groups;
	gint i;
	guint n_pipelines = 0;

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

	GST_DEBUG("libv4l-gst configuration file is found");

	/* [libv4l-gst] */
	if (g_key_file_has_group(conf_key, libv4l_gst_group)) {
		gchar *preferred_format;
		guint preferred_format_len = 0;

		/* No need to check if the external bufferpool library is set,
		   because it is not mandatory for this plugin. */
		priv->config.pool_lib_path
			= g_key_file_get_string(conf_key, libv4l_gst_group,
						"bufferpool-library",
						NULL);
		GST_DEBUG("external buffer pool library : %s",
			  priv->config.pool_lib_path ? priv->config.pool_lib_path : "none");

		priv->config.cap_min_buffers
			= g_key_file_get_integer(conf_key, libv4l_gst_group,
						 "min-buffers", NULL);
		if (priv->config.cap_min_buffers == 0)
			priv->config.cap_min_buffers = DEF_CAP_MIN_BUFFERS;

		GST_DEBUG("minimum number of buffers on CAPTURE "
			  "for the GStreamer pipeline to work : %d",
			  priv->config.cap_min_buffers);

		priv->config.max_width
			= g_key_file_get_integer(conf_key, libv4l_gst_group,
						 "max-width", NULL);
		priv->config.max_height
			= g_key_file_get_integer(conf_key, libv4l_gst_group,
						 "max-height", NULL);

		preferred_format
			= g_key_file_get_string(conf_key, libv4l_gst_group,
						"preferred-format",
						NULL);
		if (preferred_format && *preferred_format)
			preferred_format_len = strlen(preferred_format);
		if (preferred_format_len == 4) {
			priv->config.preferred_format
				= fourcc_from_string(preferred_format);
		} else if (preferred_format_len > 0) {
			GST_WARNING("Invalid FourCC for preferred-format: %s",
				    preferred_format);
		}
	}

	/* [H264], [HEVC], etc... */
	groups = g_key_file_get_groups(conf_key, &n_groups);
	GST_DEBUG("found %zu section in %s", n_groups, conf_name);
	for (i = 0; i < n_groups; i++) {
		gchar *pipeline_str;

		if (!g_strcmp0(groups[i], libv4l_gst_group))
			continue;

		GST_DEBUG("Parse section: [%s]", groups[i]);
		pipeline_str = g_key_file_get_string(conf_key, groups[i],
						     "pipeline", &err);
		if (err) {
			GST_ERROR("GStreamer pipeline is not specified");
			if (err) g_error_free(err);
			err = NULL;
			continue;
		}
		if (!g_strcmp0(groups[i], "H264")) {
			priv->config.h264_pipeline = pipeline_str;
			n_pipelines++;
			GST_DEBUG("enabled H264 pipeline: %s", pipeline_str);
		} else if (!g_strcmp0(groups[i], "HEVC")) {
			priv->config.hevc_pipeline = pipeline_str;
			n_pipelines++;
			GST_DEBUG("enabled HEVC pipeline: %s", pipeline_str);
		}
	}

	g_strfreev(groups);
free_key_file:
	g_key_file_free(conf_key);

	if (n_pipelines == 0)
		GST_ERROR("no pipeline!");

	return n_pipelines > 0;
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
get_gst_elements(struct v4l_gst *priv)
{
	GstIterator *it;
	gboolean done = FALSE;
	GValue data = { 0, };
	GstElement *elem;
	GstElementFactory *factory;
	const gchar *elem_name;
	const gchar *klass;
	const gchar *decoder_klass = "Codec/Decoder/Video";

	priv->appsrc = priv->appsink = priv->decoder = NULL;

	it = gst_bin_iterate_elements(GST_BIN(priv->pipeline));
	while (!done) {
		switch (gst_iterator_next(it, &data)) {
		case GST_ITERATOR_OK:
			elem = g_value_get_object(&data);

			factory = gst_element_get_factory(elem);
			elem_name = gst_element_factory_get_metadata
				(factory, GST_ELEMENT_METADATA_LONGNAME);
			klass = gst_element_factory_get_metadata
				(factory, GST_ELEMENT_METADATA_KLASS);
			if (!g_strcmp0(elem_name, "AppSrc"))
				priv->appsrc = elem;
			else if (!g_strcmp0(elem_name, "AppSink"))
				priv->appsink = elem;
			else if (!strncmp(klass, decoder_klass,
					  strlen(decoder_klass)))
				priv->decoder = elem;

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

	if (!priv->appsrc || !priv->appsink) {
		GST_ERROR("Failed to get app elements from the pipeline");
		return FALSE;
	}

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

static GstPad *
get_peer_pad(GstElement *elem, const gchar *pad_name, gboolean skip_queue)
{
	GstPad *peer_pad = NULL;
	GstElement *element = elem;

	g_object_ref(element);

	do {
		GstPad *pad = gst_element_get_static_pad(element, pad_name);
		GstElement *holder;
		const gchar *name;

		if (!pad)
			break;
		peer_pad = gst_pad_get_peer(pad);
		gst_object_unref(pad);
		if (!peer_pad)
			break;
		holder = gst_pad_get_parent_element(peer_pad);
		name = gst_element_get_metadata(holder,
						GST_ELEMENT_METADATA_LONGNAME);
		if (skip_queue && !strcmp("Queue", name)) {
			g_object_unref(element);
			g_object_unref(peer_pad);
			peer_pad = NULL;
			element = holder;
		}
	} while(!peer_pad);

	g_object_unref(element);

	return peer_pad;
}

static GstElement *
get_peer_element(GstElement *elem, const gchar *pad_name)
{
	GstPad *peer_pad;
	GstElement *peer_elem;

	peer_pad = get_peer_pad(elem, pad_name, FALSE);
	peer_elem = gst_pad_get_parent_element(peer_pad);
	gst_object_unref(peer_pad);

	return peer_elem;
}

static GstCaps *
get_peer_pad_template_caps(GstElement *elem, const gchar *pad_name)
{
	GstPad *peer_pad;
	GstCaps *caps;

	peer_pad = get_peer_pad(elem, pad_name, TRUE);
	caps = GST_PAD_TEMPLATE_CAPS(GST_PAD_PAD_TEMPLATE(peer_pad));
	gst_caps_ref(caps);
	gst_object_unref(peer_pad);

	return caps;
}

static gboolean
fill_config_video_format_out(struct v4l_gst *priv)
{
	struct fmt fmt;

	g_array_set_size(priv->supported_out_fmts, 0);

	if (priv->config.h264_pipeline) {
		fmt.fourcc = V4L2_PIX_FMT_H264;
		g_strlcpy(fmt.desc, "V4L2_PIX_FMT_H264", FMTDESC_NAME_LENGTH);
		g_array_append_vals(priv->supported_out_fmts, &fmt, 1);
	}
	if (priv->config.hevc_pipeline) {
		fmt.fourcc = V4L2_PIX_FMT_HEVC;
		g_strlcpy(fmt.desc, "V4L2_PIX_FMT_HEVC", FMTDESC_NAME_LENGTH);
		g_array_append_vals(priv->supported_out_fmts, &fmt, 1);
	}
	if (priv->config.h264_pipeline && priv->config.hevc_pipeline) {
		GST_DEBUG("out supported codecs : h264, hevc");
	} else if (priv->config.h264_pipeline) {
		GST_DEBUG("out supported codecs : h264");
	} else if (priv->config.hevc_pipeline) {
		GST_DEBUG("out supported codecs : hevc");
	} else {
		GST_DEBUG("out supported codecs : nothing");
	}
	return priv->supported_out_fmts->len > 0;
}

static gboolean
get_supported_video_format_out(struct v4l_gst *priv)
{
	GstCaps *caps;
	GstStructure *structure;
	const gchar *mime;
	guint fourcc;
	struct fmt *fmt;

	caps = get_peer_pad_template_caps(priv->appsrc, "src");

	structure = gst_caps_get_structure(caps, 0);
	mime = gst_structure_get_name(structure);

	if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_H264) == 0) {
		fourcc = V4L2_PIX_FMT_H264;
	} else if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_HEVC) == 0) {
		fourcc = V4L2_PIX_FMT_HEVC;
	} else {
		GST_ERROR("Unsupported codec : %s", mime);
		gst_caps_unref(caps);
		g_array_set_size(priv->supported_out_fmts, 0);
		return FALSE;
	}
	GST_DEBUG("out supported codec : %s", mime);

	g_array_set_size(priv->supported_out_fmts, 1);
	fmt = (struct fmt*)priv->supported_out_fmts->data;

	fmt->fourcc = fourcc;
	if(fourcc == V4L2_PIX_FMT_H264)
		g_strlcpy(fmt->desc, "V4L2_PIX_FMT_H264", FMTDESC_NAME_LENGTH);
	else if (fourcc == V4L2_PIX_FMT_HEVC)
		g_strlcpy(fmt->desc, "V4L2_PIX_FMT_HEVC", FMTDESC_NAME_LENGTH);
	gst_caps_unref(caps);

	return TRUE;
}

static gboolean
get_supported_video_format_cap(struct v4l_gst *priv)
{
	GstCaps *caps;
	GstStructure *structure;
	guint structs;
	const GValue *val, *list_val;
	const gchar *fmt_str;
	GstVideoFormat fmt;
	guint32 preferred = priv->config.preferred_format;
	gboolean preferred_found = FALSE;
	guint i, j;
	struct fmt color_fmt;
	gchar fourcc_str[5];

	g_array_set_size(priv->supported_cap_fmts, 0);

	caps = get_peer_pad_template_caps(priv->appsink, "sink");

	/* We treat GST_CAPS_ANY as all video formats support. */
	if (gst_caps_is_any(caps)) {
		GST_DEBUG("Use GST_VIDEO_FORMATS_ALL");
		gst_caps_unref(caps);
		caps = gst_caps_from_string
			("video/x-raw, format=" GST_VIDEO_FORMATS_ALL);
	}

	GST_DEBUG("caps: %" GST_PTR_FORMAT, caps);

	structs = gst_caps_get_size(caps);

	for (j = 0; j < structs; j++) {
		gint num_cap_formats;

		structure = gst_caps_get_structure(caps, j);
		val = gst_structure_get_value(structure, "format");
		if (!val)
			continue;

		num_cap_formats = GST_VALUE_HOLDS_LIST(val) ?
			gst_value_list_get_size(val) : 1;

		for (i = 0; i < num_cap_formats; i++) {
			list_val = GST_VALUE_HOLDS_LIST(val) ?
				gst_value_list_get_value(val, i) : val;
			fmt_str = g_value_get_string(list_val);

			fmt = gst_video_format_from_string(fmt_str);
			if (fmt == GST_VIDEO_FORMAT_UNKNOWN) {
				GST_ERROR("Unknown video format : %s", fmt_str);
				continue;
			}

			color_fmt.fourcc = fourcc_from_gst_video_format(fmt);
			if (color_fmt.fourcc == 0) {
				GST_DEBUG("Failed to convert video format "
					  "from gst to v4l2 : %s", fmt_str);
				continue;
			}

			GST_DEBUG("cap supported video format : %s", fmt_str);

			g_strlcpy(color_fmt.desc, fmt_str, FMTDESC_NAME_LENGTH);

			if (preferred && color_fmt.fourcc == preferred) {
				g_array_prepend_vals(priv->supported_cap_fmts,
						     &color_fmt, 1);

				fourcc_to_string(preferred, fourcc_str);
				GST_DEBUG("Preferred format: %s (0x%x)",
					  fourcc_str, preferred);
				preferred_found = TRUE;
			} else {
				g_array_append_vals(priv->supported_cap_fmts,
						    &color_fmt, 1);
			}
		}
	}

	if (preferred) {
		if (preferred_found) {
			/* TODO: Add a new option to force use this? */
			g_array_set_size(priv->supported_cap_fmts, 1);
		} else {
			fourcc_to_string(preferred, fourcc_str);
			GST_INFO("Preferred format %s (0x%x) isn't supported",
				 fourcc_str, preferred);
		}
	}

	gst_caps_unref(caps);

	if (priv->supported_cap_fmts->len == 0) {
		GST_ERROR("Failed to get video formats from caps");
		return FALSE;
	}

	GST_DEBUG("The total number of cap supported video format : %d",
		  priv->supported_cap_fmts->len);


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
push_source_change_event(struct v4l_gst *priv)
{
	struct v4l2_event *event = g_new0(struct v4l2_event, 1);

	event->type = V4L2_EVENT_SOURCE_CHANGE;
	event->u.src_change.changes = V4L2_EVENT_SRC_CH_RESOLUTION;
	event->pending = 0;
	event->sequence = ++priv->v4l2events.sequence;
	event->id = 0;
	clock_gettime(CLOCK_REALTIME, &event->timestamp);

	g_mutex_lock(&priv->v4l2events.mutex);
	g_queue_push_tail(priv->v4l2events.queue, event);
	g_mutex_unlock(&priv->v4l2events.mutex);
}

static void
retrieve_cap_format_info(struct v4l_gst *priv, GstVideoInfo *info)
{
	gint fourcc;

	priv->cap_fmt.width = info->width;
	priv->cap_fmt.height = info->height;

	fourcc = fourcc_from_gst_video_format(info->finfo->format);
	if (priv->cap_fmt.pixelformat != 0 &&
	    priv->cap_fmt.pixelformat != fourcc) {
		GST_WARNING("Unexpected cap video format");
	}
	priv->cap_fmt.pixelformat = fourcc;

	priv->cap_fmt.num_planes = info->finfo->n_planes;
}

static void
wait_for_cap_reqbuf_invocation(struct v4l_gst *priv)
{
	g_mutex_lock(&priv->cap_reqbuf_mutex);
	while (priv->cap_buffers_num <= 0)
		g_cond_wait(&priv->cap_reqbuf_cond, &priv->cap_reqbuf_mutex);
	g_mutex_unlock(&priv->cap_reqbuf_mutex);
}

static inline void
release_out_buffer_unlocked(struct v4l_gst *priv, GstBuffer *gstbuf)
{
	GST_TRACE("unref buffer: %p", gstbuf);
	gst_buffer_unref(gstbuf);

	set_event(priv->event_state, POLLIN);

	priv->returned_out_buffers_num++;
}

static inline void
release_out_buffer(struct v4l_gst *priv, GstBuffer *gstbuf)
{
	g_mutex_lock(&priv->queue_mutex);

	release_out_buffer_unlocked(priv, gstbuf);

	g_mutex_unlock(&priv->queue_mutex);
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

		if ((src_width  && src_width  != info.width) ||
		    (src_height && src_height != info.height)) {
			/* Sometimes decoder may send iterim resolutions that
			   differ from the original one (typically 16x16
			   macroblock based one: e.g. 640x368 vs 640x360) before
			   sending finally determined resolution.
			   Skip such interim resolutions then wait original one.
			 */
			return GST_PAD_PROBE_OK;
		}

		retrieve_cap_format_info(priv, &info);
		g_atomic_int_set(&priv->is_cap_fmt_acquirable, 1);
		push_source_change_event(priv);

		set_event(priv->event_state, POLLOUT);
		wait_for_cap_reqbuf_invocation(priv);

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
		set_buffer_pool_params(priv->sink_pool, caps, info.size,
				       0, priv->cap_buffers_num);

		gst_query_add_allocation_pool(query, priv->sink_pool,
					      info.size,
					      0, priv->cap_buffers_num);
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

static gulong
setup_query_pad_probe(struct v4l_gst *priv)
{
	GstPad *peer_pad;
	gulong probe_id;

	peer_pad = get_peer_pad(priv->appsink, "sink", TRUE);
	g_signal_connect(G_OBJECT(peer_pad), "unlinked",
			 G_CALLBACK(appsink_pad_unlinked_cb), priv);
	probe_id = gst_pad_add_probe(peer_pad,
				     GST_PAD_PROBE_TYPE_QUERY_DOWNSTREAM,
				     pad_probe_query,
				     priv, NULL);
	gst_object_unref(peer_pad);

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
		release_out_buffer(priv, priv->eos_gstbuf);
	priv->eos_state = EOS_GOT;
	g_mutex_lock(&priv->queue_mutex);
	if (priv->cap_gstbufs_queue &&
	    !g_queue_is_empty(priv->cap_gstbufs_queue)) {
	    set_event(priv->event_state, POLLOUT);
	}
	g_mutex_unlock(&priv->queue_mutex);
	GST_DEBUG("Got EOS event");
}

static GstFlowReturn
appsink_callback_new_sample(GstAppSink *appsink, gpointer user_data)
{
	struct v4l_gst *priv = user_data;
	GstBuffer *gstbuf;
	guint len;
	GQueue *queue;

	gstbuf = pull_buffer_from_sample(appsink);

	GST_TRACE("pull buffer: %p", gstbuf);

	if (priv->cap_buffers)
		queue = priv->cap_gstbufs_queue;
	else
		queue = priv->req_gstbufs_queue;

	g_mutex_lock(&priv->queue_mutex);

	g_queue_push_tail(queue, gstbuf);
	len = g_queue_get_length(queue);

	if (len == 2 || (len == 1 && priv->eos_state == EOS_GOT)) {
		/* cache 1 buffer to detect EOS */
		g_cond_signal(&priv->queue_cond);
		set_event(priv->event_state, POLLOUT);
	} else if (!priv->cap_buffers) {
		g_cond_signal(&priv->queue_cond);
	}

	g_mutex_unlock(&priv->queue_mutex);

	return GST_FLOW_OK;
}

static gboolean
init_app_elements(struct v4l_gst *priv)
{
	/* Get appsrc and appsink elements respectively from the pipeline */
	if (!get_gst_elements(priv))
		return FALSE;

	if (!get_supported_video_format_out(priv))
		return FALSE;

	if (!get_supported_video_format_cap(priv))
		return FALSE;

	/* For queuing buffers received from appsink */
	priv->cap_gstbufs_queue = g_queue_new();
	priv->req_gstbufs_queue = g_queue_new();

	/* Set the appsrc queue size to unlimited.
	   The amount of buffers is managed by the buffer pool. */
	gst_app_src_set_max_bytes(GST_APP_SRC(priv->appsrc), 0);

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

static gboolean
init_buffer_pool(struct v4l_gst *priv)
{
	/* Get the external buffer pool when it is specified in
	   the configuration file */
	if (priv->config.pool_lib_path) {
		get_buffer_pool_ops(priv->config.pool_lib_path,
				    &priv->pool_lib_handle, &priv->pool_ops);
	}

	create_buffer_pool(priv->pool_ops, &priv->src_pool, &priv->sink_pool);

	/* To hook allocation queries */
	priv->probe_id = setup_query_pad_probe(priv);
	if (priv->probe_id == 0) {
		GST_ERROR("Failed to setup query pad probe");
		goto free_pool;
	}

	return TRUE;

	/* error cases */
free_pool:
	if (priv->src_pool)
		gst_object_unref(priv->src_pool);
	if (priv->sink_pool)
		gst_object_unref(priv->sink_pool);

	return FALSE;
}

struct v4l_gst*
gst_backend_init(int fd)
{
	static gboolean gstreamer_initialized = FALSE;
	struct v4l_gst *priv;
	struct stat buf;
	int flags;

	if (!gstreamer_initialized) {
		gst_init(NULL, NULL);
		GST_DEBUG_CATEGORY_INIT(v4l_gst_debug_category,
					"v4l-gst", 0,
					"debug category for v4l-gst application");
		GST_DEBUG_CATEGORY_INIT(v4l_gst_ioctl_debug_category,
					"v4l-gst-ioctl", 0,
					"debug category for v4l-gst IOCTL operation");
		gstreamer_initialized = TRUE;
	}

	priv = g_new0(struct v4l_gst, 1);
	if (!priv) {
		GST_ERROR("Couldn't allocate memory for gst-backend");
		return NULL;
	}

	/* Reject character device */
	fstat(fd, &buf);
	if (S_ISCHR(buf.st_mode))
		return NULL;

	flags = fcntl(fd, F_GETFL);
	priv->is_non_blocking = (flags & O_NONBLOCK) ? TRUE : FALSE;
	GST_DEBUG("non-blocking : %s", (priv->is_non_blocking) ? "on" : "off");

	/*For handling event state */
	priv->event_state = new_event_state();
	if (!priv->event_state)
		goto error;

	if (dup2(event_state_fd(priv->event_state), fd) < 0) {
		GST_ERROR("dup2 failed");
		goto error;
	}

	priv->plugin_fd = fd;

	if (!parse_config_file(priv)) {
		GST_ERROR("pipeline configuration is not found at all");
		goto error;
	}

	priv->supported_out_fmts = g_array_new(FALSE, TRUE, sizeof(struct fmt));
	priv->supported_cap_fmts = g_array_new(FALSE, TRUE, sizeof(struct fmt));

	if (!fill_config_video_format_out(priv)) {
		GST_ERROR("Failed to fill in supported video format");
		goto error;
	}

	g_mutex_init(&priv->v4l2events.mutex);
	priv->v4l2events.subscribed = 0;
	priv->v4l2events.sequence = 0;
	priv->v4l2events.queue = g_queue_new();

	g_mutex_init(&priv->queue_mutex);
	g_cond_init(&priv->queue_cond);
	g_mutex_init(&priv->cap_reqbuf_mutex);
	g_cond_init(&priv->cap_reqbuf_cond);

	g_mutex_init(&priv->dev_lock);

	GST_DEBUG("Initialized gst backend");
	return priv;

error:
	if (priv->supported_out_fmts)
		g_array_free(priv->supported_out_fmts, TRUE);
	if (priv->supported_cap_fmts)
		g_array_free(priv->supported_cap_fmts, TRUE);
	g_free(priv->config.h264_pipeline);
	g_free(priv->config.hevc_pipeline);
	g_free(priv->config.pool_lib_path);
	if (priv->event_state)
		delete_event_state(priv->event_state);
	g_free(priv);

	return NULL;
}

static void
remove_query_pad_probe(GstElement *appsink, gulong probe_id)
{
	GstPad *peer_pad;

	peer_pad = get_peer_pad(appsink, "sink", TRUE);
	gst_pad_remove_probe(peer_pad, probe_id);
	gst_object_unref(peer_pad);
}

void
gst_backend_deinit(struct v4l_gst *priv)
{
	GST_DEBUG("gst_backend_deinit start");

	g_mutex_clear(&priv->dev_lock);

	if (priv->v4l2events.queue) {
		g_queue_clear_full(priv->v4l2events.queue,
				   (GDestroyNotify)g_free);
		g_queue_free(priv->v4l2events.queue);
	}
	priv->v4l2events.subscribed = 0;
	g_mutex_clear(&priv->v4l2events.mutex);

	if (priv->decoder_probe_id) {
		GstPad *pad = gst_element_get_static_pad(priv->decoder, "sink");
		gst_pad_remove_probe(pad, priv->decoder_probe_id);
		gst_object_unref(pad);
	}

	if (priv->probe_id)
		remove_query_pad_probe(priv->appsink, priv->probe_id);

	if (priv->out_buffers)
		g_free(priv->out_buffers);

	if (priv->cap_buffers)
		g_free(priv->cap_buffers);

	if (priv->src_pool)
		gst_object_unref(priv->src_pool);
	if (priv->sink_pool)
		gst_object_unref(priv->sink_pool);

	if (priv->supported_out_fmts)
		g_array_free(priv->supported_out_fmts, TRUE);
	if (priv->supported_cap_fmts)
		g_array_free(priv->supported_cap_fmts, TRUE);

	if (priv->cap_gstbufs_queue)
		g_queue_free(priv->cap_gstbufs_queue);
	if (priv->req_gstbufs_queue)
		g_queue_free(priv->req_gstbufs_queue);
	g_mutex_clear(&priv->queue_mutex);
	g_cond_clear(&priv->queue_cond);

	g_mutex_clear(&priv->cap_reqbuf_mutex);
	g_cond_clear(&priv->cap_reqbuf_cond);

	if (priv->pipeline)
		gst_object_unref(priv->pipeline);

	g_free(priv->config.h264_pipeline);
	g_free(priv->config.hevc_pipeline);
	g_free(priv->config.pool_lib_path);

	delete_event_state(priv->event_state);

	g_free(priv);

	GST_DEBUG("gst_backend_deinit end");
}

int
querycap_ioctl(struct v4l_gst *priv, struct v4l2_capability *cap)
{
	GST_DEBUG("VIDIOC_QUERYCAP");

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
	GArray *cap_fmts = priv->supported_cap_fmts;

	pix_fmt = &fmt->fmt.pix_mp;
	fourcc_to_string(pix_fmt->pixelformat, fourcc_str);

	if (!is_pix_fmt_supported((struct fmt*)priv->supported_out_fmts->data,
				  priv->supported_out_fmts->len,
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

	if (priv->pipeline) {
		if (priv->out_fmt.pixelformat == pix_fmt->pixelformat) {
			GST_WARNING("Same pixelformat with current: %s",
				    fourcc_str);
			return 0;
		} else {
			gchar current[5];

			fourcc_to_string(priv->out_fmt.pixelformat, current);
			GST_ERROR("Different pixelformat with current: "
				  "pixelformat:%s, current: %s",
				  fourcc_str, current);
			errno = EINVAL;
			return -1;
		}
	}

	if (pix_fmt->pixelformat == V4L2_PIX_FMT_H264) {
		GST_DEBUG("create H264 pipeline");
		priv->pipeline = create_pipeline(priv->config.h264_pipeline);
	} else if (pix_fmt->pixelformat == V4L2_PIX_FMT_HEVC) {
		GST_DEBUG("create HEVC pipeline");
		priv->pipeline = create_pipeline(priv->config.hevc_pipeline);
	}

	if (!priv->pipeline) {
		GST_ERROR("Failed to create pipieline for %s", fourcc_str);
		goto error;
	}

	/* Initialization regarding appsrc and appsink elements */
	if (!init_app_elements(priv))
		goto error;

	if (!init_buffer_pool(priv))
		goto error;

	priv->out_fmt = *pix_fmt;

	set_params_as_encoded_stream(pix_fmt);

	if (!priv->cap_fmt.pixelformat && cap_fmts->len > 0)
		priv->cap_fmt.pixelformat
			= ((struct fmt*)cap_fmts->data)[0].fourcc;

	return 0;

error:
	if (priv->cap_gstbufs_queue) {
		g_queue_free(priv->cap_gstbufs_queue);
		priv->cap_gstbufs_queue = NULL;
	}
	if (priv->req_gstbufs_queue) {
		g_queue_free(priv->req_gstbufs_queue);
		priv->req_gstbufs_queue = NULL;
	}
	if (priv->pipeline) {
		gst_object_unref(priv->pipeline);
		priv->pipeline = NULL;
	}
	errno = EINVAL;
	return -1;
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
set_fmt_ioctl_cap(struct v4l_gst *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;

	pix_fmt = &fmt->fmt.pix_mp;

	if (!is_pix_fmt_supported((struct fmt*)priv->supported_cap_fmts->data,
				  priv->supported_cap_fmts->len,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on CAPTURE");
		errno = EINVAL;
		return -1;
	}

	GST_OBJECT_LOCK(priv->pipeline);
	if (GST_STATE(priv->pipeline) == GST_STATE_NULL) {
		priv->cap_fmt.pixelformat = pix_fmt->pixelformat;
		init_decoded_frame_params(pix_fmt);
	} else if (priv->cap_fmt.width != pix_fmt->width ||
		   priv->cap_fmt.height != pix_fmt->height ||
		   priv->cap_fmt.pixelformat != pix_fmt->pixelformat) {
		/* TODO: Should check the pix_fmt more strictly. */
		gchar fourcc_str[5];
		fourcc_to_string(pix_fmt->pixelformat, fourcc_str);
		GST_ERROR("Changing pixel format during playing isn't supported: "
			  "width: %u, height: %u, pixelformat: %s (0x%x)",
			  pix_fmt->width, pix_fmt->height,
			  fourcc_str, pix_fmt->pixelformat);
		errno = EBUSY;
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
set_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *fmt)
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

	if (!g_atomic_int_get(&priv->is_cap_fmt_acquirable) ||
		    priv->out_cnt < INPUT_BUFFERING_CNT) {
		errno = EINVAL;
		return -1;
	}

	GST_DEBUG("cap format is acquirable. out_cnt = %d",priv->out_cnt);

	pix_fmt->width = priv->cap_fmt.width;
	pix_fmt->height = priv->cap_fmt.height;
	pix_fmt->pixelformat = priv->cap_fmt.pixelformat;
	pix_fmt->field = V4L2_FIELD_NONE;
	pix_fmt->colorspace = 0;
	pix_fmt->flags = 0;
	pix_fmt->num_planes = priv->cap_fmt.num_planes;

	fourcc_to_string(pix_fmt->pixelformat, fourcc_str);
	GST_DEBUG("width:%d height:%d, format: %s (0x%x) num_plnaes=%d",
		  pix_fmt->width, pix_fmt->height,
		  fourcc_str, pix_fmt->pixelformat,
		  pix_fmt->num_planes);

	if (priv->cap_fmt.plane_fmt[0].sizeimage > 0) {
		for (i = 0; i < pix_fmt->num_planes; i++) {
			pix_fmt->plane_fmt[i].sizeimage =
					priv->
					cap_fmt.plane_fmt[i].sizeimage;
			pix_fmt->plane_fmt[i].bytesperline =
					priv->
					cap_fmt.plane_fmt[i].bytesperline;
		}
		pix_fmt->num_planes = priv->cap_fmt.num_planes;
	} else {
		memset(pix_fmt->plane_fmt, 0, sizeof(pix_fmt->plane_fmt));
	}

	return 0;
}

int
get_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *fmt)
{
	struct v4l2_pix_format_mplane *pix_fmt;
	int ret;

	GST_DEBUG("VIDIOC_G_FMT: type: %s (0x%x)",
		  v4l2_buffer_type_to_string(fmt->type), fmt->type);

	pix_fmt = &fmt->fmt.pix_mp;

	if (fmt->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		g_mutex_lock(&priv->dev_lock);
		*pix_fmt = priv->out_fmt;
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
enum_fmt_ioctl(struct v4l_gst *priv, struct v4l2_fmtdesc *desc)
{
	struct fmt *fmts;
	gint fmts_num;
	gchar fourcc_str[5];

	GST_DEBUG("VIDIOC_ENUM_FMT: type: %s (0x%x) index: %d",
		  v4l2_buffer_type_to_string(desc->type), desc->type, desc->index);

	if (desc->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		fmts = (struct fmt*)priv->supported_out_fmts->data;
		fmts_num = priv->supported_out_fmts->len;
		desc->flags = V4L2_FMT_FLAG_COMPRESSED;
	} else if (desc->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		fmts = (struct fmt*)priv->supported_cap_fmts->data;
		fmts_num = priv->supported_cap_fmts->len;
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
	GST_DEBUG("  description: %s pixelformat: %s (0x%x)",
		  desc->description, fourcc_str, desc->pixelformat);

	return 0;
}

int
enum_framesizes_ioctl(struct v4l_gst *priv, struct v4l2_frmsizeenum *argp)
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
get_raw_video_params(GstBufferPool *pool, GstBuffer *gstbuf, GstVideoInfo *info,
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

	vmeta = gst_buffer_get_video_meta(gstbuf);
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

	if (get_raw_video_params(pool, buffers[v4l2buf->index].gstbuf, NULL,
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

	release_out_buffer(buffer->priv, buffer->gstbuf);
}

static int
qbuf_ioctl_out(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	GstFlowReturn flow_ret;
	GstBuffer *wrapped_gstbuf;
	GstMapInfo info;
	struct v4l_gst_buffer *buffer;

	if (!check_v4l2_buffer(v4l2buf, priv->out_buffers, priv->out_buffers_num,
			       priv->src_pool))
		return -1;

	buffer = &priv->out_buffers[v4l2buf->index];

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
		  priv->out_buffers[v4l2buf->index].gstbuf);

	gst_buffer_unmap(buffer->gstbuf, &buffer->info);
	memset(&buffer->info, 0, sizeof(buffer->info));

	/* Rewrap an input buffer with the just size of bytesused
	   because it will be regarded as having data filled to the entire
	   buffer size internally in the GStreame pipeline.
	   Also set the destructor (notify_unref()). */

	if (!gst_buffer_map(buffer->gstbuf, &info, GST_MAP_READ)) {
		GST_ERROR("Failed to map buffer (%p)", buffer->gstbuf);
		errno = EINVAL;
		return -1;
	}

	wrapped_gstbuf = gst_buffer_new_wrapped_full(
					GST_MEMORY_FLAG_READONLY, info.data,
					v4l2buf->m.planes[0].bytesused, 0,
					v4l2buf->m.planes[0].bytesused,
					buffer, notify_unref);

	gst_buffer_unmap(buffer->gstbuf, &info);

	GST_TRACE("buffer rewrap ts=%ld", v4l2buf->timestamp.tv_sec);
	GST_BUFFER_PTS(wrapped_gstbuf) = GST_TIMEVAL_TO_TIME(v4l2buf->timestamp);

	buffer->state = V4L_GST_BUFFER_QUEUED;

	flow_ret = gst_app_src_push_buffer(
			GST_APP_SRC(priv->appsrc), wrapped_gstbuf);
	if (flow_ret != GST_FLOW_OK) {
		GST_ERROR("Failed to push a buffer to the pipeline on OUTPUT"
			  "(index=%d)", v4l2buf->index);
		errno = EINVAL;
		return -1;
	}

	if (priv->out_cnt < INPUT_BUFFERING_CNT)
	    priv->out_cnt++;

	return 0;
}

static gboolean
push_to_cap_gstbufs_queue(struct v4l_gst *priv, GstBuffer *gstbuf)
{
	gboolean is_empty;
	gint index;

	index = g_queue_index(priv->req_gstbufs_queue, gstbuf);
	if (index < 0)
		return FALSE;

	g_mutex_lock(&priv->queue_mutex);

	is_empty = g_queue_is_empty(priv->cap_gstbufs_queue);
	g_queue_push_tail(priv->cap_gstbufs_queue, gstbuf);

	if (is_empty)
		g_cond_signal(&priv->queue_cond);

	g_mutex_unlock(&priv->queue_mutex);

	g_queue_pop_nth_link(priv->req_gstbufs_queue, index);

	return TRUE;
}

static int
qbuf_ioctl_cap(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	struct v4l_gst_buffer *buffer;

	if (!check_v4l2_buffer(v4l2buf, priv->cap_buffers, priv->cap_buffers_num,
			       priv->sink_pool))
		return -1;

	buffer = &priv->cap_buffers[v4l2buf->index];

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
	if (g_queue_get_length(priv->req_gstbufs_queue) > 0) {
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
qbuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	int ret;

	GST_TRACE("VIDIOC_QBUF: type: %s (0x%x) index: %d flags: 0x%x",
		  v4l2_buffer_type_to_string(v4l2buf->type), v4l2buf->type,
		  v4l2buf->index, v4l2buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = qbuf_ioctl_out(priv, v4l2buf);
		if (ret < 0) {
			g_mutex_unlock(&priv->dev_lock);
			return ret;
		}
	} else if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = qbuf_ioctl_cap(priv, v4l2buf);
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
set_v4l2_buffer_plane_params(struct v4l_gst *priv,
			     struct v4l_gst_buffer *buffers, guint n_planes,
			     guint bytesused[], struct timeval *timestamp,
			     struct v4l2_buffer *v4l2buf)
{
	gint i;

	memcpy(v4l2buf->m.planes, buffers[v4l2buf->index].planes,
	       sizeof(struct v4l2_plane) * n_planes);

	if (bytesused) {
		for (i = 0; i < n_planes; i++)
			v4l2buf->m.planes[i].bytesused = bytesused[i];
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

	get_raw_video_params(pool, buffers[v4l2buf->index].gstbuf, NULL, &meta);

	n_planes = (meta) ? meta->n_planes : 1;

	set_v4l2_buffer_plane_params(priv, buffers, n_planes, bytesused,
				     timestamp, v4l2buf);

	v4l2buf->flags = 0;
	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE &&
	    priv->eos_state == EOS_GOT &&
	    g_queue_is_empty(priv->cap_gstbufs_queue)) {
		GST_DEBUG("Set V4L2_BUF_FLAG_LAST");
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
dequeue_buffer(struct v4l_gst *priv, GQueue *queue, GCond *cond,
		int type)
{
	GstBuffer *gstbuf = NULL;

	g_mutex_lock(&priv->queue_mutex);

	if (priv->is_non_blocking)
		gstbuf = dequeue_non_blocking(queue);
	else
		gstbuf = dequeue_blocking(priv, queue, cond);

	if (!gstbuf)
		goto unlock;

	if (type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		if (priv->returned_out_buffers_num == 0)
			clear_event(priv->event_state, POLLIN);
	} else if (type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		guint len = g_queue_get_length(priv->cap_gstbufs_queue);

		/* cache 1 buffer to detect EOS */
		if ((priv->eos_state != EOS_GOT && len == 1) || len == 0) {
			clear_event(priv->event_state, POLLOUT);
		}
	}

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

	if (!check_no_index_v4l2_buffer(v4l2buf, priv->out_buffers,
					priv->src_pool))
		return -1;

	g_mutex_lock(&priv->queue_mutex);

	gstbuf = acquire_buffer_from_pool(priv, priv->src_pool);
	if (!gstbuf) {
		g_mutex_unlock(&priv->queue_mutex);
		return -1;
	}

	priv->returned_out_buffers_num--;

	if (priv->returned_out_buffers_num == 0) {
		clear_event(priv->event_state, POLLIN);
	}


	g_mutex_unlock(&priv->queue_mutex);

	index = get_v4l2_buffer_index(priv->out_buffers,
				      priv->out_buffers_num, gstbuf);
	if (index >= priv->out_buffers_num) {
		GST_ERROR("Failed to get a valid buffer index "
			  "on OUTPUT");
		errno = EINVAL;
		return -1;
	}

	v4l2buf->index = index;
	priv->out_buffers[v4l2buf->index].state = V4L_GST_BUFFER_DEQUEUED;

	GST_TRACE("success dequeue buffer index=%d buffer=%p", index, gstbuf);

	return fill_v4l2_buffer(priv, priv->src_pool,
				priv->out_buffers, priv->out_buffers_num,
				NULL, NULL, v4l2buf);
}

static int
dqbuf_ioctl_cap(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	GstBuffer *gstbuf;
	guint index;
	struct timeval timestamp;
	guint bytesused[GST_VIDEO_MAX_PLANES];
	gint i;

	if (!check_no_index_v4l2_buffer(v4l2buf, priv->cap_buffers,
					priv->sink_pool))
		return -1;

	gstbuf = dequeue_buffer(priv, priv->cap_gstbufs_queue,
				&priv->queue_cond, v4l2buf->type);
	if (!gstbuf)
		return -1;

	index = get_v4l2_buffer_index(priv->cap_buffers,
				      priv->cap_buffers_num, gstbuf);
	if (index >= priv->cap_buffers_num) {
		GST_ERROR("Failed to get a valid buffer index "
			  "on CAPTURE");
		errno = EINVAL;
		gst_buffer_unref(gstbuf);
		return -1;
	}

	v4l2buf->index = index;

	for (i = 0; i < priv->cap_fmt.num_planes; i++)
		bytesused[i] = priv->cap_fmt.plane_fmt[i].sizeimage;

	GST_TIME_TO_TIMEVAL(GST_BUFFER_PTS(gstbuf), timestamp);

	if (priv->cap_buffers[index].state == V4L_GST_BUFFER_DEQUEUED) {
		/* It might be occurred when a buffer is unexpectedly queued
		   after streamoff_ioctl_out(). In this case reference count of
		   the buffer should have been already incremeneted, need to
		   revert it here. */
		GST_WARNING("Already dequeued buffer %u is dequeued again", index);
		gst_buffer_unref(priv->cap_buffers[index].gstbuf);
	}
	priv->cap_buffers[v4l2buf->index].state = V4L_GST_BUFFER_DEQUEUED;

	GST_TRACE("success dequeue buffer index=%d gstbuf=%p ts=%ld",
		  index, gstbuf, timestamp.tv_sec);

	return fill_v4l2_buffer(priv, priv->sink_pool,
				priv->cap_buffers, priv->cap_buffers_num,
				bytesused, &timestamp, v4l2buf);
}

int
dqbuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
{
	int ret;

	GST_TRACE("VIDIOC_DQBUF: type: %s (0x%x) index: %d flags: 0x%x",
		  v4l2_buffer_type_to_string(v4l2buf->type), v4l2buf->type,
		  v4l2buf->index, v4l2buf->flags);

	g_mutex_lock(&priv->dev_lock);

	if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE) {
		ret = dqbuf_ioctl_out(priv, v4l2buf);
		if (ret < 0) {
			g_mutex_unlock(&priv->dev_lock);
			return ret;
		}

	} else if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		ret = dqbuf_ioctl_cap(priv, v4l2buf);
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
querybuf_ioctl(struct v4l_gst *priv, struct v4l2_buffer *v4l2buf)
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
		buffers = priv->out_buffers;
		buffers_num = priv->out_buffers_num;
		pool = priv->src_pool;
	} else if (v4l2buf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) {
		buffers = priv->cap_buffers;
		buffers_num = priv->cap_buffers_num;
		pool = priv->sink_pool;
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

static GstCaps *
get_codec_caps_from_fourcc(guint fourcc)
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

	if (!get_raw_video_params(pool, buffer->gstbuf, &info, &meta)) {
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
	get_buffer_pool_params(pool, NULL, NULL, NULL, &actual_max_buffers);
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

	while (force_dqbuf_from_pool(priv->src_pool, priv->out_buffers,
			   priv->out_buffers_num, TRUE) == GST_FLOW_OK) {
		priv->returned_out_buffers_num--;
	}

	clear_event(priv->event_state, POLLIN);

	g_mutex_unlock(&priv->queue_mutex);

	GST_DEBUG("returned_out_buffers_num : %d", priv->returned_out_buffers_num);

	return 0;
}

static int
force_cap_dqbuf(struct v4l_gst *priv)
{
	GstBuffer *gstbuf;
	guint index;

	do {
		g_mutex_lock(&priv->queue_mutex);
		gstbuf = dequeue_non_blocking(priv->cap_gstbufs_queue);
		 /* This function may set errno but not need to expose it to
		    clients in this case */
		errno = 0;
		g_mutex_unlock(&priv->queue_mutex);

		if (!gstbuf)
			break;

		index = get_v4l2_buffer_index(priv->cap_buffers,
					      priv->cap_buffers_num, gstbuf);
		if (index >= priv->cap_buffers_num) {
			GST_ERROR("Failed to get a valid buffer index "
				  "on CAPTURE");
			errno = EINVAL;
			return -1;
		}

		priv->cap_buffers[index].state = V4L_GST_BUFFER_DEQUEUED;
		GST_DEBUG("CAPTURE buffer %u is forcedly dequeued", index);
	} while (gstbuf);

	clear_event(priv->event_state, POLLOUT);

	for (index = 0; index < priv->cap_buffers_num; index++) {
		if (priv->cap_buffers[index].state == V4L_GST_BUFFER_DEQUEUED)
			continue;
		gst_buffer_ref(priv->cap_buffers[index].gstbuf);
		priv->cap_buffers[index].state = V4L_GST_BUFFER_DEQUEUED;
	}

	return 0;
}

static int
flush_pipeline(struct v4l_gst *priv)
{
	GstEvent *event;

	GST_DEBUG("flush start");

	gst_buffer_pool_set_flushing(priv->src_pool, TRUE);
	gst_buffer_pool_set_flushing(priv->sink_pool, TRUE);

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

	gst_buffer_pool_set_flushing(priv->src_pool, FALSE);
	gst_buffer_pool_set_flushing(priv->sink_pool, FALSE);

	GST_DEBUG("flush end");

	return 0;
}

static int
streamoff_ioctl_out(struct v4l_gst *priv, gboolean steal_ref)
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
		gst_buffer_ref(priv->out_buffers[0].gstbuf);

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
reqbuf_ioctl_out(struct v4l_gst *priv,
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
		for (i = 0; i < priv->out_buffers_num; i++) {
			if (priv->out_buffers[i].state ==
			    V4L_GST_BUFFER_DEQUEUED) {
				gst_buffer_unref(priv->out_buffers[i].gstbuf);
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

	caps = get_codec_caps_from_fourcc(priv->out_fmt.pixelformat);
	if (!caps) {
		errno = EINVAL;
		ret = -1;
		goto unlock;
	}

	adjusted_count = MAX(req->count, INPUT_BUFFERING_CNT);
	adjusted_count = MIN(adjusted_count, VIDEO_MAX_FRAME);

	set_buffer_pool_params(priv->src_pool, caps,
			       priv->out_fmt.plane_fmt[0].sizeimage,
			       adjusted_count, adjusted_count);

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
				gst_buffer_get_size(priv->out_buffers[i].gstbuf);
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
peek_first_cap_buffer(struct v4l_gst *priv)
{
	GstBuffer *gstbuf;

	g_mutex_lock(&priv->queue_mutex);
	gstbuf = g_queue_peek_head(priv->req_gstbufs_queue);
	while (!gstbuf) {
		g_cond_wait(&priv->queue_cond, &priv->queue_mutex);
		gstbuf = g_queue_peek_head(priv->req_gstbufs_queue);
	}
	g_mutex_unlock(&priv->queue_mutex);

	return gstbuf;
}

static void
wait_for_all_bufs_collected(struct v4l_gst *priv,
			    guint max_buffers)
{
	g_mutex_lock(&priv->queue_mutex);
	while (g_queue_get_length(priv->req_gstbufs_queue) <
	       max_buffers)
		g_cond_wait(&priv->queue_cond, &priv->queue_mutex);
	g_mutex_unlock(&priv->queue_mutex);
}

static gboolean
retrieve_cap_frame_info(GstBufferPool *pool, GstBuffer *gstbuf,
			struct v4l2_pix_format_mplane *cap_fmt)
{
	GstVideoInfo info;
	GstVideoMeta *meta;
	gint i;

	if (!get_raw_video_params(pool, gstbuf, &info, &meta)) {
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

	if (priv->cap_buffers)
		/* Cannot realloc the buffers without stopping the pipeline,
		   so return the same number of the buffers so far. */
		return priv->cap_buffers_num;

	g_mutex_unlock(&priv->dev_lock);

	first_gstbuf = peek_first_cap_buffer(priv);

	g_mutex_lock(&priv->dev_lock);

	if (!first_gstbuf->pool) {
		GST_ERROR("Cannot handle buffers not belonging to "
			  "a bufferpool");
		errno = EINVAL;
		return 0;
	}

	if (priv->sink_pool != first_gstbuf->pool) {
		GST_DEBUG("The buffer pool we prepared is not used by "
			  "the pipeline, so replace it with the pool that is "
			  "actually used");
		gst_object_unref(priv->sink_pool);
		priv->sink_pool = gst_object_ref(first_gstbuf->pool);
	}

	/* Confirm the number of buffers actually set to the buffer pool. */
	get_buffer_pool_params(priv->sink_pool, NULL, NULL, NULL,
			       &actual_max_buffers);
	if (actual_max_buffers == 0) {
		GST_ERROR("Cannot handle the unlimited amount of buffers");
		errno = EINVAL;
		return 0;
	}

	if (!retrieve_cap_frame_info(priv->sink_pool, first_gstbuf,
				     &priv->cap_fmt)) {
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
		priv->cap_buffers[i].gstbuf =
				g_queue_peek_nth(priv->req_gstbufs_queue, i);

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
		for (j = 0; j < priv->cap_fmt.num_planes; j++) {
			priv->cap_buffers[i].planes[j].length =
					priv->cap_fmt.plane_fmt[j].sizeimage;
		}

		GST_DEBUG("cap gst_buffer[%d] : %p", i,
			  priv->cap_buffers[i].gstbuf);
	}

	GST_DEBUG("The number of buffers actually set to the buffer pool is %d",
		  actual_max_buffers);

	return actual_max_buffers;
}

static int
reqbuf_ioctl_cap(struct v4l_gst *priv,
		 struct v4l2_requestbuffers *req)
{
	GstStateChangeReturn state_ret;
	int ret;
	gint i;

	if (!is_supported_memory_io(req->memory)) {
		GST_ERROR("Only V4L2_MEMORY_MMAP is supported");
		return -1;
	}

	g_mutex_lock(&priv->dev_lock);

	if (req->count == 0) {
		GST_DEBUG("req->count == 0");

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
				gst_buffer_unref(priv->cap_buffers[i].gstbuf);
			}
		}

		g_queue_clear(priv->req_gstbufs_queue);
		g_queue_clear(priv->cap_gstbufs_queue);

		g_mutex_lock(&priv->queue_mutex);
		priv->is_pipeline_started = FALSE;
		g_cond_broadcast(&priv->queue_cond);
		g_mutex_unlock(&priv->queue_mutex);

		if (priv->cap_buffers) {
			g_free(priv->cap_buffers);
			priv->cap_buffers = NULL;
		}
		init_decoded_frame_params(&priv->cap_fmt);

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

	req->count = priv->cap_buffers_num = create_cap_buffers_list(priv);
	if (req->count == 0) {
		ret = -1;
		goto unlock;
	}

	GST_DEBUG("buffers count=%d", req->count);

	ret = 0;

unlock:
	g_mutex_unlock(&priv->dev_lock);

	return ret;
}

int
reqbuf_ioctl(struct v4l_gst *priv, struct v4l2_requestbuffers *req)
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

static gboolean
relink_elements_with_caps_filtered(GstElement *src_elem, GstElement *dest_elem,
				   GstCaps *caps)
{
	gst_element_unlink(src_elem, dest_elem);
	return gst_element_link_filtered(src_elem, dest_elem, caps);
}

static gboolean
set_out_format_to_pipeline(struct v4l_gst *priv)
{
	GstCaps *caps;

	caps = get_codec_caps_from_fourcc(priv->out_fmt.pixelformat);
	if (!caps) {
		errno = EINVAL;
		return FALSE;
	}

	gst_app_src_set_caps(GST_APP_SRC(priv->appsrc), caps);
	gst_caps_unref(caps);

	return TRUE;
}

static gboolean
set_cap_format_to_pipeline(struct v4l_gst *priv)
{
	GstElement *peer_elem;
	GstCaps *caps;
	GstVideoFormat fmt;
	gboolean ret;

	fmt = fourcc_to_gst_video_format(priv->cap_fmt.pixelformat);
	if (fmt == GST_VIDEO_FORMAT_UNKNOWN) {
		gchar fourcc_str[5];
		fourcc_to_string(priv->cap_fmt.pixelformat, fourcc_str);
		GST_ERROR("Invalid format on CAPTURE: %s (0x%x)",
			  fourcc_str, priv->cap_fmt.pixelformat);
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
	GST_DEBUG("appsink element is relinked");

	ret = TRUE;

free_objects:
	gst_caps_unref(caps);
	gst_object_unref(peer_elem);

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
		gst_buffer_unref(priv->out_buffers[0].gstbuf);
	}

	priv->eos_state = EOS_NONE;

	gst_element_set_state(priv->pipeline, GST_STATE_PLAYING);

	priv->is_pipeline_started = TRUE;

	g_mutex_unlock(&priv->dev_lock);

	GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS(GST_BIN(priv->pipeline),
					  GST_DEBUG_GRAPH_SHOW_ALL,
					  "v4l-gst.streamon.snapshot");

	return 0;
}

int
streamon_ioctl(struct v4l_gst *priv, enum v4l2_buf_type *type)
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
streamoff_ioctl(struct v4l_gst *priv, enum v4l2_buf_type *type)
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

int
subscribe_event_ioctl(struct v4l_gst *priv,
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
dqevent_ioctl(struct v4l_gst *priv, struct v4l2_event *ev)
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

static int
find_out_buffer_by_offset(struct v4l_gst *priv, int64_t offset)
{
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
map_out_buffer(struct v4l_gst *priv, int index, int prot)
{
	GstMapInfo info;
	void *data;
	GstMapFlags map_flags;

	map_flags = (prot & PROT_READ) ? GST_MAP_READ : 0;
	map_flags |= (prot & PROT_WRITE) ? GST_MAP_WRITE : 0;

	if (!gst_buffer_map(priv->out_buffers[index].gstbuf, &info,
			    map_flags)) {
		GST_ERROR("Failed to map buffer (%p)",
			  priv->out_buffers[index].gstbuf);
		errno = EINVAL;
		return MAP_FAILED;
	}

	data = info.data;

	gst_buffer_unmap(priv->out_buffers[index].gstbuf, &info);

	priv->out_buffers[index].flags = map_flags;

	return data;
}

static int
find_cap_buffer_by_offset(struct v4l_gst *priv,
			  int64_t offset, int *index, int *plane)
{
	gint i, j;

	for (i = 0; i < priv->cap_buffers_num; i++) {
		for (j = 0; j < priv->cap_fmt.num_planes; j++) {
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
map_cap_buffer(struct v4l_gst *priv, int index, int plane,
	       int prot)
{
	GstVideoMeta *meta;
	GstMapInfo info;
	void *data;
	GstMapFlags map_flags;

	map_flags = (prot & PROT_READ) ? GST_MAP_READ : 0;
	map_flags |= (prot & PROT_WRITE) ? GST_MAP_WRITE : 0;

	if (!gst_buffer_map(priv->cap_buffers[index].gstbuf, &info,
			    map_flags)) {
		GST_ERROR("Failed to map buffer (%p)",
			  priv->cap_buffers[index].gstbuf);
		errno = EINVAL;
		return MAP_FAILED;
	}

	if (!get_raw_video_params(priv->sink_pool,
				  priv->cap_buffers[index].gstbuf,
				  NULL, &meta)) {
		GST_ERROR("Failed to get video meta data");
		errno = EINVAL;
		gst_buffer_unmap(priv->cap_buffers[index].gstbuf,
				 &priv->cap_buffers[index].info);
		return MAP_FAILED;
	}

	data = info.data + meta->offset[plane];

	gst_buffer_unmap(priv->cap_buffers[index].gstbuf, &info);

	priv->cap_buffers[index].flags = map_flags;

	return data;
}

void *
gst_backend_mmap(struct v4l_gst *priv, void *start, size_t length,
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
expbuf_ioctl(struct v4l_gst *priv, struct v4l2_exportbuffer *expbuf)
{
	struct v4l_gst_buffer *buffer;
	guint i = 0;
	GstMemory *mem = NULL;

	GST_TRACE("VIDIOC_EXPBUF: type: 0x%x index: %d flags: 0x%x",
		  expbuf->type, expbuf->index, expbuf->flags);

	if ((expbuf->type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE) ||
	    (expbuf->type == V4L2_BUF_TYPE_PRIVATE)) {
		buffer = &priv->cap_buffers[expbuf->index];
		if (expbuf->plane < gst_buffer_n_memory(buffer->gstbuf)) {
			i = expbuf->plane;
		}

		mem = gst_buffer_peek_memory(buffer->gstbuf, i);
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
		if (priv->cap_fmt.pixelformat == V4L2_PIX_FMT_NV12 ||
		    priv->cap_fmt.pixelformat == V4L2_PIX_FMT_NV21) {
			if (expbuf->plane == 1) {
				/* chromium V4L2 decoder implicitly use reserved[0] as frame offset, so set appropriate
				   offset to secondary plane. */
				gsize memory_size = gst_memory_get_sizes(mem, 0, NULL);
				gsize total_plane_size = priv->cap_fmt.plane_fmt[0].sizeimage + priv->cap_fmt.plane_fmt[1].sizeimage;
				if (memory_size == total_plane_size) {
					expbuf->reserved[0] = mem->offset + priv->cap_fmt.plane_fmt[0].sizeimage;
				}
			}
		}
		break;
	default:
		GST_ERROR("Can only export capture buffers as dmebuf");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int
g_selection_ioctl(struct v4l_gst *priv, struct v4l2_selection *selection)
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
	selection->r.width = priv->cap_fmt.width;
	selection->r.height = priv->cap_fmt.height;

	return 0;
}

/* See https://github.com/JeffyCN/libv4l-rkmpp/blob/master/src/libv4l-rkmpp-dec.c#L740-L776 */
int
queryctrl_ioctl(struct v4l_gst *priv, struct v4l2_queryctrl *query_ctrl)
{

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
		if (priv->config.h264_pipeline) {
			query_ctrl->minimum = V4L2_MPEG_VIDEO_H264_PROFILE_BASELINE;
			query_ctrl->maximum = V4L2_MPEG_VIDEO_H264_PROFILE_HIGH_10;
		} else {
			GST_ERROR("disabled H264 profile for query_ctrl id: %x", query_ctrl->id);
			errno = EINVAL;
			return -1;
		}
		break;
	case V4L2_CID_MPEG_VIDEO_HEVC_PROFILE:
		if (priv->config.hevc_pipeline) {
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
			GST_ERROR("unsupported H264 profile index: %x", query_menu->index);
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
			GST_ERROR("unsupported HEVC profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_HEVC_PROFILE index: %x", query_menu->index);
		break;
#if 0 // omit non-supported AV1, VP8, VP9
	case V4L2_CID_MPEG_VIDEO_AV1_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_AV1_PROFILE_MAIN) {
			GST_ERROR("unsupported VP8 profile index: %x", query_menu->index);
			errno = EINVAL;
			return -1;
		}
		GST_DEBUG("V4L2_CID_MPEG_VIDEO_AV1_PROFILE index: %x", query_menu->index);
		break;
	case V4L2_CID_MPEG_VIDEO_VP8_PROFILE:
		if (query_menu->index != V4L2_MPEG_VIDEO_VP8_PROFILE_0) {
			GST_ERROR("unsupported VP8 profile index: %x", query_menu->index);
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
			GST_ERROR("unsupported VP9 profile index: %x", query_menu->index);
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

static int
try_fmt_ioctl_out(struct v4l_gst *priv, struct v4l2_format *format)
{
	struct v4l2_pix_format_mplane *pix_fmt = &format->fmt.pix_mp;
	gchar fourcc_str[5];

	fourcc_to_string(pix_fmt->pixelformat, fourcc_str);

	if (!is_pix_fmt_supported((struct fmt*)priv->supported_out_fmts->data,
				  priv->supported_out_fmts->len,
				  pix_fmt->pixelformat)) {
		GST_ERROR("Unsupported pixelformat on OUTPUT: %s (0x%x)",
			  fourcc_str, pix_fmt->pixelformat);

		errno = EINVAL;
		return -1;
	}

	if (priv->pipeline &&
	    priv->out_fmt.pixelformat != pix_fmt->pixelformat) {
		gchar current[5];

		fourcc_to_string(priv->out_fmt.pixelformat, current);
		GST_ERROR("Different pixelformat with current: "
			  "pixelformat:%s, current: %s",
			  fourcc_str, current);

		errno = EINVAL;
		return -1;
	}

	set_params_as_encoded_stream(pix_fmt);

	return 0;
}

static int
try_fmt_ioctl_cap(struct v4l_gst *priv, struct v4l2_format *format)
{
	struct v4l2_pix_format_mplane *pix_fmt = &format->fmt.pix_mp;

	if (!is_pix_fmt_supported((struct fmt*)priv->supported_cap_fmts->data,
				  priv->supported_cap_fmts->len,
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
try_fmt_ioctl(struct v4l_gst *priv, struct v4l2_format *format)
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
g_crop_ioctl(struct v4l_gst *priv, struct v4l2_crop *crop)
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
try_decoder_cmd_ioctl(struct v4l_gst *priv,
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
unsubscribe_event_ioctl(struct v4l_gst *priv,
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

int
decoder_cmd_ioctl(struct v4l_gst *priv, struct v4l2_decoder_cmd *decoder_cmd)
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
