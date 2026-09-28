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

GstDebugCategory *v4l_gst_debug_category;
GstDebugCategory *v4l_gst_ioctl_debug_category;
GstDebugCategory *v4l_gst_buffer_debug_category;

G_DEFINE_QUARK(cap_buf_crc, cap_buf_crc)

void
v4l_gst_core_reset_cap_timestamp_state(struct v4l_gst *priv)
{
	priv->last_cap_pts = GST_CLOCK_TIME_NONE;
	priv->estimated_cap_duration = GST_CLOCK_TIME_NONE;
}


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
		gchar *preferred_format, *fixed_pipeline;
		guint preferred_format_len = 0;
		const gchar *frame_check;

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
		g_free(preferred_format);

		fixed_pipeline
			= g_key_file_get_string(conf_key, libv4l_gst_group,
						"fixed-pipeline",
						NULL);
		if (fixed_pipeline) {
			guint32 fourcc = fourcc_from_string(fixed_pipeline);
			if (fourcc == V4L2_PIX_FMT_H264 ||
			    fourcc == V4L2_PIX_FMT_HEVC) {
				priv->config.fixed_pipeline = fourcc;
			} else {
				GST_WARNING("Unknown fixed-pipeline: %s",
					    fixed_pipeline);
			}
		}
		g_free(fixed_pipeline);

		frame_check = getenv("V4L_GST_FRAME_CHECK");
		if (frame_check) {
			if (!strcmp("1", frame_check) ||
			    !strcasecmp("light", frame_check) ||
			    !strcasecmp("true", frame_check) ||
			    !strcasecmp("enable", frame_check))
				priv->config.frame_check = FRAME_CHECK_LIGHT;
			else if (!strcmp("2", frame_check) ||
				 !strcasecmp("full", frame_check))
				priv->config.frame_check = FRAME_CHECK_FULL;
		}
	}

	/* [H264], [HEVC], etc... */
	priv->config.pipelines = g_hash_table_new_full(g_str_hash, g_str_equal,
						       g_free, g_free);
	groups = g_key_file_get_groups(conf_key, &n_groups);
	GST_DEBUG("found %zu section in %s", n_groups, conf_name);
	for (i = 0; i < n_groups; i++) {
		gchar *pipeline_str;

		if (!g_strcmp0(groups[i], libv4l_gst_group))
			continue;

		/* treat only fourcc */
		if (strlen(groups[i]) != 4)
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

		g_hash_table_insert(priv->config.pipelines,
				    g_strdup(groups[i]),
				    pipeline_str);
		GST_DEBUG("enabled %s pipeline: %s", groups[i], pipeline_str);
		n_pipelines++;
	}

	g_strfreev(groups);
 free_key_file:
	g_key_file_free(conf_key);

	if (n_pipelines == 0)
		GST_ERROR("no pipeline!");

	return n_pipelines > 0;
}


GstElement *
v4l_gst_core_create_pipeline(const gchar *pipeline_str)
{
	const gchar *format_str;
	gchar *launch_str;
	GstElement *pipeline;
	GError *err = NULL;
	gboolean has_appsrc = !!strstr(pipeline_str, "appsrc");
	gboolean has_appsink = !!strstr(pipeline_str, "appsink");

	if (has_appsrc && has_appsink)
		format_str = "%s";
	else if (has_appsrc)
		format_str = "%s ! appsink";
	else if (has_appsink)
		format_str = "appsrc ! %s";
	else
		format_str = "appsrc ! %s ! appsink";

	launch_str = g_strdup_printf(format_str, pipeline_str);

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
get_peer_pad(GstElement *elem, const gchar *pad_name)
{
	GstPad *pad, *peer_pad = NULL;

	pad = gst_element_get_static_pad(elem, pad_name);
	if (!pad)
		return NULL;

	peer_pad = gst_pad_get_peer(pad);
	gst_object_unref(pad);

	return peer_pad;
}


GstElement *
v4l_gst_core_get_peer_element(GstElement *elem, const gchar *pad_name)
{
	GstPad *peer_pad;
	GstElement *peer_elem;

	peer_pad = get_peer_pad(elem, pad_name);
	if (!peer_pad)
		return NULL;

	peer_elem = gst_pad_get_parent_element(peer_pad);
	gst_object_unref(peer_pad);

	return peer_elem;
}


static GstCaps *
get_peer_pad_template_caps(GstElement *elem, const gchar *pad_name, GstPad **peer_pad)
{
	GstPad *pad, *first_peer_pad = NULL;
	GstCaps *caps = NULL, *first_caps = NULL;;

	gst_object_ref(elem);

	do {
		pad = get_peer_pad(elem, pad_name);
		gst_object_unref(elem);
		if (!pad)
			break;

		caps = GST_PAD_TEMPLATE_CAPS(GST_PAD_PAD_TEMPLATE(pad));
		if (!first_caps) {
			first_caps = caps;
			gst_caps_ref(first_caps);
			first_peer_pad = pad;
			gst_object_ref(first_peer_pad);
		}

		/* Skip meaningless elements such as queue or tee */
		if (gst_caps_is_any(caps)) {
			caps = NULL;
			elem = gst_pad_get_parent_element(pad);
			gst_object_unref(pad);
		} else {
			gst_caps_ref(caps);
		}
	} while (!caps && elem && pad);

	if (first_caps) {
		/* fallback to first peer if no meaningful caps found */
		if (!caps) {
			caps = first_caps;
			pad = first_peer_pad;
		} else {
			gst_caps_unref(first_caps);
			gst_object_unref(first_peer_pad);
		}
	}

	if (peer_pad)
		*peer_pad = pad;
	else if (pad)
		gst_object_unref(pad);

	return caps;
}


static void
fill_out_fmts_func(gpointer key, gpointer value, gpointer user_data)
{
	GArray *fmts = user_data;
	struct fmt fmt;

	fmt.fourcc = fourcc_from_string(key);
	g_strlcpy(fmt.desc, key, FMTDESC_NAME_LENGTH);
	g_array_append_vals(fmts, &fmt, 1);
}


static gboolean
fill_config_video_format_out(struct v4l_gst *priv)
{
	gint i;
	gchar codecs[256] = {0};

	g_array_set_size(priv->out.supported_fmts, 0);
	g_hash_table_foreach(priv->config.pipelines,
			     fill_out_fmts_func,
			     priv->out.supported_fmts);

	for (i = 0; i < priv->out.supported_fmts->len; i++) {
		struct fmt *fmts = (struct fmt*)priv->out.supported_fmts->data;
		g_strlcat(codecs, fmts[i].desc, sizeof(codecs));
		g_strlcat(codecs, " ", sizeof(codecs));
	}
	GST_DEBUG("supported codecs: %s", codecs);

	return priv->out.supported_fmts->len > 0;
}


static void
fill_config_video_format_cap(struct v4l_gst *priv)
{
	struct fmt color_fmt;

	if (priv->config.preferred_format) {
		color_fmt.fourcc = priv->config.preferred_format;
		fourcc_to_string(priv->config.preferred_format, color_fmt.desc);
	} else {
		color_fmt.fourcc = fourcc_from_string("NV12");
		g_strlcpy(color_fmt.desc, "NV12", FMTDESC_NAME_LENGTH);
	}
	g_array_prepend_vals(priv->cap.supported_fmts,
			     &color_fmt, 1);
}


static gboolean
get_supported_video_format_out(struct v4l_gst *priv)
{
	GstCaps *caps;
	GstStructure *structure;
	const gchar *mime;
	guint fourcc;
	struct fmt *fmt;

	caps = get_peer_pad_template_caps(priv->appsrc, "src", NULL);
	if (!caps) {
		GST_ERROR("Failed to get video format for OUTPUT");
		return FALSE;
	}

	structure = gst_caps_get_structure(caps, 0);
	mime = gst_structure_get_name(structure);

	if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_H264) == 0) {
		fourcc = V4L2_PIX_FMT_H264;
	} else if (g_strcmp0(mime, GST_VIDEO_CODEC_MIME_HEVC) == 0) {
		fourcc = V4L2_PIX_FMT_HEVC;
	} else {
		GST_ERROR("Unsupported codec : %s", mime);
		gst_caps_unref(caps);
		g_array_set_size(priv->out.supported_fmts, 0);
		return FALSE;
	}
	GST_DEBUG("out supported codec : %s", mime);

	g_array_set_size(priv->out.supported_fmts, 1);
	fmt = (struct fmt*)priv->out.supported_fmts->data;

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

	g_array_set_size(priv->cap.supported_fmts, 0);

	caps = get_peer_pad_template_caps(priv->appsink, "sink",
					  &priv->video_sink_pad);
	if (!caps) {
		GST_ERROR("Failed to get video format for CAPTURE");
		return FALSE;
	}

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
				g_array_prepend_vals(priv->cap.supported_fmts,
						     &color_fmt, 1);

				fourcc_to_string(preferred, fourcc_str);
				GST_DEBUG("Preferred format: %s (0x%x)",
					  fourcc_str, preferred);
				preferred_found = TRUE;
			} else {
				g_array_append_vals(priv->cap.supported_fmts,
						    &color_fmt, 1);
			}
		}
	}

	if (preferred) {
		if (preferred_found) {
			/* TODO: Add a new option to force use this? */
			g_array_set_size(priv->cap.supported_fmts, 1);
		} else {
			fourcc_to_string(preferred, fourcc_str);
			GST_INFO("Preferred format %s (0x%x) isn't supported",
				 fourcc_str, preferred);
		}
	}

	gst_caps_unref(caps);

	if (priv->cap.supported_fmts->len == 0) {
		GST_ERROR("Failed to get video formats from caps");
		return FALSE;
	}

	GST_DEBUG("The total number of cap supported video format : %d",
		  priv->cap.supported_fmts->len);


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


void
v4l_gst_core_push_source_change_event(struct v4l_gst *priv)
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


void
v4l_gst_core_set_pipeline_started(struct v4l_gst *priv, gboolean started)
{
	g_mutex_lock(&priv->cap.reqbuf_mutex);
	priv->cap.cancel_reqbuf_wait = !started;
	if (!started)
		g_cond_broadcast(&priv->cap.reqbuf_cond);
	g_mutex_unlock(&priv->cap.reqbuf_mutex);

	g_mutex_lock(&priv->queue_mutex);
	priv->is_pipeline_started = started;
	if (!started)
		g_cond_broadcast(&priv->queue_cond);
	g_mutex_unlock(&priv->queue_mutex);
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
	priv->cap.gstbufs_queue = g_queue_new();
	priv->out.gstbufs_queue = g_queue_new();

	if (!v4l_gst_pipeline_setup_app_elements(priv))
		return FALSE;

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

	create_buffer_pool(priv->pool_ops, &priv->out.pool, &priv->cap.pool);

	/* To hook allocation queries */
	priv->probe_id = v4l_gst_pipeline_setup_query_pad_probe(priv);
	if (priv->probe_id == 0) {
		GST_ERROR("Failed to setup query pad probe");
		goto free_pool;
	}

	return TRUE;

	/* error cases */
 free_pool:
	if (priv->out.pool)
		gst_object_unref(priv->out.pool);
	if (priv->cap.pool)
		gst_object_unref(priv->cap.pool);

	return FALSE;
}


gboolean
v4l_gst_core_init_pipeline(struct v4l_gst *priv, guint32 fourcc)
{
	gchar fourcc_str[5];
	const gchar *pipeline;

	fourcc_to_string(fourcc, fourcc_str);
	pipeline = g_hash_table_lookup(priv->config.pipelines, fourcc_str);

	if (pipeline) {
		GST_DEBUG("create %s pipeline: %s", fourcc_str, pipeline);
		priv->pipeline = v4l_gst_core_create_pipeline(pipeline);
	}

	if (!priv->pipeline) {
		GST_ERROR("Failed to create pipeline for %s", fourcc_str);
		goto error;
	}

	if (!init_app_elements(priv))
		goto error;

	if (!init_buffer_pool(priv))
		goto error;

	priv->out.fmt.pixelformat = fourcc;

	return TRUE;

 error:
	if (priv->cap.gstbufs_queue) {
		g_queue_free(priv->cap.gstbufs_queue);
		priv->cap.gstbufs_queue = NULL;
	}
	if (priv->out.gstbufs_queue) {
		g_queue_free(priv->out.gstbufs_queue);
		priv->out.gstbufs_queue = NULL;
	}
	if (priv->pipeline) {
		gst_object_unref(priv->pipeline);
		priv->pipeline = NULL;
	}
	errno = EINVAL;
	return FALSE;
}


struct v4l_gst*
v4l_gst_init(int fd)
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
		GST_DEBUG_CATEGORY_INIT(v4l_gst_buffer_debug_category,
					"v4l-gst-buffer", 0,
					"debug buffers of v4l-gst");
		gstreamer_initialized = TRUE;
	}

	priv = g_new0(struct v4l_gst, 1);
	if (!priv) {
		GST_ERROR("Couldn't allocate memory for gst-backend");
		return NULL;
	}
	v4l_gst_core_reset_cap_timestamp_state(priv);

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

	/*
	 * Only the M2M decoder role is supported at the moment:
	 * OUTPUT carries a compressed bitstream and CAPTURE
	 * carries decoded raw frames.
	 */
	priv->out.buf_type = V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE;
	priv->out.kind = V4L_GST_MEDIA_KIND_CODEC;
	priv->cap.buf_type = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
	priv->cap.kind = V4L_GST_MEDIA_KIND_RAW;

	priv->out.supported_fmts = g_array_new(FALSE, TRUE, sizeof(struct fmt));
	priv->cap.supported_fmts = g_array_new(FALSE, TRUE, sizeof(struct fmt));

	if (!fill_config_video_format_out(priv)) {
		GST_ERROR("Failed to fill in supported video format");
		goto error;
	}
	fill_config_video_format_cap(priv);

	g_mutex_init(&priv->v4l2events.mutex);
	priv->v4l2events.subscribed = 0;
	priv->v4l2events.sequence = 0;
	priv->v4l2events.queue = g_queue_new();

	g_mutex_init(&priv->queue_mutex);
	g_cond_init(&priv->queue_cond);
	g_mutex_init(&priv->cap.reqbuf_mutex);
	g_cond_init(&priv->cap.reqbuf_cond);

	g_mutex_init(&priv->dev_lock);

	if (priv->config.fixed_pipeline) {
		if (!v4l_gst_core_init_pipeline(priv, priv->config.fixed_pipeline))
			goto error;
	}

	GST_DEBUG("Initialized gst backend");
	return priv;

 error:
	if (priv->out.supported_fmts)
		g_array_free(priv->out.supported_fmts, TRUE);
	if (priv->cap.supported_fmts)
		g_array_free(priv->cap.supported_fmts, TRUE);
	if (priv->config.pipelines)
		g_hash_table_destroy(priv->config.pipelines);
	g_free(priv->config.pool_lib_path);
	if (priv->event_state)
		delete_event_state(priv->event_state);
	g_free(priv);

	return NULL;
}


void
v4l_gst_deinit(struct v4l_gst *priv)
{
	GST_DEBUG("v4l_gst_deinit start");

	v4l_gst_core_set_pipeline_started(priv, FALSE);

	g_mutex_clear(&priv->dev_lock);

	if (priv->v4l2events.queue) {
		g_queue_free_full(priv->v4l2events.queue,
				  (GDestroyNotify)g_free);
	}
	priv->v4l2events.subscribed = 0;
	g_mutex_clear(&priv->v4l2events.mutex);

	if (priv->decoder_probe_id) {
		GstPad *pad = gst_element_get_static_pad(priv->decoder, "sink");
		gst_pad_remove_probe(pad, priv->decoder_probe_id);
		gst_object_unref(pad);
	}

	if (priv->video_sink_pad) {
		if (priv->probe_id) {
			gst_pad_remove_probe(priv->video_sink_pad,
					     priv->probe_id);
		}
		gst_object_unref(priv->video_sink_pad);
	}

	if (priv->out.buffers)
		g_free(priv->out.buffers);

	if (priv->cap.buffers)
		g_free(priv->cap.buffers);

	if (priv->out.pool)
		gst_object_unref(priv->out.pool);
	if (priv->cap.pool)
		gst_object_unref(priv->cap.pool);

	if (priv->out.supported_fmts)
		g_array_free(priv->out.supported_fmts, TRUE);
	if (priv->cap.supported_fmts)
		g_array_free(priv->cap.supported_fmts, TRUE);

	if (priv->cap.gstbufs_queue)
		g_queue_free(priv->cap.gstbufs_queue);
	if (priv->out.gstbufs_queue)
		g_queue_free(priv->out.gstbufs_queue);
	g_mutex_clear(&priv->queue_mutex);
	g_cond_clear(&priv->queue_cond);

	g_mutex_clear(&priv->cap.reqbuf_mutex);
	g_cond_clear(&priv->cap.reqbuf_cond);

	if (priv->pipeline)
		gst_object_unref(priv->pipeline);

	if (priv->config.pipelines)
		g_hash_table_destroy(priv->config.pipelines);

	g_free(priv->config.pool_lib_path);

	delete_event_state(priv->event_state);

	g_free(priv);

	GST_DEBUG("v4l_gst_deinit end");
}

