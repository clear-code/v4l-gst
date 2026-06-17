Overview
========

This package adds a V4L2 plugin that creates a bridge between the V4L2 API and
GStreamer for mem-to-mem decoder components. This plugin has not been tested
in device-to-mem or mem-to-device configurations. Applications that use the
libv4l API to perform codec operations should be able to use this plugin to
connect to a GStreamer pipeline instead of a V4L hardware device without any
updates.

Dependencies
============

* v4lutils - with patches provided [here](https://github.com/clear-code/v4l-utils/tree/scarthgap/v4l-utils-1.26.1)
* [v4l-gst-bufferpool-rcar](https://github.com/igel-oss/v4l-gst-bufferpool-rcar) for use with Renesas R-Car boards (e.g. Porter)
  * It's optional and not tested with recent v4l-gst

Compile
=======

```
$ autoreconf -vif
$ ./configure
```

Configuration
=============

The setting file location is `/etc/xdg/libv4l-gst.conf`

### Settings

* `[libv4l-gst]` (global section)
  * **max-width** (default: `1920`)
    * The maximum width of the video that can be decoded through the plugin
  * **max-height** (default: `1080`)
    * The maximum height of the video that can be decoded through the plugin
  * **bufferpool-library** (default: `NULL`)
    * Path to the library that provides buffer pools for input and output nodes
  * **min-buffers** (default: `2`)
    * The minimum number of buffers for each of the above buffer pools
  * **preferred-format** (default: auto-detect or `NV12`)
    * Preffered output format by FourCC (e.g. `AR24`)
  * **fixed-pipeline** (default: auto-detect)
    * Use fixed pipeline instead of auto-detecting
	* Specify in one of the following FourCCs listed as section names (e.g. `H264`)
* `[H264]`
  * **pipeline**
    * The GStreamer pipeline to be used
	* `appsrc` and `appsink` are automatically inserted so you shouldn't include any other `src` or `sink` elements
	* If `appsrc` and `appsink` are included manually with some attributes, most of them are honored
	* You can use `tee` element here to split output for debugging.
	  If you use it, you can use any `sink` elements (e.g. `waylandsink`) but one of them should be `appsink`.
* `[H265]`
  * Ditto

### Example

The following settings are for the Renesas Porter board,
but they may be updated to use more generic settings.


```ini
[libv4l-gst]
min-buffers=2

[H264]
pipeline=h264parse ! omxh264dec

[HEVC]
pipeline=h265parse ! omxh265dec
```

Running
=======

Create a dummy V4L2 device file under /dev
```console
# touch /dev/video-gst
# chmod 666 /dev/video-gst
```
Accessing the /dev/video-gst file will allow an application to use the v4l-gst plugin
using the same API as a regular V4L2 device file.

Building and running unit tests on PC
=====================================

## Overview

Although this software intends to build on Yocto, you can run unit tests on GNU/Linux PC
using in-tree v4l-utils.

## Prerequisites

In addition to developer tools for standard build, need following tools:

* [`cutter`](https://github.com/clear-code/cutter)
* meson (to build in-tree v4l-utils)

See [the CI workflow](./.github/workflows/tests.yml) for more detail.

## Build

```console
$ ./scripts/build.sh
```

## Run tests

```console
$ make check
```
