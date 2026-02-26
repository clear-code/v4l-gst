#!/usr/bin/env ruby
#
# Copyright (C) 2026 ClearCode Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA

# Usage:
#
# $ GST_DEBUG="v4l-gst-buffer:TRACE" GST_DEBUG="v4l-gst.log" chromium /path/to/video.mp4
# $ ruby /path/to/collect-buffer-timeline.rb v4l-gst.log > buffer-timeline.csv
#
# Load buffer-timeline.csv by a spreadsheet software then highlight each labels
# to visualize

OUT_PORT_NUM = 16
CAP_PORT_NUM = 10

COLUMNS = [
  "time_sec",
  *OUT_PORT_NUM.times.collect { |i| "OUT_#{i}" },
  "pts OUT",
  "APPSINK",
  "pts APPSINK",
  *CAP_PORT_NUM.times.collect { |i| "CAP_#{i}" },
  "pts CAP"
]

queued_buffers = { "OUT" => Set[], "CAP" => Set[] }

def buf_column_index(port, i)
  idx = i.to_i
  case port
  when "OUT"
    COLUMNS.index("OUT_0") + idx
  when "CAP"
    COLUMNS.index("CAP_0") + idx
  else
    nil
  end
end

def strip_escape_sequence(line)
  line.gsub(/\e\[[0-9;]*[mK]/, '')
end

def hms_to_sec(t)
  return nil unless t
  h, m, s = t.split(":")
  (h.to_i * 3600 + m.to_i * 60 + s.to_f).to_s
end

def parse_line(line)
  table = {}

  line = strip_escape_sequence(line)

  # e.g.) 0:00:00.994448355 ... qbuf_ioctl_out: QBUF OUT: gstbuf=0x2c025f18e0, index=5, pts=633
  if line =~ /^(\d+:\d+:\d+\.\d+).*:(?:qbuf|dqbuf)_ioctl_(?:out|cap): (QBUF|DQBUF) (OUT|CAP): gstbuf=(0x[a-f0-9]+), index=(\d+)(?:, pts=(\d+))?/
    table["time"] = $1
    table["event"] = $2
    table["port"] = $3
    table["gstbuf"] = $4
    table["index"] = $5
    table["pts"] = $6

  # e.g.) 0:00:07.641034757 ... appsink_callback_new_sample: pull buffer from appsink: gstbuf=0x2c025f1d60, pts=533
  elsif line =~ /^(\d+:\d+:\d+\.\d+).*:appsink_callback_new_sample: pull buffer from appsink: gstbuf=(0x[a-f0-9]+), pts=(\d+)/
    table["time"] = $1
    table["event"] = "APPSINK_PULL"
    table["gstbuf"] = $2
    table["pts"] = $3

  # e.g.) 0:00:22.692462674 ... :streamoff_ioctl_out: STREAMOFF OUT begin: dequeue all OUT & CAP buffers
  # e.g.) 0:00:22.692462674 ... :streamoff_ioctl_out: STREAMOFF OUT end
  elsif line =~ /^(\d+:\d+:\d+\.\d+).*:streamoff_ioctl_out: STREAMOFF OUT (begin|end)/
    table["time"] = $1
    table["event"] = "STREAMOFF_#{$2.upcase}"
  end

  table
end

puts(COLUMNS.join(","))

ARGF.each_line do |line|
  row = parse_line(line)

  next if !row || !row["time"] || !row["event"]

  time = hms_to_sec(row["time"])
  port = row["port"]
  buffer_index = row["index"]
  pts = row["pts"]

  initial_val = case row["event"]
                when "STREAMOFF_BEGIN"
                  "OFF_B"
                when "STREAMOFF_END"
                  "OFF"
                else
                  ""
                end
  columns = [time, *Array.new(COLUMNS.length - 1, initial_val)]

  case row["event"]
  when "STREAMOFF_BEGIN" || "STREAMOFF_END"
    puts columns.join(",")
    queued_buffers.each { |key, set| set.clear }
    next
  when "APPSINK_PULL"
    columns[COLUMNS.index("APPSINK")] = "P"
    columns[COLUMNS.index("pts APPSINK")] = pts if pts
  when "QBUF"
    columns[buf_column_index(port, buffer_index)] = "Q"
    queued_buffers[port] << buffer_index
    columns[COLUMNS.index("pts OUT")] = pts if port == "OUT" && pts
  when "DQBUF"
    columns[buf_column_index(port, buffer_index)] = "D"
    queued_buffers[port].delete(buffer_index)
    columns[COLUMNS.index("pts CAP")] = pts if port == "CAP" && pts
  end

  queued_buffers.each do |port, buf_indexes|
    buf_indexes.each do |buf_index|
      idx = buf_column_index(port, buf_index)
      columns[idx] = "+" if columns[idx].empty?
    end
  end

  puts columns.join(",")
end
