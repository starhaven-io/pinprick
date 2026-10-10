#!/usr/bin/env ruby
# frozen_string_literal: true

# Never separate an untrusted diagnostic from its trusted line prefix.
limit = Integer(ARGV.fetch(0), 10)
abort 'byte limit must be nonnegative' if limit.negative?
lines = []
size = 0
$stdin.binmode.each_line do |line|
  line += "\n" unless line.end_with?("\n")
  lines << line
  size += line.bytesize
  size -= lines.shift.bytesize while size > limit && !lines.empty?
end
$stdout.binmode.write(lines.join)
