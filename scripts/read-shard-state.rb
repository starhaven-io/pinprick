#!/usr/bin/env ruby
# frozen_string_literal: true

Encoding.default_external = Encoding::UTF_8

# Action-derived diagnostics can forge markers. Only an exact, ordered block
# at byte zero is authoritative; anything else makes every shard pending.
module ShardState
  def self.read(path, count)
    pending = Array.new(count, 'pending')
    lines = File.binread(path).delete("\r").lines(chomp: true)
    return pending unless lines[0] == '<!-- pinprick-state:begin -->' &&
                          lines[count + 1] == '<!-- pinprick-state:end -->'

    states = count.times.map do |index|
      match = /\A<!-- pinprick-shard-#{index}:(passed|failed|pending) -->\z/.match(lines[index + 1].to_s)
      return pending unless match

      match[1]
    end
    states
  rescue SystemCallError
    pending
  end
end

if $PROGRAM_NAME == __FILE__
  unless ARGV.length == 2 && /\A[0-9]+\z/.match?(ARGV[1]) && ARGV[1].to_i.positive?
    warn 'usage: read-shard-state.rb <body-file> <positive shard-count>'
    exit 2
  end
  puts ShardState.read(ARGV[0], ARGV[1].to_i)
end
