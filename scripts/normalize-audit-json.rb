#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'

Encoding.default_external = Encoding::UTF_8

abort 'catalog JSON validation requires Ruby 4 or newer' if RUBY_VERSION.split('.').first.to_i < 4

module AuditJSON
  # Match the former Python parser's order-of-magnitude recursion bound while
  # turning excess nesting into a report error instead of a process crash.
  MAX_NESTING = 1000

  def self.parse(source)
    text = source.dup.force_encoding(Encoding::UTF_8)
    raise JSON::ParserError, 'invalid UTF-8' unless text.valid_encoding?

    reject_comments(text)
    value = JSON.parse(text, allow_duplicate_key: false, max_nesting: MAX_NESTING, allow_nan: false)
    # JSON parsers can overflow a finite exponent into Infinity; generation
    # rejects that ambiguity as well as invalid escaped Unicode sequences.
    JSON.generate(value, max_nesting: MAX_NESTING, allow_nan: false)
    value
  end

  def self.reject_comments(text)
    # Ruby's JSON parser accepts comments even with allow_comments: false.
    # A slash is legal JSON only inside a string; escaped quotes must not
    # change whether subsequent bytes are interpreted as string contents.
    quoted = false
    escaped = false
    text.each_byte do |byte|
      if quoted
        if escaped
          escaped = false
        elsif byte == 92
          escaped = true
        elsif byte == 34
          quoted = false
        end
      elsif byte == 34
        quoted = true
      elsif byte == 47
        raise JSON::ParserError, 'comments are not valid JSON'
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    print JSON.generate(AuditJSON.parse(File.binread(ARGV.fetch(0))), max_nesting: AuditJSON::MAX_NESTING)
  rescue IndexError, SystemCallError, JSON::JSONError, EncodingError, ArgumentError
    exit 1
  end
end
