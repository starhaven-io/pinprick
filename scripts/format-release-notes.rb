#!/usr/bin/env ruby
# frozen_string_literal: true

Encoding.default_external = Encoding::UTF_8

# Format gh-generated notes while retaining breaking internal changes.
module ReleaseNotes
  SECTIONS = {
    'feat' => "What's New", 'fix' => 'Fixes', 'perf' => 'Performance',
    'refactor' => 'Under the Hood', 'docs' => 'Documentation'
  }.freeze
  SKIP_TYPES = %w[build ci chore].freeze
  SKIP_SCOPES = %w[audit-actions audited-actions].freeze
  # Preserve the former formatter's Unicode whitespace and splitlines rules.
  SPACE = /[[:space:]\x1c-\x1f]/
  LINE_BREAK = /\r\n|[\n\r\v\f\x1c-\x1e\u0085\u2028\u2029]/
  PR = /\A\*#{SPACE}+(?:(?<type>[a-z]+)(?:\((?<scope>[^)]*)\))?(?<breaking>!)?:#{SPACE}*)?(?<desc>.+?)(?:#{SPACE}+by#{SPACE}+@[\p{L}\p{N}_-]+)?(?:#{SPACE}+in#{SPACE}+https?:\/\/[^[:space:]\x1c-\x1f]+)?#{SPACE}*\z/
  CHANGELOG = /\A\*\*Full Changelog\*\*:#{SPACE}*(?<url>https?:\/\/[^[:space:]\x1c-\x1f]+)/

  def self.strip_space(text) = text.gsub(/\A#{SPACE}+|#{SPACE}+\z/, '')

  def self.parse_notes(raw)
    sections = {}
    changelog_url = nil
    raw.split(LINE_BREAK).each do |line|
      line = strip_space(line)
      if (match = CHANGELOG.match(line))
        changelog_url = match[:url]
        next
      end
      match = PR.match(line)
      next unless match
      next if !match[:breaking] && (SKIP_TYPES.include?(match[:type]) || SKIP_SCOPES.include?(match[:scope]))

      section = match[:breaking] ? 'Breaking Changes' : SECTIONS.fetch(match[:type], 'Other')
      (sections[section] ||= []) << strip_space(match[:desc])
    end
    [sections, changelog_url]
  end

  def self.format_markdown(tag, sections, changelog_url)
    lines = ["## pinprick #{tag}", '']
    ['Breaking Changes', *SECTIONS.values.uniq, 'Other'].each do |heading|
      entries = sections[heading]
      next if !entries || entries.empty?

      lines.concat(["### #{heading}", *entries.map { |entry| "- #{entry}" }, ''])
    end
    lines.concat(['---', "**Full Changelog**: #{changelog_url}", '']) if changelog_url
    lines.join("\n")
  end
end

if $PROGRAM_NAME == __FILE__
  abort "Usage: #{$PROGRAM_NAME} <raw_notes_file> <tag>" if ARGV.length < 2
  print ReleaseNotes.format_markdown(ARGV[1], *ReleaseNotes.parse_notes(File.read(ARGV[0], encoding: 'UTF-8'))), "\n"
end
