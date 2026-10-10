#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'open3'
require 'tmpdir'

helper = File.join(__dir__, 'normalize-audit-json.rb')
unless File.readable?(helper)
  warn "catalog verifier helper is missing or unreadable: #{helper}"
  exit 2
end
require_relative 'normalize-audit-json'

# Fresh catalog scans must isolate both repository and global configuration,
# and must never reuse a bundled or downloaded catalog verdict.
class CatalogVerifier
  def initialize(binary, mode, arguments)
    @binary, @mode = binary, mode
    @failed = false
    @checked = 0
    @current_rules = nil
    @budget_readable = true
    @etag = nil
    @files = case mode
             when 'all', 'latest' then catalog_files
             when 'files' then arguments
             when 'shard'
               index, count = arguments
               usage("shard count must be a positive integer, got '#{count}'") unless unsigned?(count) && count.to_i.positive?
               usage("shard index must be in [0, #{count}), got '#{index}'") unless unsigned?(index) && index.to_i < count.to_i
               @shard_index, @shard_count = index.to_i, count.to_i
               catalog_files
             else usage("unknown mode '#{mode}'")
             end
  end

  def run
    if @files.empty?
      if @mode == 'files'
        warn 'no catalog files to verify'
        return 0
      end
      usage('no catalog files found under audited-actions/')
    end
    unless executable?(@binary)
      usage("catalog verifier binary is missing or not executable: #{@binary}")
    end
    @files.each { |file| verify_file(file) }
    count_inert if @current_rules
    puts "Checked #{@checked} catalog entries."
    @failed ? 1 : 0
  end

  private

  def catalog_files = Dir.glob('audited-actions/**/*.json').sort
  def unsigned?(value) = value.is_a?(String) && /\A[0-9]+\z/.match?(value)
  def numeric?(value) = value.is_a?(Numeric) && value.finite?
  def rules?(value) = numeric?(value) && value >= 1 && value <= 4_294_967_295 && value == value.to_i

  def usage(message)
    warn message
    exit 2
  end

  def error(message)
    puts "::error::#{printable(message)}"
    @failed = true
  end

  def executable?(binary)
    return File.file?(binary) && File.executable?(binary) if binary.include?(File::SEPARATOR)

    ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? do |path|
      candidate = File.join(path, binary)
      File.file?(candidate) && File.executable?(candidate)
    end
  end

  def parse_file(file) = AuditJSON.parse(File.binread(file))

  def verify_file(file)
    action = file.delete_prefix('audited-actions/').delete_suffix('.json')
    display_action = printable(action)
    puts "--- #{display_action} ---"
    begin
      entries = parse_file(file)
      raise JSON::ParserError, 'catalog must be an array' unless entries.is_a?(Array)
    rescue SystemCallError, JSON::JSONError, EncodingError, ArgumentError
      error("#{display_action} could not be parsed; entries NOT verified")
      return
    end
    entries = entries.first(1) if @mode == 'latest'
    entries.each do |entry|
      unless entry.is_a?(Hash) && entry['sha'].is_a?(String) && entry['tag'].is_a?(String) && rules?(entry['rules_version'])
        error("#{display_action} contains an invalid or unstamped catalog entry; verdict NOT verified")
        next
      end
      sha, tag, rules = entry.values_at('sha', 'tag', 'rules_version')
      unless /\A[0-9a-fA-F]{40}\z/.match?(sha)
        error("#{display_action} contains non-canonical SHA '#{sha}'")
        next
      end
      if @mode == 'shard'
        # Keep POSIX cksum's existing assignment so rollout does not reshuffle shards.
        checksum, status = Open3.capture2('cksum', stdin_data: "#{action}@#{sha}\n")
        usage('could not calculate catalog shard') unless status.success?
        next unless checksum.split.first.to_i % @shard_count == @shard_index
      end
      wait_for_api_budget
      puts "  Verifying #{printable(tag)} (#{sha[0, 7]})..."
      @checked += 1
      report, status = scan(action, sha, tag)
      unless report
        error("#{display_action}@#{sha} (#{printable(tag)}) returned malformed audit output (exit #{status}); verdict NOT verified")
        next
      end
      assess(action, sha, tag, rules, report, status)
    end
  end

  def wait_for_api_budget
    token = ENV['GITHUB_TOKEN']
    return if !token || token.empty? || !@budget_readable

    # Headers travel on stdin to keep the token out of the process list.
    request = "Authorization: Bearer #{token}\n"
    request += "If-None-Match: #{@etag}\n" if @etag
    begin
      output, status = Open3.capture2('curl', '-sS', '--max-time', '30', '-o', File::NULL,
                                    '-D', '-', '-H', '@-', 'https://api.github.com/', stdin_data: request)
      headers = status.success? ? output.delete("\r").lines.filter_map { |line| line.split(':', 2) if line.include?(':') }.to_h.transform_keys(&:downcase).transform_values(&:strip) : {}
    rescue SystemCallError
      headers = {}
    end
    remaining, reset = headers.values_at('x-ratelimit-remaining', 'x-ratelimit-reset')
    unless unsigned?(remaining) && unsigned?(reset)
      puts '::warning::could not read the GitHub API budget; verifying without waiting for resets'
      @budget_readable = false
      return
    end
    @etag = headers['etag'] unless headers['etag'].to_s.empty?
    delay = [reset.to_i - Time.now.to_i + 5, 3660].min
    return if remaining.to_i >= 100 || delay <= 0

    puts "  API budget low (#{remaining} requests left); waiting #{delay}s for its reset..."
    raise 'API budget wait failed' unless system('sleep', delay.to_s)
  end

  def scan(action, sha, tag)
    status = nil
    temporary_root = ENV['TMPDIR'].to_s
    temporary_root = '/tmp' if temporary_root.empty?
    Dir.mktmpdir('pinprick-audit.', temporary_root) do |directory|
      FileUtils.mkdir_p(File.join(directory, '.github/workflows'))
      # Keep original path/tag bytes for the scanner even when the locale
      # assigns a different encoding to command-line arguments.
      File.binwrite(File.join(directory, '.github/workflows/test.yml'), <<~YAML)
        name: test
        on: push
        jobs:
          test:
            runs-on: ubuntu-24.04
            steps:
              - uses: #{action.b}@#{sha.b} # #{tag.b}
      YAML
      output = File.join(directory, 'audit-output.json')
      system({ 'XDG_CONFIG_HOME' => File.join(directory, 'config') }, @binary,
             '--json', 'audit', '--no-repo-config', '--no-audited-catalog', directory, out: output)
      status = $?.exitstatus || 128 + $?.termsig
      begin
        report = parse_file(output)
        return [valid_report?(report) ? report : nil, status]
      rescue JSON::JSONError, EncodingError, ArgumentError
        return [nil, status]
      end
    end
  rescue SystemCallError, ArgumentError => exception
    usage("catalog verifier could not prepare or run an isolated scan: #{printable(exception.message)}")
  end

  def valid_report?(report)
    report.is_a?(Hash) && report['findings'].is_a?(Array) &&
      report['findings'].all? do |finding|
        finding.is_a?(Hash) && %w[severity source_file description].all? { |key| finding[key].is_a?(String) } &&
          (finding['line'].nil? || numeric?(finding['line']))
      end && numeric?(report['scanned_fresh']) && rules?(report['rules_version']) &&
      [true, false].include?(report['coverage_complete']) &&
      (!report.key?('coverage_failures') || (report['coverage_failures'].is_a?(Array) && report['coverage_failures'].all? { |failure| failure.is_a?(String) }))
  end

  def printable(text)
    text.dup.force_encoding(Encoding::UTF_8).scrub.gsub(/[\x00-\x08\x0a-\x1f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/, "\ufffd").gsub('##[', '## [')
  end

  def assess(action, sha, tag, rules, report, status)
    identity = "#{printable(action)}@#{sha} (#{printable(tag)})"
    current = report['rules_version']
    if @current_rules && @current_rules != current
      error("#{identity} reported rules version #{current}, expected #{@current_rules}; verdict NOT verified")
    end
    @current_rules ||= current
    error("#{identity} was stamped with rules version #{rules}, but the scanner reports #{current}; verdict NOT verified") if current != rules
    findings = report['findings']
    failures = report.fetch('coverage_failures', [])
    complete = failures.empty? && report['scanned_fresh'] == 1 && report['coverage_complete']
    return if status == 0 && findings.empty? && complete && current == rules

    unless findings.empty?
      error("#{identity} has audit findings under the current rules")
      findings.each do |finding|
        line = finding['line'].nil? ? '' : ":#{finding['line']}"
        puts printable("  finding: #{finding['severity']} #{finding['source_file']}#{line}: #{finding['description']}")
      end
    end
    if ![0, 1].include?(status) || !complete
      error("#{identity} could not be scanned (exit #{status}); verdict NOT verified")
      failures.each { |failure| puts "  coverage: #{printable(failure)}" }
    end
    if (status == 0 && !findings.empty?) || (status == 1 && findings.empty?)
      error("#{identity} returned an inconsistent audit status and report; verdict NOT verified")
    end
    @failed = true
  end

  def count_inert
    files = catalog_files
    return if files.empty?

    count = files.sum { |file| parse_file(file).count { |entry| entry['rules_version'] != @current_rules } }
    puts "Catalog entries inert under rules version #{@current_rules}: #{count}."
  rescue SystemCallError, JSON::JSONError, EncodingError, ArgumentError, TypeError, NoMethodError
    error("could not count catalog entries inert under rules version #{@current_rules}")
  end
end

if $PROGRAM_NAME == __FILE__
  $stdout.sync = true
  if ARGV.length < 2
    warn 'usage: verify-audited-actions.rb <pinprick-binary> <all|latest|shard k m|files ...>'
    exit 2
  end
  exit CatalogVerifier.new(*ARGV.shift(2), ARGV).run
end
