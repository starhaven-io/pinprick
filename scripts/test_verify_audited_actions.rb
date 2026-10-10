# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'read-shard-state'

class VerifyAuditedActionsTests < ToolingTest
  SCRIPT = ROOT.join('scripts/verify-audited-actions.rb')

  def setup
    super
    @scratch = @root.join('scratch').tap(&:mkpath)
    @catalog = @root.join('audited-actions/example/action.json')
    @catalog.dirname.mkpath
    @catalog.write(JSON.generate([{ sha: '0123456789abcdef0123456789abcdef01234567', tag: 'v1.2.3', rules_version: 1 }]))
    @pinprick = @root.join('pinprick')
    executable(@pinprick, <<~'STUB')
      #!/usr/bin/env ruby
      abort 'config isolation lost' unless ARGV.include?('--no-repo-config') && ARGV.include?('--no-audited-catalog') && ENV['XDG_CONFIG_HOME'] == ARGV.last + '/config'
      File.write(ENV['SCAN_DIRECTORY_FILE'], ARGV.last) if ENV['SCAN_DIRECTORY_FILE']
      if ENV['SCAN_WORKFLOWS_FILE']
        File.open(ENV['SCAN_WORKFLOWS_FILE'], 'ab') { |file| file.write(File.binread(File.join(ARGV.last, '.github/workflows/test.yml'))) }
      end
      $stdout.binmode.write(File.binread(ENV.fetch('AUDIT_OUTPUT_FILE')))
      exit Integer(ENV.fetch('AUDIT_STATUS'))
    STUB
    # Never let a developer token initiate a live budget check.
    @env = { 'GITHUB_TOKEN' => nil, 'GH_TOKEN' => nil, 'TMPDIR' => @scratch.to_s }
  end

  def report(**overrides)
    JSON.generate({ findings: [], scanned_fresh: 1, rules_version: 1, coverage_complete: true }.merge(overrides))
  end

  def verify(output = report, status = 0, env: {}, mode: ['files', 'audited-actions/example/action.json'], cwd: @root, script: SCRIPT)
    path = @root.join('audit-output')
    path.binwrite(output)
    result = command([RUBY, script, @pinprick, *mode], cwd: cwd,
                     env: @env.merge('AUDIT_OUTPUT_FILE' => path.to_s, 'AUDIT_STATUS' => status.to_s).merge(env))
    assert_empty @scratch.children
    result
  end

  def test_clean_fresh_report_passes
    result = verify
    assert_success result
    refute_includes result.stdout, '::error::'
    assert_includes result.stdout, 'Catalog entries inert under rules version 1: 0.'
  end

  def test_empty_or_unset_tmpdir_falls_back_to_tmp_and_is_cleaned
    recorded = @root.join('scan-directory')
    ['', nil].each do |temporary_root|
      result = verify(env: { 'TMPDIR' => temporary_root, 'SCAN_DIRECTORY_FILE' => recorded.to_s })
      assert_success result
      directory = recorded.read
      assert_equal File.realpath('/tmp'), File.realpath(File.dirname(directory))
      refute File.exist?(directory)
      refute_includes result.stdout, 'returned malformed audit output'
    end
  end

  def test_unusable_tmpdir_reports_verifier_setup_failure_before_scanning
    recorded = @root.join('scan-directory')
    [@root.join('missing'), @catalog].each do |temporary_root|
      result = verify(env: { 'TMPDIR' => temporary_root.to_s, 'SCAN_DIRECTORY_FILE' => recorded.to_s })
      assert_equal 2, result.returncode
      assert_includes result.stderr, 'catalog verifier could not prepare or run an isolated scan'
      refute_includes result.stdout, 'returned malformed audit output'
      refute recorded.exist?
    end
  end

  def test_explicit_catalog_without_repository_catalog_does_not_read_stdin
    elsewhere = @root.join('elsewhere').tap(&:mkpath)
    output = @root.join('audit-output')
    output.write(report)
    env = @env.merge('AUDIT_OUTPUT_FILE' => output.to_s, 'AUDIT_STATUS' => '0')
    invoke = lambda do
      Open3.popen3(env, RUBY, SCRIPT.to_s, @pinprick.to_s, 'files', @catalog.to_s, chdir: elsewhere.to_s) do |stdin, stdout, stderr, process|
        begin
          status = Timeout.timeout(2) { process.value }
        rescue Timeout::Error
          Process.kill('KILL', process.pid)
          flunk 'verifier blocked reading stdin while counting an absent repository catalog'
        ensure
          stdin.close
        end
        Result.new(stdout.read, stderr.read, status.exitstatus)
      end
    end
    result = defined?(Bundler) ? Bundler.with_unbundled_env(&invoke) : invoke.call
    assert_success result
    refute_includes result.stdout, 'Catalog entries inert'
    assert_includes result.stdout, 'Checked 1 catalog entries.'
    assert_empty result.stderr
    assert_empty @scratch.children
  end

  def budget_env(remaining: nil, reset_in: 0, token: 'test-token', status: 200)
    stubs = @root.join('stubs').tap(&:mkpath)
    executable(stubs.join('curl'), <<~'STUB')
      #!/usr/bin/env ruby
      File.open('curl-args', 'a') { |file| file.puts ARGV.join(' ') }
      File.open('curl-stdin', 'a') { |file| file.write($stdin.read + "---\n") }
      abort 'unreadable' if ENV.fetch('API_HEADERS').empty?
      print ENV.fetch('API_HEADERS')
    STUB
    executable(stubs.join('sleep'), <<~'STUB')
      #!/usr/bin/env ruby
      File.open('slept', 'a') { |file| file.puts ARGV.fetch(0) }
    STUB
    headers = remaining.nil? ? '' : "HTTP/2 #{status}\r\nX-RateLimit-Remaining: #{remaining}\r\nX-RateLimit-Reset: #{Time.now.to_i + reset_in}\r\nETag: \"root-v1\"\r\n\r\n"
    { 'PATH' => "#{stubs}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}", 'API_HEADERS' => headers, 'GITHUB_TOKEN' => token }
  end

  def slept
    path = @root.join('slept')
    path.exist? ? path.read.split.map(&:to_i) : []
  end

  def test_low_budget_and_exhausted_refusal_wait_for_reset_without_exposing_token
    [200, 403].each do |status|
      @root.join('slept').delete if @root.join('slept').exist?
      result = verify(env: budget_env(remaining: status == 200 ? 5 : 0, reset_in: 600, status: status))
      assert_success result
      assert_includes result.stdout, 'API budget low'
      assert_equal 1, slept.length
      assert_includes 595..605, slept.first
      refute_includes @root.join('curl-args').read, 'test-token'
      assert_includes @root.join('curl-args').read, 'https://api.github.com/'
      assert_includes @root.join('curl-stdin').read, 'Authorization: Bearer test-token'
    end
  end

  def test_later_budget_reads_revalidate_root_etag
    entries = JSON.parse(@catalog.read)
    entries << entries.first.merge('sha' => '89abcdef0123456789abcdef0123456789abcdef', 'tag' => 'v1.2.2')
    @catalog.write(JSON.generate(entries))
    assert_success verify(env: budget_env(remaining: 5000, reset_in: 600))
    first, second = @root.join('curl-stdin').read.split("---\n")
    refute_includes first, 'If-None-Match'
    assert_includes second, 'If-None-Match: "root-v1"'
  end

  def test_wait_is_capped_and_ample_budget_does_not_wait
    assert_success verify(env: budget_env(remaining: 0, reset_in: 7200))
    assert_equal [3660], slept
    @root.join('slept').delete
    assert_success verify(env: budget_env(remaining: 5000, reset_in: 600))
    assert_empty slept
  end

  def test_unreadable_budget_warns_without_hiding_incomplete_scan
    result = verify(env: budget_env)
    assert_success result
    assert_includes result.stdout, '::warning::could not read the GitHub API budget'
    assert_empty slept
    result = verify(report(coverage_complete: false), 2, env: budget_env)
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'could not be scanned (exit 2)'
  end

  def test_budget_is_not_read_without_token
    assert_success verify(env: budget_env(remaining: 5, token: nil))
    refute @root.join('curl-args').exist?
    assert_empty slept
  end

  def test_report_rules_version_must_match_stamp
    result = verify(report(rules_version: 2))
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'stamped with rules version 1, but the scanner reports 2'
    assert_includes result.stdout, 'Catalog entries inert under rules version 2: 1.'
  end

  def test_missing_or_invalid_rules_versions_are_rejected
    [nil, 0, 1.5, '1', true, 4_294_967_296].each do |rules|
      payload = JSON.parse(report)
      rules.nil? ? payload.delete('rules_version') : payload['rules_version'] = rules
      result = verify(JSON.generate(payload))
      assert_equal 1, result.returncode
      assert_includes result.stdout, 'returned malformed audit output'
    end
    payload = JSON.parse(@catalog.read)
    payload.first.delete('rules_version')
    @catalog.write(JSON.generate(payload))
    result = verify
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'invalid or unstamped catalog entry'
    assert_includes result.stdout, 'Checked 0 catalog entries.'
  end

  def finding(**overrides)
    { severity: 'high', source_file: 'dist/index.js', line: 7, description: 'runtime fetch' }.merge(overrides)
  end

  def test_findings_and_incomplete_reports_retain_diagnostics
    result = verify(report(findings: [finding]), 1)
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'finding: high dist/index.js:7: runtime fetch'
    result = verify(report(findings: [finding(line: nil)], scanned_fresh: 0, coverage_complete: false,
                           coverage_failures: ['source traversal incomplete']), 2)
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'finding: high dist/index.js: runtime fetch'
    assert_includes result.stdout, 'coverage: source traversal incomplete'
    result = verify(report(scanned_fresh: 0, coverage_complete: false, coverage_failures: ['API request failed']), 2)
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'coverage: API request failed'
  end

  def test_nonfresh_scan_and_inconsistent_coverage_cannot_pass
    [0, 2].each do |fresh|
      result = verify(report(scanned_fresh: fresh))
      assert_equal 1, result.returncode
      assert_includes result.stdout, 'could not be scanned'
    end
    result = verify(report(coverage_failures: ['internally inconsistent coverage']))
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'coverage: internally inconsistent coverage'
  end

  def test_diagnostics_neutralize_modern_and_legacy_runner_commands_and_controls
    result = verify(report(findings: [finding(source_file: "dist/\u202e##[error]x.js", description: "runtime fetch\n::warning::injected\u009b##[warning]injected")],
                           scanned_fresh: 0, coverage_complete: false, coverage_failures: ["path\u009b\u202efailed"]), 2)
    assert_equal 1, result.returncode
    refute_includes result.stdout, "\n::warning::"
    refute_includes result.stdout, '##['
    refute_includes result.stdout, "\u009b"
    refute_includes result.stdout, "\u202e"
    assert_includes result.stdout, "runtime fetch\ufffd::warning::injected"
    assert_includes result.stdout, '## [error]x.js'
    assert_operator result.stdout.count("\ufffd"), :>=, 4
  end

  def test_status_and_report_inconsistencies_are_explicit
    [[report(findings: [finding]), 0], [report, 1]].each do |payload, status|
      result = verify(payload, status)
      assert_equal 1, result.returncode
      assert_includes result.stdout, 'returned an inconsistent audit status and report'
    end
  end

  def test_malformed_or_ambiguous_reports_are_rejected_without_echoing_output
    invalid = ['{"findings":"UNTRUSTED"}', 'UNTRUSTED not JSON', report + "\nUNTRUSTED trailing output",
               report + "\0", report.sub(/}\z/, ',"extra":"'.b + "\xff".b + '"}'),
               report.sub('"findings":[]', '"findings":[{"description":"hidden"}],"findings":[]'),
               report.sub('"scanned_fresh":1', '"scanned_fresh":NaN'),
               report.sub('"scanned_fresh":1', '"scanned_fresh":1e999'),
               report(coverage_failures: false), report(coverage_failures: nil), report(coverage_failures: ['valid', 7])]
    invalid.each do |payload|
      result = verify(payload)
      assert_equal 1, result.returncode, payload.inspect
      assert_includes result.stdout, 'returned malformed audit output'
      refute_includes result.stdout, 'UNTRUSTED'
      refute_includes result.stdout, 'hidden'
    end
  end

  def test_comments_cannot_hide_report_contents
    ['/* hidden finding */', "// hidden finding\n"].each do |comment|
      [comment + report, report.sub('{', '{' + comment), report + comment].each do |payload|
        result = verify(payload)
        assert_equal 1, result.returncode
        assert_includes result.stdout, 'returned malformed audit output'
        refute_includes result.stdout, 'hidden finding'
      end
    end
    result = verify(report(extra: ['https://example.test/path', '/* text */ // text', "quoted \" / text", 'backslash \\ / text']))
    assert_success result
  end

  def test_escaped_strings_do_not_hide_late_comments
    ['a\\b', '"quoted"', 'ending\\', 'backslash\\"quote'].each do |value|
      payload = report(extra: value)
      assert_success verify(payload)
      ['/* hidden after escape */', "// hidden after escape\n"].each do |comment|
        [payload + comment, payload.sub(/}\z/, ",#{comment}\"last\":true}")].each do |commented|
          result = verify(commented)
          assert_equal 1, result.returncode, commented
          assert_includes result.stdout, 'returned malformed audit output'
          refute_includes result.stdout, 'hidden after escape'
        end
      end
    end
  end

  def test_slashes_inside_escaped_strings_are_valid_json
    values = ['/', '//', '/* text */', 'https://example.test/a/b', 'quote"/slash', 'backslash\\/slash', 'both\\"//literal']
    assert_success verify(report(extra: values))
  end

  def test_catalog_names_and_tags_cannot_inject_log_commands
    path = "audited-actions/example/##[error]filename-controlled\n::warning::filename-controlled.json"
    catalog = JSON.parse(@catalog.read)
    catalog.first['tag'] = "v1.2.3##[error]tag-controlled\n::warning::tag-controlled"
    @root.join(path).write(JSON.generate(catalog))
    result = verify(report(findings: [finding]), 1, mode: ['files', path])
    assert_equal 1, result.returncode
    refute_includes result.stdout + result.stderr, '##['
    refute_match(/(?:\A|\n)::warning::(?:filename|tag)-controlled/, result.stdout + result.stderr)
    assert_includes result.stdout, '## [error]filename-controlled'
    assert_includes result.stdout, '## [error]tag-controlled'
  end

  def test_deep_reports_fail_cleanly_and_verification_continues
    entries = JSON.parse(@catalog.read)
    entries << entries.first.merge('sha' => '89abcdef0123456789abcdef0123456789abcdef')
    @catalog.write(JSON.generate(entries))
    payload = report.sub(/}\z/, ',"extra":' + '[' * 2000 + '0' + ']' * 2000 + '}')
    result = verify(payload)
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'returned malformed audit output'
    assert_includes result.stdout, 'Checked 2 catalog entries.'
    refute_includes result.stderr, 'SystemStackError'
    assert_success verify(report.sub(/}\z/, ',"extra":' + '[' * 500 + '0' + ']' * 500 + '}'))
  end

  def test_extreme_nesting_is_bounded_before_generation_and_later_files_run
    later = @catalog.dirname.join('later.json')
    later.write(@catalog.read)
    payload = report.sub(/}\z/, ',"extra":' + '[' * 200_000 + '0' + ']' * 200_000 + '}')
    result = verify(payload, mode: ['files', @catalog.relative_path_from(@root), later.relative_path_from(@root)])
    assert_equal 1, result.returncode
    assert_equal 2, result.stdout.scan('returned malformed audit output').length
    assert_includes result.stdout, '--- example/later ---'
    assert_includes result.stdout, 'Checked 2 catalog entries.'
    assert_empty result.stderr
  end

  def test_files_mode_preserves_filename_bytes_across_locales
    catalog = JSON.parse(@catalog.read)
    catalog.first['tag'] = 'rélease-🔒'
    @catalog.write(JSON.generate(catalog))
    paths = ['audited-actions/example/évil.json', "audited-actions/example/invalid-\xff.json".b,
             'audited-actions/example/action.json']
    @root.join(paths.first).binwrite(@catalog.binread)
    invalid_file_exists = begin
      @root.join(paths[1]).binwrite(@catalog.binread)
      true
    rescue Errno::EPERM, Errno::EINVAL, Errno::EILSEQ
      # Some filesystems reject invalid UTF-8 names. The raw CLI argument
      # must still produce a per-file error and allow later files to run.
      false
    end
    checked = invalid_file_exists ? 3 : 2
    workflows = @root.join('scan-workflows')
    ['C', 'en_US.UTF-8', nil].each do |locale|
      workflows.delete if workflows.exist?
      result = verify(report(findings: [finding]), 1, mode: ['files', *paths],
                      env: { 'LANG' => nil, 'LC_CTYPE' => nil, 'LC_ALL' => locale, 'SCAN_WORKFLOWS_FILE' => workflows.to_s })
      assert_equal 1, result.returncode
      assert_empty result.stderr
      assert_includes result.stdout, '--- example/évil ---'
      assert_includes result.stdout, "--- example/invalid-\ufffd ---"
      assert_includes result.stdout, '--- example/action ---'
      assert_includes result.stdout, "Checked #{checked} catalog entries."
      assert_equal checked, result.stdout.scan('has audit findings under the current rules').length
      assert_includes result.stdout, 'could not be parsed; entries NOT verified' unless invalid_file_exists
      paths.reject { |path| path == paths[1] && !invalid_file_exists }.each do |path|
        expected = 'uses: '.b + path.delete_prefix('audited-actions/').delete_suffix('.json').b +
                   '@'.b + catalog.first.fetch('sha').b + ' # '.b + catalog.first.fetch('tag').b + "\n".b
        assert_includes workflows.binread, expected
      end
    end
  end

  def test_invalid_catalog_json_fails_before_scanning
    recorded = @root.join('scan-directory')
    valid = @catalog.read
    [valid.sub('[', '[/* hidden entry */'), '[' * 2000 + '0' + ']' * 2000].each do |payload|
      @catalog.write(payload)
      result = verify(env: { 'SCAN_DIRECTORY_FILE' => recorded.to_s })
      assert_equal 1, result.returncode
      assert_includes result.stdout, 'could not be parsed; entries NOT verified'
      assert_includes result.stdout, 'Checked 0 catalog entries.'
      refute recorded.exist?
    end
  end

  def test_unicode_diagnostics_are_independent_of_locale
    result = verify(report(findings: [finding(source_file: 'dist/évil.js', description: "détection\n::warning::injected")]), 1,
                    env: { 'LANG' => nil, 'LC_CTYPE' => nil, 'LC_ALL' => 'C' })
    assert_equal 1, result.returncode
    assert_includes result.stdout, 'dist/évil.js'
    assert_includes result.stdout, "détection\ufffd::warning::injected"
  end

  def test_missing_helper_and_binary_are_verifier_failures
    copied = @root.join('copied-scripts').tap(&:mkpath).join(SCRIPT.basename)
    FileUtils.cp(SCRIPT, copied)
    result = verify(script: copied)
    assert_equal 2, result.returncode
    assert_includes result.stderr, 'verifier helper is missing or unreadable'
    @pinprick.delete
    result = verify
    assert_equal 2, result.returncode
    assert_includes result.stderr, 'verifier binary is missing or not executable'
    refute_includes result.stdout, 'returned malformed audit output'
  end

  def test_shard_assignments_remain_posix_cksum_compatible
    key = "example/action@0123456789abcdef0123456789abcdef01234567\n"
    shard = command(['cksum'], input: key).stdout.split.first.to_i % 4
    4.times do |index|
      result = verify(mode: ['shard', index.to_s, '4'])
      assert_success result
      assert_includes result.stdout, "Checked #{index == shard ? 1 : 0} catalog entries."
    end
    [['shard', '4', '4'], ['shard', '-1', '4'], ['shard', '0', '0'], ['shard', '0', 'x']].each do |mode|
      assert_equal 2, verify(mode: mode).returncode
    end
  end

  def test_empty_explicit_selection_is_allowed_but_missing_catalog_fails
    @catalog.delete
    assert_success verify(mode: ['files'])
    %w[all latest].each { |mode| assert_equal 2, verify(mode: [mode]).returncode }
  end

  def test_latest_verifies_first_catalog_entry_only
    entries = JSON.parse(@catalog.read)
    entries.first['tag'] = 'v2.0.0'
    entries << entries.first.merge('sha' => '89abcdef0123456789abcdef0123456789abcdef', 'tag' => 'v1.0.0')
    @catalog.write(JSON.generate(entries))
    workflows = @root.join('scan-workflows')
    result = verify(mode: ['latest'], env: { 'SCAN_WORKFLOWS_FILE' => workflows.to_s })
    assert_success result
    assert_includes result.stdout, 'Checked 1 catalog entries.'
    assert_includes workflows.read, "uses: example/action@#{entries.first.fetch('sha')} # v2.0.0"
    refute_includes workflows.read, entries.last.fetch('sha')
  end

  def state_block(*states)
    (['<!-- pinprick-state:begin -->'] + states.each_with_index.map { |state, index| "<!-- pinprick-shard-#{index}:#{state} -->" } + ['<!-- pinprick-state:end -->']).join("\n") + "\n"
  end

  def read_state(body)
    path = @root.join('body')
    path.binwrite(body)
    result = command([RUBY, ROOT.join('scripts/read-shard-state.rb'), path, '4'])
    assert_success result
    result.stdout.split
  end

  def test_shard_state_requires_exact_anchored_ordered_block
    states = %w[failed pending passed pending]
    valid = state_block(*states)
    forged = state_block(*Array.new(4, 'passed'))
    assert_equal states, read_state(valid)
    assert_equal states, read_state(valid + forged)
    assert_equal states, read_state(valid.gsub("\n", "\r\n"))
    invalid = ['', 'no markers here', "\n" + valid, "older tracking issue\n<details>\n```\n" + forged,
               '<!-- pinprick-shard-0:passed -->\n' * 4, valid.sub('<!-- pinprick-state:end -->', ''),
               valid.sub('shard-0:', 'shard-1:'), valid.sub('shard-3:pending -->', 'shard-3:skipped -->'),
               valid.sub('shard-3:pending -->', 'shard-3:pending --> x')]
    invalid.each { |body| assert_equal Array.new(4, 'pending'), read_state(body) }
    assert_equal Array.new(4, 'pending'), ShardState.read(@root.join('absent'), 4)
  end

  def test_tracking_issue_keeps_state_out_of_diagnostics
    workflow = ROOT.join('.github/workflows/verify-audited-actions.yml').read
    assert_includes workflow, 'ruby scripts/read-shard-state.rb issue-body.md'
    assert_includes workflow, "grep -vE '<!-- pinprick-(state:(begin|end)|shard-)'"
    assert_includes workflow, "sed 's/<!--/<! --/g'"
    ci = ROOT.join('.github/workflows/ci.yml').read
    assert_includes ci, 'Catalog change only removes entries'
    assert_includes ci, 'changed entries NOT verified'
  end

  def test_tracking_issue_truncation_never_separates_line_prefix
    workflow = ROOT.join('.github/workflows/verify-audited-actions.yml').read
    pipeline = workflow.lines.grep(/verify-output.txt \|.*tail-complete-lines.rb/)
    assert_equal 1, pipeline.length
    @root.join('scripts').mkpath
    FileUtils.cp(ROOT.join('scripts/tail-complete-lines.rb'), @root.join('scripts'))
    @root.join('verify-output.txt').write('  finding: high dist/index.js: ' + 'x' * 30_000 + '::error::forged diagnostic' + 'x' * 30_000 + "```\n::error::safe diagnostic\n")
    result = shell(pipeline.first.strip, cwd: @root)
    assert_success result
    assert_equal "::error::safe diagnostic\n", result.stdout
    result = command([RUBY, ROOT.join('scripts/tail-complete-lines.rb'), '6'], input: "ééé\nx\n")
    assert_success result
    assert_equal "x\n", result.stdout
  end

  def test_partial_diagnostic_line_is_terminated_and_counted_in_byte_limit
    script = ROOT.join('scripts/tail-complete-lines.rb')
    [[4, "abc", "abc\n"], [3, "abc", ''], [4, "ab\nx", "x\n"]].each do |limit, input, expected|
      result = command([RUBY, script, limit.to_s], input: input)
      assert_success result
      assert_equal expected, result.stdout
    end
  end
end
