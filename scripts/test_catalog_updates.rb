# frozen_string_literal: true

require_relative 'test_helper'

class CatalogUpdateTests < ToolingTest
  def setup
    super
    assert_operator command(['bash', '-c', 'echo "$BASH_VERSION"']).stdout.to_i, :>=, 4, 'catalog workflow requires Bash 4+'
    %w[bin scripts target/debug scratch audited-actions/example].each { |path| @root.join(path).mkpath }
    FileUtils.cp(ROOT.join('scripts/audited-actions.jq'), @root.join('scripts'))
    @catalog = @root.join('audited-actions/example/action.json')
    @catalog.write("[]\n")
    @sha = 'cd2ce8fcbc39b97be8ca5fce6e763baed58fa128'
    @new_sha = '1e34f2e2acaa766b7efacb8c26352e6abbb023f9'
    @releases, @refs = [], {}
    @env = {
      'PATH' => "#{@root.join('bin')}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}",
      'TMPDIR' => @root.join('scratch').to_s, 'INPUT_ACTION' => '', 'INPUT_REF' => '',
      'GITHUB_OUTPUT' => @root.join('output').to_s
    }
    executable(@root.join('bin/gh'), <<~'STUB')
      #!/usr/bin/env ruby
      require 'json'
      require 'open3'
      abort 'unexpected command' unless ARGV[0] == 'api'
      endpoint = ARGV[1]
      fixture = JSON.parse(File.read('fixture.json'))
      File.open('api-calls', 'a') { |output| output.puts endpoint }
      value = if endpoint.end_with?('/releases/latest')
                fixture.fetch('releases').first
              elsif endpoint.include?('/releases?')
                fixture.fetch('releases')
              elsif endpoint.include?('/git/ref/tags/')
                { object: { sha: fixture.fetch('refs').fetch(endpoint.split('/git/ref/tags/', 2)[1]), type: 'commit' } }
              elsif endpoint.include?('/commits/')
                { sha: fixture.fetch('refs').fetch(endpoint.split('/commits/', 2)[1]) }
              else abort endpoint
              end
      output, status = Open3.capture2('jq', '-r', ARGV.fetch(ARGV.index('--jq') + 1), stdin_data: JSON.generate(value))
      print output
      exit status.exitstatus
    STUB
    scanner = <<~'STUB'
      #!/usr/bin/env ruby
      require 'json'
      abort 'config isolation lost' unless ARGV.include?('--no-repo-config') && ARGV.include?('--no-audited-catalog') && ENV['XDG_CONFIG_HOME'] == ARGV.last + '/config'
      workflow = File.read(File.join(ARGV.last, '.github/workflows/test.yml'))
      File.open('scans', 'a') { |output| output.puts workflow.split('uses: ', 2)[1].strip }
      report = { 'scanned_fresh' => 1, 'rules_version' => 7, 'coverage_complete' => true, 'ignored' => 0 }
      report.merge!(JSON.parse(ENV.fetch('AUDIT_REPORT_OVERRIDES', '{}')))
      puts JSON.generate(report)
      exit Integer(ENV.fetch('FIXTURE_AUDIT_STATUS', '0'))
    STUB
    executable(@root.join('target/debug/pinprick'), scanner)
    executable(@root.join('bin/cargo'), scanner)
    executable(@root.join('bin/mktemp'), "#!/usr/bin/env ruby\nrequire 'tmpdir'\nputs Dir.mktmpdir('scan.', ENV.fetch('TMPDIR'))\n")
  end

  def release(tag, sha = @sha)
    @refs[tag] = sha
    @releases << { tag_name: tag, draft: false, prerelease: false }
  end

  def entry(tag, sha = @sha, rules: 1) = { 'sha' => sha, 'tag' => tag, 'rules_version' => rules }

  def run_tool(argv, **env)
    @root.join('fixture.json').write(JSON.generate(releases: @releases, refs: @refs))
    command(argv, cwd: @root, env: @env.merge(env.transform_keys(&:to_s)))
  end

  def scan(**env) = run_tool(['bash', '-euo', 'pipefail', '-c', workflow_step('audit-actions.yml', 'Scan for new releases')], **env)
  def add_action(**env) = run_tool(['bash', '-euo', 'pipefail', '-c', just_recipe('add-action action_key'), 'add-action', 'example/action'], **env)
  def validate = run_tool(['bash', '-euo', 'pipefail', '-c', workflow_step('ci.yml', 'Check catalog format and sort order')])
  def entries = JSON.parse(@catalog.read)
  def output = @root.join('output').read.lines(chomp: true).last
  def write_entries(*values) = @catalog.write(JSON.generate(values))

  def assert_success(result)
    super
    assert_empty @root.join('scratch').children
  end

  def test_scheduled_scan_preserves_full_labels_and_adds_commits_idempotently
    write_entries(entry('v5.0.0'))
    %w[v5 v5.0 v3.0.2-node.24].each { |tag| release(tag) }
    release('2026.09.13.1', @new_sha)
    assert_success scan
    assert_equal [entry('2026.09.13.1', @new_sha, rules: 7), entry('v5.0.0', rules: 7)], entries
    scans = @root.join('scans').read.lines
    assert_equal 2, scans.length
    assert_includes scans.first, '# v3.0.2-node.24'
    assert_equal 'updated=1', output
    assert_success validate
    before = @catalog.binread
    assert_success scan
    assert_equal before, @catalog.binread
    assert_equal 'updated=0', output
  end

  def test_noop_after_changed_entry_keeps_updated_output
    write_entries(entry('v5.0.0', rules: 7))
    release('2026.09.13.1', @new_sha)
    release('v3.0.2-node.24')
    assert_success scan
    assert_equal 'updated=1', output
    assert_equal [entry('2026.09.13.1', @new_sha, rules: 7), entry('v5.0.0', rules: 7)], entries
  end

  def test_sliding_relabels_are_ignored_without_scanning
    [['v8.0.0', 'v8'], ['v3.0.0', 'v3'], ['v2.1.13', 'v2'], ['v3.0.1', 'v3'], ['v2.2.1', 'v2']].each do |original, sliding|
      write_entries(entry(original))
      before = @catalog.binread
      @releases = []
      release(sliding)
      assert_success scan
      assert_equal before, @catalog.binread
      refute @root.join('scans').exist?
      assert_equal 'updated=0', output
    end
    refute_includes @root.join('api-calls').read, '/git/ref/'
  end

  def test_manual_add_preserves_label_and_canonical_version_order_when_restamping
    write_entries(entry('v5.0.0', @new_sha), entry('v4.0.0'))
    release('v3.0.2-node.24')
    assert_success add_action
    assert_equal [entry('v5.0.0', @new_sha), entry('v4.0.0', rules: 7)], entries
    assert entries.all? { |entry| entry.keys == %w[sha tag rules_version] }
  end

  def test_manual_add_rejects_sliding_release
    release('v5')
    before = @catalog.binread
    result = add_action
    refute_equal 0, result.returncode
    assert_includes result.stderr, 'unsupported release tag'
    assert_equal before, @catalog.binread
    refute @root.join('scans').exist?
  end

  def test_nonclean_reaudits_preserve_existing_verdict
    release('v3.0.2-node.24')
    %i[scan add_action].each do |producer|
      [[1, { findings: [{ description: 'unpinned runtime fetch' }] }], [0, { coverage_complete: false }],
       [0, { scanned_fresh: 0 }], [0, { ignored: 1 }], [2, {}]].each do |status, overrides|
        write_entries(entry('v5.0.0'))
        before = @catalog.binread
        result = public_send(producer, FIXTURE_AUDIT_STATUS: status.to_s, AUDIT_REPORT_OVERRIDES: JSON.generate(overrides))
        if producer == :scan
          assert_success result
          assert_equal 'updated=0', output
        else
          refute_equal 0, result.returncode
        end
        assert_equal before, @catalog.binread
        assert_empty @root.join('scratch').children
      end
    end
  end

  def test_dispatch_rejects_sliding_tags_and_accepts_explicit_sha
    release('v5')
    assert_success scan(INPUT_ACTION: 'example/action', INPUT_REF: 'v5')
    refute @root.join('scans').exist?
    [@sha[0, 7], @sha].each do |ref|
      write_entries
      @refs[ref] = @sha
      assert_success scan(INPUT_ACTION: 'example/action', INPUT_REF: ref)
      assert_equal [entry('sha:' + @sha[0, 7], rules: 7)], entries
      assert_success validate
    end
  end

  def test_ci_rejects_sliding_or_malformed_labels_and_accepts_full_releases
    ['v8', 'v2.1', '8', '2.1', 'latest', "v1.2.3\n", 'v1.2.3-', 'v1.2.3+bad..suffix', 'sha:1234567', nil].each do |tag|
      write_entries(entry(tag))
      refute_equal 0, validate.returncode, tag.inspect
    end
    %w[v1.2.3 1.2.3 2026.09.13.1 v3.0.2-node.24 v1.2.3-rc.1+build.2].each do |tag|
      write_entries(entry(tag))
      assert_success validate
    end
  end

  def test_ci_format_errors_cannot_log_filename_workflow_commands
    path = @root.join("audited-actions/example/##[error]filename-controlled\n::warning::filename-controlled.json")
    [JSON.generate({}), JSON.generate([entry('v1.0.0'), entry('v2.0.0', @new_sha)])].each do |contents|
      path.write(contents)
      result = run_tool(['bash', '-xeuo', 'pipefail', '-c', workflow_step('ci.yml', 'Check catalog format and sort order')])
      assert_equal 1, result.returncode
      log = result.stdout + result.stderr
      refute_includes log, '##['
      refute_match(/(?:\A|\n)::warning::filename-controlled/, log)
      assert_equal 1, result.stdout.lines.grep(/^::error::/).length
      assert_includes log, '+ exit 1'
    end
  end

  def test_draft_and_prerelease_flags_are_excluded
    @releases = [{ tag_name: 'v1.0.0', draft: true, prerelease: false }, { tag_name: 'v2.0.0', draft: false, prerelease: true }]
    assert_success scan
    refute @root.join('scans').exist?
  end

  def test_missing_tag_policy_fails_scan
    release('v1.0.0')
    @root.join('scripts/audited-actions.jq').delete
    refute_equal 0, scan.returncode
    refute @root.join('scans').exist?
  end

  def test_checked_in_catalog_passes_validation
    assert_success shell(workflow_step('ci.yml', 'Check catalog format and sort order'))
  end

  def test_catalog_scan_preserves_exported_tmpdir_and_requires_fresh_coverage
    release('v1.0.0')
    release('v2.0.0', @new_sha)
    [1, 0].each do |fresh|
      write_entries
      assert_success scan(INPUT_ACTION: 'example/action', AUDIT_REPORT_OVERRIDES: JSON.generate(scanned_fresh: fresh))
      assert_equal fresh == 1 ? 2 : 0, entries.length
      assert entries.all? { |entry| entry['rules_version'] == 7 }
    end
  end
end
