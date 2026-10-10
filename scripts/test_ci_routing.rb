# frozen_string_literal: true

require_relative 'test_helper'

class CIRoutingTests < ToolingTest
  def setup
    super
    @env = ENV.keys.grep(/^GIT_/).to_h { |key| [key, nil] }.merge(
      'GIT_CONFIG_GLOBAL' => File::NULL, 'GIT_CONFIG_SYSTEM' => File::NULL,
      'GIT_AUTHOR_NAME' => 'Fixture', 'GIT_AUTHOR_EMAIL' => 'fixture@example.test',
      'GIT_COMMITTER_NAME' => 'Fixture', 'GIT_COMMITTER_EMAIL' => 'fixture@example.test',
      'GITHUB_OUTPUT' => @root.join('output').to_s, 'EVENT_NAME' => 'pull_request',
      'GITHUB_TOKEN' => nil, 'GH_TOKEN' => nil
    )
    git('init', '-q')
    git('config', 'diff.renames', 'true')
    @root.join('README.md').write("fixture\n")
    snapshot
    @env['BASE_SHA'] = git('rev-parse', 'HEAD').strip
  end

  def git(*arguments)
    result = command(['git', *arguments], cwd: @root, env: @env)
    assert_success result
    result.stdout
  end

  def snapshot
    git('add', '--all')
    git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture')
  end

  def add(path, content = "fixture content\n")
    target = @root.join(path)
    target.dirname.mkpath
    target.write(content)
  end

  def route(trace: false)
    @root.join('output').delete if @root.join('output').exist?
    script = workflow_step('ci.yml', 'Generate CI matrix')
    result = if trace
               command(['bash', '-xeuo', 'pipefail', '-c', script], cwd: @root, env: @env)
             else
               shell(script, cwd: @root, env: @env)
             end
    @routing_result = result
    assert_success result
    values = @root.join('output').read.lines.to_h { |line| line.chomp.split('=', 2) }
    [JSON.parse(values.fetch('matrix')), values]
  end

  def assert_rust_gate(matrix)
    assert_equal 3, matrix.count { |entry| entry['check'] == 'test' }
    %w[lint coverage msrv].each { |check| assert matrix.any? { |entry| entry['check'] == check }, check }
  end

  def test_unicode_newline_and_tab_source_paths_get_full_gate
    ["src/bin/évil.rs", "src/bin/new\nline.rs", "src/bin/tab\tname.rs"].each do |path|
      add(path)
      snapshot
      matrix, values = route
      assert_rust_gate(matrix)
      assert_equal 'true', values.fetch('run_pinprick')
      assert matrix.find { |entry| entry['check'] == 'verify-audited' }.fetch('verify_latest')
      @env['BASE_SHA'] = git('rev-parse', 'HEAD').strip
    end
  end

  def test_rename_out_of_source_keeps_old_path_in_routing
    add('src/main.rs')
    snapshot
    @env['BASE_SHA'] = git('rev-parse', 'HEAD').strip
    @root.join('docs').mkpath
    git('mv', 'src/main.rs', 'docs/main.md')
    snapshot
    assert_includes git('diff', '--name-status', "#{@env['BASE_SHA']}...HEAD"), "R100\tsrc/main.rs\tdocs/main.md"
    matrix, values = route
    assert_rust_gate(matrix)
    assert_equal 'true', values.fetch('run_pinprick')
  end

  def test_unicode_docs_keep_documentation_only_routing
    add('docs/écrit.md')
    snapshot
    matrix, values = route
    assert_empty matrix
    %w[run_pinprick run_zizmor run_codecov].each { |key| assert_equal 'false', values.fetch(key) }
  end

  def test_multiline_paths_cannot_qualify_as_documentation_only
    ["evil.rs\nREADME.md", "tool.sh\r\nnotes.md", "tool.sh\rREADME.md", "docs/hidden\nsource.data", "##[error]filename-controlled\nREADME.md"].each do |path|
      add(path)
      snapshot
      matrix, values = route(trace: true)
      assert_rust_gate(matrix)
      assert_equal 'true', values.fetch('run_codecov')
      refute_includes @routing_result.stdout + @routing_result.stderr, '##['
      @env['BASE_SHA'] = git('rev-parse', 'HEAD').strip
    end
  end

  def test_ruby_manifests_select_tooling_checks_with_another_classified_change
    %w[Gemfile Gemfile.lock .ruby-version].each_with_index do |path, index|
      add("site/src/fixture-#{index}.ts")
      add(path)
      snapshot
      matrix, values = route
      assert_rust_gate(matrix)
      assert matrix.any? { |entry| entry['check'] == 'site' }
      assert_equal 'true', values.fetch('run_codecov')
      @env['BASE_SHA'] = git('rev-parse', 'HEAD').strip
    end
  end

  def test_unicode_workflow_path_requires_both_security_audits
    add('.github/workflows/évil.yml')
    snapshot
    matrix, values = route
    assert_rust_gate(matrix)
    assert_equal 'true', values.fetch('run_pinprick')
    assert_equal 'true', values.fetch('run_zizmor')
  end

  def test_traced_routing_does_not_log_filename_workflow_commands
    add("src/bin/##[error]filename-controlled\n::warning::filename-controlled.rs")
    snapshot
    matrix, = route(trace: true)
    assert_rust_gate(matrix)
    log = @routing_result.stdout + @routing_result.stderr
    refute_includes log, '##['
    refute_match(/(?:\A|\n)::warning::filename-controlled/, log)
    assert_includes log, '+ echo'
  end

  def test_traced_unclassified_path_is_safe_in_fallback_routing
    add("unclassified/##[error]filename-controlled\n::warning::filename-controlled.data")
    snapshot
    matrix, = route(trace: true)
    assert_rust_gate(matrix)
    log = @routing_result.stdout + @routing_result.stderr
    refute_includes log, '##['
    refute_match(/(?:\A|\n)::warning::filename-controlled/, log)
    assert_includes log, '+ echo'
  end

  def test_diff_failure_cannot_emit_successful_routing
    @env['BASE_SHA'] = 'missing-base'
    result = shell(workflow_step('ci.yml', 'Generate CI matrix'), cwd: @root, env: @env)
    refute_equal 0, result.returncode
    refute @root.join('output').exist?
  end

  def verifier_fixture
    executable(@root.join('scripts/verify-audited-actions.rb'), <<~'STUB')
      #!/usr/bin/env ruby
      require 'json'
      File.write('verifier-arguments', JSON.generate(ARGV))
    STUB
  end

  def verify_changed
    shell(workflow_step('ci.yml', 'Verify audited-actions entries'), cwd: @root,
          env: @env.merge('VERIFY_CHANGED' => 'true', 'VERIFY_LATEST' => 'false'))
  end

  def test_catalog_selection_preserves_exact_path_bytes
    path = "audited-actions/example/évil\nname.json"
    add(path, '[]')
    snapshot
    matrix, = route
    assert matrix.find { |entry| entry['check'] == 'verify-audited' }.fetch('verify_changed')
    verifier_fixture
    assert_success verify_changed
    assert_equal ['target/release/pinprick', 'files', path], JSON.parse(@root.join('verifier-arguments').read)
  end

  def test_traced_catalog_selection_keeps_filename_commands_out_of_logs
    path = "audited-actions/example/##[error]filename-controlled\n::warning::filename-controlled.json"
    add(path, '[]')
    snapshot
    verifier_fixture
    result = command(['bash', '-xeuo', 'pipefail', '-c', workflow_step('ci.yml', 'Verify audited-actions entries')],
                     cwd: @root, env: @env.merge('VERIFY_CHANGED' => 'true', 'VERIFY_LATEST' => 'false'))
    assert_success result
    assert_equal ['target/release/pinprick', 'files', path], JSON.parse(@root.join('verifier-arguments').read)
    log = result.stdout + result.stderr
    refute_includes log, '##['
    refute_match(/(?:\A|\n)::warning::filename-controlled/, log)
    assert_includes log, '+ exit 0'
  end

  def test_catalog_deletion_is_distinct_from_failed_diff
    path = 'audited-actions/example/action.json'
    add(path, '[]')
    snapshot
    @env['BASE_SHA'] = git('rev-parse', 'HEAD').strip
    git('rm', path)
    snapshot
    verifier_fixture
    result = verify_changed
    assert_success result
    assert_includes result.stdout, 'Catalog change only removes entries'
    refute @root.join('verifier-arguments').exist?
    @env['BASE_SHA'] = 'missing-base'
    result = verify_changed
    refute_equal 0, result.returncode
    assert_includes result.stdout, 'changed entries NOT verified'
    refute @root.join('verifier-arguments').exist?
  end
end
