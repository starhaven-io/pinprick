# frozen_string_literal: true

require_relative 'test_helper'
require 'yaml'

class CIConclusionTests < ToolingTest
  RESULT_JOBS = {
    'MATRIX_RESULT' => 'generate-matrix', 'COMMITS_RESULT' => 'commits', 'CHECK_RESULT' => 'check',
    'ZIZMOR_RESULT' => 'zizmor', 'PINPRICK_RESULT' => 'pinprick', 'CODECOV_RESULT' => 'codecov'
  }.freeze

  def setup
    super
    job = YAML.load_file(ROOT.join('.github/workflows/ci.yml')).fetch('jobs').fetch('conclusion')
    @needs = Array(job.fetch('needs'))
    @step = job.fetch('steps').find { |step| step['name'] == 'Result' }
    @env = {
      'GITHUB_EVENT_NAME' => 'pull_request', 'MATRIX_RESULT' => 'success', 'COMMITS_RESULT' => 'success',
      'CHECK_RESULT' => 'success', 'ZIZMOR_RESULT' => 'success', 'PINPRICK_RESULT' => 'success',
      'CODECOV_RESULT' => 'success', 'MATRIX' => '[{"check":"coverage"}]', 'RUN_ZIZMOR' => 'true',
      'RUN_PINPRICK' => 'true', 'RUN_CODECOV' => 'true', 'CODECOV_ELIGIBLE' => 'true', 'EVENT_NAME' => 'pull_request'
    }
  end

  def conclude(**overrides)
    env = @env.merge(overrides.transform_keys(&:to_s))
    results = RESULT_JOBS.to_h { |name, job| [job, env.delete(name)] }
    @step.fetch('env').each do |name, expression|
      match = /\A\$\{\{\s*needs\.([a-z-]+)\.result\s*\}\}\z/.match(expression)
      next unless match

      # Actions exposes only direct dependencies in the needs context.
      env[name] = @needs.include?(match[1]) ? results.fetch(match[1], '') : ''
    end
    shell(@step.fetch('run'), env: env, bash: '/bin/bash')
  end

  def test_selected_pinprick_audit_must_succeed
    assert_success conclude
    %w[failure cancelled skipped].push('').each { |result| refute_equal 0, conclude(PINPRICK_RESULT: result).returncode }
  end

  def test_result_environment_names_bind_to_their_own_jobs
    expected = RESULT_JOBS.transform_values { |job| "${{ needs.#{job}.result }}" }
    assert_equal expected, @step.fetch('env').slice(*RESULT_JOBS.keys)
  end

  def test_selected_codecov_must_succeed
    assert_success conclude
    %w[failure cancelled skipped].push('').each { |result| refute_equal 0, conclude(CODECOV_RESULT: result).returncode }
  end

  def test_only_unselected_audit_may_skip
    assert_success conclude(RUN_PINPRICK: 'false', PINPRICK_RESULT: 'skipped')
    refute_equal 0, conclude(RUN_PINPRICK: 'false', PINPRICK_RESULT: 'failure').returncode
    refute_equal 0, conclude(RUN_PINPRICK: '', PINPRICK_RESULT: 'skipped').returncode
  end

  def test_every_routing_decision_fails_closed
    [{ EVENT_NAME: 'unknown', COMMITS_RESULT: 'skipped' }, { MATRIX: '', CHECK_RESULT: 'skipped' },
     { RUN_ZIZMOR: '', ZIZMOR_RESULT: 'skipped' }, { RUN_CODECOV: '', CODECOV_RESULT: 'skipped' },
     { CODECOV_ELIGIBLE: '', CODECOV_RESULT: 'skipped' }].each { |overrides| refute_equal 0, conclude(**overrides).returncode }
  end

  def test_pr_gate_keeps_fleet_audit_and_source_dogfooding
    audit = ROOT.join('.github/workflows/pinprick-audit.yml').read
    ci = ROOT.join('.github/workflows/ci.yml').read
    refute_includes audit, "  workflow_call:\n"
    assert_includes audit, "  pull_request:\n"
    assert_includes audit, "  push:\n"
    assert_includes ci, 'uses: starhaven-io/.github/.github/workflows/reusable-pinprick-audit.yml@'
    assert_includes ci, '      fail-on-findings: true'
    refute_includes ci, 'uses: $/.github/workflows/'
  end
end
