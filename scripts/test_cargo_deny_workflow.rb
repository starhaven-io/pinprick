# frozen_string_literal: true

require_relative 'test_helper'

class CargoDenyWorkflowTests < ToolingTest
  def test_dependency_policy_jobs_use_same_archive
    archives = %w[ci.yml cargo-deny.yml].map do |name|
      workflow = ROOT.join('.github/workflows', name).read
      pins = workflow.scan(/CARGO_DENY_SHA256: "([a-f0-9]{64})"\n[\s\S]*?https:\/\/github\.com\/EmbarkStudios\/cargo-deny\/releases\/download\/([0-9.]+)\/cargo-deny-([0-9.]+)-x86_64-unknown-linux-musl\.tar\.gz/)
      assert_equal 1, pins.length, "expected one cargo-deny pin in #{name}"
      assert_equal pins.first[1], pins.first[2]
      pins.first
    end
    assert_equal archives.first, archives.last
  end

  def test_setup_failure_stops_before_advisory_reporting
    %w[curl sha256sum tar cargo].each do |name|
      body = case name
             when 'sha256sum' then "cat >/dev/null\n"
             when 'cargo' then "echo \"$*\" >> \"$CARGO_CALLS\"\nexit \"$CARGO_STATUS\"\n"
             else "exit 0\n"
             end
      executable(@root.join(name), "#!/bin/sh\n" + body)
    end
    calls = @root.join('cargo-calls')
    [0, 42].each do |status|
      calls.write('')
      result = shell(workflow_step('cargo-deny.yml', 'Install cargo-deny'), cwd: @root, bash: '/bin/bash', env: {
        'PATH' => "#{@root}:/usr/bin:/bin", 'RUNNER_TEMP' => @root.to_s, 'GITHUB_PATH' => @root.join('github-path').to_s,
        'CARGO_DENY_SHA256' => 'a' * 64, 'CARGO_CALLS' => calls.to_s, 'CARGO_STATUS' => status.to_s
      })
      assert_equal status, result.returncode, result.stderr
      assert_equal "--version\n", calls.read
    end
  end
end
