# frozen_string_literal: true

Encoding.default_external = Encoding::UTF_8

require 'minitest/autorun'
require 'fileutils'
require 'json'
require 'open3'
require 'pathname'
require 'rbconfig'
require 'tmpdir'
require 'timeout'

ROOT = Pathname.new(__dir__).parent.freeze
RUBY = RbConfig.ruby.freeze
Result = Data.define(:stdout, :stderr, :returncode)

module ToolingHelpers
  def command(argv, env: {}, cwd: ROOT, input: '', timeout: 20)
    invoke = -> { Timeout.timeout(timeout) { Open3.capture3(env, *argv.map(&:to_s), chdir: cwd.to_s, stdin_data: input) } }
    stdout, stderr, status = defined?(Bundler) ? Bundler.with_unbundled_env(&invoke) : invoke.call
    Result.new(stdout, stderr, status.exitstatus)
  end

  def shell(script, env: {}, cwd: ROOT, bash: 'bash')
    command([bash, '-euo', 'pipefail', '-c', script], env: env, cwd: cwd)
  end

  def workflow_step(workflow, name)
    content = ROOT.join('.github/workflows', workflow).read
    step = content.split("      - name: #{name}\n", 2).fetch(1).split("\n      - ", 2).first
    body = step.split("        run: |\n", 2).fetch(1).lines.take_while do |line|
      line.strip.empty? || line.start_with?('          ')
    end.join
    dedent(body)
  end

  def just_recipe(signature)
    content = ROOT.join('justfile').read.split("\n#{signature}:\n", 2).fetch(1)
    body = dedent(content.split(/\n(?=\S)/, 2).first)
    raise 'recipe requires just evaluation' unless body.start_with?("#!/usr/bin/env bash\n") && !body.include?('{{')

    body
  end

  def dedent(text)
    width = text.lines.reject { |line| line.strip.empty? }.map { |line| line[/\A */].length }.min || 0
    text.lines.map { |line| line.sub(/\A {0,#{width}}/, '') }.join
  end

  def executable(path, contents)
    path = Pathname.new(path)
    path.dirname.mkpath
    path.write(contents)
    path.chmod(0o755)
  end

  def assert_success(result)
    assert_equal 0, result.returncode, result.stdout + result.stderr
  end
end

class ToolingTest < Minitest::Test
  include ToolingHelpers

  def setup
    @root = Pathname.new(Dir.mktmpdir('pinprick-test.'))
  end

  def teardown
    FileUtils.remove_entry(@root)
  end
end
