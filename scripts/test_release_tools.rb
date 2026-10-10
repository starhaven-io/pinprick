# frozen_string_literal: true

require_relative 'test_helper'
require_relative 'format-release-notes'
require 'shellwords'
require 'yaml'

class ReleaseToolsTests < ToolingTest
  def test_release_and_catalog_requests_are_retained
    [['release.yml', 'release'], ['audit-actions.yml', 'audit-actions']].each do |name, group|
      workflow = ROOT.join('.github/workflows', name).read
      concurrency = workflow.split("concurrency:\n", 2)[1].split("\n\n", 2).first
      assert_equal({ 'group' => group, 'cancel-in-progress' => 'false', 'queue' => 'max' }, concurrency.lines.to_h { |line| line.strip.split(': ', 2) })
    end
  end

  def test_rejected_site_dispatch_cannot_cancel_main_deployment
    workflow = ROOT.join('.github/workflows/deploy-site.yml').read
    assert_includes workflow, "group: ${{ github.ref == 'refs/heads/main' && 'deploy-site' || format('rejected-deploy-{0}', github.run_id) }}"
    push = workflow.split('  schedule:', 2).first
    %w[.github/workflows/deploy-site.yml scripts/check-npm-install-policy.mjs].each { |path| assert_includes push, "      - \"#{path}\"" }
  end

  def test_site_deploy_preserves_signed_output_and_uses_locked_tool
    deploy = ROOT.join('.github/workflows/deploy-site.yml').read.split("\n  deploy:\n", 2)[1]
    setup, publish = deploy.split("      - name: Deploy signed site to Cloudflare Workers\n", 2)
    assert_includes setup, "    needs: sign\n"
    assert_includes setup, "    if: github.ref == 'refs/heads/main'\n"
    assert_includes setup, 'run: node scripts/check-npm-install-policy.mjs site'
    assert_operator setup.index('run: npm ci --strict-allow-scripts'), :<, setup.index('name: signed-site')
    refute_includes setup, 'CLOUDFLARE_API_TOKEN'
    refute_includes deploy, 'CATALOG_SIGNING_KEY'
    refute_includes deploy, 'npm run build'
    assert_includes publish, "        working-directory: site\n"
    assert_includes publish, 'CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}'
    assert_includes publish, 'CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}'
    executable(@root.join('node_modules/.bin/wrangler'), <<~'STUB')
      #!/bin/sh
      set -eu
      [ "$#" = 3 ] && [ "$1" = deploy ] && [ "$2" = --config ] && [ "$3" = wrangler.jsonc ]
      [ "$CLOUDFLARE_API_TOKEN" = fixture-token ]
      printf deployed > invocation
    STUB
    @root.join('package.json').write(JSON.generate(scripts: { predeploy: 'exit 97', deploy: 'exit 98', postdeploy: 'exit 99' }))
    signed = @root.join('dist/client/catalog.json.minisig')
    signed.dirname.mkpath
    signed.write("signed fixture bytes\n")
    result = shell(workflow_step('deploy-site.yml', 'Deploy signed site to Cloudflare Workers'), cwd: @root, env: { 'CLOUDFLARE_API_TOKEN' => 'fixture-token' })
    assert_success result
    assert_equal 'deployed', @root.join('invocation').read
    assert_equal "signed fixture bytes\n", signed.binread
  end

  def test_breaking_changes_survive_internal_filter_and_sections_keep_order
    sections, changelog = ReleaseNotes.parse_notes(<<~NOTES)
      * feat!: new report schema by @author in https://example.com/1
      * build(runtime)!: require a newer runtime by @author in https://example.com/2
      * fix(cli): preserve details by @author in https://example.com/3
      * chore: refresh tooling by @author in https://example.com/4
      * fix(audit-actions): refresh catalog by @author in https://example.com/5
      **Full Changelog**: https://example.com/compare
    NOTES
    assert_equal({ 'Breaking Changes' => ['new report schema', 'require a newer runtime'], 'Fixes' => ['preserve details'] }, sections)
    rendered = ReleaseNotes.format_markdown('v1.0.0', sections, changelog)
    assert_operator rendered.index('Breaking Changes'), :<, rendered.index('Fixes')
    assert_includes rendered, '**Full Changelog**: https://example.com/compare'
    input = @root.join('notes')
    input.write('* feat: greeting by @author in https://example.com/1')
    result = command([RUBY, ROOT.join('scripts/format-release-notes.rb'), input, 'v1.0.0'])
    assert_success result
    assert_equal "## pinprick v1.0.0\n\n### What's New\n- greeting\n\n", result.stdout
  end

  def test_release_notes_preserve_unicode_whitespace_and_attribution_semantics
    ["\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\u0085", "\u2028", "\u2029"].each do |separator|
      raw = "* fix: first#{separator}* feat: second#{separator}**Full Changelog**: https://example.test/compare"
      assert_equal [{ 'Fixes' => ['first'], "What's New" => ['second'] }, 'https://example.test/compare'],
                   ReleaseNotes.parse_notes(raw), separator.inspect
    end
    ["\u00a0", "\u2007", "\u202f", "\x1f"].each do |space|
      raw = "#{space}*#{space}fix:#{space}café#{space}by#{space}@développeur#{space}in#{space}https://example.test/1#{space}"
      assert_equal [{ 'Fixes' => ['café'] }, nil], ReleaseNotes.parse_notes(raw), space.inspect
    end
    %w[développeur 作者 Ⅳ ²].each do |author|
      assert_equal [{ 'Fixes' => ['details'] }, nil], ReleaseNotes.parse_notes("* fix: details by @#{author}")
    end
    assert_equal [{ 'Fixes' => ["details by @name\u0301"] }, nil], ReleaseNotes.parse_notes("* fix: details by @name\u0301")
    assert_equal [{ 'Fixes' => ["\0details\0"] }, nil], ReleaseNotes.parse_notes("* fix: \0details\0")
    input = @root.join('unicode-notes')
    input.write("\u00a0* fix: café by @作者\u00a0\u2028**Full Changelog**:\u00a0https://example.test/compare")
    result = command([RUBY, ROOT.join('scripts/format-release-notes.rb'), input, 'v1.0.0'],
                     env: { 'LANG' => nil, 'LC_CTYPE' => nil, 'LC_ALL' => 'C' })
    assert_success result
    assert_equal "## pinprick v1.0.0\n\n### Fixes\n- café\n\n---\n**Full Changelog**: https://example.test/compare\n\n", result.stdout
  end

  def test_release_notes_distinguish_unicode_space_urls_and_connectors
    assert_equal [{}, nil], ReleaseNotes.parse_notes("\u200b* fix: ignored")
    assert_equal [{ 'Fixes' => ["preserved\u200b"] }, nil], ReleaseNotes.parse_notes("* fix: preserved\u200b")
    assert_equal [{ 'Fixes' => ["details by @user\u203fname"] }, nil],
                 ReleaseNotes.parse_notes("* fix: details by @user\u203fname in https://example.test/1")
    assert_equal [{}, 'https://example.test/compare'],
                 ReleaseNotes.parse_notes("**Full Changelog**: https://example.test/compare\u00a0ignored")
    description = "details by @author in https://example.test/a\u00a0suffix"
    assert_equal [{ 'Fixes' => [description] }, nil], ReleaseNotes.parse_notes("* fix: #{description}")
  end

  def test_notarization_requirement_and_bounded_retry
    script = <<~'STUB'
      set -euo pipefail
      count=0
      mkdir() { :; }
      cp() { :; }
      ditto() { :; }
      sleep() { :; }
      xcrun() { return "$SUBMIT_STATUS"; }
      codesign() {
        [[ "$*" == *"-R=notarized"* && "$*" == *"--check-notarization"* && "$*" == *"--strict"* ]] || return 97
        count=$((count + 1))
        if (( count <= FAILURES )); then return "$VERIFY_STATUS"; fi
      }
    STUB
    script += workflow_step('release.yml', 'Notarize binary') + "\nprintf 'verified:%s\\n' \"$count\"\n"
    [[0, 0, 0, 0, 1], [0, 3, 2, 0, 3], [0, 3, 3, 3, nil], [0, 1, 1, 1, nil], [5, 0, 0, 5, nil]].each do |submit, status, failures, expected, attempts|
      env = { 'TARGET' => 'test', 'RUNNER_TEMP' => '/unused', 'APPLE_ID' => 'test', 'NOTARIZATION_PASSWORD' => 'test',
              'DEVELOPMENT_TEAM' => 'test', 'SUBMIT_STATUS' => submit.to_s, 'VERIFY_STATUS' => status.to_s, 'FAILURES' => failures.to_s }
      result = shell(script, env: env)
      assert_equal expected, result.returncode, result.stdout + result.stderr
      attempts ? assert_includes(result.stdout, "verified:#{attempts}") : refute_includes(result.stdout, 'verified:')
    end
  end

  def test_wrapper_version_bump_requires_exact_counts_before_writing
    script = workflow_step('release.yml', 'Update default pinprick version').split("\nif git diff", 2).first
    action = "inputs:\n  version:\n    description: version\n    default: \"1.2.3\"\nrun: 1.2.3\nother: 1.2.3\n"
    readme = '1.2.3 and 1.2.3'
    @root.join('action.yml').write(action)
    @root.join('README.md').write(readme)
    result = shell(script, cwd: @root, env: { 'VERSION' => '2.0.0' })
    assert_success result
    assert_equal action.gsub('1.2.3', '2.0.0'), @root.join('action.yml').read
    assert_equal readme.gsub('1.2.3', '2.0.0'), @root.join('README.md').read
    assert_success shell(script, cwd: @root, env: { 'VERSION' => '2.0.0' })
    @root.join('action.yml').write(action)
    @root.join('README.md').write('1.2.3')
    refute_equal 0, shell(script, cwd: @root, env: { 'VERSION' => '2.0.0' }).returncode
    assert_equal action, @root.join('action.yml').read
    assert_equal '1.2.3', @root.join('README.md').read
    @root.join('action.yml').write(action + '1.2.3')
    @root.join('README.md').write(readme)
    refute_equal 0, shell(script, cwd: @root, env: { 'VERSION' => '2.0.0' }).returncode
    assert_equal readme, @root.join('README.md').read
  end

  def test_ruby_bootstrap_has_no_release_token_or_unneeded_bundler
    workflow = YAML.load_file(ROOT.join('.github/workflows/release.yml'))
    %w[release bump-action bump-cask].each do |name|
      job = workflow.fetch('jobs').fetch(name)
      steps = job.fetch('steps')
      setup = steps.find { |step| step['name'] == 'Set up Ruby' }
      assert_equal 'none', setup.fetch('with').fetch('bundler')
      assert_operator steps.index(setup), :<, steps.index { |step| step['name'].to_s.start_with?('Mint ') }
      [workflow, job, setup].each do |scope|
        refute scope.fetch('env', {}).keys.any? { |key| %w[GH_TOKEN GITHUB_TOKEN HOMEBREW_GITHUB_API_TOKEN].include?(key) }
      end
    end
    verification = YAML.load_file(ROOT.join('.github/workflows/verify-audited-actions.yml'))
    setup = verification.fetch('jobs').fetch('verify').fetch('steps').find { |step| step['name'] == 'Set up Ruby' }
    assert_equal 'none', setup.fetch('with').fetch('bundler')
  end

  def test_release_notes_do_not_inherit_tokens_and_work_without_utf8_locale
    bin = @root.join('bin').tap(&:mkpath)
    executable(bin.join('ruby'), <<~SH)
      #!/bin/sh
      test -z "${GH_TOKEN+x}" && test -z "${GITHUB_TOKEN+x}" || exit 99
      exec #{Shellwords.escape(RUBY)} "$@"
    SH
    @root.join('scripts').mkpath
    FileUtils.cp(ROOT.join('scripts/format-release-notes.rb'), @root.join('scripts'))
    @root.join('raw_notes.md').write('* feat: café by @author in https://example.test/1')
    body = workflow_step('release.yml', 'Create release and format notes atomically')
    command_lines = body.lines.drop_while { |line| !line.include?('ruby scripts/format-release-notes.rb') }.take(3).join
    result = shell(command_lines, cwd: @root, env: {
      'PATH' => "#{bin}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}", 'RUNNER_TEMP' => @root.to_s,
      'TAG' => 'v1.0.0', 'GH_TOKEN' => 'fixture-release-token', 'GITHUB_TOKEN' => 'fixture-github-token',
      'LANG' => nil, 'LC_CTYPE' => nil, 'LC_ALL' => 'C'
    })
    assert_success result
    assert_includes @root.join('formatted_notes.md').read, '- café'
  end
end

class CaskMergeProtocolTests < ToolingTest
  def test_merge_is_bounded_synchronous_and_exact_head_bound
    workflow = ROOT.join('.github/workflows/release.yml').read
    resolve = workflow_step('release.yml', 'Resolve Homebrew cask bump')
    wait = workflow_step('release.yml', 'Wait for checks on the validated head')
    revalidate = workflow_step('release.yml', 'Revalidate and merge the exact head')
    merge_job = workflow.split("\n  merge-cask-bump:\n", 2)[1]
    ['if [[ "${MATCH_COUNT}" != 1 ]]', '.user.login == $bot', '.changed_files == 1', 'echo "base_sha=', 'echo "head_sha='].each { |text| assert_includes resolve, text }
    refute_includes resolve, 'gh pr merge'
    ['CHECK_TIMEOUT_SECONDS=1500', '8) CHECK_SUMMARY=pending', 'mergeStateStatus', 'CHECK_STATUS == 0', '[[ "${MERGE_STATE}" == "CLEAN" || "${MERGE_STATE}" == "UNSTABLE" ]]'].each { |text| assert_includes wait, text }
    %w[--watch --fail-fast].each { |text| refute_includes wait, text }
    assert_operator merge_job.index('Wait for checks on the validated head'), :<, merge_job.index('Mint bot token for tap')
    ['.base.sha == $base_sha', '.head.sha == $head', '.[0].filename == $cask', '--match-head-commit "${HEAD_SHA}"'].each { |text| assert_includes revalidate, text }
    refute_includes merge_job, '--auto'
  end

  def test_partial_required_check_registration_stays_blocked
    wait = workflow_step('release.yml', 'Wait for checks on the validated head').sub('CHECK_INTERVAL_SECONDS=10', 'CHECK_INTERVAL_SECONDS=0')
    stub = <<~'STUB'
      gh() {
        if [[ "$1" == api ]]; then printf '%s\n' validated-head; return; fi
        if [[ "$1" == pr && "$2" == checks && "$*" == *--json* ]]; then printf '1\n'; return; fi
        if [[ "$1" == pr && "$2" == checks ]]; then
          index=$(< "${GH_FIXTURE_COUNTER}")
          if [[ "${index}" == 1 ]]; then return 8; fi
          return
        fi
        if [[ "$1" == pr && "$2" == view ]]; then
          index=$(< "${GH_FIXTURE_COUNTER}")
          printf '%s\n' "$((index + 1))" > "${GH_FIXTURE_COUNTER}"
          cat "${GH_FIXTURE_DIR}/${index}.json"
          return
        fi
        return 1
      }
    STUB
    counter = @root.join('counter')
    counter.write("0\n")
    %w[BLOCKED BLOCKED CLEAN].each_with_index do |state, index|
      @root.join("#{index}.json").write(JSON.generate(headRefOid: 'validated-head', mergeStateStatus: state))
    end
    result = shell(stub + wait, bash: '/bin/bash', env: { 'GH_FIXTURE_COUNTER' => counter.to_s, 'GH_FIXTURE_DIR' => @root.to_s, 'PR_NUMBER' => '159', 'HEAD_SHA' => 'validated-head' })
    assert_success result
    assert_equal '3', counter.read.strip
    assert_equal 2, result.stdout.scan('merge state: BLOCKED').length
    assert_includes result.stdout, 'merge state: CLEAN'
  end
end

class CaskDCOTests < ToolingTest
  def setup
    super
    @root = @root.realpath
    @tap = @root.join('tap checkout').tap(&:mkpath)
    @runner = @root.join('runner temp').tap(&:mkpath)
    @bin = @root.join('bin').tap(&:mkpath)
    @env = ENV.keys.grep(/^GIT_/).to_h { |key| [key, nil] }.merge(
      'GIT_CONFIG_GLOBAL' => File::NULL, 'GIT_CONFIG_SYSTEM' => File::NULL, 'GIT_TERMINAL_PROMPT' => '0',
      'GIT_AUTHOR_NAME' => 'Fixture Author', 'GIT_AUTHOR_EMAIL' => 'author@example.test',
      'PATH' => "#{@bin}#{File::PATH_SEPARATOR}#{ENV.fetch('PATH')}", 'RUNNER_TEMP' => @runner.to_s,
      'TAP_ROOT' => @tap.to_s, 'APP_SLUG' => 'fixture-bot', 'VERSION' => '1.2.3'
    )
    git('init', '-q')
    git('config', 'user.name', 'Fixture Committer')
    git('config', 'user.email', 'committer@example.test')
    git('config', 'core.hooksPath', '.githooks')
    @hooks = @tap.join('.githooks').tap(&:mkpath)
    executable(@hooks.join('commit-msg'), ROOT.join('.githooks/commit-msg').read)
    executable(@hooks.join('pre-push'), "#!/bin/sh\nexit 1\n")
    executable(@bin.join('gh'), "#!/bin/sh\nif [ \"$1\" = api ]; then printf '42\\n'; fi\n")
    executable(@bin.join('brew'), <<~'STUB')
      #!/bin/sh
      set -eu
      case "$1" in
        --repo) printf '%s\n' "$TAP_ROOT" ;;
        tap|trust) ;;
        bump-cask-pr)
          if [ "${REPLACE_HOOK:-0}" = 1 ]; then
            rm "$TAP_ROOT/.githooks/prepare-commit-msg"
            ln -s "$TAP_ROOT/keep-this-link" "$TAP_ROOT/.githooks/prepare-commit-msg"
            exit 9
          fi
          [ "${FAIL_BREW:-0}" = 0 ] || exit 9
          printf 'update\n' >> "$TAP_ROOT/cask.rb"
          git -C "$TAP_ROOT" add cask.rb
          message='pinprick 1.2.3'
          if [ "${EXISTING_SIGNOFF:-0}" = 1 ]; then
            message="$(printf '%s\n\nSigned-off-by: Fixture Author <author@example.test>\n' "$message")"
          fi
          git -C "$TAP_ROOT" -c commit.gpgSign=false commit --no-edit --verbose --message="$message" -- cask.rb
          ;;
        *) exit 8 ;;
      esac
    STUB
    @script = workflow_step('release.yml', 'Bump Homebrew cask')
  end

  def git(*args)
    result = command(['git', '-C', @tap, *args], env: @env)
    assert_success result
    result.stdout.strip
  end

  def run_bump = shell(@script, cwd: @root, env: @env, bash: '/bin/bash')

  def assert_cleaned
    refute @hooks.join('prepare-commit-msg').symlink?
    assert_empty @runner.children
    assert_equal '.githooks', git('config', '--local', 'core.hooksPath')
  end

  def test_actual_author_signed_once_and_hooks_preserved
    original = @hooks.join('commit-msg').binread
    %w[0 1].each do |duplicate|
      @env['EXISTING_SIGNOFF'] = duplicate
      assert_success run_bump
      message = git('log', '-1', '--format=%B')
      author = git('log', '-1', '--format=%an <%ae>')
      assert_equal 'pinprick 1.2.3', message.lines.first.strip
      assert_equal 1, message.scan('Signed-off-by:').length
      assert_includes message, 'Signed-off-by: ' + author
      refute_equal author, git('log', '-1', '--format=%cn <%ce>')
      assert_equal original, @hooks.join('commit-msg').binread
      assert_equal "#!/bin/sh\nexit 1\n", @hooks.join('pre-push').read
      assert_cleaned
    end
  end

  def test_existing_validator_still_blocks_commit
    executable(@hooks.join('commit-msg'), "#!/bin/sh\nexit 1\n")
    refute_equal 0, run_bump.returncode
    assert_cleaned
  end

  def test_failure_cleans_hook_for_retry
    @env['FAIL_BREW'] = '1'
    assert_equal 9, run_bump.returncode
    assert_cleaned
    @env['FAIL_BREW'] = '0'
    assert_success run_bump
    assert_cleaned
  end

  def test_existing_prepare_hook_is_preserved
    prepare = @hooks.join('prepare-commit-msg')
    executable(prepare, "#!/bin/sh\nexit 0\n")
    before = prepare.binread
    result = run_bump
    refute_equal 0, result.returncode
    assert_includes result.stdout, 'existing prepare-commit-msg'
    assert_equal before, prepare.binread
    assert_empty @runner.children
  end

  def test_external_hook_directory_is_not_modified
    external = @root.join('outside hooks').tap(&:mkpath)
    link = @tap.join('outside-link')
    link.make_symlink(external)
    [external, link].each do |location|
      git('config', 'core.hooksPath', location)
      result = run_bump
      refute_equal 0, result.returncode
      assert_includes result.stdout, 'outside the fresh checkout'
      assert_empty external.children
      assert_empty @runner.children
    end
  end

  def test_inherited_global_hook_directory_is_not_modified
    external = @root.join('global hooks').tap(&:mkpath)
    global = @root.join('gitconfig')
    @env['GIT_CONFIG_GLOBAL'] = global.to_s
    git('config', '--global', 'core.hooksPath', external)
    git('config', '--local', '--unset', 'core.hooksPath')
    before = global.binread
    refute_equal 0, run_bump.returncode
    assert_equal before, global.binread
    assert_empty external.children
    assert_empty @runner.children
  end

  def test_cleanup_preserves_substituted_link
    @env['REPLACE_HOOK'] = '1'
    assert_equal 9, run_bump.returncode
    assert_equal @tap.join('keep-this-link').to_s, @hooks.join('prepare-commit-msg').readlink.to_s
    assert_empty @runner.children
  end

  def test_hook_helpers_do_not_inherit_github_or_homebrew_tokens
    @env.merge!('GH_TOKEN' => 'fixture-gh', 'GITHUB_TOKEN' => 'fixture-github', 'HOMEBREW_GITHUB_API_TOKEN' => 'fixture-brew')
    executable(@bin.join('ruby'), <<~SH)
      #!/bin/sh
      test -z "${GH_TOKEN+x}" && test -z "${GITHUB_TOKEN+x}" && test -z "${HOMEBREW_GITHUB_API_TOKEN+x}" || exit 99
      printf 'called\n' >> #{Shellwords.escape(@root.join('ruby-calls').to_s)}
      exec #{Shellwords.escape(RUBY)} "$@"
    SH
    assert_success run_bump
    assert_equal 2, @root.join('ruby-calls').read.lines.length
    assert_cleaned
  end
end
