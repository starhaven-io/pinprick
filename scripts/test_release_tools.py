#!/usr/bin/env python3
"""Exercise workflow shell steps with local command stubs only."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def workflow_step(workflow: str, name: str) -> str:
    content = (ROOT / '.github/workflows' / workflow).read_text()
    step = content.split(f'      - name: {name}\n', 1)[1]
    step = step.split('\n      - ', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1].split('\n        id:', 1)[0])


class ReleaseToolsTests(unittest.TestCase):
    def test_distinct_release_and_catalog_requests_are_retained(self):
        for name, group in [('release.yml', 'release'), ('audit-actions.yml', 'audit-actions')]:
            workflow = (ROOT / '.github/workflows' / name).read_text()
            concurrency = workflow.split('concurrency:\n', 1)[1].split('\n\n', 1)[0]
            self.assertEqual(dict(line.strip().split(': ', 1) for line in concurrency.splitlines()), {
                'group': group, 'cancel-in-progress': 'false', 'queue': 'max',
            })

    def test_rejected_site_dispatch_cannot_cancel_main_deployment(self):
        workflow = (ROOT / '.github/workflows/deploy-site.yml').read_text()
        self.assertIn(
            "group: ${{ github.ref == 'refs/heads/main' && 'deploy-site' "
            "|| format('rejected-deploy-{0}', github.run_id) }}",
            workflow,
        )
        push = workflow.split('  schedule:', 1)[0]
        for path in ['.github/workflows/deploy-site.yml', 'scripts/check-npm-install-policy.mjs']:
            self.assertIn(f'      - "{path}"', push)

    def test_site_deploy_preserves_signed_output_and_uses_locked_tool(self):
        deploy = (ROOT / '.github/workflows/deploy-site.yml').read_text().split('\n  deploy:\n', 1)[1]
        setup, publish = deploy.split('      - name: Deploy signed site to Cloudflare Workers\n', 1)
        self.assertIn('    needs: sign\n', setup)
        self.assertIn("    if: github.ref == 'refs/heads/main'\n", setup)
        self.assertIn('run: node scripts/check-npm-install-policy.mjs site', setup)
        self.assertLess(setup.index('run: npm ci --strict-allow-scripts'), setup.index('name: signed-site'))
        self.assertNotIn('CLOUDFLARE_API_TOKEN', setup)
        self.assertNotIn('CATALOG_SIGNING_KEY', deploy)
        self.assertNotIn('npm run build', deploy)
        self.assertIn('        working-directory: site\n', publish)
        self.assertIn('CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}', publish)
        self.assertIn('CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}', publish)

        with tempfile.TemporaryDirectory() as temp:
            site = Path(temp)
            tool = site / 'node_modules/.bin/wrangler'
            tool.parent.mkdir(parents=True)
            tool.write_text('#!/bin/sh\nset -eu\n'
                            '[ "$#" = 3 ] && [ "$1" = deploy ] && [ "$2" = --config ] && [ "$3" = wrangler.jsonc ]\n'
                            '[ "$CLOUDFLARE_API_TOKEN" = fixture-token ]\n'
                            'printf deployed > invocation\n')
            tool.chmod(0o755)
            (site / 'package.json').write_text(json.dumps({'scripts': {
                'predeploy': 'exit 97', 'deploy': 'exit 98', 'postdeploy': 'exit 99',
            }}))
            signed = site / 'dist/client/catalog.json.minisig'
            signed.parent.mkdir(parents=True)
            signed.write_bytes(b'signed fixture bytes\n')
            result = subprocess.run(
                ['bash', '-euo', 'pipefail', '-c', workflow_step('deploy-site.yml', 'Deploy signed site to Cloudflare Workers')],
                cwd=site, env=dict(os.environ, CLOUDFLARE_API_TOKEN='fixture-token'),
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((site / 'invocation').read_text(), 'deployed')
            self.assertEqual(signed.read_bytes(), b'signed fixture bytes\n')

    def test_breaking_changes_survive_internal_change_filter(self):
        spec = importlib.util.spec_from_file_location('notes', ROOT / 'scripts/format-release-notes.py')
        notes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notes)
        sections, _ = notes.parse_notes(
            '* feat!: new report schema by @author in https://example.com/1\n'
            '* build(runtime)!: require a newer runtime by @author in https://example.com/2\n'
            '* fix(cli): preserve details by @author in https://example.com/3\n'
            '* chore: refresh tooling by @author in https://example.com/4\n'
        )
        self.assertEqual(sections, {
            'Breaking Changes': ['new report schema', 'require a newer runtime'],
            'Fixes': ['preserve details'],
        })
        rendered = notes.format_markdown('v1.0.0', sections, None)
        self.assertLess(rendered.index('Breaking Changes'), rendered.index('Fixes'))

    def test_notarization_requirement_and_bounded_retry(self):
        script = '''set -euo pipefail
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
''' + workflow_step('release.yml', 'Notarize binary') + '\nprintf "verified:%s\\n" "$count"\n'
        for submit, status, failures, expected, attempts in [
            (0, 0, 0, 0, 1), (0, 3, 2, 0, 3), (0, 3, 3, 3, None),
            (0, 1, 1, 1, None), (5, 0, 0, 5, None),
        ]:
            with self.subTest(submit=submit, status=status, failures=failures):
                env = dict(os.environ, TARGET='test', RUNNER_TEMP='/unused', APPLE_ID='test',
                           NOTARIZATION_PASSWORD='test', DEVELOPMENT_TEAM='test',
                           SUBMIT_STATUS=str(submit), VERIFY_STATUS=str(status), FAILURES=str(failures))
                result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
                if attempts:
                    self.assertIn(f'verified:{attempts}', result.stdout)
                else:
                    self.assertNotIn('verified:', result.stdout)

    def test_catalog_scan_keeps_exported_tmpdir_and_requires_fresh_coverage(self):
        bash = shutil.which('bash')
        version = subprocess.check_output([bash, '-c', 'echo "${BASH_VERSINFO[0]}"'], text=True)
        if int(version) < 4:
            self.skipTest('catalog workflow requires Bash 4+ (provided by its Linux runner)')
        self.assertIsNotNone(shutil.which('jq'), 'jq is required for catalog workflow tests')
        for fresh, expected_entries in [(1, 2), (0, 0)]:
            with self.subTest(fresh=fresh), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / 'bin').mkdir()
                (root / 'scratch').mkdir()
                (root / 'target/debug').mkdir(parents=True)
                (root / 'bin/gh').write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$2" in
  */releases*) printf 'v1.0.0\\nv2.0.0\\n' ;;
  */git/ref/tags/*)
    if [[ "$4" == '.object.type' ]]; then echo commit
    elif [[ "$2" == */v1.0.0 ]]; then printf '%040d\\n' 1
    else printf '%040d\\n' 2; fi ;;
  *) exit 9 ;;
esac
''')
                # BSD mktemp ignores TMPDIR without a template; model the Linux runner's
                # TMPDIR behavior explicitly while keeping all writes in this test directory.
                if sys.platform == 'darwin':
                    (root / 'bin/mktemp').write_text('#!/usr/bin/env bash\nexec /usr/bin/mktemp -d "$TMPDIR/scan.XXXXXXXX"\n')
                    (root / 'bin/mktemp').chmod(0o755)
                (root / 'target/debug/pinprick').write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *"--no-repo-config --no-audited-catalog"* ]]
[[ "$XDG_CONFIG_HOME" == "${@: -1}/config" ]]
printf '{"scanned_fresh":%s,"rules_version":7,"coverage_complete":true,"ignored":0}\\n' "$FRESH"
''')
                for executable in [root / 'bin/gh', root / 'target/debug/pinprick']:
                    executable.chmod(0o755)
                env = dict(os.environ, PATH=f'{root / "bin"}{os.pathsep}{os.environ["PATH"]}',
                           TMPDIR=str(root / 'scratch'), INPUT_ACTION='example/action', INPUT_REF='',
                           GITHUB_OUTPUT=str(root / 'output'), FRESH=str(fresh))
                result = subprocess.run([bash, '-euo', 'pipefail', '-c', workflow_step('audit-actions.yml', 'Scan for new releases')],
                                        cwd=root, env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                entries = json.loads((root / 'audited-actions/example/action.json').read_text())
                self.assertEqual(len(entries), expected_entries)
                if entries:
                    self.assertTrue(all(entry['rules_version'] == 7 for entry in entries))
                self.assertEqual(list((root / 'scratch').iterdir()), [])

    def test_add_action_restamp_preserves_canonical_version_order(self):
        just = shutil.which('just')
        if just is None:
            self.skipTest('just is required to exercise the add-action recipe')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary_dir = root / 'bin'
            binary_dir.mkdir()
            scratch = root / 'scratch'
            scratch.mkdir()
            catalog = root / 'audited-actions/example/action.json'
            catalog.parent.mkdir(parents=True)
            catalog.write_text(json.dumps([
                {'sha': ('0' * 39) + '3', 'tag': 'v3.0.0', 'rules_version': 1},
                {'sha': ('0' * 39) + '2', 'tag': 'v2.0.0', 'rules_version': 1},
            ]))
            (binary_dir / 'gh').write_text('''#!/usr/bin/env bash
set -euo pipefail
case "$2:$4" in
  */releases/latest:.tag_name) printf 'v2.0.0\n' ;;
  */git/ref/tags/v2.0.0:.object.sha) printf '%040d\n' 2 ;;
  */git/ref/tags/v2.0.0:.object.type) printf 'commit\n' ;;
  *) exit 9 ;;
esac
''')
            (binary_dir / 'cargo').write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *"--json audit --no-repo-config --no-audited-catalog"* ]]
printf '%s\n' '{"scanned_fresh":1,"rules_version":1,"coverage_complete":true,"ignored":0}'
''')
            if sys.platform == 'darwin':
                (binary_dir / 'mktemp').write_text(
                    '#!/usr/bin/env bash\nexec /usr/bin/mktemp -d "$TMPDIR/scan.XXXXXXXX"\n'
                )
            for executable in (binary_dir / 'gh', binary_dir / 'cargo'):
                executable.chmod(0o755)
            if sys.platform == 'darwin':
                (binary_dir / 'mktemp').chmod(0o755)

            result = subprocess.run(
                [just, '--justfile', str(ROOT / 'justfile'), '--working-directory',
                 str(root), 'add-action', 'example/action'],
                cwd=root,
                env=dict(
                    os.environ,
                    PATH=f'{binary_dir}{os.pathsep}{os.environ["PATH"]}',
                    TMPDIR=str(scratch),
                ),
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            entries = json.loads(catalog.read_text())
            self.assertEqual([entry['tag'] for entry in entries], ['v3.0.0', 'v2.0.0'])
            self.assertTrue(all(list(entry) == ['sha', 'tag', 'rules_version'] for entry in entries))


class CaskMergeProtocolTests(unittest.TestCase):
    def test_merge_is_bounded_synchronous_and_exact_head_bound(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        resolve = workflow_step('release.yml', 'Resolve Homebrew cask bump')
        wait = workflow_step('release.yml', 'Wait for checks on the validated head')
        revalidate = workflow_step('release.yml', 'Revalidate and merge the exact head')
        merge_job = workflow.split('\n  merge-cask-bump:\n', 1)[1]

        self.assertIn('if [[ "${MATCH_COUNT}" != 1 ]]', resolve)
        self.assertIn('.user.login == $bot', resolve)
        self.assertIn('.changed_files == 1', resolve)
        self.assertIn('echo "base_sha=', resolve)
        self.assertIn('echo "head_sha=', resolve)
        self.assertNotIn('gh pr merge', resolve)
        self.assertIn('CHECK_TIMEOUT_SECONDS=1500', wait)
        self.assertIn('8) CHECK_SUMMARY=pending', wait)
        self.assertIn('mergeStateStatus', wait)
        self.assertIn('CHECK_STATUS == 0', wait)
        self.assertIn('[[ "${MERGE_STATE}" == "CLEAN" || "${MERGE_STATE}" == "UNSTABLE" ]]', wait)
        self.assertNotIn('--watch', wait)
        self.assertNotIn('--fail-fast', wait)
        self.assertLess(merge_job.index('Wait for checks on the validated head'),
                        merge_job.index('Mint bot token for tap'))
        self.assertIn('.base.sha == $base_sha', revalidate)
        self.assertIn('.head.sha == $head', revalidate)
        self.assertIn('.[0].filename == $cask', revalidate)
        self.assertIn('--match-head-commit "${HEAD_SHA}"', revalidate)
        self.assertNotIn('--auto', merge_job)

    def test_partial_required_check_registration_stays_blocked(self):
        wait = workflow_step('release.yml', 'Wait for checks on the validated head')
        wait = wait.replace('CHECK_INTERVAL_SECONDS=10', 'CHECK_INTERVAL_SECONDS=0')
        stub = r'''
        gh() {
          if [[ "$1" == api ]]; then printf '%s\n' validated-head; return; fi
          if [[ "$1" == pr && "$2" == checks && "$*" == *--json* ]]; then
            printf '1\n'; return
          fi
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
        '''
        fixtures = [
            {'headRefOid': 'validated-head', 'mergeStateStatus': 'BLOCKED'},
            {'headRefOid': 'validated-head', 'mergeStateStatus': 'BLOCKED'},
            {'headRefOid': 'validated-head', 'mergeStateStatus': 'CLEAN'},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            counter = path / 'counter'
            counter.write_text('0\n')
            for index, fixture in enumerate(fixtures):
                (path / f'{index}.json').write_text(json.dumps(fixture))
            result = subprocess.run(
                ['/bin/bash', '-euo', 'pipefail', '-c', stub + wait],
                env={
                    **os.environ,
                    'GH_FIXTURE_COUNTER': str(counter),
                    'GH_FIXTURE_DIR': str(path),
                    'PR_NUMBER': '159',
                    'HEAD_SHA': 'validated-head',
                },
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(counter.read_text().strip(), '3')
        self.assertEqual(result.stdout.count('merge state: BLOCKED'), 2)
        self.assertIn('merge state: CLEAN', result.stdout)


class CaskDCOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.tap = self.root / "tap checkout"
        self.runner = self.root / "runner temp"
        self.bin = self.root / "bin"
        for directory in (self.tap, self.runner, self.bin):
            directory.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Fixture Author",
            "GIT_AUTHOR_EMAIL": "author@example.test",
            "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
            "RUNNER_TEMP": str(self.runner),
            "TAP_ROOT": str(self.tap),
            "APP_SLUG": "fixture-bot",
            "VERSION": "1.2.3",
        })
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture Committer")
        self.git("config", "user.email", "committer@example.test")
        self.git("config", "core.hooksPath", ".githooks")
        self.hooks = self.tap / ".githooks"
        self.hooks.mkdir()
        self.write_executable(self.hooks / "commit-msg", (ROOT / ".githooks/commit-msg").read_text())
        self.write_executable(self.hooks / "pre-push", "#!/bin/sh\nexit 1\n")
        self.write_executable(self.bin / "gh", '#!/bin/sh\nif [ "$1" = api ]; then printf "42\\n"; fi\n')
        self.write_executable(self.bin / "brew", '''#!/bin/sh
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
''')
        self.script = workflow_step('release.yml', 'Bump Homebrew cask')

    @staticmethod
    def write_executable(path, contents):
        path.write_text(contents)
        path.chmod(0o755)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.tap), *args], env=self.env, text=True).strip()

    def run_bump(self):
        return subprocess.run(
            ["/bin/bash", "-eu", "-o", "pipefail", "-c", self.script],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=20,
        )

    def assert_cleaned(self):
        self.assertFalse((self.hooks / "prepare-commit-msg").is_symlink())
        self.assertEqual(list(self.runner.iterdir()), [])
        self.assertEqual(self.git("config", "--local", "core.hooksPath"), ".githooks")

    def test_actual_author_is_signed_once_and_existing_hooks_are_preserved(self):
        original = (self.hooks / "commit-msg").read_bytes()
        for duplicate in ("0", "1"):
            self.env["EXISTING_SIGNOFF"] = duplicate
            result = self.run_bump()
            self.assertEqual(result.returncode, 0, result.stderr)
            message = self.git("log", "-1", "--format=%B")
            author = self.git("log", "-1", "--format=%an <%ae>")
            self.assertEqual(message.splitlines()[0], "pinprick 1.2.3")
            self.assertEqual(message.count("Signed-off-by:"), 1)
            self.assertIn("Signed-off-by: " + author, message)
            self.assertNotEqual(author, self.git("log", "-1", "--format=%cn <%ce>"))
            self.assertEqual((self.hooks / "commit-msg").read_bytes(), original)
            self.assertEqual((self.hooks / "pre-push").read_text(), "#!/bin/sh\nexit 1\n")
            self.assert_cleaned()

    def test_existing_validator_still_blocks_commit(self):
        self.write_executable(self.hooks / "commit-msg", "#!/bin/sh\nexit 1\n")
        self.assertNotEqual(self.run_bump().returncode, 0)
        self.assert_cleaned()

    def test_failure_cleans_hook_for_retry(self):
        self.env["FAIL_BREW"] = "1"
        self.assertEqual(self.run_bump().returncode, 9)
        self.assert_cleaned()
        self.env["FAIL_BREW"] = "0"
        self.assertEqual(self.run_bump().returncode, 0)
        self.assert_cleaned()

    def test_existing_prepare_hook_is_preserved(self):
        prepare = self.hooks / "prepare-commit-msg"
        self.write_executable(prepare, "#!/bin/sh\nexit 0\n")
        before = prepare.read_bytes()
        result = self.run_bump()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing prepare-commit-msg", result.stdout)
        self.assertEqual(prepare.read_bytes(), before)
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_external_hook_directory_is_not_modified(self):
        external = self.root / "outside hooks"
        external.mkdir()
        link = self.tap / "outside-link"
        link.symlink_to(external, target_is_directory=True)
        for location in (external, link):
            self.git("config", "core.hooksPath", str(location))
            result = self.run_bump()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside the fresh checkout", result.stdout)
            self.assertEqual(list(external.iterdir()), [])
            self.assertEqual(list(self.runner.iterdir()), [])

    def test_inherited_global_hook_directory_is_not_modified(self):
        external = self.root / "global hooks"
        external.mkdir()
        global_config = self.root / "gitconfig"
        self.env["GIT_CONFIG_GLOBAL"] = str(global_config)
        self.git("config", "--global", "core.hooksPath", str(external))
        self.git("config", "--local", "--unset", "core.hooksPath")
        before = global_config.read_bytes()
        self.assertNotEqual(self.run_bump().returncode, 0)
        self.assertEqual(global_config.read_bytes(), before)
        self.assertEqual(list(external.iterdir()), [])
        self.assertEqual(list(self.runner.iterdir()), [])

    def test_cleanup_preserves_a_substituted_link(self):
        self.env["REPLACE_HOOK"] = "1"
        self.assertEqual(self.run_bump().returncode, 9)
        self.assertEqual(os.readlink(self.hooks / "prepare-commit-msg"), str(self.tap / "keep-this-link"))
        self.assertEqual(list(self.runner.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
