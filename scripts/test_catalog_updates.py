"""Exercise catalog producers and CI with local release and scanner fixtures."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_release_tools import ROOT, just_recipe, workflow_step


class CatalogUpdateTests(unittest.TestCase):
    def setUp(self):
        self.bash = shutil.which('bash')
        version = subprocess.check_output(
            [self.bash, '-c', 'echo "$BASH_VERSION"'], text=True,
        )
        if int(version.split('.')[0]) < 4:
            self.skipTest('catalog workflow requires Bash 4+')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in ('bin', 'scripts', 'target/debug', 'scratch', 'audited-actions/example'):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / 'scripts/audited-actions.jq', self.root / 'scripts')
        self.catalog = self.root / 'audited-actions/example/action.json'
        self.catalog.write_text('[]\n')
        self.sha = 'cd2ce8fcbc39b97be8ca5fce6e763baed58fa128'
        self.new_sha = '1e34f2e2acaa766b7efacb8c26352e6abbb023f9'
        self.releases = []
        self.refs = {}
        self.env = dict(
            os.environ, PATH=f'{self.root / "bin"}{os.pathsep}{os.environ["PATH"]}',
            TMPDIR=str(self.root / 'scratch'), INPUT_ACTION='', INPUT_REF='',
            GITHUB_OUTPUT=str(self.root / 'output'),
        )
        self.executable('bin/gh', '''#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import sys
args = sys.argv[1:]
assert args[0] == 'api', args
endpoint = args[1]
fixture = json.loads(Path('fixture.json').read_text())
with Path('api-calls').open('a') as output:
    print(endpoint, file=output)
if endpoint.endswith('/releases/latest'):
    value = fixture['releases'][0]
elif '/releases?' in endpoint:
    value = fixture['releases']
elif '/git/ref/tags/' in endpoint:
    tag = endpoint.split('/git/ref/tags/', 1)[1]
    value = {'object': {'sha': fixture['refs'][tag], 'type': 'commit'}}
elif '/commits/' in endpoint:
    value = {'sha': fixture['refs'][endpoint.split('/commits/', 1)[1]]}
else:
    raise AssertionError(endpoint)
subprocess.run(['jq', '-r', args[args.index('--jq') + 1]],
               input=json.dumps(value), text=True, check=True)
''')
        scanner = '''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
assert '--no-repo-config' in args and '--no-audited-catalog' in args
assert os.environ['XDG_CONFIG_HOME'] == args[-1] + '/config'
workflow = Path(args[-1], '.github/workflows/test.yml').read_text()
with Path('scans').open('a') as output:
    print(workflow.split('uses: ', 1)[1].strip(), file=output)
report = {'scanned_fresh': 1, 'rules_version': 7,
          'coverage_complete': True, 'ignored': 0}
report.update(json.loads(os.environ.get('AUDIT_REPORT_OVERRIDES', '{}')))
print(json.dumps(report))
sys.exit(int(os.environ.get('FIXTURE_AUDIT_STATUS', '0')))
'''
        self.executable('target/debug/pinprick', scanner)
        self.executable('bin/cargo', scanner)
        self.executable('bin/mktemp', '''#!/usr/bin/env python3
import os
import tempfile
print(tempfile.mkdtemp(dir=os.environ['TMPDIR']))
''')

    def executable(self, path, content):
        file = self.root / path
        file.write_text(content)
        file.chmod(0o755)

    def release(self, tag, sha=None):
        self.refs[tag] = sha or self.sha
        self.releases.append(dict(tag_name=tag, draft=False, prerelease=False))

    def entry(self, tag, sha=None, rules=1):
        return dict(sha=sha or self.sha, tag=tag, rules_version=rules)

    def run_command(self, command, **env):
        (self.root / 'fixture.json').write_text(json.dumps(
            dict(releases=self.releases, refs=self.refs),
        ))
        return subprocess.run(
            command, cwd=self.root, env=dict(self.env, **env),
            capture_output=True, text=True, timeout=20,
        )

    def scan(self, **env):
        return self.run_command(
            [self.bash, '-euo', 'pipefail', '-c',
             workflow_step('audit-actions.yml', 'Scan for new releases')], **env,
        )

    def add_action(self, **env):
        return self.run_command([
            self.bash, '-euo', 'pipefail', '-c', just_recipe('add-action action_key'),
            'add-action', 'example/action',
        ], **env)

    def validate(self):
        return self.run_command([
            self.bash, '-euo', 'pipefail', '-c',
            workflow_step('ci.yml', 'Check catalog format and sort order'),
        ])

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(list((self.root / 'scratch').iterdir()), [])

    def test_scheduled_scan_keeps_full_labels_and_adds_new_commits(self):
        self.catalog.write_text(json.dumps([self.entry('v5.0.0')]))
        for tag in ('v5', 'v5.0', 'v3.0.2-node.24'):
            self.release(tag)
        self.release('2026.09.13.1', self.new_sha)
        self.assert_success(self.scan())
        self.assertEqual(json.loads(self.catalog.read_text()), [
            self.entry('2026.09.13.1', self.new_sha, 7),
            self.entry('v5.0.0', rules=7),
        ])
        scans = (self.root / 'scans').read_text().splitlines()
        self.assertEqual(len(scans), 2)
        self.assertIn('# v3.0.2-node.24', scans[0])
        self.assertEqual((self.root / 'output').read_text().splitlines()[-1], 'updated=1')
        self.assert_success(self.validate())
        before = self.catalog.read_bytes()
        self.assert_success(self.scan())
        self.assertEqual(self.catalog.read_bytes(), before)
        self.assertEqual((self.root / 'output').read_text().splitlines()[-1], 'updated=0')

    def test_noop_after_a_changed_entry_keeps_updated_output(self):
        self.catalog.write_text(json.dumps([self.entry('v5.0.0', rules=7)]))
        self.release('2026.09.13.1', self.new_sha)
        self.release('v3.0.2-node.24')
        self.assert_success(self.scan())
        self.assertEqual((self.root / 'output').read_text().splitlines()[-1], 'updated=1')
        self.assertEqual(json.loads(self.catalog.read_text()), [
            self.entry('2026.09.13.1', self.new_sha, 7),
            self.entry('v5.0.0', rules=7),
        ])

    def test_all_sliding_relabels_from_pr_597_are_ignored_without_scanning(self):
        for original, alias in [
            ('v8.0.0', 'v8'), ('v3.0.0', 'v3'), ('v2.1.13', 'v2'),
            ('v3.0.1', 'v3'), ('v2.2.1', 'v2'),
        ]:
            with self.subTest(original=original, alias=alias):
                self.catalog.write_text(json.dumps([self.entry(original)]))
                before = self.catalog.read_bytes()
                self.releases = []
                self.release(alias)
                self.assert_success(self.scan())
                self.assertEqual(self.catalog.read_bytes(), before)
                self.assertFalse((self.root / 'scans').exists())
                self.assertEqual((self.root / 'output').read_text().splitlines()[-1], 'updated=0')
        self.assertNotIn('/git/ref/', (self.root / 'api-calls').read_text())

    def test_manual_add_preserves_label_while_restamping(self):
        self.catalog.write_text(json.dumps([self.entry('v5.0.0')]))
        self.release('v3.0.2-node.24')
        self.assert_success(self.add_action())
        self.assertEqual(json.loads(self.catalog.read_text()), [self.entry('v5.0.0', rules=7)])

    def test_manual_add_rejects_sliding_latest_release(self):
        self.release('v5')
        before = self.catalog.read_bytes()
        result = self.add_action()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('unsupported release tag', result.stderr)
        self.assertEqual(self.catalog.read_bytes(), before)
        self.assertFalse((self.root / 'scans').exists())

    def test_nonclean_reaudits_preserve_existing_verdict(self):
        self.release('v3.0.2-node.24')
        for producer in (self.scan, self.add_action):
            for status, overrides in [
                (1, {'findings': [{'description': 'unpinned runtime fetch'}]}),
                (0, {'coverage_complete': False}),
                (0, {'scanned_fresh': 0}),
                (0, {'ignored': 1}),
                (2, {}),
            ]:
                with self.subTest(producer=producer.__name__, status=status, overrides=overrides):
                    self.catalog.write_text(json.dumps([self.entry('v5.0.0')]))
                    before = self.catalog.read_bytes()
                    result = producer(
                        FIXTURE_AUDIT_STATUS=str(status), AUDIT_REPORT_OVERRIDES=json.dumps(overrides),
                    )
                    if producer == self.scan:
                        self.assert_success(result)
                        self.assertEqual(
                            (self.root / 'output').read_text().splitlines()[-1], 'updated=0',
                        )
                    else:
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(self.catalog.read_bytes(), before)
                    self.assertEqual(list((self.root / 'scratch').iterdir()), [])

    def test_dispatch_rejects_sliding_tags_and_accepts_explicit_sha(self):
        self.release('v5')
        self.assert_success(self.scan(INPUT_ACTION='example/action', INPUT_REF='v5'))
        self.assertFalse((self.root / 'scans').exists())
        for ref in (self.sha[:7], self.sha):
            with self.subTest(ref=ref):
                self.catalog.write_text('[]\n')
                self.refs[ref] = self.sha
                self.assert_success(self.scan(INPUT_ACTION='example/action', INPUT_REF=ref))
                self.assertEqual(
                    json.loads(self.catalog.read_text()),
                    [self.entry('sha:' + self.sha[:7], rules=7)],
                )
                self.assert_success(self.validate())

    def test_ci_rejects_sliding_and_malformed_labels(self):
        for tag in ('v8', 'v2.1', '8', '2.1', 'latest', 'v1.2.3\n',
                    'v1.2.3-', 'v1.2.3+bad..suffix', 'sha:1234567', None):
            with self.subTest(tag=tag):
                self.catalog.write_text(json.dumps([self.entry(tag)]))
                result = self.validate()
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ci_accepts_full_release_labels(self):
        for tag in ('v1.2.3', '1.2.3', '2026.09.13.1',
                    'v3.0.2-node.24', 'v1.2.3-rc.1+build.2'):
            with self.subTest(tag=tag):
                self.catalog.write_text(json.dumps([self.entry(tag)]))
                self.assert_success(self.validate())

    def test_draft_and_prerelease_flags_are_still_excluded(self):
        self.releases = [
            dict(tag_name='v1.0.0', draft=True, prerelease=False),
            dict(tag_name='v2.0.0', draft=False, prerelease=True),
        ]
        self.assert_success(self.scan())
        self.assertFalse((self.root / 'scans').exists())

    def test_missing_tag_policy_fails_the_scan(self):
        self.release('v1.0.0')
        (self.root / 'scripts/audited-actions.jq').unlink()
        result = self.scan()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / 'scans').exists())

    def test_checked_in_catalog_passes_validation(self):
        result = subprocess.run(
            [self.bash, '-euo', 'pipefail', '-c',
             workflow_step('ci.yml', 'Check catalog format and sort order')],
            cwd=ROOT, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
