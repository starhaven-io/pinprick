#!/usr/bin/env python3
"""Exercise audited-action verification with local command stubs only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/verify-audited-actions.sh'


class VerifyAuditedActionsTests(unittest.TestCase):
    def setUp(self):
        self.bash = shutil.which('bash')
        version = subprocess.check_output(
            [self.bash, '-c', 'echo "${BASH_VERSINFO[0]}"'], text=True,
        )
        if int(version) < 4:
            self.skipTest('catalog verification requires Bash 4+ (provided by its Linux runner)')
        self.assertIsNotNone(shutil.which('jq'), 'jq is required for catalog verification tests')
        self.assertIsNotNone(shutil.which('python3'), 'Python is required for catalog verification tests')

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scratch = self.root / 'scratch'
        self.scratch.mkdir()
        catalog = self.root / 'audited-actions/example/action.json'
        catalog.parent.mkdir(parents=True)
        catalog.write_text(json.dumps([{
            'sha': '0123456789abcdef0123456789abcdef01234567',
            'tag': 'v1.2.3',
            'rules_version': 1,
        }]))
        self.pinprick = self.root / 'pinprick'
        self.pinprick.write_text('''#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == *"--json audit --no-repo-config --no-audited-catalog"* ]]
[[ "$XDG_CONFIG_HOME" == "${@: -1}/config" ]]
if [[ "${AUDIT_DUPLICATE_KEYS}" == "1" ]]; then
  printf '%s' '{"findings":[{"severity":"high","source_file":"dist/index.js","line":1,"description":"hidden"}],"findings":[],"scanned_fresh":1,"rules_version":1,"coverage_complete":true}'
elif [[ "${AUDIT_INVALID_UTF8}" == "1" ]]; then
  printf '%s' '{"findings":[],"scanned_fresh":1,"rules_version":1,"coverage_complete":true,"extra":"'
  printf '\\377'
  printf '%s' '"}'
else
  printf '%s' "$AUDIT_OUTPUT"
  if [[ "${AUDIT_TRAILING_NUL}" == "1" ]]; then printf '\\0'; fi
fi
exit "$AUDIT_STATUS"
''')
        self.pinprick.chmod(0o755)

    def verify(self, output, status, trailing_nul=False, invalid_utf8=False,
               duplicate_keys=False):
        env = dict(
            os.environ,
            AUDIT_OUTPUT=output,
            AUDIT_STATUS=str(status),
            AUDIT_TRAILING_NUL='1' if trailing_nul else '0',
            AUDIT_INVALID_UTF8='1' if invalid_utf8 else '0',
            AUDIT_DUPLICATE_KEYS='1' if duplicate_keys else '0',
            TMPDIR=str(self.scratch),
        )
        result = subprocess.run(
            [self.bash, str(SCRIPT), str(self.pinprick), 'files',
             'audited-actions/example/action.json'],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(list(self.scratch.iterdir()), [])
        return result

    @staticmethod
    def report(**overrides):
        report = {
            'findings': [],
            'scanned_fresh': 1,
            'rules_version': 1,
            'coverage_complete': True,
        }
        report.update(overrides)
        return json.dumps(report)

    def test_clean_fresh_report_passes(self):
        result = self.verify(self.report(), 0)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn('::error::', result.stdout)
        self.assertIn('Catalog entries inert under rules version 1: 0.', result.stdout)

    def test_files_mode_without_repository_catalog_does_not_read_stdin(self):
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir()
        catalog = self.root / 'audited-actions/example/action.json'
        process = subprocess.Popen(
            [self.bash, str(SCRIPT), str(self.pinprick), 'files', str(catalog)],
            cwd=elsewhere,
            env=dict(
                os.environ,
                AUDIT_OUTPUT=self.report(),
                AUDIT_STATUS='0',
                AUDIT_TRAILING_NUL='0',
                AUDIT_INVALID_UTF8='0',
                AUDIT_DUPLICATE_KEYS='0',
                TMPDIR=str(self.scratch),
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(process.wait(timeout=2), 0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            self.fail('verifier blocked reading stdin while counting an absent repository catalog')
        stdout, stderr = process.communicate()
        self.assertNotIn('Catalog entries inert', stdout)
        self.assertIn('Checked 1 catalog entries.', stdout)
        self.assertEqual(stderr, '')
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_report_rules_version_must_match_entry_stamp(self):
        result = self.verify(self.report(rules_version=2), 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('stamped with rules version 1, but the scanner reports 2', result.stdout)
        self.assertIn('Catalog entries inert under rules version 2: 1.', result.stdout)

    def test_missing_or_invalid_report_rules_version_is_malformed(self):
        for rules_version in (None, 0, 1.5, '1'):
            with self.subTest(rules_version=rules_version):
                report = json.loads(self.report())
                if rules_version is None:
                    del report['rules_version']
                else:
                    report['rules_version'] = rules_version
                result = self.verify(json.dumps(report), 0)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn('returned malformed audit output', result.stdout)

    def test_missing_entry_rules_version_is_rejected_before_scan(self):
        catalog = self.root / 'audited-actions/example/action.json'
        entry = json.loads(catalog.read_text())[0]
        del entry['rules_version']
        catalog.write_text(json.dumps([entry]))

        result = self.verify(self.report(), 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('invalid or unstamped catalog entry', result.stdout)
        self.assertIn('Checked 0 catalog entries.', result.stdout)

    def test_finding_report_fails_with_diagnostic(self):
        result = self.verify(self.report(findings=[{
            'severity': 'high',
            'source_file': 'dist/index.js',
            'line': 7,
            'description': 'runtime fetch',
        }]), 1)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('finding: high dist/index.js:7: runtime fetch', result.stdout)

    def test_incomplete_report_retains_findings_and_coverage(self):
        result = self.verify(self.report(
            findings=[{
                'severity': 'high',
                'source_file': 'dist/index.js',
                'line': None,
                'description': 'runtime fetch',
            }],
            scanned_fresh=0,
            coverage_complete=False,
            coverage_failures=['source traversal incomplete'],
        ), 2)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('finding: high dist/index.js: runtime fetch', result.stdout)
        self.assertIn('coverage: source traversal incomplete', result.stdout)

    def test_incomplete_only_report_fails_with_coverage(self):
        result = self.verify(self.report(
            scanned_fresh=0,
            coverage_complete=False,
            coverage_failures=['API request failed'],
        ), 2)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('coverage: API request failed', result.stdout)

    def test_report_without_exactly_one_fresh_scan_fails(self):
        for scanned_fresh in (0, 2):
            with self.subTest(scanned_fresh=scanned_fresh):
                result = self.verify(self.report(scanned_fresh=scanned_fresh), 0)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn('could not be scanned', result.stdout)

    def test_coverage_reasons_cannot_accompany_a_passing_report(self):
        result = self.verify(self.report(
            coverage_failures=['internally inconsistent coverage'],
        ), 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('coverage: internally inconsistent coverage', result.stdout)

    def test_diagnostics_cannot_inject_a_workflow_command(self):
        result = self.verify(self.report(
            findings=[{
                'severity': 'high',
                'source_file': 'dist/index.js',
                'line': 7,
                'description': 'runtime fetch\n::warning::injected',
            }],
        ), 1)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertNotIn('\n::warning::', result.stdout)
        self.assertIn('runtime fetch\ufffd::warning::injected', result.stdout)

    def test_diagnostics_match_terminal_control_and_bidi_sanitizer(self):
        c1 = '\u009b'
        bidi = '\u202e'
        result = self.verify(self.report(
            findings=[{
                'severity': 'high',
                'source_file': f'dist/{bidi}gpj.exe',
                'line': 7,
                'description': f'colored{c1}text',
            }],
            scanned_fresh=0,
            coverage_complete=False,
            coverage_failures=[f'path{c1}{bidi}failed'],
        ), 2)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertNotIn(c1, result.stdout)
        self.assertNotIn(bidi, result.stdout)
        self.assertGreaterEqual(result.stdout.count('\ufffd'), 4)

    def test_status_and_report_inconsistencies_are_explicit(self):
        finding = {
            'severity': 'high',
            'source_file': 'dist/index.js',
            'line': 7,
            'description': 'runtime fetch',
        }
        for report, status in ((self.report(findings=[finding]), 0), (self.report(), 1)):
            with self.subTest(status=status):
                result = self.verify(report, status)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn('returned an inconsistent audit status and report', result.stdout)

    def test_wrong_schema_is_rejected_without_echoing_output(self):
        result = self.verify('{"findings":"UNTRUSTED"}', 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)
        self.assertNotIn('UNTRUSTED', result.stdout)

    def test_false_or_null_coverage_failures_are_not_treated_as_absent(self):
        for invalid in (False, None):
            with self.subTest(invalid=invalid):
                result = self.verify(self.report(coverage_failures=invalid), 0)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn('returned malformed audit output', result.stdout)

    def test_non_string_coverage_failure_is_rejected(self):
        result = self.verify(self.report(coverage_failures=['valid', 7]), 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)

    def test_malformed_output_is_rejected_without_echoing_output(self):
        result = self.verify('UNTRUSTED not JSON', 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)
        self.assertNotIn('UNTRUSTED', result.stdout)

    def test_trailing_garbage_cannot_verify_a_valid_leading_report(self):
        result = self.verify(self.report() + '\nUNTRUSTED trailing output', 0)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)
        self.assertNotIn('UNTRUSTED', result.stdout)

    def test_trailing_nul_cannot_verify_a_valid_leading_report(self):
        result = self.verify(self.report(), 0, trailing_nul=True)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)

    def test_invalid_utf8_in_unused_field_cannot_verify_report(self):
        result = self.verify(self.report(), 0, invalid_utf8=True)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)

    def test_duplicate_key_cannot_hide_a_finding(self):
        result = self.verify(self.report(), 0, duplicate_keys=True)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn('returned malformed audit output', result.stdout)
        self.assertNotIn('hidden', result.stdout)

    def test_missing_normalizer_is_reported_as_verifier_failure(self):
        copied_dir = self.root / 'copied-scripts'
        copied_dir.mkdir()
        copied_script = copied_dir / SCRIPT.name
        shutil.copy2(SCRIPT, copied_script)
        result = subprocess.run(
            [self.bash, str(copied_script), str(self.pinprick), 'files',
             'audited-actions/example/action.json'],
            cwd=self.root, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn('verifier helper is missing or unreadable', result.stderr)
        self.assertNotIn('returned malformed audit output', result.stdout)

    def test_missing_binary_is_reported_as_verifier_failure(self):
        result = subprocess.run(
            [self.bash, str(SCRIPT), str(self.root / 'missing-pinprick'), 'files',
             'audited-actions/example/action.json'],
            cwd=self.root, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stderr + result.stdout)
        self.assertIn('verifier binary is missing or not executable', result.stderr)
        self.assertNotIn('returned malformed audit output', result.stdout)

    def test_diagnostics_cannot_inject_a_legacy_runner_command(self):
        # The legacy `##[...]` parser matches anywhere in a line, so the
        # two-space diagnostic prefix does not make it inert the way it does
        # for a modern `::` command.
        result = self.verify(self.report(findings=[{
            'severity': 'high',
            'source_file': 'dist/##[error]x.js',
            'line': 7,
            'description': 'runtime fetch ##[warning]injected',
        }]), 1)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertNotIn('##[', result.stdout)
        self.assertIn('## [error]x.js', result.stdout)

    def read_shard_state(self, body, count=4):
        path = self.root / 'issue-body.md'
        path.write_text(body) if isinstance(body, str) else path.write_bytes(body)
        result = subprocess.run(
            [self.bash, str(ROOT / 'scripts/read-shard-state.sh'), str(path), str(count)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.split()

    @staticmethod
    def state_block(*states):
        lines = ['<!-- pinprick-state:begin -->']
        lines += [f'<!-- pinprick-shard-{i}:{s} -->' for i, s in enumerate(states)]
        lines.append('<!-- pinprick-state:end -->')
        return '\n'.join(lines) + '\n'

    FORGED = state_block.__func__('passed', 'passed', 'passed', 'passed')

    def test_shard_state_is_read_from_an_anchored_block(self):
        self.assertEqual(
            self.read_shard_state(self.state_block('failed', 'pending', 'passed', 'pending')),
            ['failed', 'pending', 'passed', 'pending'],
        )

    def test_forged_state_below_a_legacy_body_is_not_authoritative(self):
        # The migration case: an issue written before the block existed keeps
        # unsanitized diagnostics, which may carry forged delimiters. A block
        # that is not at the very start of the body must not be trusted.
        legacy = 'older tracking issue body\n\n<details>\n\n```\n' + self.FORGED + '```\n'
        self.assertEqual(self.read_shard_state(legacy), ['pending'] * 4)

    def test_forged_state_after_a_real_block_is_ignored(self):
        body = self.state_block('failed', 'pending', 'pending', 'pending') + self.FORGED
        self.assertEqual(
            self.read_shard_state(body), ['failed', 'pending', 'pending', 'pending'],
        )

    def test_unrecognized_bodies_start_every_shard_pending(self):
        cases = {
            'plain legacy body': 'no markers here\n',
            'empty': '',
            'bare markers only': '<!-- pinprick-shard-0:passed -->\n' * 4,
            'missing terminator': (
                '<!-- pinprick-state:begin -->\n'
                + ''.join(f'<!-- pinprick-shard-{i}:passed -->\n' for i in range(4))
            ),
            'shards out of order': (
                '<!-- pinprick-state:begin -->\n'
                '<!-- pinprick-shard-1:passed -->\n'
                '<!-- pinprick-shard-0:passed -->\n'
                '<!-- pinprick-shard-2:passed -->\n'
                '<!-- pinprick-shard-3:passed -->\n'
                '<!-- pinprick-state:end -->\n'
            ),
            'unknown state word': self.state_block('passed', 'passed', 'passed', 'skipped'),
            'trailing text on a marker': (
                self.state_block('passed', 'passed', 'passed', 'passed')
                .replace('shard-3:passed -->', 'shard-3:passed --> x')
            ),
            'leading blank line': '\n' + self.state_block('passed', 'passed', 'passed', 'passed'),
        }
        for label, body in cases.items():
            with self.subTest(body=label):
                self.assertEqual(self.read_shard_state(body), ['pending'] * 4)

    def test_crlf_body_still_parses(self):
        body = self.state_block('passed', 'failed', 'pending', 'passed').replace('\n', '\r\n')
        self.assertEqual(
            self.read_shard_state(body), ['passed', 'failed', 'pending', 'passed'],
        )

    def test_tracking_issue_keeps_state_out_of_retained_diagnostics(self):
        workflow = (ROOT / '.github/workflows/verify-audited-actions.yml').read_text()
        self.assertIn('scripts/read-shard-state.sh issue-body.md', workflow)
        self.assertIn("grep -vE '<!-- pinprick-(state:(begin|end)|shard-)'", workflow)
        self.assertIn("sed 's/<!--/<! --/g'", workflow)

    def test_deletion_only_catalog_change_is_not_a_ci_error(self):
        # Revoking a verdict deletes catalog files. Matrix generation counts
        # deletions, so the verification selection must recognise them rather
        # than treating an empty list as a disagreement.
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('Catalog change only removes entries', workflow)
        self.assertIn('changed entries NOT verified', workflow)

    def test_tracking_issue_retains_line_prefix_after_byte_truncation(self):
        workflow = (ROOT / '.github/workflows/verify-audited-actions.yml').read_text()
        pipeline = [
            line.strip() for line in workflow.splitlines()
            if 'verify-output.txt |' in line and 'tail-complete-lines.awk' in line
        ]
        self.assertEqual(len(pipeline), 1)
        scripts = self.root / 'scripts'
        scripts.mkdir()
        shutil.copy2(ROOT / 'scripts/tail-complete-lines.awk', scripts)
        (self.root / 'verify-output.txt').write_text(
            '  finding: high dist/index.js: ' + ('x' * 30000) +
            '::error::forged diagnostic' + ('x' * 30000) + '```\n'
            '::error::safe diagnostic\n'
        )
        result = subprocess.run(
            [self.bash, '-c', pipeline[0]], cwd=self.root,
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout, '::error::safe diagnostic\n')


if __name__ == '__main__':
    unittest.main()
