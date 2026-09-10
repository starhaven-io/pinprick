import os
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
AUDIT_WORKFLOW = ROOT / ".github" / "workflows" / "pinprick-audit.yml"


def workflow_run_block(step_name: str) -> str:
    source = CI_WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        rf"^      - name: {re.escape(step_name)}\n(?:^        .*\n)*?^        run: \|\n(?P<run>(?:^          .*\n|^\n)+)",
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing workflow step: {step_name}")
    return textwrap.dedent(match.group("run"))


class CIConclusionTests(unittest.TestCase):
    def setUp(self):
        self.script = workflow_run_block("Result")
        self.environment = {
            "GITHUB_EVENT_NAME": "pull_request",
            "MATRIX_RESULT": "success",
            "COMMITS_RESULT": "success",
            "CHECK_RESULT": "success",
            "ZIZMOR_RESULT": "success",
            "PINPRICK_RESULT": "success",
            "CODECOV_RESULT": "success",
            "MATRIX": '[{"check":"coverage"}]',
            "RUN_ZIZMOR": "true",
            "RUN_PINPRICK": "true",
            "RUN_CODECOV": "true",
            "CODECOV_ELIGIBLE": "true",
            "EVENT_NAME": "pull_request",
        }

    def conclude(self, **overrides):
        return subprocess.run(
            ["/bin/bash", "-euo", "pipefail", "-c", self.script],
            env={**os.environ, **self.environment, **overrides},
            capture_output=True,
            text=True,
            check=False,
        )

    def test_selected_pinprick_audit_must_succeed(self):
        self.assertEqual(self.conclude().returncode, 0)
        for result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(result=result):
                self.assertNotEqual(self.conclude(PINPRICK_RESULT=result).returncode, 0)

    def test_only_unselected_pinprick_audit_may_skip(self):
        self.assertEqual(self.conclude(RUN_PINPRICK="false", PINPRICK_RESULT="skipped").returncode, 0)
        self.assertNotEqual(self.conclude(RUN_PINPRICK="false", PINPRICK_RESULT="failure").returncode, 0)
        self.assertNotEqual(self.conclude(RUN_PINPRICK="", PINPRICK_RESULT="skipped").returncode, 0)

    def test_every_routing_decision_fails_closed(self):
        self.assertNotEqual(self.conclude(EVENT_NAME="unknown", COMMITS_RESULT="skipped").returncode, 0)
        self.assertNotEqual(self.conclude(MATRIX="", CHECK_RESULT="skipped").returncode, 0)
        self.assertNotEqual(self.conclude(RUN_ZIZMOR="", ZIZMOR_RESULT="skipped").returncode, 0)
        self.assertNotEqual(self.conclude(RUN_CODECOV="", CODECOV_RESULT="skipped").returncode, 0)
        self.assertNotEqual(self.conclude(CODECOV_ELIGIBLE="", CODECOV_RESULT="skipped").returncode, 0)

    def test_pr_gate_uses_the_fleet_audit_and_keeps_source_dogfooding(self):
        audit = AUDIT_WORKFLOW.read_text(encoding="utf-8")
        ci = CI_WORKFLOW.read_text(encoding="utf-8")
        # The build-from-source audit is not callable, so the merge-critical
        # gate gets the fleet audit. It keeps its own pull request trigger so
        # a change to the engine is still audited by the engine under review.
        self.assertNotIn("  workflow_call:\n", audit)
        self.assertIn("  pull_request:\n", audit)
        self.assertIn("  push:\n", audit)
        self.assertIn(
            "uses: starhaven-io/.github/.github/workflows/reusable-pinprick-audit.yml@",
            ci,
        )
        self.assertIn("      fail-on-findings: true", ci)
        self.assertNotIn("uses: $/.github/workflows/", ci)


if __name__ == "__main__":
    unittest.main()
