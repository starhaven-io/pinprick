import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


class CargoDenyWorkflowTests(unittest.TestCase):
    def test_dependency_policy_jobs_use_the_same_cargo_deny_archive(self) -> None:
        archives = []
        for name in ("ci.yml", "cargo-deny.yml"):
            workflow = WORKFLOW.with_name(name).read_text()
            pins = re.findall(
                r'CARGO_DENY_SHA256: "([a-f0-9]{64})"\n'
                r"[\s\S]*?https://github\.com/EmbarkStudios/cargo-deny/releases/"
                r"download/([0-9.]+)/cargo-deny-([0-9.]+)-x86_64-unknown-linux-musl\.tar\.gz",
                workflow,
            )
            self.assertEqual(len(pins), 1, f"expected one cargo-deny pin in {name}")
            self.assertEqual(pins[0][1], pins[0][2], "release and archive versions must match")
            archives.append(pins[0])
        self.assertEqual(archives[0], archives[1])

    def test_toolchain_setup_failure_stops_before_advisory_reporting(self) -> None:
        workflow = WORKFLOW.with_name("cargo-deny.yml").read_text()
        step = re.search(
            r"^      - name: Install cargo-deny\n(?:^        .*\n)*?"
            r"^        run: \|\n(?P<run>(?:^          .*\n|^\n)+)",
            workflow,
            re.MULTILINE,
        )
        self.assertIsNotNone(step)
        script = textwrap.dedent(step.group("run"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("curl", "sha256sum", "tar", "cargo"):
                stub = root / name
                body = "exit 0\n"
                if name == "sha256sum":
                    body = "cat >/dev/null\n"
                elif name == "cargo":
                    body = 'echo "$*" >> "$CARGO_CALLS"\nexit "$CARGO_STATUS"\n'
                stub.write_text("#!/bin/sh\n" + body)
                stub.chmod(0o755)
            calls = root / "cargo-calls"
            for status in (0, 42):
                with self.subTest(toolchain_exit=status):
                    calls.write_text("")
                    result = subprocess.run(
                        ["/bin/bash", "-euo", "pipefail", "-c", script],
                        cwd=root,
                        env={
                            **os.environ,
                            "PATH": f"{root}:/usr/bin:/bin",
                            "RUNNER_TEMP": directory,
                            "GITHUB_PATH": str(root / "github-path"),
                            "CARGO_DENY_SHA256": "a" * 64,
                            "CARGO_CALLS": str(calls),
                            "CARGO_STATUS": str(status),
                        },
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual(calls.read_text(), "--version\n")


if __name__ == "__main__":
    unittest.main()
