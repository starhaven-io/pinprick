#!/usr/bin/env python3
"""Format raw GitHub generated release notes into clean, categorized markdown.

Expects Conventional Commits PR titles (feat:, fix:, etc.) and the output
format of `gh release create --generate-notes`.

Usage:
    python3 format-release-notes.py <raw_notes_file> <tag>
"""

import re
import sys
from pathlib import Path

SECTIONS = {
    "feat": "What's New",
    "fix": "Fixes",
    "perf": "Performance",
    "refactor": "Under the Hood",
    "docs": "Documentation",
}

# Skip changes that aren't relevant to end users
SKIP_TYPES = {"build", "ci", "chore"}

# Internal scopes that ship no user-visible behavior. `audit-actions` is the
# GitHub workflow that maintains audited-actions/, not the `audit` CLI command.
SKIP_SCOPES = {"audit-actions", "audited-actions"}

# PR line pattern from --generate-notes:
#   * feat(scope): description by @user in https://...
PR_RE = re.compile(
    r"^\*\s+"
    r"(?:(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?:\s*)?"
    r"(?P<desc>.+?)"
    r"(?:\s+by\s+@[\w-]+)?"
    r"(?:\s+in\s+https?://\S+)?"
    r"\s*$"
)

CHANGELOG_RE = re.compile(r"^\*\*Full Changelog\*\*:\s*(?P<url>https?://\S+)")


def parse_notes(raw: str) -> tuple[dict[str, list[str]], str | None]:
    """Parse raw release notes into categorized entries and changelog URL."""
    sections: dict[str, list[str]] = {}
    changelog_url = None

    for line in raw.splitlines():
        line = line.strip()

        changelog_match = CHANGELOG_RE.match(line)
        if changelog_match:
            changelog_url = changelog_match.group("url")
            continue

        pr_match = PR_RE.match(line)
        if not pr_match:
            continue

        pr_type = pr_match.group("type") or ""
        pr_scope = pr_match.group("scope") or ""
        desc = pr_match.group("desc").strip()

        if pr_type in SKIP_TYPES or pr_scope in SKIP_SCOPES:
            continue

        section = SECTIONS.get(pr_type, "Other")
        sections.setdefault(section, []).append(desc)

    return sections, changelog_url


def format_markdown(tag: str, sections: dict[str, list[str]], changelog_url: str | None) -> str:
    """Render categorized notes as markdown."""
    lines = [f"## pinprick {tag}", ""]

    ordered_keys = list(dict.fromkeys(SECTIONS.values()))
    ordered_keys.append("Other")

    for heading in ordered_keys:
        entries = sections.get(heading)
        if not entries:
            continue
        lines.append(f"### {heading}")
        for entry in entries:
            lines.append(f"- {entry}")
        lines.append("")

    if changelog_url:
        lines.append("---")
        lines.append(f"**Full Changelog**: {changelog_url}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <raw_notes_file> <tag>", file=sys.stderr)
        sys.exit(1)

    raw = Path(sys.argv[1]).read_text()
    tag = sys.argv[2]

    sections, changelog_url = parse_notes(raw)
    print(format_markdown(tag, sections, changelog_url))


if __name__ == "__main__":
    main()
