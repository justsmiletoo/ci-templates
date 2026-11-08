#!/usr/bin/env python3
"""Turn the security watch findings into one report.

Reads the tab-separated findings of every scan (target, source, package,
installed, fixed, severity, advisory, title, link), drops the duplicates and
writes two Markdown files:

  summary.md  short enough for the run summary: one line per target, then the
              packages to upgrade in each target, worst first, a few per target
  report.md   every advisory, for the downloadable artifact

Exits 1 while a vulnerability is left or a scan did not finish, so the
scheduled run fails and GitHub mails its owner.

  security-report.py <findings-dir> <summary.md> <report.md> [--scans-failed]
"""

import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]
PACKAGES_PER_TARGET = 10


def version_key(version):
    return [int(part) for part in re.findall(r"\d+", version)]


def best_fix(versions):
    """The newest fixed version named, the one that clears every advisory."""
    candidates = {v.strip() for value in versions for v in value.split(",") if v.strip() and v.strip() != "?"}
    return max(candidates, key=version_key) if candidates else "?"


def cell(text):
    return text.replace("|", "/").replace("\n", " ")


def read_findings(directory):
    seen = set()
    rows = []
    for path in sorted(Path(directory).rglob("*.tsv")):
        for line in path.read_text().splitlines():
            fields = (line.split("\t") + [""] * 9)[:9]
            key = tuple(fields[:7])
            if not fields[0] or key in seen:
                continue
            seen.add(key)
            rows.append(dict(zip(["target", "source", "package", "installed", "fixed", "severity", "advisory", "title", "link"], fields)))
    return rows


def counts(rows):
    by_severity = defaultdict(int)
    for row in rows:
        by_severity[row["severity"] if row["severity"] in SEVERITIES else "OTHER"] += 1
    return [by_severity[s] for s in SEVERITIES + ["OTHER"]]


def rank(rows):
    c = counts(rows)
    return (c[0], c[1], c[2], len(rows))


def packages(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["source"], row["package"], row["installed"])].append(row)
    return sorted(grouped.items(), key=lambda item: rank(item[1]), reverse=True)


def totals_table(targets):
    lines = ["| Target | Critical | High | Medium | Other | Total |", "|---|---:|---:|---:|---:|---:|"]
    for target, rows in targets:
        critical, high, medium, other = counts(rows)
        lines.append(f"| {cell(target)} | {critical} | {high} | {medium} | {other} | {len(rows)} |")
    return lines


def package_table(groups):
    lines = ["| Package | Installed | Upgrade to | Critical | High | Medium | Advisories |", "|---|---|---|---:|---:|---:|---:|"]
    for (source, package, installed), rows in groups:
        critical, high, medium, _ = counts(rows)
        lines.append(f"| {cell(package)} ({source}) | {cell(installed)} | {cell(best_fix(r['fixed'] for r in rows))} | {critical} | {high} | {medium} | {len(rows)} |")
    return lines


def main():
    directory, summary_path, report_path = sys.argv[1:4]
    scans_failed = "--scans-failed" in sys.argv[4:]

    rows = read_findings(directory)
    by_target = defaultdict(list)
    for row in rows:
        by_target[row["target"]].append(row)
    targets = sorted(by_target.items(), key=lambda item: rank(item[1]), reverse=True)

    head = [f"# Security watch, {datetime.now(timezone.utc):%Y-%m-%d}", "", "Fixable vulnerabilities, medium severity and above.", ""]
    if scans_failed:
        head += ["> Some scans did not finish: their targets are missing below, see the failed jobs.", ""]
    if not rows:
        head += ["Nothing to fix."]

    summary = list(head)
    report = list(head)
    if rows:
        summary += totals_table(targets) + ["", "## What to upgrade", ""]
        report += totals_table(targets) + [""]
        for target, target_rows in targets:
            groups = packages(target_rows)
            shown = groups[:PACKAGES_PER_TARGET]
            summary += [f"<details><summary><b>{cell(target)}</b>: {len(groups)} package(s)</summary>", ""]
            summary += package_table(shown)
            if len(groups) > len(shown):
                summary += ["", f"And {len(groups) - len(shown)} more package(s): see the security-report artifact."]
            summary += ["", "</details>", ""]

            report += [f"## {cell(target)}", "", "| Package | Installed | Fixed in | Severity | Advisory |", "|---|---|---|---|---|"]
            for (source, package, installed), package_rows in groups:
                for row in sorted(package_rows, key=lambda r: SEVERITIES.index(r["severity"]) if r["severity"] in SEVERITIES else 3):
                    advisory = f"[{cell(row['advisory'])}]({row['link']})" if row["link"] else cell(row["advisory"])
                    report.append(f"| {cell(package)} ({source}) | {cell(installed)} | {cell(row['fixed'])} | {row['severity']} | {advisory} {cell(row['title'])} |")
            report.append("")

    Path(summary_path).write_text("\n".join(summary) + "\n")
    Path(report_path).write_text("\n".join(report) + "\n")
    print(f"{len(rows)} fixable vulnerabilities in {len(targets)} target(s)")
    return 1 if rows or scans_failed else 0


if __name__ == "__main__":
    sys.exit(main())
