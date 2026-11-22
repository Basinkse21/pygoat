#!/usr/bin/env python3
"""Convert a Docker Scout SARIF report into a compact Markdown table.

Usage:
    python3 scout_sarif_summary.py scout-report.sarif scout-report.md

Docker Scout writes one SARIF result per vulnerability. The human readable
details live in the result message, so the message is parsed into fields.
The script is intentionally dependency-free (standard library only) and
always exits with status 0 so that it never hides the real scan status.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNSPECIFIED": 4}
FIELDS = (
    "Vulnerability",
    "Severity",
    "Package",
    "Affected range",
    "Fixed version",
    "CVSS Score",
    "CVSS Vector",
    "EPSS Score",
    "EPSS Percentile",
)


def parse_message(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"\s*([A-Za-z ]+?)\s*:\s*(.*)", line)
        if not match:
            continue
        key, value = match.group(1).strip(), match.group(2).strip()
        if key in FIELDS:
            data[key] = value
    return data


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 0

    sarif_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    if not sarif_path.is_file():
        out_path.write_text(
            "# Docker Scout report\n\nSARIF report was not generated, "
            "see the workflow log for details.\n",
            encoding="utf-8",
        )
        return 0

    report = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = []
    for run in report.get("runs", []):
        for result in run.get("results", []):
            fields = parse_message(result.get("message", {}).get("text", ""))
            if not fields:
                continue
            fields.setdefault("Vulnerability", result.get("ruleId", "unknown"))
            fields["Severity"] = fields.get("Severity", "UNSPECIFIED").upper()
            results.append(fields)

    results.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["Severity"], 99),
            -float(item.get("CVSS Score") or 0),
            item.get("Package", ""),
        )
    )

    counts: dict[str, int] = {}
    for item in results:
        counts[item["Severity"]] = counts.get(item["Severity"], 0) + 1

    lines = [
        "# Docker Scout vulnerability report",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in SEVERITY_ORDER:
        if severity in counts:
            lines.append(f"| {severity.title()} | {counts[severity]} |")
    lines.append(f"| **Total** | **{len(results)}** |")
    lines += [
        "",
        "## Findings (critical and high)",
        "",
        "| # | Vulnerability | Severity | CVSS | Package | Fixed version |",
        "| ---: | --- | --- | ---: | --- | --- |",
    ]
    for index, item in enumerate(results, start=1):
        package = item.get("Package", "").replace("pkg:", "").replace("|", "\\|")
        lines.append(
            f"| {index} | {item.get('Vulnerability', '')} | {item['Severity']} | "
            f"{item.get('CVSS Score', '')} | {package} | {item.get('Fixed version', '')} |"
        )

    lines += ["", f"Source: `{sarif_path.name}`", ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out_path} ({len(results)} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
