from __future__ import annotations

from .models import Finding, metrics


def render_markdown(findings: list[Finding]) -> str:
    summary = metrics(findings)
    lines = [
        "# Azure Storage Security Assessment",
        "",
        "Synthetic defensive assessment generated from offline configuration evidence.",
        "",
        "## Executive Summary",
        "",
        f"- Total findings: **{summary['total']}**",
        f"- Critical: **{summary['critical']}**",
        f"- High: **{summary['high']}**",
        f"- Medium: **{summary['medium']}**",
        f"- Low: **{summary['low']}**",
        "",
        "## Prioritized Findings",
        "",
        "| ID | Storage account | Control | Severity | Score |",
        "|---|---|---|---:|---:|",
    ]
    for finding in findings:
        lines.append(
            f"| {finding.finding_id} | {finding.account} | {finding.control} | "
            f"{finding.severity} | {finding.score} |"
        )
    lines.extend(["", "## Finding Detail", ""])
    for finding in findings:
        lines.extend([
            f"### {finding.finding_id} — {finding.control}",
            "",
            f"**Account:** `{finding.account}`  ",
            f"**Risk:** {finding.severity.upper()} ({finding.score}/100)  ",
            f"**Rationale:** {finding.rationale}",
            "",
            f"**Remediation:** {finding.remediation}",
            "",
            "**MITRE ATT&CK context:** " + ", ".join(finding.attack_mapping),
            "",
        ])
    lines.extend([
        "## Validation Workflow",
        "",
        "A finding is not considered closed solely because a configuration value changed. "
        "Closure should retain a change reference, accountable owner, before/after evidence, "
        "a successful validation result, and monitoring confirmation.",
        "",
        "## Scope Note",
        "",
        "This report uses fictional configuration data. ATT&CK mappings express defensive threat context; "
        "they are not evidence that an adversary technique occurred.",
    ])
    return "\n".join(lines) + "\n"
