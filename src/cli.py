from __future__ import annotations

import argparse
from pathlib import Path

from .assessor import assess_all
from .loader import load_accounts
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Azure Storage security posture assessor")
    parser.add_argument("input", help="Synthetic/exported configuration JSON")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()

    findings = assess_all(load_accounts(args.input))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(findings), encoding="utf-8")
    print(f"Wrote {len(findings)} findings to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
