from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tw_law_mcp.repository import load_default_repository


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Taiwan law snapshot for flow context.")
    parser.add_argument("--central", default="TW", help="central jurisdiction code")
    parser.add_argument("--local", default="ntpc", help="local jurisdiction code")
    parser.add_argument("--case-type", default="室內裝修", help="case type")
    parser.add_argument(
        "--procedure-stage",
        required=True,
        help="procedure stage e.g. 圖說審核 / 竣工查驗 / 變更使用併室內裝修竣工查驗 / 簡易室內裝修",
    )
    parser.add_argument("--as-of-date", required=True, help="snapshot as-of date, e.g. 2026-07-06")
    parser.add_argument(
        "--as-of-basis",
        default="run_date",
        choices=["document_issue_date", "run_date", "user_supplied_date"],
        help="basis for as-of date",
    )
    parser.add_argument("--user-supplied-date", default=None, help="user-provided as-of basis date")
    parser.add_argument("--output", default=None, help="optional output file path; default stdout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = load_default_repository()
    snapshot = repo.build_law_snapshot(
        jurisdiction={"central": args.central, "local": args.local},
        case_type=args.case_type,
        procedure_stage=args.procedure_stage,
        as_of_date=args.as_of_date,
        as_of_date_basis=args.as_of_basis,
        user_supplied_date=args.user_supplied_date,
    )
    text = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
