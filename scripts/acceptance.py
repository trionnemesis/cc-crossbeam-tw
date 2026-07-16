#!/usr/bin/env python3
"""Observable Secure Web acceptance runner.

This runner intentionally reports incomplete phases instead of treating missing
application components or external credentials as success.
"""

from __future__ import annotations

import json
import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def check(name: str, command: list[str], cwd: Path = ROOT) -> dict[str, object]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    result = {
        "name": name,
        "passed": completed.returncode == 0,
        "returncode": completed.returncode,
    }
    print(json.dumps(result, ensure_ascii=False))
    if completed.returncode != 0:
        tail = (completed.stderr or completed.stdout).splitlines()[-3:]
        print(json.dumps({"name": name, "error_tail": tail}, ensure_ascii=False))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="run local web/worker E2E; services must be running")
    parser.add_argument("--codex", action="store_true", help="run a synthetic Codex-auth provider request")
    args = parser.parse_args()
    checks: list[dict[str, object]] = []
    checks.append(
        check(
            "python-domain-tests",
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        )
    )
    checks.append(check("codex-auth", ["codex", "login", "status"]))

    architecture = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    missing_requirements = [f"R{index}" for index in range(1, 13) if f"| R{index} |" not in architecture]
    architecture_result = {
        "name": "architecture-orphan-check",
        "passed": not missing_requirements,
        "requirements": 12,
        "missing": missing_requirements,
    }
    print(json.dumps(architecture_result, ensure_ascii=False))
    checks.append(architecture_result)

    web = ROOT / "web"
    if not (web / "package.json").exists():
        result = {
            "name": "secure-web",
            "passed": False,
            "reason": "web/package.json is not implemented yet",
        }
        print(json.dumps(result, ensure_ascii=False))
        checks.append(result)
    else:
        checks.extend(
            [
                check("web-tests", ["npm", "test", "--", "--run"], web),
                check("web-typecheck", ["npm", "run", "typecheck"], web),
                check("web-lint", ["npm", "run", "lint"], web),
                check("web-build", ["npm", "run", "build"], web),
            ]
        )
        if args.live:
            checks.append(check("secure-upload-e2e", ["npm", "run", "acceptance:upload"], web))
    if args.codex:
        checks.append(
            check(
                "codex-provider-smoke",
                [sys.executable, "scripts/run_codex_provider_smoke.py"],
            )
        )

    summary = {
        "all_local_passed": all(bool(item["passed"]) for item in checks),
        "checks": len(checks),
        "single_user_external_acceptance": "not-run-no-google-line-domain-credentials",
        "cloud_production_acceptance": "not-in-current-single-user-scope",
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary["all_local_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
