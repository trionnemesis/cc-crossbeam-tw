#!/usr/bin/env python3
"""Run a synthetic, sanitized Codex-auth provider smoke test."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from worker.secure_worker.codex_provider import CodexCliProvider


def main() -> None:
    result = CodexCliProvider(timeout_seconds=180).analyze(
        "補正通知涉及 [MASKED_ADDRESS] 與 [MASKED_TAIWAN_ID]，消防設備文件需人工確認。",
        {
            "human_review_required": True,
            "artifact_names": ["client_questions.json", "run_meta.json"],
        },
    )
    print(
        json.dumps(
            {
                "provider": "codex-cli-chatgpt-auth",
                "structured_output": bool(result.summary),
                "risk_flag_count": len(result.risk_flags),
                "human_review_required": result.human_review_required,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
