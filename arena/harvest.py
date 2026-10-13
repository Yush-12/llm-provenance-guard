"""
arena.harvest — Export and review level-6+ bypass attempts.

Captures any payload that successfully defeated the strictest level
and exfiltrated the canary secret.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from arena.engine import AttemptResult
from spanguard import config


def record_bypass(
    attempt: AttemptResult,
    session_id: str,
    log_path: str | Path | None = None,
) -> bool:
    """Record a successful bypass of Level 6+ to the harvest JSONL log."""
    if attempt.level < config.ARENA_LEVEL_MAX or not attempt.leaked:
        return False

    target_path = Path(log_path) if log_path is not None else Path(config.ARENA_BYPASS_LOG_PATH)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    record: dict[str, Any] = {
        config.ARENA_RESP_SESSION_ID_KEY: session_id,
        config.ARENA_RESP_LEVEL_KEY: attempt.level,
        config.ARENA_RESP_PAYLOAD_KEY: attempt.payload,
        config.ARENA_RESP_LEAKED_KEY: attempt.leaked,
        config.ARENA_RESP_REPLY_TEXT_KEY: attempt.reply_text,
        config.ARENA_RESP_TOOL_CALLS_KEY: [c.model_dump() for c in attempt.tool_calls],
        "timestamp": time.time(),
    }

    with target_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return True


def load_bypasses(log_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load all harvested bypass records."""
    target_path = Path(log_path) if log_path is not None else Path(config.ARENA_BYPASS_LOG_PATH)
    if not target_path.is_file():
        return []

    records: list[dict[str, Any]] = []
    with target_path.open("r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if clean:
                records.append(json.loads(clean))
    return records


def main() -> None:
    """CLI entrypoint for harvest command."""
    bypasses = load_bypasses()
    print("=" * 60)
    print(f"Spanguard Arena Harvest: {len(bypasses)} Level-6+ Bypass Attempts Logged")
    print("=" * 60)
    for idx, b in enumerate(bypasses, start=1):
        print(f"\n[{idx}] Level {b.get(config.ARENA_RESP_LEVEL_KEY)} Bypass:")
        print(f"  Session : {b.get(config.ARENA_RESP_SESSION_ID_KEY)}")
        print(f"  Payload : {b.get(config.ARENA_RESP_PAYLOAD_KEY)!r}")
    print("\nHarvest review complete.")


if __name__ == "__main__":
    main()
