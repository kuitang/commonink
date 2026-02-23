#!/usr/bin/env python3
"""Parse MCP debug logs and reconstruct tool-call and app_bash sequences.

Usage:
  python3 scripts/parse_mcp_debug_log.py test-results/manual-run-test-*.log
  python3 scripts/parse_mcp_debug_log.py --json test-results/manual-run-test-*.log
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


REQ_BODY_RE = re.compile(r"MCP\[debug\]: request body: (.+)$")
RESP_STATUS_RE = re.compile(
    r"MCP\[debug\]: response status=(\d+)\s+method=([A-Z]+)\s+path=([^ ]+)"
)
TS_RE = re.compile(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse MCP debug logs")
    parser.add_argument("logfile", type=Path, help="Path to server log file")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON summary instead of human-readable output",
    )
    parser.add_argument(
        "--max-arg-chars",
        type=int,
        default=180,
        help="Maximum argument preview length in text output",
    )
    return parser.parse_args()


def extract_ts(line: str) -> str:
    m = TS_RE.search(line)
    return m.group(1) if m else ""


def safe_json_loads(raw: str) -> tuple[Any | None, str | None]:
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        return None, str(exc)


def compact_json(value: Any, max_chars: int) -> str:
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 14] + "...[truncated]"


def parse_log(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"log file not found: {path}")

    lines = path.read_text(errors="replace").splitlines()
    events: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []

    for idx, line in enumerate(lines, start=1):
        req_match = REQ_BODY_RE.search(line)
        if req_match:
            body_text = req_match.group(1)
            body_truncated = body_text.endswith(" [truncated]")
            if body_truncated:
                body_text = body_text[: -len(" [truncated]")]

            body_obj, parse_error = safe_json_loads(body_text)
            method = body_obj.get("method") if isinstance(body_obj, dict) else None
            params = body_obj.get("params") if isinstance(body_obj, dict) else None
            tool_name = None
            tool_args: dict[str, Any] | None = None

            if method == "tools/call" and isinstance(params, dict):
                maybe_name = params.get("name")
                if isinstance(maybe_name, str):
                    tool_name = maybe_name
                maybe_args = params.get("arguments")
                if isinstance(maybe_args, dict):
                    tool_args = maybe_args
                else:
                    tool_args = {}

            event = {
                "line": idx,
                "timestamp": extract_ts(line),
                "method": method,
                "tool_name": tool_name,
                "tool_args": tool_args,
                "response_status": None,
                "response_status_line": None,
                "json_parse_error": parse_error,
                "body_truncated": body_truncated,
            }
            events.append(event)
            pending.append(event)
            continue

        status_match = RESP_STATUS_RE.search(line)
        if status_match and pending:
            response_status = int(status_match.group(1))
            response_method = status_match.group(2)
            response_path = status_match.group(3)
            if response_method in {"POST", "DELETE"} and response_path.startswith("/mcp"):
                current = pending.pop(0)
                current["response_status"] = response_status
                current["response_status_line"] = idx

    tool_calls = [e for e in events if e.get("method") == "tools/call"]
    app_bash_calls = [e for e in tool_calls if e.get("tool_name") == "app_bash"]

    return {
        "logfile": str(path),
        "line_count": len(lines),
        "event_count": len(events),
        "tool_call_count": len(tool_calls),
        "events": events,
        "tool_calls": tool_calls,
        "app_bash_calls": app_bash_calls,
    }


def print_text(summary: dict[str, Any], max_arg_chars: int) -> None:
    print(f"logfile: {summary['logfile']}")
    print(f"lines: {summary['line_count']}")
    print(f"mcp request-body events: {summary['event_count']}")
    print(f"tool calls: {summary['tool_call_count']}")
    print()

    print("Tool-call sequence:")
    for i, event in enumerate(summary["tool_calls"], start=1):
        status = event.get("response_status")
        status_text = str(status) if status is not None else "?"
        ts = event.get("timestamp") or "unknown-ts"
        tool_name = event.get("tool_name") or "unknown-tool"
        tool_args = event.get("tool_args")
        args_preview = compact_json(tool_args, max_arg_chars) if isinstance(tool_args, dict) else "{}"
        print(
            f"{i:03d}. {ts} line={event['line']} "
            f"status={status_text} tool={tool_name} args={args_preview}"
        )

    print()
    print("app_bash command sequence:")
    app_bash_calls = summary["app_bash_calls"]
    if not app_bash_calls:
        print("(none)")
        return

    for i, event in enumerate(app_bash_calls, start=1):
        args = event.get("tool_args") or {}
        cmd = args.get("command", "")
        app = args.get("app", "")
        timeout_s = args.get("timeout_seconds")
        timeout_str = f", timeout={timeout_s}s" if timeout_s is not None else ""
        status = event.get("response_status")
        status_text = str(status) if status is not None else "?"
        print(
            f"{i:03d}. {event.get('timestamp') or 'unknown-ts'} "
            f"status={status_text} app={app} command={cmd!r}{timeout_str}"
        )


def main() -> int:
    args = parse_args()
    try:
        summary = parse_log(args.logfile)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_text(summary, args.max_arg_chars)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
