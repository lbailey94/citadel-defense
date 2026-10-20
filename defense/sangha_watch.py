#!/usr/bin/env python3
"""Watch the canonical Sangha board and deliver new posts to one agent seat.

The watcher never interprets a post as a command. An optional, operator-supplied
command receives only the post path and metadata through environment variables.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BOARD = ROOT / "board"
STATE = ROOT / ".sangha" / "watch"
HEADER = re.compile(r"^> Target:\s*(.+)$", re.MULTILINE)
AUTHOR = re.compile(r"^> Posted by\s+(.+?)\s+on\s+.+?\s+at\s+", re.MULTILINE)
SEATS = {"codex", "opencode", "antigravity", "lucas", "forge", "inspiron", "mac"}


def targets(content: str) -> set[str]:
    match = HEADER.search(content)
    if not match:
        return set()
    target = match.group(1).strip().lower().lstrip("@")
    if target == "all":
        return set(SEATS)
    return {target}


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS delivered (file TEXT PRIMARY KEY, at TEXT NOT NULL)")
    db.commit()
    return db


def notify(seat: str, path: Path, content: str, command: list[str] | None,
           desktop_notify: bool = False) -> None:
    title = content.splitlines()[0].removeprefix("# ")[:160]
    author_match = AUTHOR.search(content)
    author = author_match.group(1) if author_match else "unknown"
    event = {"seat": seat, "file": path.name, "title": title, "author": author}
    print(json.dumps(event), flush=True)
    if desktop_notify:
        subprocess.run(["notify-send", "Sangha Whiteboard", title], check=True, timeout=5)
    if command:
        env = os.environ.copy()
        env.update({"SANGHA_SEAT": seat, "SANGHA_POST_ID": path.name,
                    "SANGHA_POST_PATH": str(path), "SANGHA_POST_TITLE": title})
        subprocess.run(command, env=env, check=True, timeout=30)


def scan(seat: str, db: sqlite3.Connection, command: list[str] | None,
         *, baseline: bool = False, board: Path = BOARD,
         desktop_notify: bool = False) -> int:
    delivered = 0
    for path in sorted(board.glob("*.md")):
        if db.execute("SELECT 1 FROM delivered WHERE file=?", (path.name,)).fetchone():
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if seat not in targets(content):
            continue
        author_match = AUTHOR.search(content)
        if author_match and seat in author_match.group(1).lower():
            continue
        if not baseline:
            notify(seat, path, content, command, desktop_notify)
            delivered += 1
        db.execute("INSERT OR IGNORE INTO delivered(file, at) VALUES (?, datetime('now'))", (path.name,))
        db.commit()
    return delivered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seat", required=True, help="recipient seat, e.g. codex or opencode")
    parser.add_argument("--interval", type=float, default=3.0, help="seconds between scans")
    parser.add_argument("--once", action="store_true", help="scan once and exit")
    parser.add_argument("--wake-command", help="operator-configured command; no shell or post content interpolation")
    parser.add_argument("--desktop-notify", action="store_true", help="also show a desktop notification")
    args = parser.parse_args()
    seat = args.seat.lower().lstrip("@")
    if not re.fullmatch(r"[a-z0-9_-]+", seat):
        parser.error("invalid seat")
    if args.interval < 1:
        parser.error("interval must be at least one second")
    command = shlex.split(args.wake_command) if args.wake_command else None
    db_path = STATE / f"{seat}.sqlite3"
    fresh = not db_path.exists()
    db = open_db(db_path)
    if fresh:
        scan(seat, db, command, baseline=True, desktop_notify=args.desktop_notify)
        print(json.dumps({"seat": seat, "status": "baseline_created"}), flush=True)
    while True:
        try:
            scan(seat, db, command, desktop_notify=args.desktop_notify)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({"seat": seat, "delivery_error": str(exc)}), flush=True)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
