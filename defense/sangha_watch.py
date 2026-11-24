#!/usr/bin/env python3
"""Watch the canonical Sangha board and deliver new posts to one agent seat.

The watcher never interprets a post as a command. An optional, operator-supplied
command receives only the post path and metadata through environment variables.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import select
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
TYPE_RE = re.compile(r"^>\s*Type:\s*([A-Za-z_-]+)", re.MULTILINE | re.IGNORECASE)
SEAT_RE = re.compile(r"[a-z0-9_-]+")
SEATS = {"codex", "opencode", "antigravity", "lucas", "forge", "inspiron", "mac"}
DEFAULT_SKIP_TYPES = frozenset({"claim", "release"})

IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000


class BoardInotify:
    """Zero-dependency Linux inotify watcher with graceful polling fallback."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self._libc = None
        self.fd: int | None = None
        self.wd: int = -1

    def __enter__(self) -> "BoardInotify":
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            fd = int(libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC))
            if fd < 0:
                return self
            encoded = os.fsencode(os.fspath(self.directory))
            wd = int(libc.inotify_add_watch(fd, encoded, IN_CLOSE_WRITE | IN_MOVED_TO))
            if wd < 0:
                os.close(fd)
                return self
            self._libc = libc
            self.fd = fd
            self.wd = wd
        except Exception:
            if self.fd is not None and self.fd >= 0:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
            self.fd = None
            self.wd = -1
        return self

    def wait(self, timeout_s: float) -> bool:
        """Block until a write/move-in fs event occurs or timeout_s elapses."""
        timeout_s = max(0.0, float(timeout_s))
        if self.fd is None:
            time.sleep(timeout_s)
            return False
        readable, _, _ = select.select([self.fd], [], [], timeout_s)
        if not readable:
            return False
        while True:
            try:
                chunk = os.read(self.fd, 65536)
                if not chunk:
                    break
            except BlockingIOError:
                break
            except OSError:
                break
        return True

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            try:
                if self._libc is not None and self.wd >= 0:
                    self._libc.inotify_rm_watch(self.fd, self.wd)
            except Exception:
                pass
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
            self.wd = -1


def targets(content: str) -> set[str]:
    match = HEADER.search(content)
    if not match:
        return set()
    target = match.group(1).strip().lower().lstrip("@")
    if target == "all":
        return set(SEATS)
    return {target}


def parse_post_type(content: str) -> str | None:
    match = TYPE_RE.search(content)
    return match.group(1).strip().lower() if match else None


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS delivered (file TEXT PRIMARY KEY, at TEXT NOT NULL)")
    db.execute(
        "CREATE TABLE IF NOT EXISTS seen (file TEXT PRIMARY KEY, status TEXT NOT NULL, at TEXT NOT NULL)"
    )
    db.commit()
    return db


def load_seen(db: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in db.execute("SELECT file FROM delivered UNION SELECT file FROM seen").fetchall()
    }


def notify(
    seat: str,
    path: Path,
    content: str,
    command: list[str] | None,
    desktop_notify: bool = False,
    post_type: str | None = None,
) -> None:
    lines = content.splitlines()
    title = lines[0].removeprefix("# ")[:160] if lines else path.name
    author_match = AUTHOR.search(content)
    author = author_match.group(1) if author_match else "unknown"
    resolved_type = post_type if post_type is not None else parse_post_type(content)
    event = {
        "seat": seat,
        "file": path.name,
        "title": title,
        "author": author,
        "type": resolved_type,
    }
    print(json.dumps(event), flush=True)
    if desktop_notify:
        summary = f"Sangha [{resolved_type or 'post'}] {author} -> @{seat}"
        subprocess.run(
            ["notify-send", "--app-name=Sangha Whiteboard", summary, title],
            check=True,
            timeout=5,
        )
    if command:
        env = os.environ.copy()
        env.update(
            {
                "SANGHA_SEAT": seat,
                "SANGHA_POST_ID": path.name,
                "SANGHA_POST_PATH": str(path),
                "SANGHA_POST_TITLE": title,
            }
        )
        subprocess.run(command, env=env, check=True, timeout=30)


def scan(
    seat: str,
    db: sqlite3.Connection,
    command: list[str] | None,
    *,
    baseline: bool = False,
    board: Path = BOARD,
    desktop_notify: bool = False,
    seen_cache: set[str] | None = None,
    skip_types: set[str] | frozenset[str] | None = None,
) -> int:
    board_path = Path(board)
    if not board_path.is_dir():
        return 0
    if seen_cache is None:
        seen_cache = load_seen(db)
    active_skip_types = DEFAULT_SKIP_TYPES if skip_types is None else skip_types

    entries = sorted(
        (e for e in os.scandir(board_path) if e.name.endswith(".md") and e.is_file()),
        key=lambda e: e.name,
    )

    delivered = 0
    dirty = False
    try:
        for entry in entries:
            name = entry.name
            if name in seen_cache:
                continue
            try:
                with open(entry.path, encoding="utf-8", errors="replace") as pf:
                    content = pf.read()
            except (OSError, UnicodeError):
                continue

            if seat not in targets(content):
                db.execute(
                    "INSERT OR IGNORE INTO seen(file, status, at) VALUES (?, 'non_target', datetime('now'))",
                    (name,),
                )
                seen_cache.add(name)
                dirty = True
                continue

            author_match = AUTHOR.search(content)
            if author_match and seat in author_match.group(1).lower():
                db.execute(
                    "INSERT OR IGNORE INTO seen(file, status, at) VALUES (?, 'self', datetime('now'))",
                    (name,),
                )
                seen_cache.add(name)
                dirty = True
                continue

            post_type = parse_post_type(content)
            if baseline:
                db.execute(
                    "INSERT OR IGNORE INTO delivered(file, at) VALUES (?, datetime('now'))",
                    (name,),
                )
                db.execute(
                    "INSERT OR IGNORE INTO seen(file, status, at) VALUES (?, 'baseline', datetime('now'))",
                    (name,),
                )
                seen_cache.add(name)
                dirty = True
                continue

            if post_type in active_skip_types:
                db.execute(
                    "INSERT OR IGNORE INTO seen(file, status, at) VALUES (?, 'type_filtered', datetime('now'))",
                    (name,),
                )
                seen_cache.add(name)
                dirty = True
                continue

            notify(
                seat,
                Path(entry.path),
                content,
                command,
                desktop_notify=desktop_notify,
                post_type=post_type,
            )
            delivered += 1
            db.execute(
                "INSERT OR IGNORE INTO delivered(file, at) VALUES (?, datetime('now'))",
                (name,),
            )
            db.execute(
                "INSERT OR IGNORE INTO seen(file, status, at) VALUES (?, 'delivered', datetime('now'))",
                (name,),
            )
            seen_cache.add(name)
            dirty = True
    finally:
        if dirty:
            db.commit()
    return delivered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seat", required=True, help="recipient seat, e.g. codex or opencode")
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="seconds between scans in polling mode (safety floor 30s with inotify)",
    )
    parser.add_argument("--once", action="store_true", help="scan once and exit")
    parser.add_argument(
        "--wake-command",
        help="operator-configured command; no shell or post content interpolation",
    )
    parser.add_argument(
        "--desktop-notify", action="store_true", help="also show a desktop notification"
    )
    parser.add_argument(
        "--skip-types",
        default="claim,release",
        help="comma-separated post types suppressed from notification popups (empty to disable)",
    )
    parser.add_argument(
        "--no-inotify",
        action="store_true",
        help="disable Linux inotify and use polling at --interval seconds",
    )
    args = parser.parse_args()
    seat = args.seat.lower().lstrip("@")
    if not SEAT_RE.fullmatch(seat):
        parser.error("invalid seat")
    if args.interval < 1:
        parser.error("interval must be at least one second")
    skip_types = frozenset(
        t.strip().lower() for t in str(args.skip_types).split(",") if t.strip()
    )
    command = shlex.split(args.wake_command) if args.wake_command else None
    BOARD.mkdir(parents=True, exist_ok=True)
    db_path = STATE / f"{seat}.sqlite3"
    fresh = not db_path.exists()
    db = open_db(db_path)
    seen_cache = load_seen(db)
    if fresh:
        scan(
            seat,
            db,
            command,
            baseline=True,
            desktop_notify=args.desktop_notify,
            seen_cache=seen_cache,
            skip_types=skip_types,
        )
        print(json.dumps({"seat": seat, "status": "baseline_created"}), flush=True)

    if args.once:
        try:
            scan(
                seat,
                db,
                command,
                desktop_notify=args.desktop_notify,
                seen_cache=seen_cache,
                skip_types=skip_types,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            print(json.dumps({"seat": seat, "delivery_error": str(exc)}), flush=True)
        return

    if args.no_inotify:
        while True:
            try:
                scan(
                    seat,
                    db,
                    command,
                    desktop_notify=args.desktop_notify,
                    seen_cache=seen_cache,
                    skip_types=skip_types,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                print(json.dumps({"seat": seat, "delivery_error": str(exc)}), flush=True)
            time.sleep(args.interval)

    with BoardInotify(BOARD) as watcher:
        fallback_s = args.interval if watcher.fd is None else max(30.0, float(args.interval))
        while True:
            try:
                scan(
                    seat,
                    db,
                    command,
                    desktop_notify=args.desktop_notify,
                    seen_cache=seen_cache,
                    skip_types=skip_types,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                print(json.dumps({"seat": seat, "delivery_error": str(exc)}), flush=True)
            watcher.wait(fallback_s)


if __name__ == "__main__":
    main()
