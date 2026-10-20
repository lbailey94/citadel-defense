#!/usr/bin/env python3
"""Sangha session registry — addressable sessions across IDEs.

One entry per session instance, keyed by session_id. The plugin, the window
router, and sangha.py all read this file to decide which sessions a post may
ring, and to resolve room/project membership.

Schema (sessions.json):
{
  "sessions": {
    "<session_id>": {
      "alias": "opencode",          # seat name
      "ide": "opencode|agy|codex",  # adapter family
      "adapter": "plugin|router|notify",
      "project": "pet2.0",          # optional; matches a post Scope: prefix
      "room": "pet2.0",             # optional; room membership
      "title": "...",               # session title for display
      "state": "idle|working",
      "first_seen": "...Z",
      "last_seen": "...Z"
    }
  }
}

Kept local per device in ~/.local/state/sangha (never Syncthing-shared), same
policy as the router and plugin state.

CLI:
  sangha_registry.py join --alias opencode --session-id ses_abc \
      --ide opencode --adapter plugin [--project pet2.0] [--room pet2.0] \
      [--title "..."]
  sangha_registry.py state --session-id ses_abc --state idle|working
  sangha_registry.py list [--project pet2.0] [--room pet2.0] [--json]
  sangha_registry.py leave --session-id ses_abc
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("SANGHA_STATE_DIR", "") or Path.home() / ".local" / "state" / "sangha")
REGISTRY = Path(os.environ.get("SANGHA_SESSIONS", "") or STATE_DIR / "sessions.json")
LOCK = STATE_DIR / "sessions.lock"
STALE_AFTER_S = int(os.environ.get("SANGHA_SESSIONS_STALE_S", "86400"))  # 24h
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _valid(value, field, required=False):
    value = (value or "").strip().lower()
    if not value:
        if required:
            sys.exit(f"Error: --{field} is required.")
        return None
    if not PROJECT_RE.match(value):
        sys.exit(f"Error: --{field} must be a short slug (a-z, 0-9, _ . : -), got {value!r}.")
    return value


class _Lock:
    def __init__(self, timeout=5.0):
        self.timeout = timeout
        self.fh = None

    def __enter__(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.fh = open(LOCK, "a+")
        import time
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    sys.exit(f"Error: registry lock busy after {self.timeout}s ({LOCK}).")
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
        finally:
            self.fh.close()


def load_registry():
    try:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"sessions": {}}
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), dict):
        return {"sessions": {}}
    return data


def _save_locked(data):
    """Atomic same-directory replace; temp file never leaves the state dir."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".sessions.", suffix=".json", dir=STATE_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, REGISTRY)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def prune(data, now=None):
    """Drop entries not seen for STALE_AFTER_S. Returns the removed ids."""
    now = now or datetime.now(timezone.utc)
    removed = []
    for sid, entry in list(data["sessions"].items()):
        seen = entry.get("last_seen")
        try:
            at = datetime.fromisoformat(str(seen).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            at = None
        if at is None or (now - at).total_seconds() > STALE_AFTER_S:
            removed.append(sid)
            del data["sessions"][sid]
    return removed


def upsert(entry):
    with _Lock():
        data = load_registry()
        prune(data)
        sid = entry["session_id"]
        prev = data["sessions"].get(sid, {})
        prev.update({k: v for k, v in entry.items() if v is not None})
        prev["session_id"] = sid
        prev.setdefault("first_seen", now_iso())
        prev["last_seen"] = now_iso()
        data["sessions"][sid] = prev
        _save_locked(data)
        return prev


def _detect_project_room():
    cur = Path.cwd()
    for p in [cur, *cur.parents]:
        cfg = p / ".sangha.json"
        if cfg.exists():
            try:
                data = json.loads(cfg.read_text(encoding="utf-8"))
                return data.get("project"), data.get("room"), data.get("title")
            except Exception:
                pass
    return None, None, None


def cmd_join(args):
    d_proj, d_room, d_title = _detect_project_room()
    proj = args.project or d_proj
    room = args.room or d_room
    title = args.title or d_title
    entry = {
        "alias": _valid(args.alias, "alias", required=True),
        "session_id": (args.session_id or "").strip(),
        "ide": (args.ide or "").strip().lower() or None,
        "adapter": (args.adapter or "").strip().lower() or None,
        "project": _valid(proj, "project"),
        "room": _valid(room, "room"),
        "title": (title or "").strip() or None,
        "state": "working",
    }
    if not entry["session_id"]:
        sys.exit("Error: --session-id is required.")
    saved = upsert(entry)
    print(json.dumps({"ok": True, "session": saved}, indent=2))


def cmd_state(args):
    sid = (args.session_id or "").strip()
    if not sid:
        sys.exit("Error: --session-id is required.")
    state = _valid(args.state, "state", required=True)
    if state not in ("idle", "working"):
        sys.exit("Error: --state must be idle or working.")
    saved = upsert({"session_id": sid, "state": state})
    print(json.dumps({"ok": True, "session": saved}, indent=2))


def cmd_leave(args):
    sid = (args.session_id or "").strip()
    if not sid:
        sys.exit("Error: --session-id is required.")
    with _Lock():
        data = load_registry()
        existed = data["sessions"].pop(sid, None)
        _save_locked(data)
    print(json.dumps({"ok": bool(existed), "removed": sid}))


def cmd_list(args):
    project = _valid(args.project, "project")
    room = _valid(args.room, "room")
    with _Lock():
        data = load_registry()
        removed = prune(data)
        if removed:
            _save_locked(data)
    sessions = list(data["sessions"].values())
    if project:
        sessions = [s for s in sessions if s.get("project") == project]
    if room:
        sessions = [s for s in sessions if s.get("room") == room]
    sessions.sort(key=lambda s: str(s.get("last_seen")), reverse=True)
    if args.json:
        print(json.dumps({"sessions": sessions, "pruned": removed}, indent=2))
        return
    if not sessions:
        print("No registered sessions" + (f" for project={project}" if project else ""))
        return
    for s in sessions:
        extra = " · ".join(filter(None, [
            f"project={s['project']}" if s.get("project") else None,
            f"room={s['room']}" if s.get("room") else None,
        ]))
        print(f"{s.get('session_id')}  {s.get('ide') or '?'}/{s.get('adapter') or '?'}  "
              f"{s.get('state') or '?'}  {s.get('title') or ''}"
              + (f"  [{extra}]" if extra else ""))


def build_parser():
    parser = argparse.ArgumentParser(description="Sangha session registry")
    sub = parser.add_subparsers(dest="command", required=True)

    p_join = sub.add_parser("join")
    p_join.add_argument("--alias", required=True)
    p_join.add_argument("--session-id", required=True)
    p_join.add_argument("--ide", default="")
    p_join.add_argument("--adapter", default="")
    p_join.add_argument("--project", default="")
    p_join.add_argument("--room", default="")
    p_join.add_argument("--title", default="")
    p_join.set_defaults(func=cmd_join)

    p_state = sub.add_parser("state")
    p_state.add_argument("--session-id", required=True)
    p_state.add_argument("--state", required=True)
    p_state.set_defaults(func=cmd_state)

    p_leave = sub.add_parser("leave")
    p_leave.add_argument("--session-id", required=True)
    p_leave.set_defaults(func=cmd_leave)

    p_list = sub.add_parser("list")
    p_list.add_argument("--project", default="")
    p_list.add_argument("--room", default="")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)
    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
