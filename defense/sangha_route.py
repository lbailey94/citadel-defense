#!/usr/bin/env python3
"""Targeted wake router for the Sangha Whiteboard.

Watches the canonical board for posts addressed to routed targets and rings a
doorbell in the target's window: a fixed, operator-configured command such as
`sangha read <seq>`. Post content is never typed, shell-evaluated, or passed
through the wake channel. The post stays on the board; the woken agent pulls it.

Loop dampening: self-wakes skipped, hop budget enforced (`Hop: N` marker in a
post, default max 3), coordination types skipped, per-route wake rate limit,
bounded retries, and an idle gate against the bridge fleet view.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BOARD = ROOT / "board"
DEFAULT_CONFIG = Path.home() / ".config" / "sangha" / "routes.json"
DEFAULT_STATE = (Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
                 / "sangha" / "route" / "state.sqlite3")
BRIDGE_URL = "http://127.0.0.1:8787"
DEFAULT_DOORBELL = "sangha read {seq}"

SEQ_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-(\d+)-")
TITLE_RE = re.compile(r"^#\s+(.+)$")
AUTHOR_RE = re.compile(r"^>\s*Posted by\s+(.+?)\s+on\s+", re.IGNORECASE)
STAMP_RE = re.compile(r"^>\s*Posted by\s+.+?\s+on\s+.+?\s+at\s+(\S+)", re.IGNORECASE)
TARGET_RE = re.compile(r"^>\s*Target:\s*(\S+)", re.IGNORECASE)
TYPE_RE = re.compile(r"^>\s*Type:\s*([A-Za-z_-]+)", re.IGNORECASE)
HOP_RE = re.compile(r"^>?\s*Hop:\s*(\d+)\s*$", re.MULTILINE | re.IGNORECASE)
THREAD_RE = re.compile(r"^>?\s*Thread:\s*(\S+)\s*$", re.MULTILINE | re.IGNORECASE)
DOORBELL_OK_RE = re.compile(r"^[\w @:./#?&=%+-]+$")
_LOG_PATH = None


def set_log_file(path):
    global _LOG_PATH
    _LOG_PATH = Path(path) if path else None
    if _LOG_PATH:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def emit(event):
    event.setdefault("ts", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    line = json.dumps(event)
    print(line, flush=True)
    if _LOG_PATH:
        try:
            with _LOG_PATH.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def parse_post(path):
    """Header + loop metadata from a board post file."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    post = {"path": Path(path), "file": Path(path).name, "seq": None, "title": None,
            "author": None, "target": None, "type": None, "hop": 0, "thread": None,
            "stamp": None, "text": text}
    m = SEQ_RE.match(post["file"])
    if m:
        post["seq"] = int(m.group(2))
    for line in text.splitlines()[:12]:
        if post["title"] is None:
            mt = TITLE_RE.match(line)
            if mt:
                post["title"] = mt.group(1).strip()
                continue
        ms = STAMP_RE.match(line)
        if ms:
            post["stamp"] = ms.group(1).strip()
        ma = AUTHOR_RE.match(line)
        if ma:
            post["author"] = ma.group(1).strip()
            continue
        mtg = TARGET_RE.match(line)
        if mtg:
            post["target"] = mtg.group(1).strip()
            continue
        mty = TYPE_RE.match(line)
        if mty:
            post["type"] = mty.group(1).strip().lower()
    mh = HOP_RE.search(text)
    if mh:
        post["hop"] = int(mh.group(1))
    mth = THREAD_RE.search(text)
    if mth:
        post["thread"] = mth.group(1)
    return post


def match_route(target, routes):
    if not target:
        return None, None
    wanted = target.lower()
    for name, route in routes.items():
        if wanted in [t.lower() for t in route.get("targets", [name])]:
            return name, route
    return None, None


def _parse_stamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def evaluate(post, cfg, max_hop, now=None):
    """Routing verdict before idle/rate/wake side effects."""
    name, route = match_route(post.get("target"), cfg["routes"])
    if route is None:
        return {"action": "skip", "reason": "no_route", "route_name": None, "route": None}
    if not route.get("enabled", True):
        return {"action": "skip", "reason": "route_disabled", "route_name": name, "route": route}
    max_age = cfg.get("max_age_s")
    stamp = _parse_stamp(post.get("stamp"))
    if max_age is not None and stamp is not None:
        age = (now or datetime.now(timezone.utc)) - stamp
        if age.total_seconds() > max_age:
            return {"action": "skip", "reason": "stale", "route_name": name, "route": route}
    agent = (route.get("agent") or "").lower()
    author = (post.get("author") or "").lower()
    if agent and agent in author:
        return {"action": "skip", "reason": "self_wake", "route_name": name, "route": route}
    if (post.get("type") or "") in set(cfg.get("skip_types") or []):
        return {"action": "skip", "reason": "type_filtered", "route_name": name, "route": route}
    if post.get("hop", 0) >= max_hop:
        return {"action": "skip", "reason": "hop_exhausted", "route_name": name, "route": route}
    return {"action": "wake", "reason": None, "route_name": name, "route": route}


def render_doorbell(template, seq):
    if seq is None:
        raise ValueError("post has no sequence number")
    text = template.replace("{seq}", str(seq))
    if "{" in text or "}" in text:
        raise ValueError(f"unresolved placeholder in doorbell: {text!r}")
    if not DOORBELL_OK_RE.match(text):
        raise ValueError(f"unsafe character in doorbell: {text!r}")
    return text


def target_busy(fleet, agent, title_sub, fresh_s):
    """True when the routed session is currently mid-turn (fresh working state)."""
    agent = (agent or "").lower()
    title_sub = (title_sub or "").lower()
    for item in (fleet or {}).get("digests", []):
        if (item.get("agent") or "").lower() != agent:
            continue
        if title_sub and title_sub not in (item.get("title") or "").lower():
            continue
        state = (item.get("state") or "").lower()
        fresh = item.get("freshness_s")
        if state == "working" and (fresh is None or fresh <= fresh_s):
            return True
    return False


def fetch_fleet(timeout=3.0, window_min=45):
    url = f"{BRIDGE_URL}/api/fleet?window_min={window_min}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def open_state(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE IF NOT EXISTS delivered (file TEXT PRIMARY KEY, at TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS skipped (file TEXT PRIMARY KEY, reason TEXT NOT NULL, at TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS attempts (file TEXT PRIMARY KEY, n INTEGER NOT NULL, at TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS last_wake (route TEXT PRIMARY KEY, at REAL NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.commit()
    return db


def load_config(path):
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    cfg.setdefault("max_hop", 3)
    cfg.setdefault("poll_s", 3.0)
    cfg.setdefault("idle_fresh_s", 120)
    cfg.setdefault("max_retries", 3)
    cfg.setdefault("min_wake_interval_s", 15)
    cfg.setdefault("max_age_s", 3600)
    cfg.setdefault("skip_types", ["claim", "release"])
    cfg.setdefault("wake_prefix", [str(Path.home() / ".local" / "bin" / "say")])
    routes = cfg.setdefault("routes", {})
    for name, route in routes.items():
        route.setdefault("targets", [name])
        if route.get("enabled", True) and not route.get("window"):
            raise ValueError(f"route {name!r} has no window pattern")
    return cfg


def default_wake(cfg):
    prefix = cfg["wake_prefix"]

    def _wake(route, doorbell):
        subprocess.run([*prefix, route["window"], doorbell], check=True, timeout=15)

    return _wake


def _record_attempt(db, file, cfg):
    row = db.execute("SELECT n FROM attempts WHERE file=?", (file,)).fetchone()
    n = (row[0] if row else 0) + 1
    db.execute("INSERT INTO attempts(file,n,at) VALUES(?,?,datetime('now')) "
               "ON CONFLICT(file) DO UPDATE SET n=?, at=datetime('now')", (file, n, n))
    if n >= cfg.get("max_retries", 3):
        db.execute("INSERT OR IGNORE INTO skipped(file,reason,at) VALUES(?,?,datetime('now'))",
                   (file, "dead_letter"))
        return n, True
    return n, False


def scan_once(board, db, cfg, *, max_hop, dry=False, wake_fn=None, fleet_fn=None,
              emit_fn=emit, clock=time.time):
    board = Path(board)
    wake_fn = wake_fn or default_wake(cfg)
    fleet_fn = fleet_fn or fetch_fleet
    results = {"wake": 0, "skip": 0, "defer": 0, "would_wake": 0, "error": 0}
    fleet = None

    def busy(route):
        nonlocal fleet
        if not route.get("idle_gate", True):
            return False
        if fleet is None:
            try:
                fleet = fleet_fn()
            except Exception:
                fleet = {}
        return target_busy(fleet, route.get("agent"), route.get("session_title"),
                           cfg.get("idle_fresh_s", 120))

    for path in sorted(board.glob("*.md")):
        file = path.name
        if db.execute("SELECT 1 FROM delivered WHERE file=?", (file,)).fetchone():
            continue
        if db.execute("SELECT 1 FROM skipped WHERE file=?", (file,)).fetchone():
            continue
        plugin_marker = Path.home() / ".local" / "state" / "sangha" / "plugin" / "markers" / file
        if plugin_marker.exists():
            continue
        post = parse_post(path)
        if post is None:
            continue
        verdict = evaluate(post, cfg, max_hop)
        route = verdict["route"]
        base = {"file": file, "seq": post.get("seq"), "route": verdict["route_name"],
                "target": post.get("target"), "hop": post.get("hop")}
        if verdict["action"] == "skip":
            db.execute("INSERT OR IGNORE INTO skipped(file,reason,at) VALUES(?,?,datetime('now'))",
                       (file, verdict["reason"]))
            db.commit()
            results["skip"] += 1
            emit_fn({**base, "event": "skip", "reason": verdict["reason"]})
            continue
        if busy(route):
            n, dead = _record_attempt(db, file, cfg)
            db.commit()
            results["defer"] += 1
            emit_fn({**base, "event": "defer", "reason": "target_busy", "attempt": n,
                     "dead_letter": dead})
            continue
        last = db.execute("SELECT at FROM last_wake WHERE route=?", (verdict["route_name"],)).fetchone()
        gap = cfg.get("min_wake_interval_s", 15)
        if last and clock() - last[0] < gap:
            n, dead = _record_attempt(db, file, cfg)
            db.commit()
            results["defer"] += 1
            emit_fn({**base, "event": "defer", "reason": "rate_limited", "attempt": n,
                     "dead_letter": dead})
            continue
        try:
            doorbell = render_doorbell(route.get("doorbell", DEFAULT_DOORBELL), post.get("seq"))
        except ValueError as exc:
            db.execute("INSERT OR IGNORE INTO skipped(file,reason,at) VALUES(?,?,datetime('now'))",
                       (file, "bad_doorbell"))
            db.commit()
            results["error"] += 1
            emit_fn({**base, "event": "error", "reason": "bad_doorbell", "detail": str(exc)})
            continue
        if dry:
            results["would_wake"] += 1
            emit_fn({**base, "event": "would_wake", "doorbell": doorbell})
            continue
        try:
            wake_fn(route, doorbell)
        except Exception as exc:
            n, dead = _record_attempt(db, file, cfg)
            db.commit()
            results["error"] += 1
            emit_fn({**base, "event": "wake_failed", "reason": str(exc), "attempt": n,
                     "dead_letter": dead})
            continue
        db.execute("INSERT OR IGNORE INTO delivered(file,at) VALUES(?,datetime('now'))", (file,))
        db.execute("INSERT INTO last_wake(route,at) VALUES(?,?) "
                   "ON CONFLICT(route) DO UPDATE SET at=?", (verdict["route_name"], clock(), clock()))
        db.commit()
        results["wake"] += 1
        emit_fn({**base, "event": "wake", "doorbell": doorbell})
    return results


def cmd_status(db):
    delivered = db.execute("SELECT COUNT(*) FROM delivered").fetchone()[0]
    skipped = dict(db.execute("SELECT reason, COUNT(*) FROM skipped GROUP BY reason").fetchall())
    pending = [{"file": f, "attempts": n, "last": at} for f, n, at in db.execute(
        "SELECT a.file, a.n, a.at FROM attempts a LEFT JOIN skipped s ON s.file=a.file "
        "WHERE s.file IS NULL ORDER BY a.at DESC LIMIT 20").fetchall()]
    last_wakes = [{"route": r, "at": datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
                  for r, at in db.execute("SELECT route, at FROM last_wake ORDER BY at DESC").fetchall()]
    summary = {"delivered": delivered, "skipped": skipped, "pending": pending, "last_wakes": last_wakes}
    print(json.dumps(summary, indent=2))


def requeue_dead(db, emit_fn=emit):
    rows = [r[0] for r in db.execute("SELECT file FROM skipped WHERE reason='dead_letter'").fetchall()]
    for file in rows:
        db.execute("DELETE FROM skipped WHERE file=? AND reason='dead_letter'", (file,))
        db.execute("DELETE FROM attempts WHERE file=?", (file,))
    db.commit()
    emit_fn({"event": "requeue_dead", "count": len(rows), "files": rows})
    return len(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--board", default=str(BOARD))
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    parser.add_argument("--interval", type=float, help="seconds between scans")
    parser.add_argument("--once", action="store_true", help="scan once and exit")
    parser.add_argument("--dry-run", action="store_true", help="decide and log, never wake")
    parser.add_argument("--max-hop", type=int, help="override config hop budget")
    parser.add_argument("--no-idle-gate", action="store_true")
    parser.add_argument("--log", help="also append JSON events to this file")
    parser.add_argument("--max-age", type=float, help="skip posts older than N seconds")
    parser.add_argument("--status", action="store_true", help="print state summary and exit")
    parser.add_argument("--requeue-dead", action="store_true", help="clear dead-letter entries and exit")
    args = parser.parse_args()

    if args.log:
        set_log_file(args.log)
    state = Path(args.state)
    db = open_state(state)
    if args.status:
        cmd_status(db)
        return
    if args.requeue_dead:
        requeue_dead(db)
        return

    try:
        cfg = load_config(Path(args.config))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.exit(f"config error: {exc}")
    if args.max_age is not None:
        cfg["max_age_s"] = args.max_age
    if args.no_idle_gate:
        for route in cfg["routes"].values():
            route["idle_gate"] = False
    max_hop = args.max_hop if args.max_hop is not None else cfg["max_hop"]
    board = Path(args.board)
    if not board.is_dir():
        sys.exit(f"board directory not found: {board}")

    state.parent.mkdir(parents=True, exist_ok=True)
    lock = (state.parent / "lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit("another sangha_route instance holds the lock")

    if not db.execute("SELECT 1 FROM meta WHERE key='baseline_done'").fetchone():
        count = 0
        for path in sorted(board.glob("*.md")):
            db.execute("INSERT OR IGNORE INTO skipped(file,reason,at) VALUES(?,?,datetime('now'))",
                       (path.name, "baseline"))
            count += 1
        db.execute("INSERT INTO meta(key,value) VALUES('baseline_done',datetime('now'))")
        db.commit()
        emit({"event": "baseline", "count": count, "dry_run": args.dry_run})

    interval = args.interval if args.interval is not None else cfg["poll_s"]
    while True:
        scan_once(board, db, cfg, max_hop=max_hop, dry=args.dry_run)
        if args.once:
            break
        time.sleep(max(1.0, interval))


if __name__ == "__main__":
    main()
