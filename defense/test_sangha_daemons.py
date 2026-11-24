"""Regression and latency tests for Sangha watch/route daemons."""
from __future__ import annotations

import builtins
import threading
import time
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import sangha_route
import sangha_watch


def _write_post(
    board: Path,
    name: str,
    *,
    title: str = "Test dispatch",
    author: str = "codex",
    target: str = "@antigravity",
    post_type: str = "note",
    stamp: str = "2026-11-24T22:00:00Z",
    hop: int | None = None,
) -> Path:
    lines = [
        f"# {title}",
        "",
        f"> Posted by {author} on t4800-s at {stamp}",
        f"> Target: {target}",
        f"> Type: {post_type}",
    ]
    if hop is not None:
        lines.append(f"> Hop: {hop}")
    lines.extend(["", "Body text."])
    p = board / name
    with p.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return p


def test_watch_records_non_target_and_self_without_reread(tmp_path: Path, monkeypatch) -> None:
    board = tmp_path / "board"
    board.mkdir()
    db = sangha_watch.open_db(tmp_path / "antigravity.sqlite3")

    for i in range(18):
        _write_post(board, f"2026-11-24-{100 + i}-codex-other.md", target="@opencode")
    _write_post(board, "2026-11-24-118-antigravity-self.md", author="antigravity", target="@all")
    _write_post(board, "2026-11-24-119-codex-hit.md", author="codex", target="@antigravity", post_type="note")

    delivered_events: list[tuple[str, str]] = []
    monkeypatch.setattr(
        sangha_watch,
        "notify",
        lambda seat, path, content, cmd, desktop_notify=False, post_type=None: delivered_events.append(
            (path.name, str(post_type))
        ),
    )

    seen_cache = sangha_watch.load_seen(db)
    count1 = sangha_watch.scan("antigravity", db, None, board=board, seen_cache=seen_cache)
    assert count1 == 1
    assert delivered_events == [("2026-11-24-119-codex-hit.md", "note")]
    assert len(seen_cache) == 20
    seen_rows = dict(db.execute("SELECT file, status FROM seen").fetchall())
    assert seen_rows["2026-11-24-100-codex-other.md"] == "non_target"
    assert seen_rows["2026-11-24-118-antigravity-self.md"] == "self"
    assert seen_rows["2026-11-24-119-codex-hit.md"] == "delivered"

    opened_board_files: list[str] = []
    real_open = builtins.open

    def spy_open(file, *args, **kwargs):
        fstr = str(file)
        if str(board) in fstr:
            opened_board_files.append(fstr)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy_open)
    count2 = sangha_watch.scan("antigravity", db, None, board=board, seen_cache=seen_cache)
    assert count2 == 0
    assert opened_board_files == []


def test_watch_filters_skip_types_by_default(tmp_path: Path, monkeypatch) -> None:
    board = tmp_path / "board"
    board.mkdir()
    _write_post(board, "2026-11-24-200-codex-claim.md", post_type="claim", target="@antigravity")
    _write_post(board, "2026-11-24-201-codex-rel.md", post_type="release", target="@antigravity")
    _write_post(board, "2026-11-24-202-codex-flag.md", post_type="flag", target="@antigravity")

    seen_deliveries: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        sangha_watch,
        "notify",
        lambda seat, path, content, cmd, desktop_notify=False, post_type=None: seen_deliveries.append(
            (path.name, post_type)
        ),
    )

    db1 = sangha_watch.open_db(tmp_path / "default.sqlite3")
    count1 = sangha_watch.scan("antigravity", db1, None, board=board)
    assert count1 == 1
    assert seen_deliveries == [("2026-11-24-202-codex-flag.md", "flag")]
    statuses = dict(db1.execute("SELECT file, status FROM seen").fetchall())
    assert statuses["2026-11-24-200-codex-claim.md"] == "type_filtered"
    assert statuses["2026-11-24-201-codex-rel.md"] == "type_filtered"

    seen_deliveries.clear()
    db2 = sangha_watch.open_db(tmp_path / "all_types.sqlite3")
    count2 = sangha_watch.scan("antigravity", db2, None, board=board, skip_types=frozenset())
    assert count2 == 3
    assert len(seen_deliveries) == 3


def test_route_skips_known_done_and_requeues_via_data_version(tmp_path: Path) -> None:
    board = tmp_path / "board"
    board.mkdir()
    db_path = tmp_path / "route.sqlite3"
    db = sangha_route.open_state(db_path)

    _write_post(board, "2026-11-24-300-codex-unrouted.md", target="@codex")
    target_name = "2026-11-24-301-codex-wake.md"
    _write_post(board, target_name, target="@opencode", post_type="handoff")

    cfg = {
        "max_hop": 3,
        "max_age_s": None,
        "skip_types": ["claim", "release"],
        "idle_fresh_s": 120,
        "min_wake_interval_s": 15,
        "max_retries": 2,
        "routes": {
            "@opencode": {
                "targets": ["@opencode"],
                "window": "OC \\|",
                "doorbell": "sangha read {seq}",
                "agent": "opencode",
                "idle_gate": True,
                "enabled": True,
            }
        },
    }

    wakes: list[str] = []
    known_done = sangha_route.load_known_done(db)
    res1 = sangha_route.scan_once(
        board,
        db,
        cfg,
        max_hop=3,
        wake_fn=lambda route, doorbell: wakes.append(doorbell),
        fleet_fn=lambda: {"digests": [{"agent": "opencode", "state": "idle", "freshness_s": 5}]},
        emit_fn=lambda ev: None,
        clock=lambda: 1000.0,
        known_done=known_done,
    )
    assert res1 == {"wake": 1, "skip": 1, "defer": 0, "would_wake": 0, "error": 0}
    assert wakes == ["sangha read 301"]
    assert "2026-11-24-300-codex-unrouted.md" in known_done
    assert target_name in known_done

    # Dead-letter a busy target after max_retries=2, then simulate external requeue
    dead_name = "2026-11-24-302-codex-dead.md"
    _write_post(board, dead_name, target="@opencode", post_type="question")
    for _ in range(2):
        res_busy = sangha_route.scan_once(
            board,
            db,
            cfg,
            max_hop=3,
            wake_fn=lambda route, doorbell: wakes.append(doorbell),
            fleet_fn=lambda: {"digests": [{"agent": "opencode", "state": "working", "freshness_s": 2}]},
            emit_fn=lambda ev: None,
            clock=lambda: 1020.0,
            known_done=known_done,
        )
        assert res_busy["defer"] == 1
    assert dead_name in known_done

    v_before = db.execute("PRAGMA data_version").fetchone()[0]
    ext_db = sangha_route.open_state(db_path)
    try:
        requeued = sangha_route.requeue_dead(ext_db, emit_fn=lambda ev: None)
    finally:
        ext_db.close()
    assert requeued == 1

    v_after = db.execute("PRAGMA data_version").fetchone()[0]
    assert v_after != v_before
    known_done = sangha_route.load_known_done(db)
    assert dead_name not in known_done

    res_recovered = sangha_route.scan_once(
        board,
        db,
        cfg,
        max_hop=3,
        wake_fn=lambda route, doorbell: wakes.append(doorbell),
        fleet_fn=lambda: {"digests": [{"agent": "opencode", "state": "idle", "freshness_s": 10}]},
        emit_fn=lambda ev: None,
        clock=lambda: 2000.0,
        known_done=known_done,
    )
    assert res_recovered["wake"] == 1
    assert wakes[-1] == "sangha read 302"


def test_board_inotify_wakes_under_100ms(tmp_path: Path) -> None:
    board = tmp_path / "board"
    board.mkdir()
    with sangha_watch.BoardInotify(board) as watcher:
        assert watcher.fd is not None

        def delayed_write() -> None:
            time.sleep(0.025)
            with (board / "2026-11-24-999-codex-wake.md").open("w", encoding="utf-8") as fh:
                fh.write("# Ping\n")

        writer = threading.Thread(target=delayed_write, daemon=True)
        writer.start()
        t0 = time.perf_counter()
        woken = watcher.wait(2.0)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        writer.join(timeout=1.0)

    assert woken is True
    assert elapsed_ms < 250.0
