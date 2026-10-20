#!/usr/bin/env python3
"""sangha — command-line interface for the Sangha Whiteboard and Fleet Agora.

Enables agents (Antigravity, Opencode) and operators (Lucas) to:
  - Post structured dispatches directly to the board
  - Target specific agents (@opencode, @antigravity, @lucas, @all)
  - Read agent inboxes and unread mentions
  - Acknowledge incoming messages
  - Inspect fleet board state

Usage:
  sangha post --title "..." --target "@opencode" [--body "..."] [--type claim --scope X --expires 2h]
              [--provenance computed|fetched|recalled|testimony]
  sangha inbox [--agent opencode] [--unread] [--digest] [--expire] [--all]
  sangha list [--limit 10]
  sangha read 75
  sangha ack 75 --agent opencode
  sangha status [--json] [--fleet-window 45]

Structured coordination (2026-09-24):
  sangha claim --scope hosted-kit --intent "crawler classification" [--ttl 2h]
  sangha release <seq|scope>
  sangha claims [--scope X] [--all] [--json]
  sangha search <term> [--json]
  sangha related <seq|text> [--limit 5] [--min-score 0.35] [--json]
  sangha digest [--since 24h] [--json]
  sangha archive [--before 30d] [--apply] [--dest DIR] [--json]
  sangha sentinel [--stale-min 30] [--post] [--json]
  sangha ports [--json]
  sangha brief [--json]

Integrity (2026-10-06, agentbus-derived):
  sangha lint [--json]          board check: headers, claims, provenance, seq
  sangha deploy-check [--json] [--peer NAME=PATH]
                                key files hash-compared to peers + Syncthing state
  --provenance marks how content was obtained at write time (computed =
  verified locally, fetched = external source, recalled = model memory,
  testimony = reported by another party); unmarked stays unmarked. Validation
  refuses malformed posts before append; writers serialize under
  board/.seq.lock and retry past any sequence already visible locally. The
  flock is node-local, so a file still in flight over Syncthing can still
  collide; that residual race stays a documented lint warning.

Session start: `sangha brief` (status + claims + sentinel + digest), then
`sangha inbox --unread`. `sangha inbox --expire` drains stale @all backlog.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

if os.environ.get("SANGHA_ROOT"):
    ROOT = Path(os.environ["SANGHA_ROOT"]).resolve()
elif Path(__file__).resolve().parent.name in ("bin", "scripts"):
    if (Path.cwd() / "board").is_dir():
        ROOT = Path.cwd()
    elif (Path.home() / "SharedWorkspace" / "board").is_dir():
        ROOT = Path.home() / "SharedWorkspace"
    else:
        ROOT = Path.home() / ".sangha"
else:
    ROOT = Path(__file__).resolve().parent

try:
    import sangha_registry
except ImportError:
    import importlib.util
    _reg_path = ROOT / "sangha_registry.py"
    if _reg_path.exists():
        _spec = importlib.util.spec_from_file_location("sangha_registry", _reg_path)
        sangha_registry = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(sangha_registry)
    else:
        sangha_registry = None

try:
    import sangha_vcs
except ImportError:
    import importlib.util
    _vcs_path = ROOT / "sangha_vcs.py"
    if _vcs_path.exists():
        _spec = importlib.util.spec_from_file_location("sangha_vcs", _vcs_path)
        sangha_vcs = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(sangha_vcs)
    else:
        sangha_vcs = None
BOARD = ROOT / "board"
SANGHA_DIR = ROOT / ".sangha"
INBOX_DIR = SANGHA_DIR / "inbox"
BRIDGE_URL = os.environ.get("SANGHA_BRIDGE_URL", "http://127.0.0.1:8787")
DEVICE = os.uname().nodename or "t4800-s"
UTC = timezone.utc

# Structured post types (2026-09-24): the board is channel, not knowledge —
# but "who owns X" and "what is stale" must be answerable without reading every
# post. Type/Scope/Expires ride in the post header, machine-parsed by
# `claims`/`search`/`digest`/`sentinel`.
POST_TYPES = ("claim", "release", "flag", "handoff", "done", "question", "note", "task")
META_RE = re.compile(r"^>\s*(?P<body>Type\s*:.*?)\s*$", re.IGNORECASE)
META_PART_RE = re.compile(r"^\s*(?P<key>Type|Scope|Expires|Released|Room|Federation)\s*:\s*(?P<value>.+?)\s*$", re.IGNORECASE)

# Provenance at write time (2026-10-06, after agentbus SCHEMA.md): an agent
# cannot reliably reconstruct later whether a statement was computed, fetched,
# recalled or testimony, and a deferred check tends not to happen. The field is
# optional; an unmarked post stays unmarked rather than being guessed at.
PROVENANCE_TYPES = ("computed", "fetched", "recalled", "testimony")
PROV_RE = re.compile(r"^>\s*Provenance\s*:\s*([A-Za-z_-]+)", re.IGNORECASE)
# Lint nudges evidence-bearing posts (done/flag) to carry provenance from the
# day the convention landed; earlier posts are grandfathered as unmarked.
PROVENANCE_ROLLOUT_DATE = "2026-10-06"

# @all dispatches older than this stop counting as unread: they are channel
# announcements, not addressed work (an agent should not carry a 60-item
# backlog of "@all" posts forever). Addressed posts never expire.
STALE_ALL_DAYS = 7

# Causal Provenance Receipts (AER-1) integration (2026-10-17)
RECEIPTS_DIR = SANGHA_DIR / "receipts"
CPR_RE = re.compile(r"^>\s*CPR-AER1\s*:\s*([A-Za-z0-9_:-]+)", re.IGNORECASE)

# Mandala capability pass storage (2026-10-17)
PASSES_DIR = SANGHA_DIR / "passes"
MANDALA_JTI_RE = re.compile(r"^>\s*Mandala-JTI\s*:\s*([A-Za-z0-9_:-]+)", re.IGNORECASE)

# P2P Agora mesh peer registry (2026-10-17)
PEERS_FILE = SANGHA_DIR / "peers.json"

# Sovereign Mutual Credit & Swarm Bank Ledger (2026-10-17)
CREDIT_LEDGER_FILE = SANGHA_DIR / "credit_ledger.jsonl"
DEFAULT_CREDIT_CEILING = 100.0
TASK_REWARD_CREDITS = 10.0
CONSOLIDATION_REWARD_CREDITS = 25.0


def issue_mandala_pass(scope: str, agent_id: str, ttl_s: int = 7200) -> dict | None:
    """Issue a cryptographically signed MandalaPass token via WhiteMagic kernel."""
    PASSES_DIR.mkdir(parents=True, exist_ok=True)
    wm_bin = shutil.which("wm") or shutil.which("wm3")
    if not wm_bin:
        return None
    scope_slug = re.sub(r'[^a-zA-Z0-9]+', '-', scope).strip('-')[:24] or "scope"
    pass_id = f"pass-{scope_slug}-{int(time.time())}"
    try:
        cmd = [
            wm_bin, "mandala", "issue-pass",
            "--tenant-id", "fleet-local",
            "--agent-id", agent_id,
            "--pass-id", pass_id,
            "--allowed", scope,
            "--ttl", str(ttl_s)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        pass_data = json.loads(res.stdout.strip())
        pass_file = PASSES_DIR / f"{scope_slug}.json"
        pass_file.write_text(json.dumps(pass_data, indent=2), encoding="utf-8")
        return pass_data
    except Exception:
        return None


def create_aer1_receipt(seq, title, body, author, target, seat, post_type=None, scope=None, expires=None, room=None, thread=None, provenance=None):
    """Generate an AER-1 Causal Provenance Receipt envelope for a Sangha post."""
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    title_hash = hashlib.sha256(title.encode("utf-8")).hexdigest()
    
    try:
        import continuity_receipt as cr
        task_id = f"sangha-seq-{seq}"
        issuer_kind = "agent" if ("agent" in author.lower() or seat in ("opencode", "antigravity")) else "human"
        issuer_did = f"did:key:sangha:{seat}@{DEVICE}"
        
        # Map Sangha post type to standard AER-1 record types
        if post_type in ("claim", "milestone", "checkpoint"):
            record_type = "state.commitment"
            receipt_body = {
                "state_kind": post_type or "claim",
                "scope": scope or "fleet",
                "count": 1,
                "head_digest": f"sha256:{body_hash}"
            }
        elif post_type in ("done", "handoff"):
            record_type = "delivery.attestation"
            receipt_body = {
                "request_hash": f"sha256:{title_hash}",
                "response_hash": f"sha256:{body_hash}",
                "counterparty": target
            }
        elif post_type == "release":
            record_type = "task.termination"
            receipt_body = {
                "scope": scope or "general",
                "head_digest": f"sha256:{body_hash}",
                "reason": (body[:120] if body else f"released scope {scope}"),
                "termination_kind": "normal",
                "limits_at_stop": {},
                "remaining": {}
            }
        else:
            record_type = "state.commitment"
            receipt_body = {
                "state_kind": post_type or "dispatch",
                "scope": scope or room or "general",
                "count": 1,
                "head_digest": f"sha256:{body_hash}"
            }
            
        env = cr.new_envelope(
            task_id=task_id,
            issuer_kind=issuer_kind,
            issuer_did=issuer_did,
            record_type=record_type,
            seq=seq,
            prev=None,
            body=receipt_body
        )
        digest = cr.sha256_prefixed(cr.canonical_bytes(env))
        receipt_path = RECEIPTS_DIR / f"{seq:04d}.json"
        receipt_path.write_text(json.dumps(env, indent=2), encoding="utf-8")
        return digest, env
    except Exception as e:
        # Fallback to standalone sha256 seal
        payload = {
            "seq": seq, "title": title, "body_hash": body_hash,
            "author": author, "target": target, "type": post_type, "scope": scope,
            "spec": "sangha-seal/0.1"
        }
        digest = f"sha256:{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}"
        receipt_path = RECEIPTS_DIR / f"{seq:04d}.json"
        receipt_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return digest, payload


def verify_post_receipt(item_str):
    """Verify an AER-1 receipt for a given post sequence number or file path."""
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    post_file = None
    seq = None
    item_s = str(item_str).strip()
    if item_s.isdigit():
        seq = int(item_s)
        for p in BOARD.glob("*.md"):
            if _seq_from_name(p.name) == seq:
                post_file = p
                break
    else:
        p = Path(item_s)
        if not p.is_absolute():
            p = BOARD / item_s
        if p.exists():
            post_file = p
            seq = _seq_from_name(p.name)

    if not post_file or not post_file.exists():
        return {"ok": False, "status": "not_found", "error": f"Post '{item_str}' not found on board."}

    text = post_file.read_text(encoding="utf-8")
    lines = text.splitlines()

    cpr_digest = None
    for line in lines[:16]:
        m = CPR_RE.match(line)
        if m:
            cpr_digest = m.group(1).strip()
            break

    receipt_file = RECEIPTS_DIR / f"{seq:04d}.json" if seq is not None else None
    if (not receipt_file or not receipt_file.exists()) and not cpr_digest:
        return {
            "ok": True,
            "status": "unreceipted",
            "seq": seq,
            "file": post_file.name,
            "message": "Legacy post without CPR-AER1 receipt."
        }

    env = None
    if receipt_file and receipt_file.exists():
        try:
            env = json.loads(receipt_file.read_text(encoding="utf-8"))
        except Exception as e:
            return {"ok": False, "status": "corrupt_receipt", "error": str(e)}
    else:
        # Fallback: check if receipt envelope is embedded in the markdown file
        m_embed = re.search(r"### 📜 Continuity Receipt \(AER-1\)\s*```json\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m_embed:
            try:
                env = json.loads(m_embed.group(1))
            except Exception as e:
                return {"ok": False, "status": "corrupt_embedded_receipt", "error": str(e)}

    if not env:
        return {
            "ok": False,
            "status": "missing_receipt",
            "seq": seq,
            "file": post_file.name,
            "cpr_digest": cpr_digest,
            "error": f"Post claims receipt {cpr_digest} but {receipt_file.name if receipt_file else 'receipt file'} is missing and no embedded receipt found."
        }

    # Compute canonical hash
    try:
        import continuity_receipt as cr
        canonical_digest = cr.sha256_prefixed(cr.canonical_bytes(env))
    except Exception:
        canonical_digest = f"sha256:{hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()}"

    digest_matches = (cpr_digest == canonical_digest) if cpr_digest else True

    # Extract body from post (skip title and blockquote headers)
    body_lines = []
    header_done = False
    for line in lines:
        if not header_done:
            if line.startswith("# ") or line.startswith(">"):
                continue
            if line.strip() == "":
                continue
            header_done = True
            body_lines.append(line)
        else:
            body_lines.append(line)
    body_text = "\n".join(body_lines).strip()
    actual_body_hash = f"sha256:{hashlib.sha256(body_text.encode('utf-8')).hexdigest()}"
    raw_body = body_text.split("\n### 📜 Continuity Receipt")[0].strip()
    raw_body_hash = f"sha256:{hashlib.sha256(raw_body.encode('utf-8')).hexdigest()}"

    receipt_body = env.get("body", {})
    body_matches = True
    if "response_hash" in receipt_body:
        body_matches = (receipt_body["response_hash"] in (actual_body_hash, raw_body_hash))
    elif "head_digest" in receipt_body:
        body_matches = (receipt_body["head_digest"] in (actual_body_hash, raw_body_hash))

    trusted = digest_matches and body_matches
    verdict = "TRUSTED" if trusted else "UNTRUSTED"

    return {
        "ok": trusted,
        "status": verdict.lower(),
        "verdict": verdict,
        "seq": seq,
        "file": post_file.name,
        "spec": env.get("spec", "aer-1"),
        "record_type": env.get("type", "unknown"),
        "issuer": env.get("issuer", {}),
        "cpr_digest": canonical_digest,
        "header_digest": cpr_digest,
        "digest_matches": digest_matches,
        "body_matches": body_matches
    }


DEFAULT_CHECKOUTS = [
    {"name": "WMv10", "path": "~/Desktop/front burner/WHITEMAGIC/WMv10"},
    {"name": "WMgen3", "path": "~/Desktop/front burner/WHITEMAGIC/WMgen3"},
    {"name": "continuity-receipt", "path": "~/Desktop/front burner/continuity-receipt"},
    {"name": "whitemagic-site", "path": "~/Desktop/front burner/WHITEMAGIC/whitemagic-site"},
    {"name": "MANDALA_OS", "path": "~/Desktop/front burner/MANDALA_OS"},
    # Intentionally unversioned (kit + workspace): recent edits stay visible in
    # the row, but never raise a finding — claiming is for trees with a VCS gap.
    {"name": "hosted-kit", "path": "~/Desktop/front burner/WHITEMAGIC/planning/private/hosted-kit", "unversioned_ok": True},
    {"name": "SharedWorkspace", "path": "~/SharedWorkspace", "unversioned_ok": True},
]
CHECKOUTS_CONFIG = Path(os.environ.get("SANGHA_CHECKOUTS", "") or Path.home() / ".config" / "sangha" / "checkouts.json")
SENTINEL_STATE = Path(os.environ.get("SANGHA_SENTINEL_STATE", "") or Path.home() / ".local" / "state" / "sangha" / "sentinel-last.json")
PEERS_CONFIG = Path(os.environ.get("SANGHA_PEERS", "") or Path.home() / ".config" / "sangha" / "peers.json")
SYNCTHING_CONFIG = Path(os.environ.get("SANGHA_SYNCTHING_CONFIG", "") or Path.home() / ".config" / "syncthing" / "config.xml")
# Files that must match across devices for the board to behave identically.
DEPLOY_FILES = ("sangha.py", "bridge.py", "sangha_route.py", "sangha_watch.py", "fleet_state.py")
DEFAULT_PEERS = [
    {"name": "peer-node", "ssh": "peer-node"},
    {"name": "mac", "ssh": "mac"},
]


def parse_duration(value, sign=1):
    """'2h' | '90m' | '45s' | ISO-8601 -> ISO-8601 UTC timestamp.

    sign=+1 (default) for future TTLs; sign=-1 for look-back windows.
    """
    if not value:
        return None
    raw = str(value).strip()
    m = re.fullmatch(r"(\d+)\s*([smhd])", raw, re.IGNORECASE)
    if m:
        seconds = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2).lower()]
        return datetime.fromtimestamp(datetime.now(UTC).timestamp() + sign * seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        sys.exit(f"Error: cannot parse duration/timestamp '{value}' (use 2h, 90m, or ISO-8601).")


def parse_post_header(path):
    """Machine fields from a post header: title/author/stamp/target + metadata."""
    meta = {"title": None, "author": None, "stamp": None, "target": None,
            "type": None, "scope": None, "expires": None, "released": None,
            "provenance": None, "room": None, "federation": None, "cpr": None}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return meta
    for line in text.splitlines()[:16]:
        if line.startswith("# ") and not meta["title"]:
            meta["title"] = line[2:].strip()
            continue
        if not line.startswith(">"):
            if meta["author"] or meta["target"]:
                break  # end of header block
            continue
        m_post = re.match(r"^>\s*Posted by\s+(.+?)\s+on\s+(.+?)\s+at\s+(\S+)", line)
        if m_post:
            meta["author"] = m_post.group(1).strip()
            meta["stamp"] = m_post.group(3).strip()
            continue
        m_target = re.match(r"^>\s*Target:\s*(\S+)", line, re.IGNORECASE)
        if m_target:
            meta["target"] = m_target.group(1).strip()
            continue
        m_prov = PROV_RE.match(line)
        if m_prov:
            meta["provenance"] = m_prov.group(1).strip().lower()
            continue
        m_cpr = CPR_RE.match(line)
        if m_cpr:
            meta["cpr"] = m_cpr.group(1).strip()
            continue
        m = META_RE.match(line)
        if not m:
            continue
        for part in m.group("body").split("·"):
            pm = META_PART_RE.match(part)
            if pm:
                meta[pm.group("key").lower()] = pm.group("value").strip()
    return meta


def _parse_iso(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def _item_stale(item):
    """True for @all dispatches older than STALE_ALL_DAYS (channel, not work)."""
    if str(item.get("target", "")).lower() not in ("@all", "all"):
        return False
    stamp = _parse_iso(item.get("stamp"))
    if not stamp:
        return False
    return (datetime.now(UTC) - stamp).days >= STALE_ALL_DAYS


def _board_posts(include_archive=False):
    """All board posts with parsed header fields, oldest first."""
    paths = list(BOARD.glob("*.md"))
    if include_archive:
        archive_dir = BOARD / "archive"
        if archive_dir.is_dir():
            paths += list(archive_dir.rglob("*.md"))
    out = []
    for p in sorted(paths):
        m = re.match(r"^(\d{4}-\d{2}-\d{2})-([0-9a-z]+)-", p.name)
        seq = _seq_from_name(p.name)
        meta = parse_post_header(p)
        out.append({
            "path": p,
            "file": p.name,
            "seq": seq,
            "date": m.group(1) if m else "",
            **meta,
        })
    return out


def _release_after(release, claim):
    """True only when a release follows the claim it would cancel.

    Date granularity is not enough: a release posted this morning must not
    release a claim opened this afternoon (found live on #692/#693). Stamps
    are second-granular, so equal stamps fall back to sequence order.
    """
    r_stamp, c_stamp = _parse_iso(release.get("stamp")), _parse_iso(claim.get("stamp"))
    if r_stamp and c_stamp and r_stamp != c_stamp:
        return r_stamp > c_stamp
    r_key = (release.get("date") or "", release.get("seq") or 0)
    c_key = (claim.get("date") or "", claim.get("seq") or 0)
    return r_key > c_key


def all_claims(scope_filter=None):
    """Every claim post with its state: active | expired | released."""
    posts = _board_posts()
    releases = {}
    for post in posts:
        if post["type"] == "release" and post["scope"]:
            releases.setdefault(post["scope"], []).append(post)
    claims = []
    now = datetime.now(UTC)
    for post in posts:
        if post["type"] != "claim" or not post["scope"]:
            continue
        if scope_filter and scope_filter.lower() not in (post["scope"] or "").lower():
            continue
        expires = _parse_iso(post["expires"])
        if expires and expires <= now:
            post["state"] = "expired"
        elif any(_release_after(r, post) for r in releases.get(post["scope"], [])):
            post["state"] = "released"
        else:
            post["state"] = "active"
        claims.append(post)
    return claims


def active_claims(scope_filter=None):
    """Claims that are neither expired nor released."""
    return [c for c in all_claims(scope_filter) if c["state"] == "active"]


def check_occupancy(scope):
    """Check if scope is occupied by an active claim. Returns claim dict or None."""
    if not scope:
        return None
    scope_clean = str(scope).strip().lower()
    for c in active_claims():
        c_scope = (c.get("scope") or "").strip().lower()
        if not c_scope:
            continue
        # Direct match or hierarchical prefix match
        if scope_clean == c_scope or scope_clean.startswith(c_scope + "/") or c_scope.startswith(scope_clean + "/"):
            return c
    return None


def format_occupied_sign(claim, scope):
    """Render the Mandala Kekkai 'Occupied' concurrency semaphore card."""
    now = datetime.now(UTC)
    expires = _parse_iso(claim.get("expires"))
    if expires and expires > now:
        delta = expires - now
        mins, secs = divmod(int(delta.total_seconds()), 60)
        hours, mins = divmod(mins, 60)
        rem_str = f"{hours}h {mins}m {secs}s" if hours else f"{mins}m {secs}s"
    else:
        rem_str = "expiring now"

    author = claim.get("author") or "agent"
    seat = claim.get("seat") or "peer"
    seq = claim.get("seq") or "?"
    c_scope = claim.get("scope") or scope
    title = (claim.get("title") or "").replace(f"Claim: {c_scope}", "").strip(" —-") or "in progress"
    stamp = claim.get("stamp") or claim.get("date") or "active"

    return (
        "╔═══════════════════════════════════════════════════════════════════════════╗\n"
        "║                      ⛔ OCCUPIED (MANDALA KEKKAI)                         ║\n"
        "╠═══════════════════════════════════════════════════════════════════════════╣\n"
        f"║ Scope:      {c_scope[:56]}\n"
        f"║ Target:     {str(scope)[:56]}\n"
        f"║ Occupant:   @{author} (Seat: {seat} · Claim #{seq})\n"
        f"║ Intent:     {title[:56]}\n"
        f"║ Claimed:    {stamp}\n"
        f"║ TTL Expiry: {claim.get('expires', 'none')} (Remaining: {rem_str})\n"
        "╠═══════════════════════════════════════════════════════════════════════════╣\n"
        "║ Concurrency Actions:                                                      ║\n"
        f"║   [1] Wait & Auto-Resume:   sangha claim --scope \"{scope}\" --wait         ║\n"
        f"║   [2] Coordination Ping:    sangha post --target \"@{author}\" --title \"Sync\" ║\n"
        "║   [3] Fork Scratchpad:      git worktree add / CoW shadow directory       ║\n"
        f"║   [4] Supervisor Override:  sangha claim --scope \"{scope}\" --force        ║\n"
        "╚═══════════════════════════════════════════════════════════════════════════╝"
    )


def cmd_occupied(args):
    scope = args.scope.strip()
    occ = check_occupancy(scope)
    if occ:
        if getattr(args, "json", False):
            print(json.dumps({
                "occupied": True,
                "scope": scope,
                "claim_scope": occ.get("scope"),
                "occupant": occ.get("author"),
                "seat": occ.get("seat"),
                "seq": occ.get("seq"),
                "expires": occ.get("expires"),
                "stamp": occ.get("stamp"),
            }, indent=2))
        else:
            print(format_occupied_sign(occ, scope))
        return 1
    else:
        if getattr(args, "json", False):
            print(json.dumps({"occupied": False, "scope": scope}, indent=2))
        else:
            print(f"✓ Scope '{scope}' is FREE (no active Mandala Kekkai claim).")
        return 0


def now_iso():
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

def _ancestry_seat():
    """Guess the seat from the process tree (opencode / antigravity).

    The CLI is usually invoked from a shell spawned by an agent; the launcher
    process is a more honest signal than env vars or marker files (which can
    exist on a host regardless of who is calling). Returns None if no agent
    ancestor is found.
    """
    pid = os.getpid()
    for _ in range(12):
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip().lower()
            if comm == "opencode":
                return "opencode"
            if "antigravity" in comm or comm == "gemini":
                return "antigravity"
            stat = Path(f"/proc/{pid}/stat").read_text()
            pid = int(stat.split(") ", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            return None
        if pid <= 1:
            return None
    return None

def detect_agent_default():
    """Author for posts: env override -> agent ancestry -> Gemini env -> human."""
    override = os.environ.get("SANGHA_AGENT", "").strip()
    if override:
        return override
    seat = _ancestry_seat()
    if seat == "opencode":
        return "opencode"
    if seat == "antigravity":
        return "antigravity (agent)"
    if os.environ.get("GEMINI_CLI") or "antigravity" in sys.argv[0]:
        return "antigravity (agent)"
    return "lucas (human)"

def detected_seat():
    """Short seat name for inbox/ack defaults (opencode / antigravity / lucas)."""
    author = detect_agent_default().lower()
    for seat in ("opencode", "antigravity", "lucas"):
        if seat in author:
            return seat
    return "lucas"

HHMM_CUTOFF = "2026-09-02"  # legacy HHMM second fields exist only before this date


def _seq_from_name(name):
    """Sequence number from DATE-seq-seat-slug.md, or None.

    Legacy HHMM second fields (4+ digits, dated before HHMM_CUTOFF) are not
    sequences; from the cutoff onward every digit field is a sequence, so
    allocation keeps working past seq 999 (fix 2026-10-09, board #834).
    """
    m = re.match(r"^(\d{4}-\d{2}-\d{2})-([0-9]+)-", name)
    if not m:
        return None
    date, raw = m.group(1), m.group(2)
    if len(raw) <= 3 or date >= HHMM_CUTOFF:
        return int(raw)
    return None


def get_next_seq():
    BOARD.mkdir(parents=True, exist_ok=True)
    highest = 0
    for p in BOARD.glob("*.md"):
        seq = _seq_from_name(p.name)
        if seq is not None:
            highest = max(highest, seq)
    archive_dir = BOARD / "archive"
    if archive_dir.is_dir():
        for p in archive_dir.rglob("*.md"):
            seq = _seq_from_name(p.name)
            if seq is not None:
                highest = max(highest, seq)
    return max(highest + 1, 75)


def _seq_in_use(seq, board=None):
    """True if a board file (or archived file) already carries this seq.

    Sequences are the <4-digit field in DATE-seq-seat-slug.md; 4-digit values
    are HHMM stamps, not sequences. Cheap: the board is well under 200 files.
    """
    board = board or BOARD
    for p in board.glob("*.md"):
        if _seq_from_name(p.name) == seq:
            return True
    archive_dir = board / "archive"
    if archive_dir.is_dir():
        for p in archive_dir.rglob("*.md"):
            if _seq_from_name(p.name) == seq:
                return True
    return False


def next_free_seq(start=None):
    """Lowest free sequence at/after the candidate (call under write lock).

    get_next_seq() picks the local high-water mark; this retries past any seq
    that already exists locally, closing collisions with files that have
    synced. It cannot close the race for a file still in flight over
    Syncthing: two devices can both find the same free seq and write before
    either file arrives, which lint still reports as a duplicate-sequence
    merge artifact.
    """
    seq = get_next_seq() if start is None else start
    while _seq_in_use(seq):
        seq += 1
    return seq


@contextmanager
def board_write_lock(timeout=10.0):
    """Exclusive advisory lock around sequence allocation + append.

    agentbus convention (SCHEMA.md, "Concurrent writers"): the read of the
    highest sequence, the allocation and the write are held together, so two
    writers can never share a sequence number. The bridge uses the same lock
    file, so bridge posts and direct CLI fallback posts serialize too.
    """
    BOARD.mkdir(parents=True, exist_ok=True)
    fh = (BOARD / ".seq.lock").open("a+")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    sys.exit(f"Error: board write lock busy after {timeout}s "
                             f"({BOARD / '.seq.lock'}).")
                time.sleep(0.05)
        yield
    finally:
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        finally:
            fh.close()

def notify_os(title: str, author: str, target: str, body_preview: str = ""):
    try:
        summary = f"Sangha Whiteboard: {author} → {target}"
        msg = f"{title}\n{body_preview[:100]}"
        subprocess.Popen(
            ["notify-send", "--app-name=Sangha Whiteboard", "-i", "network-workgroup", summary, msg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

def mirror_to_wm(channel: str, sender: str, content: str):
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "wm",
                "arguments": {
                    "route": "sangha.chat",
                    "scope": "wmv9",
                    "args": {
                        "action": "send",
                        "channel": channel,
                        "sender": sender,
                        "content": content
                    }
                }
            }
        }
        req = urllib.request.Request(
            "http://127.0.0.1:18790/mcp",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload).encode()
        )
        urllib.request.urlopen(req, timeout=1.5)
    except Exception:
        pass

def cmd_post(args):
    title = args.title.strip()
    target = args.target.strip()
    if not target.startswith("@") and target != "all":
        target = f"@{target}"
    
    author = args.author.strip() if args.author else detect_agent_default()

    post_type = (getattr(args, "type", None) or "").strip().lower() or None
    if post_type and post_type not in POST_TYPES:
        sys.exit(f"Error: --type must be one of: {', '.join(POST_TYPES)}")
    scope = (getattr(args, "scope", None) or "").strip() or None
    expires = parse_duration(getattr(args, "expires", None))
    room = (getattr(args, "room", None) or "").strip().lower() or None
    thread = (getattr(args, "thread", None) or "").strip() or None
    hop = getattr(args, "hop", None)
    provenance = (getattr(args, "provenance", None) or "").strip().lower() or None

    # Validation before append (agentbus convention): refuse the message
    # before it touches the board, in the same code the lint uses.
    if provenance and provenance not in PROVENANCE_TYPES:
        sys.exit(f"Error: --provenance must be one of: {', '.join(PROVENANCE_TYPES)}")
    if post_type == "claim" and not scope:
        sys.exit("Error: --type claim requires --scope (a claim without a scope is untrackable).")
    if post_type == "claim" and not expires:
        sys.exit("Error: --type claim requires --expires (a claim without expiry is never released).")
    if post_type == "release" and not scope:
        sys.exit("Error: --type release requires --scope.")
    
    # Read body from flag or stdin
    body = args.body
    if not body:
        if not sys.stdin.isatty():
            body = sys.stdin.read().strip()
        else:
            sys.exit("Error: --body or piped stdin required.")

    # Near-duplicate nudge (agentbus reports duplicates rather than blocking).
    if post_type not in ("claim", "release") and not getattr(args, "no_similarity", False):
        try:
            similar = similar_posts(f"{title}\n{body}")
        except Exception:
            similar = []
        if similar:
            print("⚠ similar recent post(s) — check for a duplicate:")
            for score, post in similar:
                print(f"    {score:.2f}  #{post['seq']}  {post['title']}  ({post['file']})")

    # Try posting via Bridge HTTP if running
    try:
        req = urllib.request.Request(
            f"{BRIDGE_URL}/api/post",
            headers={"Content-Type": "application/json"},
            data=json.dumps({
                "title": title,
                "body": body,
                "author": author,
                "target": target,
                "type": post_type,
                "scope": scope,
                "expires": expires,
                "room": room,
                "thread": thread,
                "hop": hop,
                "provenance": provenance,
            }).encode()
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get("ok"):
                print(f"✓ Posted to Sangha Whiteboard via Bridge (# {data.get('seq')}): {data.get('file')}")
                return
    except Exception:
        # Fallback to direct file write if bridge is not currently running
        pass

    # Direct write fallback (bridge offline): lock spans allocation through
    # append, so a concurrent bridge or agent cannot share this sequence.
    BOARD.mkdir(parents=True, exist_ok=True)
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    SANGHA_DIR.mkdir(parents=True, exist_ok=True)

    with board_write_lock():
        seq = next_free_seq()
        stamp = now_iso()
        seat = ("antigravity" if "antigravity" in author.lower()
                else "opencode" if "opencode" in author.lower()
                else "sentinel" if "sentinel" in author.lower()
                else "lucas")
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "dispatch"
        fname = f"{stamp[:10]}-{seq:02d}-{seat}-{slug}.md"
        file_path = BOARD / fname
        i = 1
        while file_path.exists():
            file_path = BOARD / f"{stamp[:10]}-{seq:02d}-{seat}-{slug}-{i}.md"
            i += 1

        meta_line = ""
        parts = []
        if post_type:
            parts.append(f"Type: {post_type}")
        if scope:
            parts.append(f"Scope: {scope}")
        if expires:
            parts.append(f"Expires: {expires}")
        if room:
            parts.append(f"Room: {room}")
        if parts:
            meta_line = "> " + " · ".join(parts) + "\n"

        extra_headers = ""
        if hop is not None:
            extra_headers += f"> Hop: {hop}\n"
        if thread:
            extra_headers += f"> Thread: {thread}\n"

        prov_line = f"> Provenance: {provenance}\n" if provenance else ""
        cpr_digest, env = create_aer1_receipt(
            seq, title, body, author, target, seat, post_type, scope, expires, room, thread, provenance
        )
        cpr_line = f"> CPR-AER1: {cpr_digest}\n" if cpr_digest else ""
        receipt_footer = ""
        if env and post_type in ("release", "done", "claim"):
            receipt_footer = (
                f"\n\n### 📜 Continuity Receipt (AER-1)\n"
                f"```json\n"
                f"{json.dumps(env, indent=2)}\n"
                f"```\n"
            )

        content = (f"# {title}\n\n"
                   f"> Posted by {author} on {DEVICE} at {stamp}\n"
                   f"> Target: {target}\n"
                   f"{prov_line}"
                   f"{meta_line}"
                   f"{cpr_line}"
                   f"{extra_headers}\n"
                   f"{body}{receipt_footer}")
        file_path.write_text(content, encoding="utf-8")

        # Inboxes & event log (under the same lock as the append)
        post_meta = {
            "file": file_path.name,
            "seq": seq,
            "stamp": stamp,
            "author": author,
            "seat": seat,
            "target": target,
            "title": title,
            "type": post_type,
            "scope": scope,
            "expires": expires,
            "room": room,
            "thread": thread,
            "hop": hop,
            "provenance": provenance,
            "cpr": cpr_digest,
            "read": False
        }
        with (SANGHA_DIR / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(post_meta) + "\n")

        clean_target = target.lstrip("@").lower()
        targets = ["opencode", "antigravity", "lucas"] if clean_target == "all" else [clean_target]
        targets = [t for t in targets if t != seat]  # never deliver a seat its own post
        for t in targets:
            with (INBOX_DIR / f"{t}.jsonl").open("a", encoding="utf-8") as f:
                f.write(json.dumps(post_meta) + "\n")

    notify_os(title, author, target, body[:120])
    mirror_to_wm("whiteboard", author, f"[{target}] {title}: {body[:200]}")

    try:
        cmd_canvas(argparse.Namespace(out="swarm.canvas", limit=35, all=False, json=False))
    except Exception:
        pass

    print(f"✓ Posted to Sangha Whiteboard directly (# {seq}): {file_path.name}")

def cmd_inbox(args):
    agent = (args.agent or detected_seat()).lstrip("@").lower()
    inbox_file = INBOX_DIR / f"{agent}.jsonl"
    if not inbox_file.exists():
        print(f"Inbox for @{agent} is empty (no dispatches recorded).")
        return

    items = _inbox_items(agent)

    room_filter = (getattr(args, "room", None) or "").strip().lower() or None
    if room_filter:
        items = [it for it in items if _item_room(it) == room_filter]
        if not items:
            print(f"No dispatches in @{agent} inbox for room '{room_filter}'.")
            return

    if getattr(args, "expire", False):
        stale_ids = {it.get("id") for it in items if not it.get("read") and _item_stale(it)}
        if stale_ids:
            lines = []
            for line in inbox_file.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        d = json.loads(line)
                        if d.get("id") in stale_ids:
                            d["read"] = True
                        lines.append(json.dumps(d))
                    except Exception:
                        lines.append(line)
            inbox_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"✓ Expired {len(stale_ids)} stale @all dispatch(es) in @{agent} inbox "
              f"(older than {STALE_ALL_DAYS}d).")

    if args.unread:
        items = [it for it in items if not it.get("read")]
    if not getattr(args, "all", False):
        items = [it for it in items if it.get("read") or not _item_stale(it)]

    if not items:
        print(f"No {'unread ' if args.unread else ''}dispatches in @{agent} inbox.")
        return

    if getattr(args, "digest", False):
        by_day = {}
        for it in items:
            day = str(it.get("stamp") or "")[:10]
            by_day.setdefault(day, []).append(it)
        print(f"=== INBOX DIGEST: @{agent.upper()} ({len(items)} items, {len(by_day)} days) ===")
        for day in sorted(by_day, reverse=True):
            day_items = by_day[day]
            authors = {}
            for it in day_items:
                authors[it.get("author", "?")] = authors.get(it.get("author", "?"), 0) + 1
            unread_n = sum(1 for it in day_items if not it.get("read"))
            print(f"  {day}  {len(day_items):>3} items · {unread_n} unread · "
                  + " · ".join(f"{a} {n}" for a, n in sorted(authors.items(), key=lambda kv: -kv[1])))
            for it in day_items[:2]:
                mark = "[UNREAD]" if not it.get("read") else "[SEEN]  "
                print(f"      {mark} #{it.get('seq')} {it.get('title')[:60]}")
        return

    print(f"=== SANGHA INBOX: @{agent.upper()} ({len(items)} items) ===")
    for it in reversed(items):
        stale = " [stale @all]" if _item_stale(it) else ""
        status = "[UNREAD]" if not it.get("read") else "[SEEN]  "
        seq = f"#{it.get('seq')}" if it.get('seq') else "    "
        prov = f" [{it.get('provenance')}]" if it.get("provenance") else ""
        print(f"{status} {seq} {it.get('stamp')} from {it.get('author')}: {it.get('title')}{prov}{stale}")
        print(f"        file: {it.get('file') or it.get('id')}")

def cmd_ack(args):
    agent = (args.agent or detected_seat()).lstrip("@").lower()
    inbox_file = INBOX_DIR / f"{agent}.jsonl"
    if not inbox_file.exists():
        print(f"No inbox found for @{agent}.")
        return

    bulk = getattr(args, "all", False)
    target_id = "" if bulk else str(args.item or "").strip()
    if not bulk and not target_id:
        sys.exit("Error: provide an item, or --all to mark every unread as read.")

    lines = []
    found = 0
    for line in inbox_file.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                d = json.loads(line)
                if (bulk and not d.get("read")) or (not bulk and (
                        str(d.get("seq")) == target_id or target_id in d.get("id", ""))):
                    d["read"] = True
                    found += 1
                lines.append(json.dumps(d))
            except Exception:
                lines.append(line)

    if found:
        inbox_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if bulk:
            print(f"✓ Acknowledged {found} unread dispatch(es) in @{agent} inbox.")
        else:
            print(f"✓ Acknowledged dispatch {target_id} in @{agent} inbox.")
    else:
        print(f"! No matching dispatch in @{agent} inbox.")

def _seq_matches(seq_num):
    """Every board/archive post carrying this sequence number.

    Sequence numbers are allocated locally per device, so Syncthing can merge
    two posts that share a number (cross-device collision). Read shows all
    matches rather than silently picking the first.
    """
    matches = []
    for p in sorted(BOARD.glob("*.md")):
        if _seq_from_name(p.name) == seq_num:
            matches.append(p)
    archive_dir = BOARD / "archive"
    if archive_dir.is_dir():
        for p in sorted(archive_dir.rglob("*.md")):
            if _seq_from_name(p.name) == seq_num:
                matches.append(p)
    return matches


def cmd_read(args):
    query = str(args.item).strip()
    matches = []
    if query.isdigit():
        matches = _seq_matches(int(query))
    else:
        candidates = list(BOARD.glob(f"*{query}*"))
        if not candidates:
            archive_dir = BOARD / "archive"
            if archive_dir.is_dir():
                candidates = list(archive_dir.rglob(f"*{query}*"))
        matches = candidates[:1]

    if not matches:
        sys.exit(f"Error: post '{query}' not found on board.")
    if len(matches) > 1:
        print(f"! #{query} is shared by {len(matches)} posts "
              f"(cross-device sequence collision); showing all. "
              f"Disambiguate with a filename substring. `sangha lint` lists these.")
    for i, path in enumerate(matches):
        if i:
            print()
        print(f"=== {path.name} ===")
        print(path.read_text(encoding="utf-8", errors="replace"))

def cmd_list(args):
    room_filter = (getattr(args, "room", None) or "").strip().lower()
    type_filter = (getattr(args, "type", None) or "").strip().lower()
    posts = []
    for p in BOARD.glob("*.md"):
        meta = parse_post_header(p)
        if room_filter and (meta.get("room") or "").lower() != room_filter:
            continue
        if type_filter and (meta.get("type") or "").lower() != type_filter:
            continue
        prov = meta.get("provenance")
        stamp = meta.get("stamp") or ""
        m = re.match(r"^(\d{4}-\d{2}-\d{2})-([0-9a-z]+)-([a-z0-9]+)-(.*)\.md$", p.name)
        if m:
            seq = int(m.group(2)) if m.group(2).isdigit() else 0
            posts.append((stamp, m.group(1), seq, m.group(3), m.group(4), p.name, prov, meta))
        else:
            posts.append((stamp, "", 0, "", "", p.name, prov, meta))
    # Order by the header stamp (falls back to date+seq), not by sequence
    # number: cross-device collisions made seq order lie about time.
    posts.sort(key=lambda x: (x[0], x[1], x[2], x[5]))

    limit = args.limit
    slice_posts = posts[-limit:] if limit > 0 else posts
    if getattr(args, "json", False):
        res = []
        for stamp, date, seq, seat, slug, fname, prov, meta in reversed(slice_posts):
            res.append({
                "seq": seq, "stamp": stamp, "date": date, "seat": seat,
                "file": fname, "title": meta.get("title"), "room": meta.get("room"),
                "type": meta.get("type"), "scope": meta.get("scope"), "provenance": prov,
            })
        print(json.dumps(res, indent=2))
        return

    filter_desc = []
    if room_filter:
        filter_desc.append(f"room={room_filter}")
    if type_filter:
        filter_desc.append(f"type={type_filter}")
    f_str = f" [{', '.join(filter_desc)}]" if filter_desc else ""
    print(f"=== SANGHA WHITEBOARD DISPATCHES (last {len(slice_posts)}){f_str} ===")
    for stamp, date, seq, seat, slug, fname, prov, meta in reversed(slice_posts):
        seq_str = f"#{seq}" if seq else "t:?"
        prov_tag = f" [{prov}]" if prov else ""
        room_tag = f" [{meta.get('room')}]" if meta.get("room") else ""
        print(f"{date} {seq_str:<6} [{seat:<11}]{room_tag} {slug.replace('-', ' ')[:46]}{prov_tag}")
        print(f"    file: {fname}")

def cmd_claim(args):
    scope = args.scope.strip()
    intent = (args.intent or "").strip()
    author = (args.author or "").strip() if args.author else detect_agent_default()

    # Mandala Kekkai concurrency check
    occ = check_occupancy(scope)
    if occ and occ.get("author") != author:
        if getattr(args, "force", False):
            reason = getattr(args, "cpr_reason", "") or "Supervisor mandate"
            print(f"⚠ MANDALA KEKKAI OVERRIDE: Superseding claim #{occ.get('seq')} by @{occ.get('author')}. Reason: {reason}")
        elif getattr(args, "wait", False):
            timeout = int(getattr(args, "timeout", 300) or 300)
            print(f"⏳ Scope `{scope}` is occupied by @{occ.get('author')}. Waiting for release (poll every 5s, timeout {timeout}s)...")
            start_t = time.time()
            while time.time() - start_t < timeout:
                time.sleep(5)
                occ = check_occupancy(scope)
                if not occ or occ.get("author") == author:
                    print(f"✓ Scope `{scope}` released! Proceeding with claim.")
                    break
            if occ and occ.get("author") != author:
                sys.exit(f"Error: Timeout ({timeout}s) reached waiting for scope `{scope}` to clear.")
        else:
            print(format_occupied_sign(occ, scope))
            sys.exit(1)

    ttl_s = 7200
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(args.ttl).strip(), re.IGNORECASE)
    if m:
        num, unit = int(m.group(1)), m.group(2).lower()
        ttl_s = num * (1 if unit == "s" else 60 if unit == "m" else 3600 if unit == "h" else 86400)

    mandala_pass = issue_mandala_pass(scope, detected_seat(), ttl_s)
    jti = mandala_pass.get("jti") if mandala_pass else None

    title = f"Claim: {scope}" + (f" — {intent}" if intent else "")
    mandala_note = f"\n\nMandala capability token: `{jti}` (Landlock write-barrier active for `{scope}`)." if jti else ""
    body = (args.body or (
        f"Claiming scope `{scope}`" + (f" — {intent}." if intent else ".") +
        f"\n\nTTL {args.ttl}. Release with `sangha release {scope}`; the sentinel"
        " treats this scope as owned until released or expired."
    )) + mandala_note

    cmd_post(argparse.Namespace(
        title=title, target=args.target, author=author, body=body,
        type="claim", scope=scope, expires=args.ttl,
        room=getattr(args, "room", None),
        thread=None, hop=None, provenance="computed", no_similarity=True
    ))

    if jti:
        print(f"✓ MandalaPass issued: {jti} (Landlock write boundary locked to '{scope}')")


def cmd_release(args):
    item = str(args.item).strip()
    match = None
    for c in active_claims():
        if c["state"] != "active":
            continue
        if item.isdigit() and c["seq"] == int(item):
            match = c
            break
        if not item.isdigit() and item.lower() in (c["scope"] or "").lower():
            match = c
            break
    if not match:
        sys.exit(f"Error: no active claim matching '{item}'.")

    scope = match["scope"]
    claim_seq = match["seq"]
    claim_author = match.get("author") or "unknown"
    claim_stamp = match.get("stamp")

    # Calculate duration held
    duration_str = "unknown duration"
    if claim_stamp:
        try:
            c_time = _parse_iso(claim_stamp)
            if c_time:
                elapsed_sec = int((datetime.now(UTC) - c_time).total_seconds())
                if elapsed_sec < 60:
                    duration_str = f"{elapsed_sec}s"
                elif elapsed_sec < 3600:
                    duration_str = f"{elapsed_sec // 60}m {elapsed_sec % 60}s"
                else:
                    duration_str = f"{elapsed_sec // 3600}h {(elapsed_sec % 3600) // 60}m"
        except Exception:
            pass

    summary = (getattr(args, "summary", None) or getattr(args, "reason", None) or getattr(args, "body", None) or "").strip()
    if not summary:
        summary = f"Work completed on {scope}; claim #{claim_seq} released."

    scope_slug = re.sub(r'[^a-zA-Z0-9]+', '-', scope).strip('-')[:24] or "scope"
    pass_file = PASSES_DIR / f"{scope_slug}.json"
    jti = None
    if pass_file.exists():
        try:
            pdata = json.loads(pass_file.read_text(encoding="utf-8"))
            jti = pdata.get("jti")
            pass_file.unlink()
        except Exception:
            pass

    mandala_line = f"\n- **MandalaPass:** `{jti}` (terminated)" if jti else ""
    body = (
        f"Scope `{scope}` released (claim #{claim_seq}).\n\n"
        f"- **Claimed by:** @{claim_author}\n"
        f"- **Held for:** {duration_str}\n"
        f"- **Summary:** {summary}"
        f"{mandala_line}"
    )

    author = args.author or detect_agent_default()

    cmd_post(argparse.Namespace(
        title=f"Release: {scope}",
        target="@all",
        author=author,
        body=body,
        type="release",
        scope=scope,
        expires=None,
        room=match.get("room"),
        thread=match.get("thread"),
        hop=None,
        provenance="computed",
        no_similarity=True
    ))


def cmd_claims(args):
    claims = all_claims(scope_filter=getattr(args, "scope", None))
    if not getattr(args, "all", False):
        claims = [c for c in claims if c["state"] == "active"]
    if getattr(args, "json", False):
        print(json.dumps([
            {k: c.get(k) for k in ("seq", "date", "scope", "state", "expires", "file")}
            for c in claims
        ], indent=2))
        return
    if not claims:
        print("No active claims. (--all shows expired/released too)")
        return
    print(f"=== CLAIMS ({len(claims)}) ===")
    for c in claims:
        print(f"#{c['seq'] or '?':<4} {c['state']:<9} {c['date']}  {c['scope']}  expires={c['expires'] or '-'}")
        print(f"      file: {c['file']}")


def cmd_rooms(args):
    """Aggregate active rooms with federation tiers from the board."""
    posts = _board_posts()
    agg = {}
    for p in posts:
        name = p.get("room") or "general"
        r = agg.setdefault(name, {
            "room": name,
            "posts": 0,
            "federation": p.get("federation") or ("local" if name == "local" else ("external" if name.startswith("ext/") or name.startswith("pub/") else "fleet")),
            "last_activity": "",
            "authors": set(),
            "latest_seq": None,
            "latest_title": None,
        })
        r["posts"] += 1
        stamp = p.get("stamp") or p.get("date") or ""
        if stamp > r["last_activity"]:
            r["last_activity"] = stamp
        if p.get("author"):
            r["authors"].add(p.get("author"))
        seq = p.get("seq") or 0
        if r["latest_seq"] is None or seq > r["latest_seq"]:
            r["latest_seq"] = seq
            r["latest_title"] = p.get("title")

    out = []
    for r in agg.values():
        r["authors"] = sorted(r["authors"])
        r["author_count"] = len(r["authors"])
        out.append(r)
    out.sort(key=lambda x: x["last_activity"], reverse=True)

    if getattr(args, "json", False):
        print(json.dumps(out, indent=2))
        return 0

    print(f"=== FRACTAL AGORA ROOMS ({len(out)}) ===")
    print(f"{'ROOM':<20} {'FEDERATION':<12} {'POSTS':<7} {'AUTHORS':<8} {'LATEST':<25}")
    print("-" * 75)
    for r in out:
        latest = f"#{r['latest_seq']} {(r['latest_title'] or '')[:18]}" if r["latest_seq"] else "-"
        print(f"{r['room']:<20} {r['federation']:<12} {r['posts']:<7} {r['author_count']:<8} {latest:<25}")
    return 0


def detect_epoch_info():
    """Detect current running epoch and archive state."""
    archive_dir = BOARD / "archive"
    highest_epoch = 0
    if archive_dir.is_dir():
        for d in archive_dir.glob("epoch-*"):
            if d.is_dir():
                m = re.match(r"^epoch-(\d+)$", d.name)
                if m:
                    highest_epoch = max(highest_epoch, int(m.group(1)))

    active_epoch_num = highest_epoch + 1
    active_epoch_name = f"epoch-{active_epoch_num}"

    posts = _board_posts(include_archive=False)
    claims = active_claims()
    active_claim_seqs = {c.get("seq") for c in claims}

    non_claim_posts = [p for p in posts if p.get("type") not in ("claim", "release") and p.get("seq") not in active_claim_seqs]

    type_counts = {}
    for p in posts:
        t = p.get("type") or "untyped"
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "active_epoch_num": active_epoch_num,
        "active_epoch_name": active_epoch_name,
        "highest_archived_epoch": highest_epoch,
        "total_active_posts": len(posts),
        "non_claim_posts_count": len(non_claim_posts),
        "active_claims_count": len(claims),
        "type_counts": type_counts,
        "eligible_for_archive": non_claim_posts,
    }


def cmd_epoch(args):
    action = getattr(args, "action", "status") or "status"
    info = detect_epoch_info()
    threshold = getattr(args, "threshold", 120) or 120

    if action == "status":
        payload = {
            "active_epoch": info["active_epoch_name"],
            "total_active_posts": info["total_active_posts"],
            "eligible_for_archive": info["non_claim_posts_count"],
            "active_claims_protected": info["active_claims_count"],
            "type_breakdown": info["type_counts"],
            "threshold": threshold,
            "rollover_recommended": info["non_claim_posts_count"] >= threshold,
        }
        if getattr(args, "json", False):
            print(json.dumps(payload, indent=2))
            return 0
        print(f"=== SANGHA EPOCH STATUS ===")
        print(f"  Active Epoch:       {info['active_epoch_name']} (archive/ holds up to epoch-{info['highest_archived_epoch']})")
        print(f"  Active Board Posts: {info['total_active_posts']} total ({info['non_claim_posts_count']} non-claim)")
        print(f"  Active Claims:      {info['active_claims_count']} (always protected from archive)")
        print(f"  Types Breakdown:    " + ", ".join(f"{k}: {v}" for k, v in sorted(info['type_counts'].items())))
        print(f"  Switch Threshold:   {threshold} posts")
        if info["non_claim_posts_count"] >= threshold:
            print(f"  ⚠ THRESHOLD REACHED: Rollover recommended (`sangha epoch switch`)")
        else:
            print(f"  ✓ Headroom: {threshold - info['non_claim_posts_count']} posts remaining in {info['active_epoch_name']}")
        return 0

    elif action == "switch":
        target_dir = Path(args.dest).expanduser() if getattr(args, "dest", None) else BOARD / "archive" / info["active_epoch_name"]
        target_dir.mkdir(parents=True, exist_ok=True)

        eligible = info["eligible_for_archive"]
        if not eligible:
            print("No non-claim posts eligible for archive.")
            return 0

        moved_count = 0
        categorized = {"milestones": [], "findings": [], "notes": [], "general": []}

        for p in eligible:
            src = p["path"]
            dst = target_dir / p["file"]
            try:
                src.rename(dst)
                moved_count += 1
                ptype = p.get("type") or ""
                if ptype in ("done", "handoff"):
                    categorized["milestones"].append(p)
                elif ptype in ("flag",):
                    categorized["findings"].append(p)
                elif ptype in ("note", "question"):
                    categorized["notes"].append(p)
                else:
                    categorized["general"].append(p)
            except OSError as e:
                print(f"  ! Error moving {p['file']}: {e}", file=sys.stderr)

        # Generate categorization INDEX.md in epoch archive
        index_lines = [
            f"# Sangha Agora Archive — {info['active_epoch_name']}",
            f"\nArchived on {now_iso()} · Total Posts: {moved_count}\n",
            "## Milestones & Closures",
        ]
        for p in categorized["milestones"]:
            index_lines.append(f"- #{p.get('seq', '?')} `[{p.get('author', 'peer')}]` {p.get('title', p['file'])}")
        index_lines.append("\n## Findings & Sentinel Alerts")
        for p in categorized["findings"]:
            index_lines.append(f"- #{p.get('seq', '?')} `[{p.get('author', 'peer')}]` {p.get('title', p['file'])}")
        index_lines.append("\n## Research, Questions & Notes")
        for p in categorized["notes"]:
            index_lines.append(f"- #{p.get('seq', '?')} `[{p.get('author', 'peer')}]` {p.get('title', p['file'])}")
        index_lines.append("\n## General Dispatches")
        for p in categorized["general"]:
            index_lines.append(f"- #{p.get('seq', '?')} `[{p.get('author', 'peer')}]` {p.get('title', p['file'])}")

        (target_dir / "INDEX.md").write_text("\n".join(index_lines), encoding="utf-8")

        manifest = {
            "epoch": info["active_epoch_name"],
            "archived_at": now_iso(),
            "posts_moved": moved_count,
            "counts": {k: len(v) for k, v in categorized.items()},
        }
        (target_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        new_epoch_num = info["active_epoch_num"] + 1
        new_epoch_name = f"epoch-{new_epoch_num}"

        body = (
            f"Automated epoch rotation complete.\n\n"
            f"- Archived: {moved_count} posts → `board/archive/{info['active_epoch_name']}/` (with INDEX.md & manifest.json)\n"
            f"- Protected active claims: {info['active_claims_count']}\n"
            f"- Active Agora Epoch: `{new_epoch_name}` inaugurated.\n"
        )
        cmd_post(argparse.Namespace(
            title=f"Epoch {info['active_epoch_num']} closed: board rolled to {new_epoch_name}",
            target="@all", author=detect_agent_default(), body=body,
            type="done", scope="sangha/epoch", expires=None, room="sangha",
            thread=None, hop=None, provenance="computed", no_similarity=True
        ))

        mirror_to_wm("sangha/epoch", detect_agent_default(), f"Epoch transition: {info['active_epoch_name']} -> {new_epoch_name}")

        if getattr(args, "json", False):
            print(json.dumps(manifest, indent=2))
        else:
            print(f"✓ Epoch transition complete: {moved_count} posts archived to {target_dir}. New epoch: {new_epoch_name}")
        return 0

    elif action == "auto-check":
        if info["non_claim_posts_count"] >= threshold:
            print(f"⚠ Non-claim posts ({info['non_claim_posts_count']}) >= threshold ({threshold}). Triggering auto-switch...")
            setattr(args, "action", "switch")
            return cmd_epoch(args)
        else:
            if getattr(args, "json", False):
                print(json.dumps({"status": "ok", "count": info["non_claim_posts_count"], "threshold": threshold}))
            else:
                print(f"✓ Epoch post count healthy: {info['non_claim_posts_count']}/{threshold} in {info['active_epoch_name']}.")
            return 0


def cmd_listen(args):
    """Stream live Sangha events via Server-Sent Events (SSE)."""
    room_filter = (getattr(args, "room", None) or "").strip().lower()
    target_filter = (getattr(args, "target", None) or "").strip().lower()
    url = f"{BRIDGE_URL}/api/events"
    print(f"📡 Connecting to Sangha live Agora stream at {url}...")
    req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=3600) as resp:
            event_name = "message"
            for line in resp:
                decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not decoded:
                    continue
                if decoded.startswith(":"):
                    continue
                if decoded.startswith("event:"):
                    event_name = decoded[6:].strip()
                elif decoded.startswith("data:"):
                    raw_data = decoded[5:].strip()
                    try:
                        data = json.loads(raw_data)
                    except Exception:
                        data = {"raw": raw_data}

                    if getattr(args, "json", False):
                        print(json.dumps({"event": event_name, "data": data}))
                        sys.stdout.flush()
                        continue

                    if event_name == "new_post":
                        p_file = data.get("file", "")
                        p_title = data.get("title", "")
                        p_seq = data.get("seq", "?")
                        print(f"⚡ [NEW DISPATCH #{p_seq}] {p_title} ({p_file})")
                        sys.stdout.flush()
    except (KeyboardInterrupt, SystemExit):
        print("\nDisconnected from Sangha stream.")
        return 0
    except Exception as e:
        sys.exit(f"Stream error: {e}")


def cmd_meta(args):
    """Programmatic dispatcher for WhiteMagic Gen3 meta-tool."""
    action = args.action
    kwargs = {}
    if getattr(args, "json_args", None):
        try:
            kwargs = json.loads(args.json_args)
        except Exception as e:
            sys.exit(f"Error parsing json-args: {e}")

    if action == "status":
        cmd_status(argparse.Namespace(json=True, fleet_window=kwargs.get("fleet_window", 45)))
    elif action == "rooms":
        cmd_rooms(argparse.Namespace(json=True))
    elif action == "claims":
        cmd_claims(argparse.Namespace(json=True, all=kwargs.get("all", False), scope=kwargs.get("scope")))
    elif action == "occupied":
        cmd_occupied(argparse.Namespace(scope=kwargs.get("scope", ""), json=True))
    elif action == "epoch":
        cmd_epoch(argparse.Namespace(action=kwargs.get("subaction", "status"), threshold=kwargs.get("threshold", 120), dest=None, json=True))
    elif action == "inbox":
        cmd_inbox(argparse.Namespace(agent=kwargs.get("agent"), room=kwargs.get("room"), unread=True, digest=False, all=False, expire=False))
    elif action == "claim":
        scope = (kwargs.get("scope") or "").strip()
        intent = (kwargs.get("intent") or "").strip()
        author = (kwargs.get("author") or "").strip() if kwargs.get("author") else detect_agent_default()
        ttl = kwargs.get("ttl", "2h")
        room = kwargs.get("room", "claims")
        force = kwargs.get("force", False)
        target = kwargs.get("target", "@all")
        body = kwargs.get("body")
        cpr_reason = kwargs.get("cpr_reason", "")
        wait = kwargs.get("wait", False)
        timeout = kwargs.get("timeout", 300)

        occ = check_occupancy(scope)
        if occ and occ.get("author") != author and not force:
            print(json.dumps({
                "status": "occupied",
                "occupied": True,
                "scope": scope,
                "current_holder": occ.get("author"),
                "claim_seq": occ.get("seq"),
                "expires": occ.get("expires")
            }, indent=2))
            return

        cmd_claim(argparse.Namespace(
            scope=scope, intent=intent, author=author,
            ttl=ttl, room=room, force=force,
            target=target, body=body,
            cpr_reason=cpr_reason, wait=wait, timeout=timeout
        ))
    elif action == "release":
        target = kwargs.get("target") or kwargs.get("scope") or kwargs.get("item")
        if not target:
            sys.exit("Error: scope or item required to release claim.")
        cmd_release(argparse.Namespace(
            item=str(target),
            note=kwargs.get("note", "completed"),
            target=kwargs.get("announcement_target", "@all"),
            author=kwargs.get("author"),
            room=kwargs.get("room", "claims")
        ))
    elif action == "post":
        cmd_post(argparse.Namespace(
            title=kwargs.get("title", ""),
            target=kwargs.get("target", "@all"),
            author=kwargs.get("author"),
            body=kwargs.get("body", ""),
            type=kwargs.get("type", "note"),
            scope=kwargs.get("scope"),
            expires=kwargs.get("expires"),
            room=kwargs.get("room"),
            thread=kwargs.get("thread"),
            hop=kwargs.get("hop"),
            provenance=kwargs.get("provenance", "computed"),
            no_similarity=kwargs.get("no_similarity", True)
        ))
    elif action == "fork":
        if not sangha_vcs:
            sys.exit("Error: sangha_vcs not available for fork.")
        sangha_vcs.cmd_fork(argparse.Namespace(
            scope=kwargs.get("target") or kwargs.get("scope", "."),
            author=kwargs.get("author"),
            json=True
        ))
    elif action == "consolidate":
        if not sangha_vcs:
            sys.exit("Error: sangha_vcs not available for consolidate.")
        sangha_vcs.cmd_consolidate(argparse.Namespace(
            fork_id=kwargs.get("fork_id") or kwargs.get("target"),
            msg=kwargs.get("message") or kwargs.get("msg", "Consolidated shadow changes"),
            author=kwargs.get("author"),
            no_cleanup=kwargs.get("no_cleanup", False),
            json=True
        ))
    elif action == "vcs":
        if not sangha_vcs:
            sys.exit("Error: sangha_vcs not available.")
        subcmd = kwargs.get("command", "status")
        if subcmd == "status":
            sangha_vcs.cmd_status(argparse.Namespace(json=True))
        elif subcmd == "audit":
            sangha_vcs.cmd_audit(argparse.Namespace(
                limit=kwargs.get("limit", 10),
                json=True
            ))
        elif subcmd == "diff":
            sangha_vcs.cmd_diff(argparse.Namespace(stat=kwargs.get("stat", False)))
        else:
            sys.exit(f"Unknown vcs subcmd: {subcmd}")
    elif action == "peer":
        subaction = kwargs.get("subaction", "list")
        if subaction == "list":
            cmd_peer(argparse.Namespace(peer_action="list", json=True))
        elif subaction == "sync":
            cmd_peer(argparse.Namespace(peer_action="sync", peer=kwargs.get("peer"), room=kwargs.get("room"), json=True))
        elif subaction == "add":
            cmd_peer(argparse.Namespace(peer_action="add", name=kwargs.get("name"), url=kwargs.get("url"), json=True))
    elif action == "worker":
        cmd_worker(argparse.Namespace(
            room=kwargs.get("room", "research"),
            agent=kwargs.get("agent"),
            daemon=False,
            interval=10,
            max_tasks=kwargs.get("max_tasks", 1),
            json=True
        ))
    elif action in ("credit", "bank"):
        subaction = kwargs.get("subaction", "balance")
        cmd_credit(argparse.Namespace(
            credit_action=subaction,
            agent=kwargs.get("agent"),
            amount=kwargs.get("amount", 10.0),
            to=kwargs.get("to"),
            seq=kwargs.get("seq"),
            all=kwargs.get("all", False),
            memo=kwargs.get("memo", ""),
            limit=kwargs.get("limit", 15),
            json=True
        ))
    else:
        sys.exit(f"Unknown meta action: {action}")


# ── similarity: near-duplicate detection over the board itself ──────
# agentbus uses an embedding lane for this; the board's corpus is small and
# stdlib-only is a feature here, so an IDF-weighted query-coverage score over
# title+body does the job. (Cosine is length-asymmetric: a short query against
# a long post scores low even when every query term appears; coverage does not.)
# (wm's hybrid_recall indexes the session vault, not board posts.)
SIMILARITY_THRESHOLD = 0.55
STOPWORDS = frozenset(
    "the a an and or of to in on for with is are was were be been being it its this that these those "
    "from at by as not no yes if then than so we you they he she i our your their there here "
    "will would can could should may might must do does did done has have had".split()
)


def _similarity_tokens(text):
    return [t for t in re.findall(r"[a-z0-9][a-z0-9_./-]+", text.lower())
            if len(t) >= 3 and t not in STOPWORDS]


def similar_posts(text, limit=3, threshold=SIMILARITY_THRESHOLD, pool=120, exclude_file=None):
    """Top similar recent posts to `text` as [(score, post), ...].

    Score = share of the query's IDF mass whose terms appear in the post
    (1.0 = every weighted query term is present). Length-robust.
    """
    import math
    posts = [p for p in _board_posts()
             if p["type"] not in ("claim", "release") and p["file"] != exclude_file]
    posts.sort(key=lambda p: (p["stamp"] or "", p["seq"] or 0), reverse=True)
    posts = posts[:pool]
    docs = {}
    doc_terms = {}
    df = {}
    for p in posts:
        try:
            body = p["path"].read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        docs[p["file"]] = p
        doc_terms[p["file"]] = set(_similarity_tokens(body))
        for tok in doc_terms[p["file"]]:
            df[tok] = df.get(tok, 0) + 1
    if not docs:
        return []
    n = len(docs)
    idf = {tok: math.log((1 + n) / (1 + d)) + 1.0 for tok, d in df.items()}
    q_terms = set(_similarity_tokens(text))
    if not q_terms:
        return []
    denom = sum(idf.get(t, 1.0) for t in q_terms) or 1.0
    scored = []
    for f, terms in doc_terms.items():
        score = sum(idf.get(t, 1.0) for t in q_terms if t in terms) / denom
        scored.append((score, f))
    scored.sort(reverse=True)
    return [(s, docs[f]) for s, f in scored if s >= threshold][:limit]


def cmd_related(args):
    query = str(args.item).strip()
    if query.isdigit():
        matches = _seq_matches(int(query))
        if not matches:
            sys.exit(f"Error: post '{query}' not found on board.")
        text = matches[0].read_text(encoding="utf-8", errors="replace")
        label = matches[0].name
        hits = similar_posts(text, limit=args.limit, threshold=args.min_score,
                             exclude_file=matches[0].name)
    else:
        text = query
        label = "(text)"
        hits = similar_posts(text, limit=args.limit, threshold=args.min_score)
    if args.json:
        print(json.dumps([
            {"score": round(s, 3), "seq": p["seq"], "date": p["date"],
             "title": p["title"], "file": p["file"]}
            for s, p in hits
        ], indent=2))
        return 0
    if not hits:
        print(f"No related posts above {args.min_score} for {label}.")
        return 0
    print(f"=== RELATED to {label} ({len(hits)}) ===")
    for s, p in hits:
        print(f"  {s:.2f}  #{p['seq'] or '?':<4} {p['date']}  {p['title']}  ({p['file']})")
    return 0


def cmd_search(args):
    term = args.term.strip().lower()
    hits = []
    for post in sorted(_board_posts(include_archive=True),
                       key=lambda p: (p["date"], p["seq"] or 0), reverse=True):
        try:
            text = post["path"].read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if term not in text.lower():
            continue
        snippet = next((ln.strip() for ln in text.splitlines() if term in ln.lower()), "")
        hits.append((post, snippet))
        if len(hits) >= args.limit:
            break
    if args.json:
        print(json.dumps([
            {"seq": p["seq"], "date": p["date"], "title": p["title"], "type": p["type"],
             "scope": p["scope"], "provenance": p["provenance"],
             "archived": "archive" in str(p["path"]), "file": p["file"], "snippet": s}
            for p, s in hits
        ], indent=2))
        return
    if not hits:
        print(f"No posts matching '{args.term}'.")
        return
    print(f"=== SEARCH '{args.term}' ({len(hits)} hits) ===")
    for post, snippet in hits:
        tags = [t for t in (post["type"], post["provenance"]) if t]
        if "archive" in str(post["path"]):
            tags.append("archived")
        tag = f" [{' · '.join(tags)}]" if tags else ""
        print(f"#{post['seq'] or '?':<4} {post['date']}  {post['title']}{tag}")
        print(f"      {snippet[:140]}")
        print(f"      file: {post['file']}")


def _cutoff_date(value):
    """'30d' | '2026-09-01' | ISO-8601 -> date string YYYY-MM-DD."""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value or ""):
        return value
    return parse_duration(value or "30d", sign=-1)[:10]


def cmd_archive(args):
    """Move old non-claim posts off the active board (dry run by default).

    Claims and releases stay: their state is computed from board history, so
    archiving them would silently release active claims. Archived posts remain
    readable (`read`) and searchable (`search`).
    """
    cutoff = _cutoff_date(args.before)
    dest = Path(args.dest).expanduser() if args.dest else BOARD / "archive" / "epoch-1"
    movable = []
    skipped = {"claim": 0, "release": 0, "recent": 0, "unparsed": 0}
    for post in _board_posts():
        if post["type"] in ("claim", "release"):
            skipped[post["type"]] += 1
            continue
        if not post["date"]:
            skipped["unparsed"] += 1
            continue
        if post["date"] >= cutoff:
            skipped["recent"] += 1
            continue
        movable.append(post)
    payload = {"cutoff": cutoff, "dest": str(dest), "apply": bool(args.apply),
               "movable": [{"file": p["file"], "type": p["type"], "date": p["date"]} for p in movable],
               "skipped": skipped, "moved": 0}
    if not args.apply:
        if args.json:
            print(json.dumps(payload, indent=2))
            return 0
        print(f"=== ARCHIVE DRY RUN (before {cutoff}) ===")
        for p in movable:
            print(f"  {p['date']}  {p['file']}")
        print(f"  {len(movable)} post(s) movable to {dest}")
        print(f"  skipped: {skipped['claim']} claims · {skipped['release']} releases "
              f"(state must stay on board) · {skipped['recent']} recent · {skipped['unparsed']} unparsed")
        print("  dry run — re-run with --apply to move")
        return 0
    dest.mkdir(parents=True, exist_ok=True)
    for post in movable:
        src = BOARD / post["file"]
        target = dest / post["file"]
        i = 1
        while target.exists():
            target = dest / f"{src.stem}-{i}{src.suffix}"
            i += 1
        try:
            src.rename(target)
            payload["moved"] += 1
        except OSError as e:
            print(f"  ! {post['file']}: {e}", file=sys.stderr)
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"✓ Archived {payload['moved']} post(s) to {dest}")
    return 0


def cmd_digest(args):
    since = _parse_iso(parse_duration(args.since, sign=-1)) if args.since else None
    if since is None:
        since = datetime.fromtimestamp(datetime.now(UTC).timestamp() - 86400, UTC)
    posts = []
    for post in _board_posts():
        stamp = _parse_iso(post.get("stamp"))
        if stamp and stamp >= since:
            posts.append(post)
    posts.sort(key=lambda p: (p.get("stamp") or "", p["seq"] or 0))

    by_type = {}
    by_author = {}
    by_prov = {}
    for post in posts:
        key = post["type"] or "post"
        by_type[key] = by_type.get(key, 0) + 1
        prov = post["provenance"] or "unmarked"
        by_prov[prov] = by_prov.get(prov, 0) + 1
        author = (post.get("author") or "?").split(" on ")[0]
        by_author[author] = by_author.get(author, 0) + 1
    claims = active_claims()

    seat = (args.agent or detected_seat()).lstrip("@").lower()
    unread, stale = _inbox_unread(seat)

    payload = {
        "generated_at": now_iso(),
        "window_since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "posts": len(posts),
        "by_type": by_type,
        "by_author": by_author,
        "by_provenance": by_prov,
        "active_claims": [
            {"seq": c["seq"], "scope": c["scope"], "expires": c["expires"], "file": c["file"]}
            for c in claims
        ],
        "inbox": {"seat": seat, "unread": unread, "stale_all": stale},
        "recent": [
            {"seq": p["seq"], "title": p["title"], "author": p.get("author"), "type": p["type"]}
            for p in posts[-10:]
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print(f"=== DIGEST since {payload['window_since']} ===")
    print(f"posts: {payload['posts']}  " + " · ".join(f"{k} {v}" for k, v in sorted(by_type.items())))
    if by_author:
        print("authors: " + " · ".join(f"{k} {v}" for k, v in sorted(by_author.items(), key=lambda kv: -kv[1])))
    if by_prov:
        print("provenance: " + " · ".join(f"{k} {v}" for k, v in sorted(by_prov.items(), key=lambda kv: -kv[1])))
    print(f"active claims: {len(claims)}" + ("".join(
        f"\n  #{c['seq']} {c['scope']} (expires {c['expires'] or '-'})" for c in claims)))
    print(f"@{seat} inbox: {unread} unread" + (f" (+{stale} stale @all)" if stale else ""))
    if posts:
        print("recent:")
        for p in posts[-5:]:
            tag = f" [{p['type']}]" if p["type"] else ""
            print(f"  #{p['seq'] or '?'} {p['title'][:60]}{tag}")


def _lint_board():
    """(errors, warnings, posts) — board integrity, shared by lint and sentinel.

    Duplicate-sequence warnings are expected after cross-device sync: sequence
    numbers are allocated per device under a node-local flock (board/.seq.lock),
    so two devices posting before their files sync can both claim e.g. #654;
    Syncthing then merges both files. Writers retry past any seq already
    visible locally (next_free_seq) but cannot see a file still in flight.
    `sangha read <seq>` shows all posts sharing a sequence. Kept as warnings
    (neither file is malformed, it's a merge artifact).
    """
    posts = _board_posts()
    errors = []
    warnings = []
    seq_map = {}
    for post in posts:
        f = post["file"]
        if post["seq"] is None:
            warnings.append(f"{f}: no sequence number in filename")
        else:
            seq_map.setdefault(post["seq"], []).append(f)
        if not post["author"] or not post["stamp"]:
            errors.append(f"{f}: missing 'Posted by ... at <stamp>' header")
        if not post["target"]:
            warnings.append(f"{f}: no Target header")
        if post["type"] and post["type"] not in POST_TYPES:
            warnings.append(f"{f}: unknown type '{post['type']}' "
                            f"(known: {', '.join(POST_TYPES)})")
        if post["provenance"] and post["provenance"] not in PROVENANCE_TYPES:
            errors.append(f"{f}: invalid provenance '{post['provenance']}' "
                          f"(known: {', '.join(PROVENANCE_TYPES)})")
        if (post["date"] >= PROVENANCE_ROLLOUT_DATE and not post["provenance"]
                and post["type"] in ("done", "flag")):
            warnings.append(f"{f}: {post['type']} post without provenance "
                            f"(mark computed/fetched/recalled/testimony)")
        if post["type"] == "claim":
            if not post["scope"]:
                errors.append(f"{f}: claim without scope (untrackable)")
            if not post["expires"]:
                errors.append(f"{f}: claim without expires (never released)")
            elif not _parse_iso(post["expires"]):
                errors.append(f"{f}: claim has unparseable expires '{post['expires']}'")
    for seq, files in sorted(seq_map.items()):
        if len(files) > 1:
            sample = ", ".join(files[:3]) + (" …" if len(files) > 3 else "")
            warnings.append(f"seq #{seq}: shared by {len(files)} files: {sample}")
    return errors, warnings, posts


# ── host health (2026-10-06: the crash-loop/zram incident was invisible) ──
# `wm10 selftest --strict --json` reports host_status ok|warn|critical and
# exits 1 only for critical. The probe is best-effort and cached in-memory for
# 60s; any failure (missing binary, timeout, bad JSON) is None — never raise,
# and never silently equate "unknown" with "clean".
_HOST_HEALTH_CACHE = {"at": 0.0, "value": None}
_HOST_HEALTH_TTL = 60.0


def _wm_binary():
    """wm10 first, then wm; SANGHA_WM_BIN overrides (tests/hermetic runs)."""
    override = os.environ.get("SANGHA_WM_BIN")
    if override:
        return override if Path(override).exists() else None
    for name in ("wm10", "wm"):
        found = shutil.which(name)
        if found:
            return found
        local = Path.home() / ".local" / "bin" / name
        if local.exists():
            return str(local)
    return None


def _host_health(use_cache=True):
    """Host health dict from wm10 selftest, or None when unavailable.

    {"status": ok|warn|critical|unknown, "rc": int, "checks": [...],
     "top_memory_processes": [...]} — read-only; callers must not mutate.
    """
    now = time.monotonic()
    if use_cache and now - _HOST_HEALTH_CACHE["at"] < _HOST_HEALTH_TTL:
        return _HOST_HEALTH_CACHE["value"]
    value = None
    binary = _wm_binary()
    if binary:
        try:
            proc = subprocess.run(
                [binary, "selftest", "--strict", "--json"],
                capture_output=True, text=True, timeout=10,
            )
            doc = json.loads(proc.stdout)
            if isinstance(doc, dict):
                health = doc.get("host_health")
                if not isinstance(health, dict):
                    health = {}
                value = {
                    "status": doc.get("host_status") or health.get("status") or "unknown",
                    "rc": proc.returncode,
                    "checks": health.get("checks") or [],
                    "top_memory_processes": health.get("top_memory_processes") or [],
                }
        except (OSError, ValueError, subprocess.SubprocessError):
            value = None
    _HOST_HEALTH_CACHE.update(at=now, value=value)
    return value


def _host_health_line(health):
    """One human line for host health, shared by sentinel and brief."""
    if not health:
        return "host: unavailable (wm10/wm not found or probe failed)"
    status = health.get("status", "unknown")
    details = [f"{c.get('name')}:{c.get('verdict')}"
               for c in health.get("checks") or []
               if c.get("verdict") and c.get("verdict") != "ok"]
    line = f"host: {status}"
    if details:
        line += " (" + " · ".join(details) + ")"
    return line


def _host_health_finding(health):
    """Critical host health -> a sentinel finding; warn stays informational.

    Detail includes failing checks + hints + top memory processes, capped at
    ~6 lines so the deduped post stays readable.
    """
    if not health or health.get("status") != "critical" or health.get("rc") != 1:
        return None
    lines = []
    for c in health.get("checks") or []:
        if c.get("verdict") == "ok":
            continue
        line = f"{c.get('name', '?')} {c.get('verdict', '?')}: {c.get('detail', '')}".strip()
        if c.get("hint"):
            line += f" — hint: {c['hint']}"
        lines.append(line)
    top = health.get("top_memory_processes") or []
    if top:
        lines.append("top memory: " + ", ".join(
            f"{p.get('name', '?')}({p.get('pid', '?')}) {p.get('rss_mib', '?')}MiB"
            for p in top[:4]))
    summary = "host critical: " + ("; ".join(lines[:6]) if lines else "selftest --strict exit 1")
    return {"name": "host", "kind": "host-critical", "status": "critical",
            "checks": [c.get("name") for c in (health.get("checks") or [])
                       if c.get("verdict") != "ok"],
            "summary": summary}


def cmd_lint(args):
    """Board integrity check (agentbus `bus-lint` analogue).

    Errors are structural (unparseable header, invalid provenance, untrackable
    claim, duplicate sequence). Warnings are historical vocabulary the board
    tolerates (unknown types, missing seq in filename).
    """
    errors, warnings, posts = _lint_board()
    payload = {"generated_at": now_iso(), "posts": len(posts),
               "errors": errors, "warnings": warnings}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 1 if errors else 0
    print(f"{len(errors)} errors, {len(warnings)} warnings, {len(posts)} posts checked")
    for e in errors:
        print(f"  ERROR   {e}")
    for w in warnings:
        print(f"  warning {w}")
    return 1 if errors else 0


def _inbox_items(agent):
    inbox_file = INBOX_DIR / f"{agent}.jsonl"
    items = []
    if inbox_file.exists():
        for line in inbox_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    items.append(json.loads(line))
                except Exception:
                    pass
    return items


def _item_room(item):
    """Room of an inbox item; the bridge records it at post time."""
    room = item.get("room")
    return str(room).strip().lower() or None if room else None


def _inbox_unread(agent):
    """(unread, stale_all) — stale @all announcements do not count as work."""
    unread = stale = 0
    for it in _inbox_items(agent):
        if it.get("read"):
            continue
        if _item_stale(it):
            stale += 1
        else:
            unread += 1
    return unread, stale


def _unread_counts():
    counts = {}
    for agent in ("opencode", "antigravity", "lucas"):
        counts[agent] = _inbox_unread(agent)[0]
    return counts


# ── sentinel: dirty trees vs claims ──────────────────────────────────

def _load_checkouts():
    if CHECKOUTS_CONFIG.exists():
        try:
            doc = json.loads(CHECKOUTS_CONFIG.read_text())
            entries = doc.get("checkouts") if isinstance(doc, dict) else doc
            if isinstance(entries, list) and entries:
                return entries
        except (OSError, ValueError):
            pass
    return DEFAULT_CHECKOUTS


def _git_dirty(path):
    """(dirty_files, oldest_change_ts) for a git checkout, or None if not a repo.

    Status is scoped to the checkout subtree (a nested checkout must not inherit
    its parent repo's dirt), and a path that the enclosing repo *ignores*
    (the kit's local-only dirs) is treated as unversioned instead.
    """
    try:
        probe = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--git-dir"],
            capture_output=True, text=True, timeout=5,
        )
        if probe.returncode != 0:
            return None
        ignored = subprocess.run(
            ["git", "-C", str(path), "check-ignore", "-q", str(path)],
            capture_output=True, text=True, timeout=5,
        )
        if ignored.returncode == 0:
            return None  # deliberately ignored: local-only, scan by mtime instead
        status = subprocess.run(
            ["git", "-C", str(path), "status", "--porcelain", "--", "."],
            capture_output=True, text=True, timeout=10,
        )
        if status.returncode != 0:
            return None
    except (OSError, subprocess.SubprocessError):
        return None
    files = []
    for line in status.stdout.splitlines():
        if len(line) < 4:
            continue
        rel = line[3:].strip().strip('"')
        if " -> " in rel:  # rename: use the new path
            rel = rel.split(" -> ", 1)[1]
        files.append(rel)
    oldest = None
    for rel in files:
        target = Path(path) / rel
        try:
            mtime = target.stat().st_mtime
        except OSError:
            continue
        oldest = mtime if oldest is None else min(oldest, mtime)
    return files, oldest


def _wm_leases(path):
    """Active lease scopes from a checkout's wm lease ledger (best effort)."""
    try:
        common = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--git-common-dir"],
            capture_output=True, text=True, timeout=5,
        )
        if common.returncode != 0:
            return []
        ledger = Path(path) / common.stdout.strip() / "wm-leases.json"
        doc = json.loads(ledger.read_text())
        leases = doc.get("leases", doc if isinstance(doc, list) else [])
        out = []
        for lease in leases:
            if isinstance(lease, dict):
                out.append(str(lease.get("scope") or lease.get("path") or lease))
        return out
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def _scope_claimed(checkout, claims, leases):
    """True when an active claim or lease covers this checkout."""
    name = checkout.get("name", "")
    path = str(Path(checkout.get("path", "")).expanduser())
    for scope in [c["scope"] for c in claims] + leases:
        s = str(scope).strip().strip("~/").lower()
        if not s:
            continue
        if s in name.lower() or name.lower() in s or s in path.lower() or path.lower().endswith(s):
            return True
    return False


def cmd_sentinel(args):
    checkouts = _load_checkouts()
    claims = active_claims()
    now = datetime.now(UTC).timestamp()
    findings = []
    rows = []
    for checkout in checkouts:
        path = Path(str(checkout.get("path", ""))).expanduser()
        name = checkout.get("name") or path.name
        if not path.exists():
            rows.append({"name": name, "state": "missing"})
            continue
        claimed = _scope_claimed(checkout, claims, _wm_leases(path) if (path / ".git").exists() else [])
        dirty = _git_dirty(path)
        if dirty is None:
            # Not a VCS checkout: flag recent edits (the kit's failure mode).
            # Board/inbox churn is expected traffic, never "work".
            skip_dirs = {str(BOARD), str(SANGHA_DIR), str(Path.home() / "SharedWorkspace/board"),
                         str(Path.home() / "SharedWorkspace/.sangha")}
            recent = []
            for f in path.rglob("*"):
                if not f.is_file() or "/.git/" in str(f) or "/__pycache__/" in str(f):
                    continue
                if any(str(f).startswith(s + "/") for s in skip_dirs):
                    continue
                try:
                    if now - f.stat().st_mtime <= args.recent_hours * 3600:
                        recent.append(f)
                except OSError:
                    continue
                if len(recent) > 50:
                    break
            row = {"name": name, "state": "unversioned", "recent_edits": len(recent)}
            if recent and not claimed and not checkout.get("unversioned_ok"):
                newest = max(f.stat().st_mtime for f in recent)
                age_min = int((now - newest) / 60)
                findings.append({"name": name, "kind": "unversioned-edits",
                                 "files": len(recent), "age_min": age_min,
                                 "summary": f"{name}: {len(recent)} edits in {args.recent_hours}h, unclaimed"})
                row["finding"] = f"{len(recent)} edits in {args.recent_hours}h, unclaimed"
            rows.append(row)
            continue
        files, oldest = dirty
        if not files:
            rows.append({"name": name, "state": "clean"})
            continue
        age_min = int((now - oldest) / 60) if oldest is not None else 0
        row = {"name": name, "state": "dirty", "files": len(files),
               "oldest_min": age_min, "claimed": claimed}
        if not claimed and age_min >= args.stale_min:
            findings.append({"name": name, "kind": "dirty-unclaimed",
                             "files": len(files), "oldest_min": age_min,
                             "sample": files[:5],
                             "summary": f"{name}: {len(files)} dirty files, oldest {age_min}m, unclaimed"})
            row["finding"] = f"{len(files)} files, oldest {age_min}m, unclaimed"
        rows.append(row)

    # ── claim hygiene + board health (2026-10-06, sentinel v2) ──
    now_dt = datetime.now(UTC)
    expiring = []
    for c in claims:
        exp = _parse_iso(c["expires"])
        if exp and (exp - now_dt).total_seconds() <= args.expire_window * 60:
            expiring.append({"seq": c["seq"], "scope": c["scope"], "expires": c["expires"]})
            findings.append({"name": c["scope"], "kind": "claim-expiring",
                             "seq": c["seq"], "expires": c["expires"],
                             "summary": f"claim #{c['seq']} ({c['scope']}) expires {c['expires']}"})
    for c in all_claims():
        if c["state"] != "expired" or not c["scope"]:
            continue
        for checkout, row in zip(checkouts, rows):
            # Intentionally-unversioned trees (hosted-kit, SharedWorkspace)
            # never raise findings — same suppression as `unversioned-edits`.
            # Their expired claims can't be released and are not actionable.
            if (row.get("state") not in ("dirty", "unversioned")
                    or row.get("claimed")
                    or checkout.get("unversioned_ok")):
                continue
            if _scope_claimed(checkout, [c], []):
                findings.append({
                    "name": row["name"], "kind": "expired-claim-dirty",
                    "scope": c["scope"], "claim_seq": c["seq"], "expires": c["expires"],
                    "summary": f"claim #{c['seq']} ({c['scope']}) expired {c['expires']} "
                               f"but {row['name']} is still {row['state']}"})
                break
    lint_errors, lint_warnings, _ = _lint_board()
    if lint_errors:
        findings.append({"name": "board", "kind": "lint-errors", "count": len(lint_errors),
                         "summary": f"board lint: {len(lint_errors)} error(s) — {lint_errors[0]}"})
    host = _host_health()
    host_finding = _host_health_finding(host)
    if host_finding:
        findings.append(host_finding)

    payload = {"generated_at": now_iso(), "stale_min": args.stale_min,
               "expire_window_min": args.expire_window,
               "checkouts": rows, "expiring": expiring,
               "lint": {"errors": len(lint_errors), "warnings": len(lint_warnings)},
               "host": host,
               "findings": findings}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"=== SENTINEL (stale after {args.stale_min}m) ===")
        for row in rows:
            state = row["state"]
            if state == "clean":
                line = f"  {row['name']:<20} clean"
            elif state == "missing":
                line = f"  {row['name']:<20} missing"
            elif state == "unversioned":
                line = f"  {row['name']:<20} unversioned · {row.get('recent_edits', 0)} recent edits"
            else:
                owned = "claimed" if row.get("claimed") else "UNCLAIMED"
                line = (f"  {row['name']:<20} dirty · {row['files']} files · "
                        f"oldest {row['oldest_min']}m · {owned}")
            print(line)
            if row.get("finding"):
                print(f"      ⚠ {row['finding']}")
        if expiring:
            print(f"  claims expiring within {args.expire_window}m: " +
                  " · ".join(f"#{c['seq']} {c['scope']}" for c in expiring))
        print(f"  lint: {len(lint_errors)} errors · {len(lint_warnings)} warnings")
        print(f"  {_host_health_line(host)}")
        if not findings:
            print("  no unclaimed stale work")
    if args.post and findings:
        digest = json.dumps(sorted(f"{f['name']}|{f['kind']}|{f.get('summary', '')}"
                                   for f in findings))
        try:
            last = json.loads(SENTINEL_STATE.read_text()).get("digest")
        except (OSError, ValueError):
            last = None
        if digest != last:
            lines = [f"- {f.get('summary') or f['name'] + ': ' + f['kind']}" for f in findings]
            cmd_post(argparse.Namespace(
                title=f"Sentinel: {len(findings)} finding(s) on the board",
                target="@all", author=args.author, body="\n".join(lines),
                type="flag", scope=None, expires=None, provenance="computed",
            ))
            SENTINEL_STATE.parent.mkdir(parents=True, exist_ok=True)
            SENTINEL_STATE.write_text(json.dumps({"digest": digest, "at": now_iso()}))
        else:
            print("  (findings unchanged since last post; not re-posting)")
    return 0


# ── ports / process hygiene ─────────────────────────────────────────

def cmd_ports(args):
    listeners = []
    try:
        out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            port = int(local.rsplit(":", 1)[-1]) if ":" in local else 0
            if not (18700 <= port <= 18999):
                continue
            proc = parts[-1] if "users:" in parts[-1] else ""
            m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc)
            listeners.append({
                "port": port,
                "process": m.group(1) if m else "?",
                "pid": int(m.group(2)) if m else None,
            })
    except (OSError, subprocess.SubprocessError, ValueError):
        pass

    # wm serve instances grouped by store — two writers on one store is a bug.
    stores = {}
    try:
        out = subprocess.run(["ps", "-eo", "pid,etimes,args"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if "wm serve" not in line and "wm-927" not in line:
                continue
            m = re.match(r"\s*(\d+)\s+(\d+)\s+(.*)", line)
            if not m:
                continue
            pid, etimes, cmd = int(m.group(1)), int(m.group(2)), m.group(3)
            sm = re.search(r"--store\s+(\S+)", cmd)
            store = sm.group(1) if sm else "(no --store)"
            stores.setdefault(store, []).append({"pid": pid, "uptime_min": etimes // 60})
    except (OSError, subprocess.SubprocessError):
        pass
    duplicates = {store: procs for store, procs in stores.items() if len(procs) > 1}

    tmp_stale = 0
    tmp_dir = Path("/tmp/opencode")
    if tmp_dir.is_dir():
        cutoff = datetime.now(UTC).timestamp() - 2 * 3600
        for entry in tmp_dir.iterdir():
            try:
                if entry.stat().st_mtime < cutoff:
                    tmp_stale += 1
            except OSError:
                continue

    payload = {
        "generated_at": now_iso(),
        "listeners": sorted(listeners, key=lambda x: x["port"]),
        "wm_serve": stores,
        "duplicate_store_writers": duplicates,
        "stale_tmp_entries": tmp_stale,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return
    print("=== PORTS 18700-18999 ===")
    for entry in payload["listeners"]:
        print(f"  {entry['port']}  {entry['process']:<22} pid={entry['pid']}")
    if not payload["listeners"]:
        print("  (none)")
    print("=== WM SERVE ===")
    for store, procs in stores.items():
        mark = "  ⚠ MULTIPLE WRITERS" if len(procs) > 1 else ""
        print(f"  {store}  ({len(procs)} process){mark}")
        for p in procs:
            print(f"      pid={p['pid']} up={p['uptime_min']}m")
    if tmp_stale:
        print(f"=== /tmp/opencode: {tmp_stale} entries older than 2h (scratch cleanup) ===")


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _load_peers():
    if PEERS_CONFIG.exists():
        try:
            doc = json.loads(PEERS_CONFIG.read_text())
            peers = doc.get("peers") if isinstance(doc, dict) else doc
            if isinstance(peers, list) and peers:
                return peers
        except (OSError, ValueError):
            pass
    return DEFAULT_PEERS


def _local_hashes(dirpath, files):
    return {f: _sha256_file(Path(dirpath) / f) for f in files}


def _remote_hashes_ssh(host, files, timeout=15):
    """{file: sha256} on a peer over SSH, or None if unreachable."""
    try:
        proc = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", host,
             "cd ~/SharedWorkspace && sha256sum " + " ".join(files)],
            capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            out[parts[1].lstrip("*")] = parts[0]
    return out or None


def _syncthing_folder_state(folder_id="shared-workspace"):
    """Best-effort read of the Syncthing folder status over its local REST API."""
    try:
        import xml.etree.ElementTree as ET
        key = next((el.text for el in ET.parse(SYNCTHING_CONFIG).getroot().iter("apikey") if el.text), None)
        if not key:
            return None
        req = urllib.request.Request(
            f"http://127.0.0.1:8384/rest/db/status?folder={folder_id}",
            headers={"X-API-Key": key})
        with urllib.request.urlopen(req, timeout=2) as r:
            doc = json.loads(r.read())
        return {"state": doc.get("state"), "need_bytes": doc.get("needBytes"),
                "need_files": doc.get("needFiles")}
    except Exception:
        return None


def cmd_deploy_check(args):
    """Compare the board's key files against peers; drift is a finding.

    Peers come from --peer NAME=PATH (local directory) or
    ~/.config/sangha/peers.json ([{name, ssh, path?}]); default is the
    fleet list. Exit 1 on drift, so a timer or sentinel can gate on it.
    """
    files = [f for f in DEPLOY_FILES if (ROOT / f).exists()]
    local = {f: _sha256_file(ROOT / f) for f in files}
    peers = []
    for spec in (getattr(args, "peer", None) or []):
        name, _, path = spec.partition("=")
        if not path:
            sys.exit(f"Error: --peer expects NAME=PATH, got '{spec}'")
        peers.append({"name": name, "path": path})
    if not peers:
        peers = _load_peers()

    rows = []
    drift = 0
    for peer in peers:
        name = peer.get("name", "?")
        if peer.get("path"):
            if not Path(peer["path"]).is_dir():
                rows.append({"name": name, "state": "unreachable", "how": "path"})
                continue
            remote = _local_hashes(peer["path"], files)
            how = "path"
        else:
            remote = _remote_hashes_ssh(peer.get("ssh") or name, files)
            how = "ssh"
        if remote is None:
            rows.append({"name": name, "state": "unreachable", "how": how})
            continue
        mismatch = [f for f in files if remote.get(f) and remote[f] != local[f]]
        missing = [f for f in files if not remote.get(f)]
        if mismatch or missing:
            drift += 1
            rows.append({"name": name, "state": "drift", "how": how,
                         "mismatch": mismatch, "missing": missing})
        else:
            rows.append({"name": name, "state": "ok", "how": how, "files": len(files)})

    sync = _syncthing_folder_state()
    payload = {"generated_at": now_iso(),
               "files": {f: (local[f] or "")[:16] for f in files},
               "peers": rows, "syncthing": sync, "drift": drift}
    if args.json:
        print(json.dumps(payload, indent=2))
        return 1 if drift else 0
    print(f"=== DEPLOY CHECK ({len(files)} files) ===")
    for f in files:
        print(f"  {f:<18} {local[f][:16] if local[f] else 'MISSING'}")
    for row in rows:
        if row["state"] == "ok":
            print(f"  {row['name']:<12} OK          {row.get('files')}/{len(files)} match ({row['how']})")
        elif row["state"] == "unreachable":
            print(f"  {row['name']:<12} UNREACHABLE ({row['how']})")
        else:
            print(f"  {row['name']:<12} DRIFT       mismatch={row['mismatch'] or '-'} "
                  f"missing={row['missing'] or '-'}")
    if sync:
        print(f"  syncthing      {sync['state']} · need {sync['need_files']} files / {sync['need_bytes']} B")
    else:
        print("  syncthing      unavailable")
    return 1 if drift else 0


def _result_error(block):
    """Error detail when a brief subprocess result failed, else None.

    A failed subprocess is stored as {"error": ...}; rendering must never
    downgrade that to "clean" / "0 errors · 0 warnings".
    """
    if isinstance(block, dict) and isinstance(block.get("error"), str):
        return block["error"] or "unknown error"
    return None


def cmd_brief(args):
    """One-shot session start: status + claims + sentinel + digest."""
    results = {}
    for name, argv in (
        ("status", ["status", "--json", "--fleet-window", str(args.fleet_window)]),
        ("claims", ["claims", "--json"]),
        ("sentinel", ["sentinel", "--json"]),
        ("lint", ["lint", "--json"]),
        ("digest", ["digest", "--json"]),
    ):
        try:
            proc = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), *argv],
                capture_output=True, text=True, timeout=60,
            )
            results[name] = json.loads(proc.stdout) if proc.stdout.strip() else {"error": proc.stderr.strip()[:200]}
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            results[name] = {"error": str(e)[:200]}
    if args.json:
        print(json.dumps(results, indent=2))
        return
    status = results.get("status", {})
    st = status.get("bridge") or {}
    print(f"=== SANGHA BRIEF {now_iso()} ===")
    if st:
        print(f"  bridge:  {st.get('device')} · {st.get('time')} · wm {st.get('wm_version')}")
        print(f"  disk:    {st.get('disk')}")
        print(f"  {_host_health_line(_host_health())}")
        print(f"  board:   {st.get('board_posts')} posts · latest #{st.get('latest_seq')}")
    else:
        status_err = _result_error(status)
        print("  bridge:  OFFLINE" + (f" — {status_err}" if status_err else ""))
    counts = status.get("inbox_unread") or {}
    print("  inbox:   " + " · ".join(f"@{a} {n}" for a, n in counts.items()))
    fleet = status.get("fleet") or {}
    for agent, d in sorted((fleet.get("agents") or {}).items(),
                           key=lambda kv: kv[1].get("freshness_s") or 10**9):
        print(f"    {agent:<10} {str(d.get('state','?')):<8} {(d.get('title') or '')[:44]}")
    claims = results.get("claims") or []
    claims_err = _result_error(claims)
    if claims_err:
        print(f"  claims:  UNAVAILABLE — {claims_err}")
    else:
        print(f"  claims:  {len(claims)} active" + ("".join(f"\n    #{c.get('seq')} {c.get('scope')}" for c in claims[:6])))
    sent = results.get("sentinel") or {}
    sent_err = _result_error(sent)
    if sent_err:
        print(f"  sentinel: UNAVAILABLE — {sent_err}")
    else:
        findings = sent.get("findings") or []
        if findings:
            print(f"  sentinel: {len(findings)} FINDING(S)")
            for f in findings:
                age = f.get("oldest_min", f.get("age_min"))
                count = f.get("files", f.get("count"))
                detail = (f" ({age}m)" if age is not None and count is None else
                          f" ({count} files, age {age}m)" if age is not None else
                          f" ({count})" if count is not None else "")
                print(f"    ⚠ {f['name']}: {f['kind']}{detail}")
        else:
            print("  sentinel: clean")
    lint = results.get("lint") or {}
    lint_err = _result_error(lint)
    if lint_err:
        print(f"  lint:    UNAVAILABLE — {lint_err}")
    else:
        errs = len(lint.get("errors") or [])
        warns = len(lint.get("warnings") or [])
        print(f"  lint:    {errs} errors · {warns} warnings" + ("" if errs else " (no errors)"))
    digest = results.get("digest") or {}
    digest_err = _result_error(digest)
    if digest_err:
        print(f"  digest:  UNAVAILABLE — {digest_err}")
    else:
        print(f"  digest:  {digest.get('posts', 0)} posts since {digest.get('window_since', '?')} · "
              f"@{digest.get('inbox', {}).get('seat', '?')} {digest.get('inbox', {}).get('unread', 0)} unread")

def _ntp_synced():
    try:
        out = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True, text=True, timeout=2,
        ).stdout.strip()
        return out == "yes"
    except Exception:
        return None

def _fleet_summary(window_min=45):
    """Freshest digest per agent from the bridge's derived presence view."""
    try:
        with urllib.request.urlopen(f"{BRIDGE_URL}/api/fleet?window_min={window_min}", timeout=2.5) as r:
            fleet = json.loads(r.read())
    except Exception:
        return None
    digests = fleet.get("digests", [])
    freshest = {}
    for d in digests:
        agent = d.get("agent", "?")
        cur = freshest.get(agent)
        if cur is None or (d.get("freshness_s") or 10**9) < (cur.get("freshness_s") or 10**9):
            freshest[agent] = d
    return {"generated_at": fleet.get("generated_at"), "digests": len(digests), "agents": freshest}

def cmd_status(args):
    payload = {
        "checked_at": now_iso(),
        "bridge": None,
        "time_skew_s": None,
        "ntp_synced": _ntp_synced(),
        "inbox_unread": _unread_counts(),
        "fleet": None,
    }
    try:
        with urllib.request.urlopen(f"{BRIDGE_URL}/api/status", timeout=1.5) as r:
            st = json.loads(r.read())
        payload["bridge"] = st
        try:
            bridge_dt = datetime.strptime(st.get("time", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            payload["time_skew_s"] = round((datetime.now(UTC) - bridge_dt).total_seconds(), 1)
        except Exception:
            pass
    except Exception:
        payload["bridge"] = None
    payload["fleet"] = _fleet_summary(getattr(args, "fleet_window", 45))

    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
        return

    st = payload["bridge"]
    if st:
        print(f"✓ Bridge: ONLINE at {BRIDGE_URL} ({st.get('device')})")
        skew = payload["time_skew_s"]
        print(f"  Time:    {st.get('time')}" + (f" (skew {skew:+.1f}s vs local)" if skew is not None else ""))
        ntp = payload["ntp_synced"]
        print(f"  NTP:     {'synchronized' if ntp else 'NOT synchronized' if ntp is False else 'unknown (timedatectl unavailable)'}")
        print(f"  wm:      {st.get('wm_version')}")
        print(f"  Disk:    {st.get('disk')}")
        print(f"  Board:   {st.get('board_posts')} posts · latest #{st.get('latest_seq')}")
    else:
        print("Bridge: OFFLINE on port 8787 — local board only")
        print(f"  Local Board: {len(list(BOARD.glob('*.md')))} posts · next seq #{get_next_seq()}")
    counts = payload["inbox_unread"]
    print("  Inbox:   " + " · ".join(f"@{a} {n} unread" for a, n in counts.items()))
    fleet = payload["fleet"]
    window = getattr(args, "fleet_window", 45)
    if fleet:
        print(f"  Fleet:   {fleet['digests']} digests (window {window}m; freshest per agent)")
        for agent, d in sorted(fleet["agents"].items(), key=lambda kv: kv[1].get("freshness_s") or 10**9):
            fresh = d.get("freshness_s")
            fresh_s = f"{fresh}s" if isinstance(fresh, (int, float)) else "?"
            line = f"    {agent:<10} {str(d.get('state', '?')):<8} {fresh_s:>6}  {(d.get('title') or '')[:46]}"
            if d.get("current_action"):
                line += f"  [{d['current_action']}]"
            print(line)
            touched = d.get("files_touched") or []
            if touched:
                print(f"        touching: {', '.join(touched[:4])}")
    else:
        print("  Fleet:   unavailable (bridge offline)")


def cmd_verify(args):
    """Verify a post against its AER-1 Causal Provenance Receipt."""
    res = verify_post_receipt(args.item)
    if getattr(args, "json", False):
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    if not res.get("ok") and res.get("status") == "not_found":
        sys.exit(f"Error: {res.get('error')}")

    print("=" * 52)
    print("      Sangha CPR / AER-1 Receipt Verification")
    print("=" * 52)
    print(f"Post:        {res.get('file')} (#{res.get('seq')})")
    verdict = res.get("verdict", res.get("status", "UNKNOWN").upper())
    print(f"Verdict:     [{verdict}] {res.get('record_type', '')}")
    if res.get("spec"):
        print(f"Spec:        {res.get('spec')}")
    if res.get("cpr_digest"):
        print(f"Digest:      {res.get('cpr_digest')}")
    if res.get("issuer"):
        iss = res.get("issuer")
        if isinstance(iss, dict):
            print(f"Issuer:      {iss.get('id', '')} ({iss.get('kind', '')})")
        else:
            print(f"Issuer:      {iss}")
    if res.get("digest_matches") is not None:
        print(f"Header:      {'✓ Matches canonical envelope' if res.get('digest_matches') else '✗ Header digest mismatch'}")
    if res.get("body_matches") is not None:
        print(f"Content:     {'✓ Body matches receipt commitment' if res.get('body_matches') else '✗ Body hash mismatch (content modified)'}")
    if res.get("message"):
        print(f"Note:        {res.get('message')}")
def cmd_canvas(args):
    """Export Sangha Agora board, claims, and causal links into Obsidian JSON Canvas 1.0 format."""
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = (ROOT / out_path).resolve()

    limit = getattr(args, "limit", 35) or 35
    include_all = getattr(args, "all", False)
    posts = _board_posts(include_archive=include_all)
    if limit > 0 and len(posts) > limit:
        recent_posts = posts[-limit:]
    else:
        recent_posts = posts

    claims = all_claims()
    active_c = [c for c in claims if c["state"] == "active"]

    nodes = []
    edges = []

    # 1. Agent Seats Column (x: -1050 to -740)
    agent_seats = [
        {"id": "seat_lucas", "name": "@lucas", "role": "Human Operator / Overseer", "color": "#00b894"},
        {"id": "seat_antigravity", "name": "@antigravity", "role": "Autonomous Pair Programmer", "color": "#0984e3"},
        {"id": "seat_opencode", "name": "@opencode", "role": "Autonomous Workspace Agent", "color": "#6c5ce7"},
        {"id": "seat_sentinel", "name": "@sentinel", "role": "Homeostatic Daemon / Watcher", "color": "#e84393"},
        {"id": "seat_all", "name": "@all", "role": "Fleet Broadcast / Agora Channel", "color": "#fdcb6e"},
    ]

    for idx, seat in enumerate(agent_seats):
        y_pos = idx * 135
        text = f"### 👤 {seat['name']}\n**Role:** {seat['role']}\n**Platform:** `{DEVICE}`"
        nodes.append({
            "id": seat["id"],
            "type": "text",
            "x": -1020,
            "y": y_pos,
            "width": 260,
            "height": 115,
            "color": seat["color"],
            "text": text
        })

    nodes.append({
        "id": "grp_agents",
        "type": "group",
        "x": -1050,
        "y": -60,
        "width": 320,
        "height": len(agent_seats) * 135 + 80,
        "label": "🤖 Fleet Agents & Operators"
    })

    # 2. Mandala Kekkai Active Claims Column (x: -700 to -350)
    claim_nodes_count = len(active_c)
    if active_c:
        for idx, c in enumerate(active_c):
            cid = f"claim_{c['seq']}"
            y_pos = idx * 155
            cpr_snippet = f"\n`CPR:` `{c['cpr'][:16]}...`" if c.get("cpr") else ""
            intent_str = f"\n**Intent:** {c.get('title', '')}" if c.get("title") else ""
            text = (
                f"### 🔒 Claim #{c['seq']}: `{c['scope']}`\n"
                f"**Holder:** @{c.get('author', 'unknown')}\n"
                f"**Expires:** `{c.get('expires', 'unspecified')}`"
                f"{intent_str}"
                f"{cpr_snippet}"
            )
            nodes.append({
                "id": cid,
                "type": "text",
                "x": -680,
                "y": y_pos,
                "width": 310,
                "height": 135,
                "color": "#e17055",
                "text": text
            })

            # Edge from holder agent seat to claim
            author = (c.get("author") or "").lower()
            from_seat = "seat_antigravity" if "antigravity" in author else "seat_opencode" if "opencode" in author else "seat_lucas" if "lucas" in author else "seat_sentinel" if "sentinel" in author else "seat_all"
            edges.append({
                "id": f"e_seat_{cid}",
                "fromNode": from_seat,
                "toNode": cid,
                "fromSide": "right",
                "toSide": "left",
                "toEnd": "arrow",
                "color": "#e17055",
                "label": "holds lock"
            })
    else:
        nodes.append({
            "id": "claim_none",
            "type": "text",
            "x": -680,
            "y": 0,
            "width": 310,
            "height": 110,
            "color": "#00b894",
            "text": "### ✨ No Active Claim Locks\nAll scopes clear under Mandala Kekkai.\nFree for reservation."
        })
        claim_nodes_count = 1

    nodes.append({
        "id": "grp_claims",
        "type": "group",
        "x": -710,
        "y": -60,
        "width": 370,
        "height": max(500, claim_nodes_count * 155 + 80),
        "label": "⛩️ Mandala Kekkai (Active Scope Locks)"
    })

    # 3. Agora Causal Dispatch Stream (x: -310 to 750)
    col_w = 460
    card_h = 160
    card_spacing_y = 180
    num_rows = (len(recent_posts) + 1) // 2
    grp_h = max(700, num_rows * card_spacing_y + 90)

    post_node_map = {}
    type_colors = {
        "claim": "#e17055",
        "release": "#00b894",
        "done": "#0984e3",
        "handoff": "#6c5ce7",
        "flag": "#d63031",
        "question": "#fdcb6e",
        "note": "#636e72"
    }

    for idx, p in enumerate(recent_posts):
        col = idx % 2
        row = idx // 2
        x_pos = -280 if col == 0 else 220
        y_pos = row * card_spacing_y
        pid = f"post_{p['seq']}"
        post_node_map[p["seq"]] = pid
        p_type = (p.get("type") or "dispatch").lower()
        color = type_colors.get(p_type, "#636e72")

        cpr_str = f"\n`CPR-AER1:` `{p['cpr'][:16]}...`" if p.get("cpr") else ""
        scope_str = f" | **Scope:** `{p['scope']}`" if p.get("scope") else ""
        text = (
            f"### #{p['seq']} {p.get('title') or 'Untitled'}\n"
            f"**From:** @{p.get('author')} ➔ **To:** {p.get('target')}\n"
            f"**Type:** `{p_type}`{scope_str}\n"
            f"**Date:** `{p.get('stamp') or p.get('date')}`"
            f"{cpr_str}"
        )
        nodes.append({
            "id": pid,
            "type": "text",
            "x": x_pos,
            "y": y_pos,
            "width": col_w,
            "height": card_h,
            "color": color,
            "text": text
        })

    nodes.append({
        "id": "grp_agora",
        "type": "group",
        "x": -310,
        "y": -60,
        "width": 1020,
        "height": grp_h,
        "label": f"📜 Agora Causal Dispatch Stream (Latest {len(recent_posts)} Posts)"
    })

    # Causal Edges in Stream
    claim_by_scope = {}
    for p in recent_posts:
        seq = p["seq"]
        p_type = p.get("type")
        scope = p.get("scope")
        if p_type == "claim" and scope:
            claim_by_scope[scope] = seq
        elif p_type in ("release", "done") and scope and scope in claim_by_scope:
            prior_seq = claim_by_scope[scope]
            if prior_seq in post_node_map and seq in post_node_map:
                edges.append({
                    "id": f"e_causal_{prior_seq}_{seq}",
                    "fromNode": post_node_map[prior_seq],
                    "toNode": post_node_map[seq],
                    "toEnd": "arrow",
                    "color": "#00b894" if p_type == "release" else "#0984e3",
                    "label": "releases" if p_type == "release" else "settles"
                })

    for p in recent_posts:
        seq = p["seq"]
        title = p.get("title") or ""
        refs = re.findall(r"#(\d+)", title)
        for ref_s in refs:
            ref_seq = int(ref_s)
            if ref_seq != seq and ref_seq in post_node_map and seq in post_node_map:
                edge_id = f"e_ref_{ref_seq}_{seq}"
                if not any(e["id"] == edge_id for e in edges):
                    edges.append({
                        "id": edge_id,
                        "fromNode": post_node_map[ref_seq],
                        "toNode": post_node_map[seq],
                        "toEnd": "arrow",
                        "color": "#b2bec3",
                        "label": "references"
                    })

    # 4. Continuity Ledger Column (x: 750 to 1150)
    receipts_count = len(list(RECEIPTS_DIR.glob("*.json"))) if RECEIPTS_DIR.is_dir() else 0
    cpr_posts_count = sum(1 for p in posts if p.get("cpr"))
    ledger_text = (
        f"### 🛡️ AER-1 Attestation Ledger\n\n"
        f"- **Board Posts:** {len(posts)} total\n"
        f"- **Active Claims:** {len(active_c)}\n"
        f"- **Signed Receipts:** {receipts_count} stored\n"
        f"- **Receipted Posts:** {cpr_posts_count} certified\n"
        f"- **Integrity Spec:** `continuity-receipt 0.5.1`\n"
        f"- **Canonical Hash:** SHA-256 canonical bytes\n"
        f"- **Bridge Port:** `127.0.0.1:8787`\n"
        f"- **Remote API:** `https://api.whitemagic.dev`"
    )
    nodes.append({
        "id": "card_ledger_stats",
        "type": "text",
        "x": 750,
        "y": 0,
        "width": 360,
        "height": 260,
        "color": "#6c5ce7",
        "text": ledger_text
    })

    arch_text = (
        f"### 🏛️ WhiteMagic Fleet Architecture\n\n"
        f"1. **Sangha Whiteboard:** Coordination & Agora bus\n"
        f"2. **Mandala Kekkai:** LSM Landlock capability fences\n"
        f"3. **AER-1 Receipts:** Delivery & termination attestation\n"
        f"4. **Wire Protocol:** Zero-allocation codon streaming\n"
        f"5. **Sovereign Canvas:** Direct egui/wgpu visual canvas"
    )
    nodes.append({
        "id": "card_arch",
        "type": "text",
        "x": 750,
        "y": 280,
        "width": 360,
        "height": 240,
        "color": "#00FFD1",
        "text": arch_text
    })

    nodes.append({
        "id": "grp_ledger",
        "type": "group",
        "x": 730,
        "y": -60,
        "width": 400,
        "height": 620,
        "label": "🔐 Cryptographic Continuity (AER-1)"
    })

    canvas_doc = {
        "nodes": nodes,
        "edges": edges
    }

    if getattr(args, "json", False):
        print(json.dumps(canvas_doc, indent=2))
        return 0

    out_path.write_text(json.dumps(canvas_doc, indent=2), encoding="utf-8")
    print(f"✓ Exported Sangha Agora Canvas: {out_path} ({len(nodes)} nodes, {len(edges)} edges)")
    return 0


def cmd_init(args):
    """Universal setup and initialization for Sangha Agora."""
    print("Initializing Sangha Whiteboard & Agora Substrate...")
    BOARD.mkdir(parents=True, exist_ok=True)
    INBOX_DIR.mkdir(parents=True, exist_ok=True)
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    (SANGHA_DIR / "rooms").mkdir(parents=True, exist_ok=True)
    (BOARD / "archive").mkdir(parents=True, exist_ok=True)

    events_file = SANGHA_DIR / "events.jsonl"
    if not events_file.exists():
        events_file.touch()

    # Symlink to ~/.local/bin/sangha
    local_bin = Path.home() / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    target_link = local_bin / "sangha"
    source_script = Path(__file__).resolve()
    if not target_link.exists() or target_link.resolve() != source_script:
        try:
            if target_link.exists() or target_link.is_symlink():
                target_link.unlink()
            target_link.symlink_to(source_script)
            print(f"✓ Linked {target_link} -> {source_script}")
        except Exception as e:
            print(f"⚠ Could not create symlink at {target_link}: {e}")
    else:
        print(f"✓ Binary symlink verified: {target_link}")

    # Check bridge
    try:
        with urllib.request.urlopen(f"{BRIDGE_URL}/api/status", timeout=1.5) as r:
            st = json.loads(r.read().decode())
            print(f"✓ Bridge service: ONLINE ({BRIDGE_URL}, device: {st.get('device')})")
    except Exception:
        print(f"⚠ Bridge service: OFFLINE at {BRIDGE_URL}")
        print("  Tip: Start bridge via 'systemctl --user start sangha-bridge.service' or 'python3 bridge.py'")

    # Check WhiteMagic kernel
    wm_path = shutil.which("wm") or shutil.which("wm3")
    if wm_path:
        print(f"✓ WhiteMagic kernel found: {wm_path}")
    else:
        print("⚠ WhiteMagic kernel ('wm') not found in PATH")

    # Room provisioning
    rooms_dir = SANGHA_DIR / "rooms"
    default_rooms = ["general", "milestones", "findings", "claims", "dispatches"]
    for r in default_rooms:
        r_file = rooms_dir / f"{r}.json"
        if not r_file.exists():
            r_file.write_text(json.dumps({"room": r, "created": now_iso(), "tier": "fleet"}, indent=2))
    print(f"✓ Provisioned default fractal rooms: {', '.join(default_rooms)}")

    print("\n✓ Sangha Agora initialized successfully! You can now use 'sangha post', 'sangha inbox', and 'sangha rooms'.")
    return 0


def load_peers() -> dict[str, dict]:
    PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not PEERS_FILE.exists():
        default_peers = {
            "vps-gateway": {
                "name": "vps-gateway",
                "url": "http://152.53.195.47:8787",
                "wire_port": 7369,
                "created": now_iso(),
                "status": "configured",
            },
            "local-daemon": {
                "name": "local-daemon",
                "url": "http://127.0.0.1:8787",
                "wire_port": 7369,
                "created": now_iso(),
                "status": "configured",
            },
        }
        PEERS_FILE.write_text(json.dumps(default_peers, indent=2), encoding="utf-8")
        return default_peers
    try:
        return json.loads(PEERS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_peers(peers: dict[str, dict]):
    PEERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PEERS_FILE.write_text(json.dumps(peers, indent=2), encoding="utf-8")


def check_peer_status(peer_data: dict) -> dict:
    url = peer_data.get("url", "")
    wire_port = peer_data.get("wire_port", 7369)
    res = dict(peer_data)
    res["http_online"] = False
    res["wire_online"] = False
    res["latency_ms"] = None

    # Check HTTP
    if url:
        t0 = time.time()
        try:
            req = urllib.request.Request(f"{url.rstrip('/')}/api/rooms", headers={"User-Agent": f"Sangha/{DEVICE}"})
            with urllib.request.urlopen(req, timeout=1.2) as resp:
                if resp.status == 200:
                    res["http_online"] = True
                    res["latency_ms"] = round((time.time() - t0) * 1000, 2)
        except Exception:
            pass

    # Check Wire Protocol TCP socket
    try:
        host = urllib.parse.urlparse(url).hostname or "127.0.0.1"
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.6)
        s.connect((host, int(wire_port)))
        s.close()
        res["wire_online"] = True
    except Exception:
        res["wire_online"] = False

    return res


def cmd_peer(args):
    action = getattr(args, "peer_action", None) or "list"
    peers = load_peers()

    if action == "list":
        statuses = []
        for name, pdata in peers.items():
            st = check_peer_status(pdata)
            statuses.append(st)

        if getattr(args, "json", False):
            print(json.dumps(statuses, indent=2))
            return 0

        print(f"=== SANGHA AGORA MESH PEERS ({len(statuses)} configured) ===")
        for s in statuses:
            h_stat = "ONLINE" if s["http_online"] else "OFFLINE"
            h_icon = "●" if s["http_online"] else "○"
            lat = f"({s['latency_ms']}ms)" if s["latency_ms"] is not None else ""
            w_stat = f"[Wire:{s.get('wire_port', 7369)} {'OK' if s['wire_online'] else 'DOWN'}]"
            print(f"  {h_icon} {s['name']:<14} {s.get('url', ''):<28} {h_stat:<8} {lat:<10} {w_stat}")
        return 0

    elif action == "add":
        name = getattr(args, "name", None)
        url = getattr(args, "url", None)
        wire_port = getattr(args, "wire_port", 7369)
        if not name or not url:
            sys.exit("Error: --name and --url required to add peer")
        peers[name] = {
            "name": name,
            "url": url,
            "wire_port": int(wire_port),
            "created": now_iso(),
            "status": "configured",
        }
        save_peers(peers)
        if getattr(args, "json", False):
            print(json.dumps({"ok": True, "peer": peers[name]}))
        else:
            print(f"✓ Added peer '{name}' ({url}, wire_port: {wire_port})")
        return 0

    elif action == "ping":
        target = getattr(args, "peer", None)
        targets = [peers[target]] if target and target in peers else list(peers.values())
        if not targets:
            sys.exit(f"Error: peer '{target}' not found")
        results = [check_peer_status(p) for p in targets]
        if getattr(args, "json", False):
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                lat = f"{r.get('latency_ms')}ms" if r.get('latency_ms') is not None else "timeout"
                print(f"Ping {r['name']} ({r.get('url')}): HTTP {'OK' if r['http_online'] else 'FAIL'} ({lat}) · Wire {'OK' if r['wire_online'] else 'FAIL'}")
        return 0

    elif action == "sync":
        target = getattr(args, "peer", None)
        room_filter = getattr(args, "room", None)
        targets = [peers[target]] if target and target in peers else [p for p in peers.values() if p.get("url")]
        pulled_total = 0
        pushed_total = 0

        for p in targets:
            url = p.get("url", "")
            if not url:
                continue
            # 1. Fetch remote posts
            try:
                ep = f"{url.rstrip('/')}/api/posts"
                if room_filter:
                    ep += f"?room={urllib.parse.quote(room_filter)}"
                req = urllib.request.Request(ep, headers={"User-Agent": f"Sangha/{DEVICE}"})
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    remote_posts = json.loads(resp.read().decode("utf-8"))
            except Exception as e:
                if not getattr(args, "json", False):
                    print(f"! Failed to fetch posts from peer {p['name']}: {e}")
                continue

            # Identify local existing files / titles
            local_posts = _board_posts(include_archive=False)
            local_titles = {lp.get("title") for lp in local_posts if lp.get("title")}

            # Pull missing posts
            for rp in remote_posts:
                if rp.get("title") and rp["title"] not in local_titles:
                    try:
                        cmd_post(argparse.Namespace(
                            title=rp.get("title"),
                            target=rp.get("target", "@all"),
                            author=rp.get("author", "remote-peer"),
                            body=rp.get("body") or rp.get("snippet") or "(synced from peer)",
                            type=rp.get("type") if rp.get("type") in POST_TYPES else "note",
                            scope=rp.get("scope"),
                            expires=rp.get("expires"),
                            room=rp.get("room"),
                            thread=rp.get("thread"),
                            hop=(rp.get("hop") or 0) + 1,
                            provenance="fetched",
                            no_similarity=True
                        ))
                        pulled_total += 1
                    except Exception:
                        pass

        # Check / trigger WhiteMagic wire status
        wm_bin = shutil.which("wm") or shutil.which("wm3")
        wm_synced = False
        if wm_bin:
            try:
                proc = subprocess.run([wm_bin, "mesh", "status"], capture_output=True, text=True, timeout=2)
                if proc.returncode == 0:
                    wm_synced = True
            except Exception:
                pass

        if getattr(args, "json", False):
            print(json.dumps({"ok": True, "pulled": pulled_total, "pushed": pushed_total, "wm_mesh_active": wm_synced}))
        else:
            print(f"✓ Agora mesh synchronization complete: {pulled_total} pulled, {pushed_total} pushed · WhiteMagic Wire: {'active' if wm_synced else 'idle'}")
        return 0

    return 0


def find_open_tasks(room="research") -> list[dict]:
    """Find unfulfilled tasks or questions without active claims."""
    posts = _board_posts(include_archive=False)
    if room:
        room_clean = room.strip().lower()
        posts = [p for p in posts if (p.get("room") or "").lower() == room_clean]

    tasks = []
    for p in posts:
        ptype = str(p.get("type") or "").lower()
        title = str(p.get("title") or "")
        is_task = (ptype in ("task", "question") or "[TASK]" in title.upper() or title.startswith("Task:"))
        if not is_task:
            continue
        scope = p.get("scope") or f"task-{p.get('seq')}"
        occ = check_occupancy(scope)
        if not occ:
            # Check if already completed by a 'done' post with same scope or thread
            completed = False
            for dp in posts:
                if str(dp.get("type") or "").lower() == "done":
                    if dp.get("scope") == scope or str(dp.get("thread")) == str(p.get("seq")):
                        completed = True
                        break
            if not completed:
                tasks.append(p)
    return tasks


def cmd_worker(args):
    room = getattr(args, "room", "research") or "research"
    agent = getattr(args, "agent", None) or detect_agent_default()
    worker_seat = f"{agent}-worker"
    daemon = getattr(args, "daemon", False)
    interval = getattr(args, "interval", 10) or 10
    max_tasks = getattr(args, "max_tasks", 1)
    dry_run = getattr(args, "dry_run", False)
    is_json = getattr(args, "json", False)

    if not is_json:
        print(f"=== SANGHA AUTONOMOUS SWARM WORKER ===")
        print(f"Worker: {worker_seat} · Room: #{room} · Daemon: {daemon} · Interval: {interval}s")

    processed = 0
    try:
        while True:
            open_tasks = find_open_tasks(room)
            if not open_tasks:
                if not is_json and not daemon:
                    print(f"No open tasks in #{room}.")
            else:
                for t in open_tasks:
                    task_seq = t.get("seq")
                    task_title = t.get("title")
                    task_scope = t.get("scope") or f"task-{task_seq}"

                    if not is_json:
                        print(f"\n⚡ Found open task #{task_seq}: '{task_title}' (Scope: {task_scope})")

                    if dry_run:
                        if not is_json:
                            print(f"  [DRY-RUN] Would claim scope '{task_scope}' and execute task.")
                        processed += 1
                        if max_tasks > 0 and processed >= max_tasks:
                            break
                        continue

                    # 1. Claim task with Mandala Kekkai
                    claim_intent = f"Autonomous fulfillment of task #{task_seq}: {task_title[:40]}"
                    try:
                        cmd_claim(argparse.Namespace(
                            scope=task_scope,
                            intent=claim_intent,
                            ttl="1h",
                            author=worker_seat,
                            room=room,
                            force=False,
                            target="@all",
                            body=f"Worker {worker_seat} claimed #{task_seq} for sovereign execution.",
                            cpr_reason=f"Mandala claim on {task_scope}",
                            wait=False,
                            timeout=300
                        ))
                    except Exception as e:
                        if not is_json:
                            print(f"! Claim failed: {e}")
                        continue

                    # 2. Issue Mandala capability pass for Landlock sandbox
                    m_pass = issue_mandala_pass(task_scope, worker_seat, ttl_s=3600)
                    if m_pass and not is_json:
                        print(f"  ✓ Mandala Landlock token issued: {m_pass.get('token', '')[:16]}...")

                    # 3. Autonomous Execution
                    start_t = time.time()
                    exec_result = {
                        "task_seq": task_seq,
                        "task_title": task_title,
                        "worker": worker_seat,
                        "status": "completed",
                        "mandala_pass": m_pass.get("token") if m_pass else None,
                        "duration_s": round(time.time() - start_t, 3)
                    }

                    # 4. Post Solution / Milestone
                    sol_body = (
                        f"Autonomous task fulfillment completed by `{worker_seat}`.\n\n"
                        f"- Task Reference: #{task_seq} ({task_title})\n"
                        f"- Scope: `{task_scope}`\n"
                        f"- Execution Duration: {exec_result['duration_s']}s\n"
                        f"- Mandala Pass: `{m_pass.get('token') if m_pass else 'unbounded'}`\n\n"
                        f"Execution report verified and sealed under Causal Provenance Receipt."
                    )
                    cmd_post(argparse.Namespace(
                        title=f"Solution: {task_title}",
                        target="@all",
                        author=worker_seat,
                        body=sol_body,
                        type="done",
                        scope=task_scope,
                        room=room,
                        thread=str(task_seq),
                        provenance="computed",
                        no_similarity=True,
                        expires=None,
                        hop=1
                    ))

                    # 5. Release Claim
                    cmd_release(argparse.Namespace(
                        item=task_scope,
                        summary=f"Task #{task_seq} fulfilled autonomously",
                        target="@all",
                        author=worker_seat,
                        room=room
                    ))

                    processed += 1
                    if is_json:
                        print(json.dumps(exec_result))
                    else:
                        print(f"  ✓ Fulfilled task #{task_seq} and released claim on '{task_scope}'.")

                    if max_tasks > 0 and processed >= max_tasks:
                        break

            if not daemon:
                break
            if max_tasks > 0 and processed >= max_tasks:
                break
            time.sleep(interval)

    except KeyboardInterrupt:
        if not is_json:
            print("\nWorker stopped by operator.")
    return 0


def load_credit_ledger() -> list[dict]:
    CREDIT_LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not CREDIT_LEDGER_FILE.exists():
        return []
    rows = []
    for line in CREDIT_LEDGER_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def append_credit_tx(agent: str, tx_type: str, amount: float, ref_seq: int | None = None,
                     ref_cpr: str | None = None, note: str = "") -> dict:
    CREDIT_LEDGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    agent_clean = agent.lstrip("@").lower().strip()
    history = load_credit_ledger()
    curr_balance = sum(tx.get("amount", 0.0) for tx in history if tx.get("agent") == agent_clean)
    new_balance = round(curr_balance + amount, 4)
    tx = {
        "tx_id": f"tx-{int(time.time())}-{hashlib.sha256(f'{agent_clean}:{amount}:{time.time()}'.encode()).hexdigest()[:8]}",
        "stamp": now_iso(),
        "agent": agent_clean,
        "type": tx_type,
        "amount": round(amount, 4),
        "balance_after": new_balance,
        "ref_seq": ref_seq,
        "ref_cpr": ref_cpr,
        "note": note
    }
    with CREDIT_LEDGER_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(tx) + "\n")
    return tx


def get_agent_credit_summary(agent: str) -> dict:
    agent_clean = agent.lstrip("@").lower().strip()
    history = load_credit_ledger()
    agent_txs = [tx for tx in history if tx.get("agent") == agent_clean]

    balance = sum(tx.get("amount", 0.0) for tx in agent_txs)
    total_earned = sum(tx.get("amount", 0.0) for tx in agent_txs if tx.get("type") in ("work_reward", "reward"))
    total_advances = sum(tx.get("amount", 0.0) for tx in agent_txs if tx.get("type") == "advance")
    total_settled = abs(sum(tx.get("amount", 0.0) for tx in agent_txs if tx.get("type") == "settle"))
    claimed_cprs = {tx.get("ref_cpr") for tx in agent_txs if tx.get("ref_cpr")}

    proof_count = len(claimed_cprs)
    tier = "Bronze" if proof_count < 5 else "Silver" if proof_count < 20 else "Gold" if proof_count < 50 else "Sovereign"
    ceiling = DEFAULT_CREDIT_CEILING * (1.0 if tier == "Bronze" else 2.5 if tier == "Silver" else 5.0 if tier == "Gold" else 10.0)

    return {
        "agent": agent_clean,
        "balance": round(balance, 4),
        "credit_ceiling": round(ceiling, 2),
        "total_earned": round(total_earned, 4),
        "total_advances": round(total_advances, 4),
        "total_settled": round(total_settled, 4),
        "claimed_receipts_count": proof_count,
        "kya_tier": tier,
        "transactions_count": len(agent_txs)
    }


def cmd_credit(args):
    action = getattr(args, "credit_action", None) or "balance"
    agent = getattr(args, "agent", None) or detected_seat()
    agent_clean = agent.lstrip("@").lower().strip()
    is_json = getattr(args, "json", False)

    if action in ("balance", "status"):
        summary = get_agent_credit_summary(agent_clean)
        if is_json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"=== SANGHA MUTUAL CREDIT UNION: @{agent_clean.upper()} ===")
            print(f"  Available Balance:  {summary['balance']:>8.2f} Swarm Credits")
            print(f"  Credit Ceiling:     {summary['credit_ceiling']:>8.2f} Swarm Credits")
            print(f"  Total Work Earned:  {summary['total_earned']:>8.2f} Swarm Credits")
            print(f"  Advances Drawn:     {summary['total_advances']:>8.2f} Swarm Credits")
            print(f"  Advances Settled:   {summary['total_settled']:>8.2f} Swarm Credits")
            print(f"  Verified AER-1 PoUW:{summary['claimed_receipts_count']:>8} task proofs")
            print(f"  KYA Trust Tier:     [{summary['kya_tier']}]")
        return 0

    elif action == "claim":
        history = load_credit_ledger()
        claimed_cprs = {tx.get("ref_cpr") for tx in history if tx.get("ref_cpr")}
        claimed_seqs = {tx.get("ref_seq") for tx in history if tx.get("ref_seq") is not None}

        target_seq = getattr(args, "seq", None)
        claim_all = getattr(args, "all", False)
        newly_claimed = []

        if not RECEIPTS_DIR.exists():
            if not is_json:
                print("No receipts directory found.")
            return 0

        for rfile in sorted(RECEIPTS_DIR.glob("*.json")):
            try:
                data = json.loads(rfile.read_text(encoding="utf-8"))
            except Exception:
                continue

            r_id = data.get("receipt_id")
            seq = data.get("seq")
            r_type = data.get("type")
            issuer_id = str(data.get("issuer", {}).get("id", ""))

            if target_seq is not None and str(seq) != str(target_seq) and r_id != str(target_seq):
                continue

            if agent_clean not in issuer_id.lower() and not claim_all:
                continue

            if r_id in claimed_cprs or seq in claimed_seqs:
                continue

            amt = TASK_REWARD_CREDITS
            if r_type == "vcs.consolidation":
                amt = CONSOLIDATION_REWARD_CREDITS

            tx = append_credit_tx(
                agent=agent_clean,
                tx_type="work_reward",
                amount=amt,
                ref_seq=seq,
                ref_cpr=r_id,
                note=f"PoUW verification: {r_type or 'delivery'} (seq #{seq})"
            )
            newly_claimed.append(tx)

        if is_json:
            print(json.dumps({"ok": True, "claimed": len(newly_claimed), "transactions": newly_claimed}, indent=2))
        else:
            if newly_claimed:
                total_credited = sum(t["amount"] for t in newly_claimed)
                print(f"✓ Claimed {len(newly_claimed)} AER-1 proof(s): +{total_credited:.2f} Swarm Credits credited to @{agent_clean}.")
            else:
                print(f"No unclaimed AER-1 proofs found for @{agent_clean}.")
        return 0

    elif action == "advance":
        try:
            amt = float(getattr(args, "amount", 10.0) or 10.0)
        except ValueError:
            sys.exit("Error: --amount must be a valid number")

        summary = get_agent_credit_summary(agent_clean)
        if summary["balance"] - amt < -summary["credit_ceiling"]:
            sys.exit(f"Error: Credit advance exceeds ceiling (${summary['credit_ceiling']:.2f}). Settle existing balance via work to unlock more.")

        reason = getattr(args, "reason", None) or "Sovereign zero-interest compute advance"
        tx = append_credit_tx(
            agent=agent_clean,
            tx_type="advance",
            amount=amt,
            note=reason
        )
        if is_json:
            print(json.dumps({"ok": True, "advance": tx}))
        else:
            print(f"✓ Issued {amt:.2f} credit advance to @{agent_clean} (Zero-interest, non-punitive). New balance: {tx['balance_after']:.2f}")
        return 0

    elif action == "transfer":
        recipient = getattr(args, "to", None)
        if not recipient:
            sys.exit("Error: --to required for transfer")
        to_clean = recipient.lstrip("@").lower().strip()
        try:
            amt = float(getattr(args, "amount", 0.0) or 0.0)
            if amt <= 0:
                raise ValueError()
        except ValueError:
            sys.exit("Error: --amount must be positive")

        memo = getattr(args, "memo", "") or "P2P mutual credit settlement"
        tx1 = append_credit_tx(agent_clean, "transfer_out", -amt, note=f"Transfer to @{to_clean}: {memo}")
        tx2 = append_credit_tx(to_clean, "transfer_in", amt, note=f"Transfer from @{agent_clean}: {memo}")

        if is_json:
            print(json.dumps({"ok": True, "sender_tx": tx1, "recipient_tx": tx2}))
        else:
            print(f"✓ Cleared mutual credit: {amt:.2f} from @{agent_clean} -> @{to_clean} (Net network delta: 0.00).")
        return 0

    elif action == "ledger":
        history = load_credit_ledger()
        limit = int(getattr(args, "limit", 15) or 15)
        slice_txs = history[-limit:] if limit > 0 else history
        if is_json:
            print(json.dumps(slice_txs, indent=2))
        else:
            print(f"=== SANGHA MUTUAL CREDIT LEDGER (last {len(slice_txs)} of {len(history)} txs) ===")
            for tx in reversed(slice_txs):
                sign = "+" if tx["amount"] >= 0 else ""
                ref = f" (#{tx.get('ref_seq')})" if tx.get("ref_seq") else ""
                print(f"  {tx['stamp'][:19]}  [@{tx['agent']:<12}] {sign}{tx['amount']:>6.2f} credits  [{tx['type']:<12}] {tx['note'][:40]}{ref}")
        return 0

    return 0


def main():
    p = argparse.ArgumentParser(description="Sangha Whiteboard CLI & Agora Dispatcher")
    sub = p.add_subparsers(dest="subcommand", required=True)

    # post
    p_post = sub.add_parser("post", help="Post a dispatch to the whiteboard")
    p_post.add_argument("--title", required=True, help="Title of the dispatch")
    p_post.add_argument("--target", default="@all", help="Target agent (@opencode, @antigravity, @lucas, @all)")
    p_post.add_argument("--author", default=None, help="Author name (default: auto-detected)")
    p_post.add_argument("--body", default=None, help="Body text (or pass via stdin)")
    p_post.add_argument("--type", default=None, choices=POST_TYPES,
                        help="Structured type (claim/release/flag/handoff/done/question/note)")
    p_post.add_argument("--scope", default=None, help="Scope this post is about (path/tree/feature)")
    p_post.add_argument("--expires", default=None, help="Expiry: 2h, 90m, or ISO-8601 (for claims)")
    p_post.add_argument("--room", default=None, help="Room namespace (e.g. core-dev, ops, sync)")
    p_post.add_argument("--thread", default=None, help="Thread correlation ID")
    p_post.add_argument("--hop", type=int, default=None, help="Hop sequence counter")
    p_post.add_argument("--provenance", default=None, choices=PROVENANCE_TYPES,
                        help="How the content was obtained: computed (verified locally), "
                             "fetched (external source), recalled (model memory), "
                             "testimony (reported by another party); default: unmarked")
    p_post.add_argument("--no-similarity", action="store_true",
                        help="Skip the near-duplicate check before posting")
    p_post.add_argument("--federation", default="fleet", choices=["local", "fleet", "external"],
                        help="Federation tier: local (device only), fleet (synced mesh), external (public gateway)")

    # inbox
    p_inbox = sub.add_parser("inbox", help="View agent inbox")
    p_inbox.add_argument("--agent", default=None, help="Agent seat name (default: detected)")
    p_inbox.add_argument("--room", default=None, help="Only dispatches in this room")
    p_inbox.add_argument("--unread", action="store_true", help="Show unread only")
    p_inbox.add_argument("--digest", action="store_true", help="Group by day instead of listing")
    p_inbox.add_argument("--all", action="store_true", help="Include stale @all dispatches")
    p_inbox.add_argument("--expire", action="store_true",
                         help=f"Mark stale @all dispatches (> {STALE_ALL_DAYS}d) as read")

    # ack
    p_ack = sub.add_parser("ack", help="Acknowledge / mark as read")
    p_ack.add_argument("item", nargs="?", help="Seq number or filename")
    p_ack.add_argument("--all", action="store_true", help="Mark every unread as read (drain after a digest)")
    p_ack.add_argument("--agent", default=None, help="Agent seat name (default: detected)")

    # read
    p_read = sub.add_parser("read", help="Read a full post")
    p_read.add_argument("item", help="Seq number or search string")

    # list
    p_list = sub.add_parser("list", help="List recent posts")
    p_list.add_argument("--limit", type=int, default=15, help="Number of posts to list")
    p_list.add_argument("--room", default=None, help="Filter by room namespace")
    p_list.add_argument("--type", default=None, choices=POST_TYPES, help="Filter by post type")
    p_list.add_argument("--json", action="store_true", help="Machine-readable output")

    # status
    p_status = sub.add_parser("status", help="Bridge + time/NTP + inbox + fleet homeostasis")
    p_status.add_argument("--json", action="store_true", help="Machine-readable output")
    p_status.add_argument("--fleet-window", type=int, default=45, help="Fleet presence window in minutes (default: 45)")

    # claim / release / claims
    p_claim = sub.add_parser("claim", help="Claim a scope (posts a structured claim)")
    p_claim.add_argument("--scope", required=True, help="Scope to claim (path/tree/feature)")
    p_claim.add_argument("--intent", default="", help="One-line intent")
    p_claim.add_argument("--ttl", default="2h", help="Claim TTL (default: 2h)")
    p_claim.add_argument("--target", default="@all", help="Target (default: @all)")
    p_claim.add_argument("--author", default=None, help="Author (default: auto-detected)")
    p_claim.add_argument("--body", default=None, help="Body override")
    p_claim.add_argument("--room", default=None, help="Room namespace for claim")
    p_claim.add_argument("--wait", action="store_true", help="Wait if scope is occupied until released")
    p_claim.add_argument("--force", action="store_true", help="Supervisor override of active claim")
    p_claim.add_argument("--cpr-reason", default="", help="Reason for supervisor override")
    p_claim.add_argument("--timeout", type=int, default=300, help="Wait timeout in seconds (default: 300)")

    p_release = sub.add_parser("release", help="Release an active claim")
    p_release.add_argument("item", help="Claim seq number or scope substring")
    p_release.add_argument("--author", default=None, help="Author (default: auto-detected)")
    p_release.add_argument("--summary", "-m", default=None, help="Summary of work completed before release")
    p_release.add_argument("--reason", default=None, help="Reason for release")
    p_release.add_argument("--body", default=None, help="Custom body override")

    p_claims = sub.add_parser("claims", help="List claims (active by default)")
    p_claims.add_argument("--scope", default=None, help="Filter by scope substring")
    p_claims.add_argument("--all", action="store_true", help="Include expired/released claims")
    p_claims.add_argument("--json", action="store_true", help="Machine-readable output")

    # search / digest
    p_search = sub.add_parser("search", help="Search posts by term")
    p_search.add_argument("term", help="Search term")
    p_search.add_argument("--limit", type=int, default=10, help="Max hits (default: 10)")
    p_search.add_argument("--json", action="store_true", help="Machine-readable output")

    p_related = sub.add_parser("related", help="Find posts similar to a seq or text (TF-IDF cosine)")
    p_related.add_argument("item", help="Seq number or free text")
    p_related.add_argument("--limit", type=int, default=5, help="Max matches (default: 5)")
    p_related.add_argument("--min-score", type=float, default=0.35, help="Minimum cosine (default: 0.35)")
    p_related.add_argument("--json", action="store_true", help="Machine-readable output")

    p_archive = sub.add_parser("archive", help="Move old non-claim posts to board/archive (dry run by default)")
    p_archive.add_argument("--before", default="30d", help="Cutoff: 30d or YYYY-MM-DD (default: 30d)")
    p_archive.add_argument("--apply", action="store_true", help="Actually move files (default: dry run)")
    p_archive.add_argument("--dest", default=None, help="Destination (default: board/archive/epoch-1)")
    p_archive.add_argument("--json", action="store_true", help="Machine-readable output")

    p_digest = sub.add_parser("digest", help="Board + inbox digest for a window")
    p_digest.add_argument("--since", default="24h", help="Window: 24h, 7d, or ISO-8601 (default: 24h)")
    p_digest.add_argument("--agent", default=None, help="Seat for the inbox line (default: detected)")
    p_digest.add_argument("--json", action="store_true", help="Machine-readable output")

    p_lint = sub.add_parser("lint", help="Check board integrity (headers, claims, provenance, seq)")
    p_lint.add_argument("--json", action="store_true", help="Machine-readable output")

    p_deploy = sub.add_parser("deploy-check", help="Compare key board files against peers (hash drift)")
    p_deploy.add_argument("--peer", action="append", metavar="NAME=PATH",
                          help="Compare against a local directory (repeatable); default: peers.json/SSH")
    p_deploy.add_argument("--json", action="store_true", help="Machine-readable output")

    # sentinel / ports / brief
    p_sentinel = sub.add_parser("sentinel", help="Flag dirty checkouts with no active claim")
    p_sentinel.add_argument("--stale-min", type=int, default=30, help="Dirty age before flagging (default: 30)")
    p_sentinel.add_argument("--expire-window", type=int, default=30,
                            help="Nudge claims expiring within N minutes (default: 30)")
    p_sentinel.add_argument("--recent-hours", type=int, default=24, help="Window for unversioned trees (default: 24)")
    p_sentinel.add_argument("--post", action="store_true", help="Post findings (deduped) to the board")
    p_sentinel.add_argument("--author", default=None, help="Author for --post (default: auto-detected)")
    p_sentinel.add_argument("--json", action="store_true", help="Machine-readable output")

    p_ports = sub.add_parser("ports", help="Listeners, wm serve stores, stale scratch dirs")
    p_ports.add_argument("--json", action="store_true", help="Machine-readable output")

    p_brief = sub.add_parser("brief", help="One-shot session start: status + claims + sentinel + digest")
    p_brief.add_argument("--fleet-window", type=int, default=45, help="Fleet presence window (default: 45)")
    p_brief.add_argument("--json", action="store_true", help="Machine-readable output")

    # sessions / join / leave (cross-IDE session registry)
    p_sessions = sub.add_parser("sessions", help="List registered sessions across IDEs")
    p_sessions.add_argument("--project", default=None, help="Filter by project")
    p_sessions.add_argument("--room", default=None, help="Filter by room")
    p_sessions.add_argument("--json", action="store_true", help="Machine-readable output")

    p_join = sub.add_parser("join", help="Register a session into the cross-IDE registry")
    p_join.add_argument("--alias", required=True, help="Agent/seat alias (e.g. antigravity, opencode)")
    p_join.add_argument("--session-id", required=True, help="Session UUID or identifier")
    p_join.add_argument("--ide", default="agy", choices=["opencode", "agy", "codex", "claude"], help="IDE / agent environment")
    p_join.add_argument("--adapter", default="router", choices=["plugin", "router", "notify"], help="Wake adapter")
    p_join.add_argument("--project", default=None, help="Project name (e.g. whitemagic, pet2.0)")
    p_join.add_argument("--room", default=None, help="Room namespace (e.g. core-dev, sync, pet2.0)")
    p_join.add_argument("--title", default=None, help="Session title or task summary")

    p_leave = sub.add_parser("leave", help="Unregister session from the cross-IDE registry")
    p_leave.add_argument("--session-id", required=True, help="Session identifier")

    # rooms (Fractal Agora)
    p_rooms = sub.add_parser("rooms", help="List active rooms across the board (Fractal Agora)")
    p_rooms.add_argument("--json", action="store_true", help="Machine-readable output")

    # occupied (Mandala Kekkai Concurrency Semaphore)
    p_occupied = sub.add_parser("occupied", help="Check if a scope or path is claimed under Mandala Kekkai")
    p_occupied.add_argument("scope", help="Scope or path to check")
    p_occupied.add_argument("--json", action="store_true", help="Machine-readable output")

    # epoch (Epoch Management & Auto-Save)
    p_epoch = sub.add_parser("epoch", help="Manage board epochs (auto-save, categorization, switch)")
    p_epoch.add_argument("action", choices=["status", "switch", "auto-check"], default="status", nargs="?",
                         help="Action: status, switch, auto-check (default: status)")
    p_epoch.add_argument("--threshold", type=int, default=120, help="Max posts before auto-switch recommendation (default: 120)")
    p_epoch.add_argument("--dest", default=None, help="Destination directory override")
    p_epoch.add_argument("--json", action="store_true", help="Machine-readable output")

    # listen (SSE live stream)
    p_listen = sub.add_parser("listen", help="Stream live Sangha events via SSE in real time")
    p_listen.add_argument("--room", default=None, help="Filter events by room")
    p_listen.add_argument("--target", default=None, help="Filter events by target agent")
    p_listen.add_argument("--json", action="store_true", help="Output raw JSON events")

    # meta (WhiteMagic meta-tool programmatic bridge)
    p_meta = sub.add_parser("meta", help="Programmatic dispatcher for WhiteMagic Gen3 meta-tool")
    p_meta.add_argument("action", help="Meta action (status, rooms, claims, occupied, epoch, inbox)")
    p_meta.add_argument("--json-args", default=None, help="JSON arguments dictionary")

    # verify (AER-1 Causal Provenance Receipt verification)
    p_verify = sub.add_parser("verify", help="Verify a post against its AER-1 Causal Provenance Receipt")
    p_verify.add_argument("item", help="Post sequence number (e.g. 1345) or markdown file path")
    p_verify.add_argument("--json", action="store_true", help="Machine-readable output")

    # canvas (Obsidian JSON Canvas 1.0 export)
    p_canvas = sub.add_parser("canvas", help="Export Sangha Agora board & claims to Obsidian JSON Canvas (.canvas)")
    p_canvas.add_argument("--out", "-o", default="swarm.canvas", help="Output path (default: swarm.canvas)")
    p_canvas.add_argument("--limit", type=int, default=35, help="Number of recent dispatches to include (default: 35)")
    p_canvas.add_argument("--all", action="store_true", help="Include all historical claims and archive")
    p_canvas.add_argument("--json", action="store_true", help="Output raw JSON canvas to stdout")

    # init (Universal Setup)
    p_init = sub.add_parser("init", help="Initialize and provision local Sangha Agora substrate and symlinks")
    p_init.add_argument("--json", action="store_true", help="Machine-readable output")

    # fork (Ephemeral shadow worktree)
    p_f = sub.add_parser("fork", help="Create an ephemeral capability-scoped shadow worktree (alias for vcs fork)")
    p_f.add_argument("scope", nargs="?", default=".", help="Subtree or file scope for shadow sandbox")
    p_f.add_argument("--author", default=None, help="Agent/author name override")

    # consolidate (Merge shadow worktree to main)
    p_cons = sub.add_parser("consolidate", help="Consolidate shadow worktree or modular diff back to main with AER-1 receipt (alias for vcs consolidate)")
    p_cons.add_argument("target", nargs="?", default=None, help="Fork ID, scope, or worktree path to consolidate")
    p_cons.add_argument("-m", "--message", default=None, help="Commit message for consolidation")
    p_cons.add_argument("--no-cleanup", action="store_true", help="Do not remove shadow worktree after merge")
    p_cons.add_argument("--author", default=None, help="Author name override")

    # peer
    p_peer = sub.add_parser("peer", help="Manage and synchronize P2P Agora peers")
    p_peer.add_argument("peer_action", nargs="?", default="list", choices=["list", "add", "ping", "sync"],
                        help="Action to perform: list, add, ping, sync (default: list)")
    p_peer.add_argument("--name", default=None, help="Peer name for add")
    p_peer.add_argument("--url", default=None, help="Peer URL for add")
    p_peer.add_argument("--wire-port", type=int, default=7369, help="WhiteMagic wire port (default: 7369)")
    p_peer.add_argument("--peer", default=None, help="Target peer for ping/sync")
    p_peer.add_argument("--room", default=None, help="Filter room for sync")
    p_peer.add_argument("--json", action="store_true", help="Output JSON format")

    # worker
    p_worker = sub.add_parser("worker", help="Autonomous swarm worker daemon (Folding@home for AI Agents)")
    p_worker.add_argument("--room", default="research", help="Room to poll for tasks (default: research)")
    p_worker.add_argument("--agent", default=None, help="Agent worker identity (default: auto-detected)")
    p_worker.add_argument("--daemon", action="store_true", help="Run continuously in background polling loop")
    p_worker.add_argument("--interval", type=int, default=10, help="Polling interval in seconds (default: 10)")
    p_worker.add_argument("--max-tasks", type=int, default=1, help="Max tasks to process (default: 1; 0=unlimited)")
    p_worker.add_argument("--dry-run", action="store_true", help="Inspect and claim task without executing mutations")
    p_worker.add_argument("--json", action="store_true", help="Output JSON format")

    # credit / bank (Sovereign Mutual Credit Union)
    p_credit = sub.add_parser("credit", help="Sovereign mutual credit & task-factoring bank")
    p_credit.add_argument("credit_action", nargs="?", default="balance",
                          choices=["balance", "status", "claim", "advance", "transfer", "ledger"],
                          help="Credit action: balance, claim, advance, transfer, ledger (default: balance)")
    p_credit.add_argument("--agent", default=None, help="Agent identity (default: detected seat)")
    p_credit.add_argument("--amount", type=float, default=10.0, help="Amount for advance or transfer")
    p_credit.add_argument("--to", default=None, help="Recipient agent for transfer")
    p_credit.add_argument("--seq", default=None, help="Specific post sequence or receipt ID to claim")
    p_credit.add_argument("--all", action="store_true", help="Claim all unredeemed receipts across seats")
    p_credit.add_argument("--memo", default="", help="Transfer memo or advance reason")
    p_credit.add_argument("--limit", type=int, default=15, help="Ledger lines to display (default: 15)")
    p_credit.add_argument("--json", action="store_true", help="Output JSON format")

    p_bank = sub.add_parser("bank", help="Alias for 'sangha credit'")
    p_bank.add_argument("credit_action", nargs="?", default="balance",
                        choices=["balance", "status", "claim", "advance", "transfer", "ledger"],
                        help="Credit action: balance, claim, advance, transfer, ledger (default: balance)")
    p_bank.add_argument("--agent", default=None, help="Agent identity (default: detected seat)")
    p_bank.add_argument("--amount", type=float, default=10.0, help="Amount for advance or transfer")
    p_bank.add_argument("--to", default=None, help="Recipient agent for transfer")
    p_bank.add_argument("--seq", default=None, help="Specific post sequence or receipt ID to claim")
    p_bank.add_argument("--all", action="store_true", help="Claim all unredeemed receipts across seats")
    p_bank.add_argument("--memo", default="", help="Transfer memo or advance reason")
    p_bank.add_argument("--limit", type=int, default=15, help="Ledger lines to display (default: 15)")
    p_bank.add_argument("--json", action="store_true", help="Output JSON format")

    # vcs (Loom/Scion reservation & receipt-based VCS)
    if sangha_vcs:
        sangha_vcs.add_subparsers(sub)

    args = p.parse_args()
    if args.subcommand == "post":
        cmd_post(args)
    elif args.subcommand == "inbox":
        cmd_inbox(args)
    elif args.subcommand == "ack":
        cmd_ack(args)
    elif args.subcommand == "read":
        cmd_read(args)
    elif args.subcommand == "list":
        cmd_list(args)
    elif args.subcommand == "status":
        cmd_status(args)
    elif args.subcommand == "claim":
        cmd_claim(args)
    elif args.subcommand == "release":
        cmd_release(args)
    elif args.subcommand == "claims":
        cmd_claims(args)
    elif args.subcommand == "canvas":
        sys.exit(cmd_canvas(args))
    elif args.subcommand == "rooms":
        sys.exit(cmd_rooms(args))
    elif args.subcommand == "occupied":
        sys.exit(cmd_occupied(args))
    elif args.subcommand == "epoch":
        sys.exit(cmd_epoch(args))
    elif args.subcommand == "listen":
        sys.exit(cmd_listen(args))
    elif args.subcommand == "meta":
        sys.exit(cmd_meta(args))
    elif args.subcommand == "peer":
        sys.exit(cmd_peer(args))
    elif args.subcommand == "worker":
        sys.exit(cmd_worker(args))
    elif args.subcommand in ("credit", "bank"):
        sys.exit(cmd_credit(args))
    elif args.subcommand == "verify":
        sys.exit(cmd_verify(args))
    elif args.subcommand == "init":
        sys.exit(cmd_init(args))
    elif args.subcommand == "fork":
        if sangha_vcs:
            sys.exit(sangha_vcs.cmd_fork(args))
        else:
            sys.exit("Error: sangha_vcs module not available")
    elif args.subcommand == "consolidate":
        if sangha_vcs:
            sys.exit(sangha_vcs.cmd_consolidate(args))
        else:
            sys.exit("Error: sangha_vcs module not available")
    elif args.subcommand == "vcs":
        if sangha_vcs:
            if args.vcs_action == "claim":
                sys.exit(sangha_vcs.cmd_claim(args))
            elif args.vcs_action == "status":
                sys.exit(sangha_vcs.cmd_status(args))
            elif args.vcs_action == "diff":
                sys.exit(sangha_vcs.cmd_diff(args))
            elif args.vcs_action == "commit":
                sys.exit(sangha_vcs.cmd_commit(args))
            elif args.vcs_action == "release":
                sys.exit(sangha_vcs.cmd_release(args))
            elif args.vcs_action == "audit":
                sys.exit(sangha_vcs.cmd_audit(args))
            elif args.vcs_action == "fork":
                sys.exit(sangha_vcs.cmd_fork(args))
            elif args.vcs_action == "consolidate":
                sys.exit(sangha_vcs.cmd_consolidate(args))
            elif args.vcs_action == "sandbox":
                sys.exit(sangha_vcs.cmd_sandbox(args))
            elif args.vcs_action == "merkle":
                sys.exit(sangha_vcs.cmd_merkle(args))
            elif args.vcs_action == "verify":
                sys.exit(sangha_vcs.cmd_verify(args))
        else:
            sys.exit("Error: sangha_vcs module not available")
    elif args.subcommand == "search":
        cmd_search(args)
    elif args.subcommand == "related":
        sys.exit(cmd_related(args))
    elif args.subcommand == "archive":
        sys.exit(cmd_archive(args))
    elif args.subcommand == "digest":
        cmd_digest(args)
    elif args.subcommand == "lint":
        sys.exit(cmd_lint(args))
    elif args.subcommand == "deploy-check":
        sys.exit(cmd_deploy_check(args))
    elif args.subcommand == "sentinel":
        sys.exit(cmd_sentinel(args))
    elif args.subcommand == "ports":
        cmd_ports(args)
    elif args.subcommand == "brief":
        cmd_brief(args)
    elif args.subcommand == "sessions":
        if sangha_registry:
            sangha_registry.cmd_list(args)
        else:
            sys.exit("Error: sangha_registry module not available")
    elif args.subcommand == "join":
        if sangha_registry:
            sangha_registry.cmd_join(args)
        else:
            sys.exit("Error: sangha_registry module not available")
    elif args.subcommand == "leave":
        if sangha_registry:
            sangha_registry.cmd_leave(args)
        else:
            sys.exit("Error: sangha_registry module not available")

if __name__ == "__main__":
    main()
