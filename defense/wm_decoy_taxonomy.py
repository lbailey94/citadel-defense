#!/usr/bin/env python3
"""wm_decoy_taxonomy.py - shared decoy-class taxonomy and safelist.

Used by wm-flytrap.py (60 s promotion loop) and wm-export-iocs.py (twice-daily feed) so both
agree on what counts as touching a decoy.

Two distinct decoy classes touched by one source inside the flytrap window is the promotion
rule. The classes are deliberately coarse: hitting /.env twice is one class, hitting /.env and
/.git/config is two.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path

# First match wins. Matching is on the lower-cased URL path (query string removed).
_PATH_PREFIX_CLASSES = (
    ("secret_files", ("/.env", "/credentials", "/vault")),
    ("vcs_exposure", ("/.git",)),
    ("cloud_metadata", ("/latest", "/computemetadata", "/aws/")),
    ("container_api", ("/api/v1/namespaces", "/v1.")),
    ("app_debug", ("/actuator", "/debug/", "/_profiler", "/phpinfo", "/solr")),
    ("cms_php", ("/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php", "/phpmyadmin")),
    ("llm_api_probe", ("/v1/models", "/v1/chat/", "/v1/completions", "/v1/messages",
                       "/v1/embeddings", "/v1/responses")),
)

CANARY_REPLAY = "canary_replay"          # conclusive on its own
SSH_SESSION = "ssh_decoy_session"        # a login attempt against the Cowrie decoy
SSH_ACTION = "ssh_decoy_action"          # command, download or proxy pivot inside the decoy

ALL_CLASSES = tuple(c for c, _ in _PATH_PREFIX_CLASSES) + (SSH_SESSION, SSH_ACTION, CANARY_REPLAY)

# Addresses that are never promoted or published: this node and the operator.
PROTECTED_PUBLIC_IPS = frozenset({"152.53.195.47", "174.56.168.79"})

DEFAULT_ALLOWLIST_FILE = "/etc/whitemagic-hosted/flytrap-allow.txt"


def classify_web_path(path: str) -> str | None:
    """Decoy class for an HTTP path, or None if it is not a decoy path."""
    p = (path or "").split("?", 1)[0].lower()
    for cls, prefixes in _PATH_PREFIX_CLASSES:
        if p.startswith(prefixes):
            return cls
    if ".php" in p:
        return "cms_php"
    return None


def classify_cowrie_event(eventid: str) -> str | None:
    """Decoy class for a Cowrie event id. Connect-only and banner events are not classes."""
    if eventid in ("cowrie.login.failed", "cowrie.login.success"):
        return SSH_SESSION
    if eventid in ("cowrie.command.input", "cowrie.session.file_download",
                   "cowrie.direct-tcpip.request"):
        return SSH_ACTION
    return None


class Allowlist:
    """Operator safelist: plain addresses and CIDRs, one per line, '#' comments."""

    def __init__(self, entries=()):
        self._nets = []
        for raw in entries:
            token = str(raw).split("#", 1)[0].strip()
            if not token:
                continue
            try:
                self._nets.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                continue

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Allowlist":
        entries = []
        env = os.environ.get("WM_FLYTRAP_ALLOW", "")
        entries.extend(x for x in env.split(",") if x.strip())
        file_path = Path(path or os.environ.get("WM_FLYTRAP_ALLOW_FILE", DEFAULT_ALLOWLIST_FILE))
        try:
            entries.extend(file_path.read_text(encoding="utf-8").splitlines())
        except OSError:
            pass
        return cls(entries)

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._nets if net.version == addr.version)


def is_protected(ip: str, allow: Allowlist | None = None) -> bool:
    """True for addresses that must never be tarpitted or published."""
    if not ip or ip in ("unknown", "localhost") or ip in PROTECTED_PUBLIC_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
        if str(addr) in PROTECTED_PUBLIC_IPS:
            return True
    if (addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified or addr.is_reserved):
        return True
    return bool(allow and allow.contains(str(addr)))
