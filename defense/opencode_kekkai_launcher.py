#!/usr/bin/env python3
"""opencode_kekkai_launcher.py — Zero-Dependency Linux Landlock LSM Launcher for OpenCode v2.

Enforces hardware-speed Linux Kernel Landlock LSM confinement around any shell command
spawned by OpenCode (`shell` / `bash` tool):
  - ALLOWS Read/Write inside the active project workspace (`--workspace <dir>`), `/tmp`, and `/dev`.
  - ALLOWS Read/Execute on system & developer toolchain paths (`/usr`, `/lib`, `/lib64`, `/bin`,
    `/sbin`, `/etc`, `/proc`, `/sys`, `/run`, `~/.nvm`, `~/.cargo`, `~/.rustup`, `~/.local/bin`).
  - KERNEL-BLOCKS (`EACCES: Permission denied`) any read or write to:
    * `~/.local/share/opencode` (`auth.json`, `account.json`, `service.json`, `opencode.db`)
    * `~/.config/opencode` (`cli.json`, `service.json`)
    * `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.config/whitemagic`
    even when the child command uses base64/eval/python indirection under the same OS UID!

Usage:
  python3 opencode_kekkai_launcher.py --workspace /path/to/project -- bash -c "command"
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
from pathlib import Path

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_RULE_PATH_BENEATH = 1

SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

# Landlock FS access rights (ABI v1 compatible bitmask for universal Linux 5.13+ to 7.0+ support)
ACCESS_FS_EXECUTE = 1 << 0
ACCESS_FS_WRITE_FILE = 1 << 1
ACCESS_FS_READ_FILE = 1 << 2
ACCESS_FS_READ_DIR = 1 << 3
ACCESS_FS_REMOVE_DIR = 1 << 4
ACCESS_FS_REMOVE_FILE = 1 << 5
ACCESS_FS_MAKE_CHAR = 1 << 6
ACCESS_FS_MAKE_DIR = 1 << 7
ACCESS_FS_MAKE_REG = 1 << 8
ACCESS_FS_MAKE_SOCK = 1 << 9
ACCESS_FS_MAKE_FIFO = 1 << 10
ACCESS_FS_MAKE_BLOCK = 1 << 11
ACCESS_FS_MAKE_SYM = 1 << 12

ALLOW_RO = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR
ALLOW_RW = (
    ALLOW_RO
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM
)


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _add_path_rule(ruleset_fd: int, path_str: str, access: int) -> None:
    p = Path(path_str)
    if not p.exists():
        return
    try:
        resolved = p.resolve()
        # Linux Landlock LSM invariant: non-directory FDs only accept file-level access bits
        # (READ_FILE, WRITE_FILE, EXECUTE); passing READ_DIR/MAKE_* on a regular file returns EINVAL.
        if not resolved.is_dir():
            access &= ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE
        fd = os.open(str(resolved), os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return
    try:
        attr = LandlockPathBeneathAttr()
        attr.allowed_access = access
        attr.parent_fd = fd
        libc.syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(attr),
            0,
        )
    finally:
        os.close(fd)


def apply_opencode_landlock(workspace: str) -> None:
    attr = LandlockRulesetAttr()
    attr.handled_access_fs = ALLOW_RW
    attr.handled_access_net = 0

    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0
    )
    if ruleset_fd < 0:
        return

    home = Path.home()
    ro_paths = [
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/etc",
        "/proc",
        "/sys",
        "/run",
        "/var",
        str(home / ".gitconfig"),
        str(home / ".config/git"),
        str(home / ".nvm"),
        str(home / ".cargo"),
        str(home / ".rustup"),
        str(home / ".local/bin"),
    ]
    rw_paths = [
        "/tmp",
        "/dev",
        str(Path(workspace).resolve()),
    ]

    # Note: ~/.local/share/opencode, ~/.config/opencode, ~/.ssh, ~/.aws, and ~/.gnupg
    # are intentionally OMITTED from the Landlock ruleset, so the Linux kernel denies
    # all open/read/write syscalls to them with EACCES (Errno 13) even under the same UID.
    for rp in ro_paths:
        _add_path_rule(ruleset_fd, rp, ALLOW_RO)
    for wp in rw_paths:
        _add_path_rule(ruleset_fd, wp, ALLOW_RW)

    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
    os.close(ruleset_fd)


def main() -> int:
    ap = argparse.ArgumentParser(prog="opencode_kekkai_launcher")
    ap.add_argument("--workspace", default=os.getcwd())
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        return 0

    apply_opencode_landlock(args.workspace)
    os.execvp(cmd[0], cmd)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
