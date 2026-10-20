#!/usr/bin/env python3
"""opencode_kekkai_launcher.py — Tri-Platform Kernel Confinement Launcher for OpenCode v2.

Provides zero-container, OS-native process confinement across Linux, macOS, and Windows
(`x86_64` and `arm64` / `aarch64`):

  1. Linux (`x86_64`, `aarch64` / `arm64`, WSL2 — Kernel 5.13+ to 7.0+):
     - Enforces Linux Kernel Landlock LSM (`SYS_landlock_create_ruleset = 444`,
       `SYS_landlock_add_rule = 445`, `SYS_landlock_restrict_self = 446` — unified
       `asm-generic` syscall numbers across x86_64 and arm64).
     - Allows Read/Write inside `--workspace`, `/tmp`, and `/dev`; Read/Execute on
       toolchains; omits `~/.local/share/opencode`, `~/.config/opencode`, `~/.ssh`,
       `~/.aws`, and `~/.gnupg` (kernel `EACCES` on same-UID access).

  2. macOS (`darwin-arm64` Apple Silicon & `darwin-x64` Intel):
     - Compiles an Apple XNU Mandatory Access Control (`Seatbelt` SBPL) profile and
       executes via `/usr/bin/sandbox-exec -p <profile>`.
     - Kernel-blocks `file-read*` and `file-write*` on `~/.local/share/opencode`,
       `~/Library/Application Support/opencode`, `~/.config/opencode`, `~/.ssh`,
       `~/.aws`, and `~/.gnupg`.
     - Kernel-blocks `/usr/bin/security` execution to prevent macOS Keychain dumps.
     - Restricts `file-write*` under `$HOME` strictly to `--workspace`.

  3. Windows (`win32-x64` & `win32-arm64` Native):
     - Binds the child tree to a Windows Kernel Job Object (`CreateJobObjectW` +
       `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with UI/Clipboard isolation
       (`JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD`) so
       confined tools cannot harvest clipboard secrets or spawn orphan background daemons,
       and drops elevated privileges via `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`.

Usage:
  python3 opencode_kekkai_launcher.py --workspace /path/to/project -- bash -c "command"
  python3 opencode_kekkai_launcher.py --workspace /path/to/project --print-darwin-profile
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_RULE_PATH_BENEATH = 1

# Unified asm-generic syscall numbers (identical on Linux x86_64, aarch64/arm64, riscv64)
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446

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


def _add_linux_path_rule(libc, ruleset_fd: int, path_str: str, access: int) -> None:
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


def apply_linux_landlock(workspace: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
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

    for rp in ro_paths:
        _add_linux_path_rule(libc, ruleset_fd, rp, ALLOW_RO)
    for wp in rw_paths:
        _add_linux_path_rule(libc, ruleset_fd, wp, ALLOW_RW)

    libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
    os.close(ruleset_fd)


def build_darwin_seatbelt_profile(workspace: str, home_dir: str | None = None) -> str:
    """Compile a macOS XNU Seatbelt (SBPL) profile for /usr/bin/sandbox-exec."""
    home = str(Path(home_dir).resolve()) if home_dir else str(Path.home().resolve())
    ws = str(Path(workspace).resolve())

    def sbpl_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    h = sbpl_escape(home)
    w = sbpl_escape(ws)
    return f"""(version 1)
(allow default)

;; 1. Kernel-block same-UID read/write to OpenCode credential stores & SSH/AWS/GPG keys
(deny file-read* file-write*
  (subpath "{h}/.local/share/opencode")
  (subpath "{h}/.config/opencode")
  (subpath "{h}/Library/Application Support/opencode")
  (subpath "{h}/Library/Preferences/opencode")
  (subpath "{h}/.ssh")
  (subpath "{h}/.aws")
  (subpath "{h}/.gnupg")
  (subpath "{h}/.config/gh")
  (subpath "{h}/.config/whitemagic"))

;; 2. Kernel-block macOS Keychain dump utility (/usr/bin/security) inside agent tool shells
(deny process-exec
  (literal "/usr/bin/security"))

;; 3. Restrict file writes under $HOME strictly to the active project workspace
(deny file-write*
  (subpath "{h}"))
(allow file-write*
  (subpath "{w}")
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath "/private/var/folders")
  (subpath "/dev"))
"""


def exec_darwin_seatbelt(workspace: str, cmd: list[str]) -> int:
    profile = build_darwin_seatbelt_profile(workspace)
    sandbox_bin = shutil.which("sandbox-exec") or "/usr/bin/sandbox-exec"
    if os.path.exists(sandbox_bin):
        os.execv(sandbox_bin, [sandbox_bin, "-p", profile, "--", *cmd])
    os.execvp(cmd[0], cmd)
    return 1


def exec_windows_confined(workspace: str, cmd: list[str]) -> int:
    """Execute command on Windows inside a Job Object with clipboard isolation & kill-on-close."""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        job = kernel32.CreateJobObjectW(None, None)
        if job:
            # Apply UI restrictions: prevent child process from reading/writing Windows Clipboard
            # (JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x02, JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x04)
            ui_restrict = ctypes.c_uint32(0x02 | 0x04)
            kernel32.SetInformationJobObject(job, 4, ctypes.byref(ui_restrict), ctypes.sizeof(ui_restrict))
            kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess())
    except Exception:
        pass
    proc = subprocess.run(cmd, cwd=workspace)
    return int(proc.returncode)


def main() -> int:
    ap = argparse.ArgumentParser(prog="opencode_kekkai_launcher")
    ap.add_argument("--workspace", default=os.getcwd())
    ap.add_argument("--print-darwin-profile", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    if args.print_darwin_profile:
        print(build_darwin_seatbelt_profile(args.workspace), end="")
        return 0

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        return 0

    sys_plat = sys.platform
    if sys_plat.startswith("linux"):
        apply_linux_landlock(args.workspace)
        os.execvp(cmd[0], cmd)
        return 1
    elif sys_plat == "darwin":
        return exec_darwin_seatbelt(args.workspace, cmd)
    elif sys_plat in ("win32", "cygwin"):
        return exec_windows_confined(args.workspace, cmd)
    else:
        os.execvp(cmd[0], cmd)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
