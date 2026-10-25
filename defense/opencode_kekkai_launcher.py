#!/usr/bin/env python3
"""Fail-closed filesystem confinement for OpenCode child commands.

Linux uses Landlock and records the ABI plus the filesystem rules actually
installed. Landlock network rights are deliberately not handled here: this
launcher confines filesystem access only and does not claim zero network egress.
macOS retains its Seatbelt profile. Windows and unknown platforms refuse to run
until a real, tested confinement backend is available.

Usage:
  python3 opencode_kekkai_launcher.py --workspace /path/to/project -- command args...
  python3 opencode_kekkai_launcher.py --workspace /path/to/project --print-darwin-profile
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_CREATE_RULESET_VERSION = 1

# asm-generic syscall numbers used by supported Linux x86_64 and arm64 kernels.
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
ACCESS_FS_REFER = 1 << 13       # Landlock ABI 2
ACCESS_FS_TRUNCATE = 1 << 14    # Landlock ABI 3
ACCESS_FS_IOCTL_DEV = 1 << 15   # Landlock ABI 5

_BASE_FS = (
    ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_READ_DIR
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
_READ_ONLY = ACCESS_FS_EXECUTE | ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR
_READ_WRITE = (
    _READ_ONLY
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_SYM
    | ACCESS_FS_REFER
    | ACCESS_FS_TRUNCATE
    | ACCESS_FS_IOCTL_DEV
)

_ACCESS_NAMES = (
    (ACCESS_FS_EXECUTE, "execute"),
    (ACCESS_FS_WRITE_FILE, "write_file"),
    (ACCESS_FS_READ_FILE, "read_file"),
    (ACCESS_FS_READ_DIR, "read_dir"),
    (ACCESS_FS_REMOVE_DIR, "remove_dir"),
    (ACCESS_FS_REMOVE_FILE, "remove_file"),
    (ACCESS_FS_MAKE_CHAR, "make_char"),
    (ACCESS_FS_MAKE_DIR, "make_dir"),
    (ACCESS_FS_MAKE_REG, "make_reg"),
    (ACCESS_FS_MAKE_SOCK, "make_sock"),
    (ACCESS_FS_MAKE_FIFO, "make_fifo"),
    (ACCESS_FS_MAKE_BLOCK, "make_block"),
    (ACCESS_FS_MAKE_SYM, "make_sym"),
    (ACCESS_FS_REFER, "refer"),
    (ACCESS_FS_TRUNCATE, "truncate"),
    (ACCESS_FS_IOCTL_DEV, "ioctl_dev"),
)


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        # Kept zero: this implementation intentionally does not install network rules.
        ("handled_access_net", ctypes.c_uint64),
    ]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _os_error(operation: str) -> OSError:
    code = ctypes.get_errno() or errno.EIO
    return OSError(code, f"{operation}: {os.strerror(code)}")


def _check_syscall(result: int, operation: str) -> int:
    if result < 0:
        raise _os_error(operation)
    return int(result)


def _access_names(mask: int) -> list[str]:
    return [name for bit, name in _ACCESS_NAMES if mask & bit]


def _supported_fs_access(abi: int) -> int:
    supported = _BASE_FS
    if abi >= 2:
        supported |= ACCESS_FS_REFER
    if abi >= 3:
        supported |= ACCESS_FS_TRUNCATE
    if abi >= 5:
        supported |= ACCESS_FS_IOCTL_DEV
    return supported


def _add_linux_path_rule(
    libc,
    ruleset_fd: int,
    path_str: str,
    access: int,
    handled_access_fs: int,
) -> dict[str, object] | None:
    path = Path(path_str)
    if not path.exists():
        return None
    resolved = path.resolve(strict=True)
    granted = access & handled_access_fs
    if not resolved.is_dir():
        # File rules need no directory or execute right. No rule grants a
        # standalone executable file; executables are reached through toolchain dirs.
        granted &= ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE | ACCESS_FS_TRUNCATE | ACCESS_FS_IOCTL_DEV
    try:
        fd = os.open(str(resolved), os.O_PATH | os.O_CLOEXEC)
    except OSError as exc:
        raise OSError(exc.errno, f"open Landlock rule path {resolved}: {exc.strerror}") from exc
    try:
        attr = LandlockPathBeneathAttr()
        attr.allowed_access = granted
        attr.parent_fd = fd
        ctypes.set_errno(0)
        result = libc.syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(attr),
            0,
        )
        _check_syscall(result, f"Landlock add_rule for {resolved}")
    finally:
        os.close(fd)
    return {
        "path": str(resolved),
        "access_mask": granted,
        "access": _access_names(granted),
    }


def apply_linux_landlock(workspace: str, private_tmp: str) -> dict[str, object]:
    """Install Landlock on the calling process or raise before any child can run."""
    workspace_path = Path(workspace).resolve(strict=True)
    private_tmp_path = Path(private_tmp).resolve(strict=True)
    if not workspace_path.is_dir():
        raise ValueError(f"workspace is not a directory: {workspace_path}")
    if not private_tmp_path.is_dir():
        raise ValueError(f"private temporary path is not a directory: {private_tmp_path}")

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    abi = _check_syscall(
        libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION),
        "query Landlock ABI",
    )
    if abi < 1:
        raise OSError(errno.EOPNOTSUPP, f"unsupported Landlock ABI {abi}")

    handled_access_fs = _supported_fs_access(abi)
    attr = LandlockRulesetAttr()
    attr.handled_access_fs = handled_access_fs
    attr.handled_access_net = 0
    ctypes.set_errno(0)
    ruleset_fd = _check_syscall(
        libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0),
        "create Landlock ruleset",
    )

    rules: list[dict[str, object]] = []
    try:
        home = Path.home()
        read_only_paths = [
            "/usr", "/lib", "/lib64", "/bin", "/sbin",
            # Runtime identity, DNS, TLS and loader data; avoid broad /run and /var grants.
            "/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
            "/etc/hosts", "/etc/resolv.conf", "/etc/gai.conf", "/etc/localtime",
            "/etc/ssl/certs", "/etc/ssl/openssl.cnf",
            str(home / ".gitconfig"), str(home / ".config/git"),
            str(home / ".nvm"), str(home / ".cargo"), str(home / ".rustup"),
            str(home / ".local/bin"),
            "/dev/urandom", "/dev/random",
        ]
        read_write_paths = [
            str(workspace_path), str(private_tmp_path), "/dev/null",
        ]
        for path in read_only_paths:
            rule = _add_linux_path_rule(libc, ruleset_fd, path, _READ_ONLY, handled_access_fs)
            if rule is not None:
                rule["mode"] = "read_only"
                rules.append(rule)
        for path in read_write_paths:
            rule = _add_linux_path_rule(libc, ruleset_fd, path, _READ_WRITE, handled_access_fs)
            if rule is None:
                raise FileNotFoundError(f"required Landlock write path is missing: {path}")
            rule["mode"] = "read_write"
            rules.append(rule)

        ctypes.set_errno(0)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise _os_error("prctl(PR_SET_NO_NEW_PRIVS)")
        ctypes.set_errno(0)
        _check_syscall(
            libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0),
            "Landlock restrict_self",
        )
    finally:
        os.close(ruleset_fd)

    return {
        "backend": "Landlock",
        "abi": abi,
        "enforced": "filesystem access rights listed below",
        "handled_access_fs_mask": handled_access_fs,
        "handled_access_fs": _access_names(handled_access_fs),
        "handled_access_net_mask": 0,
        "network": "unrestricted by this launcher; no network confinement is installed",
        "rules": rules,
    }


def build_darwin_seatbelt_profile(workspace: str, home_dir: str | None = None) -> str:
    """Build a macOS Seatbelt profile for /usr/bin/sandbox-exec."""
    home = str(Path(home_dir).resolve()) if home_dir else str(Path.home().resolve())
    ws = str(Path(workspace).resolve())

    def sbpl_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    h = sbpl_escape(home)
    w = sbpl_escape(ws)
    return f"""(version 1)
(allow default)

;; Block reads and writes to OpenCode credentials and common user keys.
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

(deny process-exec
  (literal "/usr/bin/security"))

(deny file-write*
  (subpath "{h}"))
(allow file-write*
  (subpath "{w}")
  (subpath "/dev"))
"""


def exec_darwin_seatbelt(workspace: str, cmd: list[str]) -> int:
    workspace_path = Path(workspace).resolve(strict=True)
    if not workspace_path.is_dir():
        raise ValueError(f"workspace is not a directory: {workspace_path}")
    profile = build_darwin_seatbelt_profile(workspace)
    sandbox_bin = shutil.which("sandbox-exec") or "/usr/bin/sandbox-exec"
    if not os.path.isfile(sandbox_bin) or not os.access(sandbox_bin, os.X_OK):
        raise RuntimeError("macOS sandbox-exec is unavailable; refusing unconfined execution")
    private_tmp = tempfile.mkdtemp(prefix=".opencode-kekkai-tmp-", dir=str(workspace_path))
    child_env = os.environ.copy()
    child_env["TMPDIR"] = private_tmp
    child_env["TMP"] = private_tmp
    child_env["TEMP"] = private_tmp
    try:
        return int(subprocess.run(
            [sandbox_bin, "-p", profile, "--", *cmd],
            cwd=str(workspace_path),
            env=child_env,
        ).returncode)
    finally:
        shutil.rmtree(private_tmp)


def exec_linux_confined(workspace: str, cmd: list[str]) -> int:
    workspace_path = Path(workspace).resolve(strict=True)
    if not workspace_path.is_dir():
        raise ValueError(f"workspace is not a directory: {workspace_path}")
    # A unique 0700 temp root inside the already-authorized workspace avoids
    # granting writes to shared /tmp just so the launcher can clean up afterward.
    private_tmp = tempfile.mkdtemp(prefix=".opencode-kekkai-tmp-", dir=str(workspace_path))
    try:
        policy = apply_linux_landlock(str(workspace_path), private_tmp)
        print("KEKKAI_POLICY " + json.dumps(policy, sort_keys=True), file=sys.stderr, flush=True)
        child_env = os.environ.copy()
        child_env["TMPDIR"] = private_tmp
        child_env["TMP"] = private_tmp
        child_env["TEMP"] = private_tmp
        return int(subprocess.run(cmd, cwd=str(workspace_path), env=child_env).returncode)
    finally:
        # The private directory itself is explicitly writable by the restricted process.
        shutil.rmtree(private_tmp)


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
        ap.error("a command is required unless --print-darwin-profile is used")

    try:
        sys_plat = sys.platform
        if sys_plat.startswith("linux"):
            return exec_linux_confined(args.workspace, cmd)
        if sys_plat == "darwin":
            return exec_darwin_seatbelt(args.workspace, cmd)
        if sys_plat in ("win32", "cygwin"):
            raise RuntimeError("no supported Windows confinement backend; refusing unconfined execution")
        raise RuntimeError(f"no supported confinement backend for platform {sys_plat!r}; refusing unconfined execution")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"opencode_kekkai_launcher: confinement failed: {exc}", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
