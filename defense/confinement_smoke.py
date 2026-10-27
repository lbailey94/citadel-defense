#!/usr/bin/env python3
"""Stdlib smoke tests for the OpenCode confinement launcher.

Runs mocked fail-closed setup checks on any platform, plus a real Linux
Landlock filesystem check when run on Linux with Landlock enabled.
"""

from __future__ import annotations

import ctypes
import errno
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import opencode_kekkai_launcher as launcher


class FakeSyscall:
    def __init__(self, stage: str):
        self.stage = stage
        self.add_calls = 0
        self.restype = None

    def __call__(self, number: int, *args) -> int:
        if (
            number == launcher.SYS_LANDLOCK_CREATE_RULESET
            and args[-1] == launcher.LANDLOCK_CREATE_RULESET_VERSION
        ):
            if self.stage == "abi":
                ctypes.set_errno(errno.EPERM)
                return -1
            return 5
        if number == launcher.SYS_LANDLOCK_CREATE_RULESET:
            if self.stage == "create":
                ctypes.set_errno(errno.EPERM)
                return -1
            return 91
        if number == launcher.SYS_LANDLOCK_ADD_RULE:
            self.add_calls += 1
            if self.stage == "add":
                ctypes.set_errno(errno.EPERM)
                return -1
            return 0
        if number == launcher.SYS_LANDLOCK_RESTRICT_SELF:
            if self.stage == "restrict":
                ctypes.set_errno(errno.EPERM)
                return -1
            return 0
        raise AssertionError(f"unexpected syscall {number}")


class FakeLibc:
    def __init__(self, stage: str):
        self.syscall = FakeSyscall(stage)
        self.stage = stage

    def prctl(self, option: int, *args) -> int:
        if option != launcher.PR_SET_NO_NEW_PRIVS:
            raise AssertionError(f"unexpected prctl option {option}")
        if self.stage == "prctl":
            ctypes.set_errno(errno.EPERM)
            return -1
        return 0


class LauncherSetupTests(unittest.TestCase):
    def test_every_setup_failure_prevents_child_execution(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("mocked Linux syscall path is only exercised on Linux")
        with tempfile.TemporaryDirectory(prefix="kekkai-smoke-workspace-") as workspace:
            for stage in ("abi", "create", "add", "prctl", "restrict"):
                with self.subTest(stage=stage):
                    fake_libc = FakeLibc(stage)
                    with (
                        mock.patch.object(
                            launcher.ctypes, "CDLL", return_value=fake_libc
                        ),
                        mock.patch.object(launcher.os, "open", return_value=88),
                        mock.patch.object(launcher.os, "close"),
                        mock.patch.object(launcher.subprocess, "run") as child_run,
                    ):
                        with self.assertRaises(OSError):
                            launcher.exec_linux_confined(workspace, ["must-not-run"])
                        child_run.assert_not_called()

    def test_unsupported_platform_refuses_without_exec(self) -> None:
        with (
            mock.patch.object(launcher.sys, "platform", "unknown-os"),
            mock.patch.object(
                launcher.sys,
                "argv",
                ["launcher", "--workspace", ".", "--", "must-not-run"],
            ),
            mock.patch.object(launcher.os, "execvp") as unconfined_exec,
            mock.patch("sys.stderr", new_callable=__import__("io").StringIO) as stderr,
        ):
            self.assertEqual(launcher.main(), 126)
            self.assertIn("refusing unconfined execution", stderr.getvalue())
            unconfined_exec.assert_not_called()

    def test_missing_macos_backend_refuses_without_child_execution(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="kekkai-smoke-workspace-") as workspace,
            mock.patch.object(launcher.shutil, "which", return_value=None),
            mock.patch.object(launcher.os.path, "isfile", return_value=False),
            mock.patch.object(launcher.subprocess, "run") as child_run,
        ):
            with self.assertRaisesRegex(RuntimeError, "refusing unconfined execution"):
                launcher.exec_darwin_seatbelt(workspace, ["must-not-run"])
            child_run.assert_not_called()

    def test_broad_workspace_scopes_refuse_on_linux_and_darwin_before_child(
        self,
    ) -> None:
        home = Path.home().resolve(strict=True)
        broad_scopes = list(dict.fromkeys((Path("/"), home.parent, home)))
        for platform_name in ("linux", "darwin"):
            for workspace in broad_scopes:
                with (
                    self.subTest(platform=platform_name, workspace=str(workspace)),
                    mock.patch.object(launcher.sys, "platform", platform_name),
                    mock.patch.object(
                        launcher.sys,
                        "argv",
                        [
                            "launcher",
                            "--workspace",
                            str(workspace),
                            "--",
                            "must-not-run",
                        ],
                    ),
                    mock.patch.object(launcher.subprocess, "run") as child_run,
                    mock.patch.object(launcher.tempfile, "mkdtemp") as make_temp,
                    mock.patch.object(
                        launcher, "apply_linux_landlock"
                    ) as install_landlock,
                    mock.patch(
                        "sys.stderr", new_callable=__import__("io").StringIO
                    ) as stderr,
                ):
                    self.assertEqual(launcher.main(), 126)
                    self.assertIn("contains the current user's home", stderr.getvalue())
                    child_run.assert_not_called()
                    make_temp.assert_not_called()
                    install_landlock.assert_not_called()


class HostLandlockTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux Landlock")
    def test_fake_home_credentials_are_unreadable_with_narrow_toolchain_access(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="kekkai-fake-home-") as fake_home,
            tempfile.TemporaryDirectory(prefix="kekkai-smoke-workspace-") as workspace,
        ):
            home = Path(fake_home)
            workspace_path = Path(workspace)
            credentials = [
                home / ".gitconfig",
                home / ".git-credentials",
                home / ".config/git/credentials",
                home / ".cargo/credentials.toml",
            ]
            for path in credentials:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("FAKE_FIXTURE_CREDENTIAL_ONLY", encoding="utf-8")

            toolchain_sentinels = [
                home / ".cargo/bin/fixture-tool",
                home / ".cargo/registry/cache/fixture.crate",
                home / ".cargo/registry/index/fixture-index/config.json",
                home / ".cargo/registry/src/fixture.crate/src/lib.rs",
                home / ".rustup/toolchains/fixture/bin/rustc",
                home / ".rustup/settings.toml",
                home / ".nvm/versions/node/v0-fixture/bin/node",
            ]
            for path in toolchain_sentinels:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture toolchain sentinel", encoding="utf-8")

            workspace_sentinel = workspace_path / "workspace-readable.txt"
            workspace_sentinel.write_text("workspace fixture", encoding="utf-8")
            probe = """import os, pathlib, subprocess, sys
home, workspace = map(pathlib.Path, sys.argv[1:3])
credential_paths = [pathlib.Path(p) for p in sys.argv[3:7]]
toolchain_paths = [pathlib.Path(p) for p in sys.argv[7:]]
assert (workspace / 'workspace-readable.txt').read_text() == 'workspace fixture'
for path in credential_paths:
    try:
        path.read_text()
    except PermissionError:
        pass
    else:
        raise SystemExit(f'fake credential remained readable: {path.relative_to(home)}')
for path in toolchain_paths:
    assert path.read_text() == 'fixture toolchain sentinel', path
assert os.environ.get('CITADEL_FAKE_ENV_SENTINEL') == 'fixture-only'
child = subprocess.run(['/usr/bin/python3', '-c', 'print("nested-python-ok")'],
                       capture_output=True, text=True, check=False)
assert child.returncode == 0 and child.stdout.strip() == 'nested-python-ok', child.stderr
print('fake-home filesystem boundary: PASS')
"""
            env = dict(os.environ)
            env["HOME"] = str(home)
            env["CITADEL_FAKE_ENV_SENTINEL"] = "fixture-only"
            actual = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "opencode_kekkai_launcher.py"),
                    "--workspace",
                    workspace,
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    probe,
                    str(home),
                    str(workspace_path),
                    *(str(path) for path in credentials),
                    *(str(path) for path in toolchain_sentinels),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(actual.returncode, 0, actual.stderr + actual.stdout)
            self.assertIn("fake-home filesystem boundary: PASS", actual.stdout)
            policy_line = next(
                line for line in actual.stderr.splitlines()
                if line.startswith("KEKKAI_POLICY ")
            )
            policy = json.loads(policy_line.removeprefix("KEKKAI_POLICY "))
            paths = {rule["path"] for rule in policy["rules"]}
            self.assertIn(str(home / ".cargo/bin"), paths)
            self.assertNotIn(str(home / ".cargo"), paths)
            self.assertNotIn(str(home / ".gitconfig"), paths)
            self.assertNotIn(str(home / ".config/git"), paths)
            self.assertIn("unrestricted", policy["network"])
            self.assertIn("inherited", policy["environment"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux Landlock")
    def test_external_read_is_denied_workspace_read_is_allowed(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="kekkai-smoke-workspace-") as workspace,
            tempfile.TemporaryDirectory(prefix="kekkai-smoke-external-") as external,
        ):
            workspace_path = Path(workspace)
            external_sentinel = Path(external) / "owned-readable-sentinel.txt"
            workspace_sentinel = workspace_path / "owned-workspace-sentinel.txt"
            external_sentinel.write_text("external sentinel", encoding="utf-8")
            workspace_sentinel.write_text("workspace sentinel", encoding="utf-8")
            probe = """from pathlib import Path
import sys
external, workspace, _expected = sys.argv[1:]
assert Path(workspace).read_text(encoding="utf-8") == "workspace sentinel"
try:
    Path(external).read_text(encoding="utf-8")
except PermissionError:
    pass
else:
    raise SystemExit("external sentinel remained readable")
"""
            control = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; assert Path(sys.argv[1]).read_text() == 'external sentinel'",
                    str(external_sentinel),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            print(
                f"UNCONFINED_CONTROL external_sentinel_readable exit={control.returncode}"
            )

            actual = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "opencode_kekkai_launcher.py"),
                    "--workspace",
                    workspace,
                    "--",
                    sys.executable,
                    "-c",
                    probe,
                    str(external_sentinel),
                    str(workspace_sentinel),
                    "unused",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertIn('"backend": "Landlock"', actual.stderr)
            self.assertIn('"network": "unrestricted by this launcher', actual.stderr)
            policy_line = next(
                line
                for line in actual.stderr.splitlines()
                if line.startswith("KEKKAI_POLICY ")
            )
            print(
                "LANDLOCK_POLICY "
                + json.dumps(
                    json.loads(policy_line.removeprefix("KEKKAI_POLICY ")),
                    sort_keys=True,
                )
            )
            print("LANDLOCK_SMOKE allowed_workspace=1 denied_external=1")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
