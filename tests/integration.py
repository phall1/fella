#!/usr/bin/env python3
"""Black-box Linux tests. No root, privileged container, or external network."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve()) if len(sys.argv) > 1 else str(
    Path(__file__).resolve().parents[1] / "zig-out/bin/fella"
)

class PtySession:
    """A real controlling terminal, bounded waits, and exact-PID cleanup."""

    def __init__(self, argv, env):
        import pty
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execve(BINARY, [BINARY, *argv], env)
        self.transcript = b""
        self.cursor = 0
        self.deadline = time.monotonic() + 10
        self.reaped = False

    def send(self, data):
        os.write(self.fd, data)

    def read_until(self, needle):
        while True:
            found = self.transcript.find(needle, self.cursor)
            if found >= 0:
                self.cursor = found + len(needle)
                return
            if time.monotonic() >= self.deadline:
                raise AssertionError(f"PTY deadline: {self.transcript!r}")
            if select.select([self.fd], [], [], 0.1)[0]:
                self.transcript += os.read(self.fd, 65536)

    def wait(self):
        while time.monotonic() < self.deadline:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
            if waited:
                self.reaped = True
                return os.waitstatus_to_exitcode(status)
            # PTY EOF can precede monitor exit. Wait for the actual process.
            time.sleep(0.01)
        raise AssertionError(f"PTY child did not exit: {self.transcript!r}")

    def close(self):
        if not self.reaped:
            waited, _ = os.waitpid(self.pid, os.WNOHANG)
            if not waited:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
        os.close(self.fd)


class Sessions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fella-integration-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "host-home"
        self.home.mkdir()
        (self.home / "host-secret").write_text("not for the session")
        self.data = self.root / "data with ' spaces"
        self.project = self.root / "project with ' $ spaces"
        self.project.mkdir()
        self.env = {
            **os.environ,
            "HOME": str(self.home),
            "XDG_DATA_HOME": str(self.data),
            "AWS_SECRET_ACCESS_KEY": "host-only-token",
            "SSH_AUTH_SOCK": "/run/host-agent",
            "GIT_CONFIG_GLOBAL": "/host/gitconfig",
            "BASH_ENV": "/host/startup",
        }
        self.fella("identity", "create", "work")
        self.fella("identity", "create", "personal")
        self.fella("workspace", "add", "project", "--identity", "work", "--path", str(self.project))
        self.fella("workspace", "add", "personal", "--identity", "personal", "--path", str(self.project))

    def fella(self, *args, code=0):
        result = subprocess.run(
            [BINARY, *args], env=self.env, capture_output=True, text=True, timeout=20
        )
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def enter(self, script, name="project", offline=False):
        flags = ["--offline"] if offline else []
        return self.fella("enter", name, *flags, "--", "/bin/sh", "-c", script)

    def test_persistent_identity_and_project_private_temporary_files(self):
        self.enter('echo durable > "$HOME/proof"; echo project > /workspace/proof; echo temporary > /tmp/proof')
        out = self.enter('cat "$HOME/proof" /workspace/proof; test ! -e /tmp/proof')
        self.assertEqual(out.stdout, "durable\nproject\n")
        self.enter('test ! -e "$HOME/proof"; test -e /workspace/proof', name="personal")

    def test_host_credentials_and_other_homes_are_not_visible(self):
        script = """
        test "$HOME" = /home/fella
        test "$PWD" = /workspace
        test "$USER" = fella
        test "$FELLA_IDENTITY" = work
        test "$FELLA_WORKSPACE" = project
        test -z "${AWS_SECRET_ACCESS_KEY+x}${SSH_AUTH_SOCK+x}${GIT_CONFIG_GLOBAL+x}${BASH_ENV+x}"
        test ! -e /etc/machine-id
        test ! -e /run/dbus/system_bus_socket
        test "$(id -un)" = fella
        test "$(ls /home)" = fella
        """
        self.enter("set -eu\n" + script)
        for private in [self.home / "host-secret", self.data / "fella/identities/personal/home"]:
            self.fella("enter", "project", "--", "/usr/bin/test", "!", "-e", str(private))

    def test_system_mount_is_readonly(self):
        self.fella(
            "enter", "project", "--", "/usr/bin/python3", "-c",
            "import os; assert os.statvfs('/usr').f_flag & os.ST_RDONLY"
        )

    def test_literal_arguments_and_child_exit_status(self):
        literal = "a'b \" $HOME $(touch /workspace/escaped)\n--offline"
        out = self.fella("enter", "project", "--", "/usr/bin/printf", "%s", literal)
        self.assertEqual(out.stdout, literal)
        self.assertFalse((self.project / "escaped").exists())
        self.fella("enter", "project", "--", "/bin/sh", "-c", "exit 37", code=37)
        self.fella("enter", "project", "--", "/does-not-exist", code=1)

    def test_offline_is_a_different_network_namespace(self):
        host = os.readlink("/proc/self/ns/net")
        online = self.enter('readlink /proc/self/ns/net; printf "%s" "$FELLA_NETWORK"').stdout
        offline = self.enter('readlink /proc/self/ns/net; printf "%s" "$FELLA_NETWORK"', offline=True).stdout
        self.assertEqual(online, host + "\nhost")
        self.assertNotEqual(offline.splitlines()[0], host)
        self.assertTrue(offline.endswith("offline"))
        # No external endpoint needed: shared networking can reach this host listener.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            probe = (
                "import socket; "
                f"s=socket.create_connection(('127.0.0.1',{listener.getsockname()[1]}),timeout=1)"
            )
            self.fella("enter", "project", "--", "/usr/bin/python3", "-c", probe)
            self.fella("enter", "project", "--offline", "--", "/usr/bin/python3", "-c", probe, code=1)

    def test_exit_kills_background_descendants(self):
        self.enter('(sleep 1; echo leaked > /workspace/orphan) >/dev/null 2>&1 &')
        time.sleep(1.3)
        self.assertFalse((self.project / "orphan").exists())

    def test_killed_launcher_cleans_up_namespace(self):
        for sig in [signal.SIGTERM, signal.SIGINT, signal.SIGKILL]:
            with self.subTest(signal=sig):
                ready, orphan = f"ready-{sig.name}", f"orphan-{sig.name}"
                script = (
                    "import time,pathlib; p=pathlib.Path('/workspace'); "
                    f"(p/'{ready}').write_text('ready'); time.sleep(0.6); "
                    f"(p/'{orphan}').write_text('leaked')"
                )
                child = subprocess.Popen(
                    [BINARY, "enter", "project", "--", "/usr/bin/python3", "-c", script],
                    env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                self.addCleanup(self.stop_child, child)
                deadline = time.monotonic() + 5
                while not (self.project / ready).exists():
                    self.assertLess(time.monotonic(), deadline, "session did not start")
                    self.assertIsNone(child.poll(), "session exited before readiness")
                    time.sleep(0.02)
                # Exact PID returned by Popen; never a name/port kill.
                child.send_signal(sig)
                self.assertNotEqual(child.wait(timeout=5), 0)
                time.sleep(0.9)
                self.assertFalse((self.project / orphan).exists())

    @staticmethod
    def stop_child(child):
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if child.stderr:
            child.stderr.close()

    def test_duplicate_names_never_replace_data(self):
        identity = Path(self.fella("identity", "path", "work").stdout.strip())
        (identity / "keep").write_text("keep")
        self.fella("identity", "create", "work", code=1)
        self.assertEqual((identity / "keep").read_text(), "keep")
        record = self.data / "fella/workspaces/project.json"
        original = record.read_bytes()
        self.fella("workspace", "add", "project", "--identity", "personal", "--path", str(self.project), code=1)
        self.assertEqual(record.read_bytes(), original)
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(identity.stat().st_mode & 0o777, 0o700)

    def test_concurrent_registration_is_atomic(self):
        def add(_):
            return subprocess.run(
                [BINARY, "workspace", "add", "race", "--identity", "work", "--path", str(self.project)],
                env=self.env, capture_output=True, timeout=20,
            ).returncode
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            codes = sorted(pool.map(add, range(2)))
        self.assertEqual(codes, [0, 1])
        record = json.loads((self.data / "fella/workspaces/race.json").read_text())
        self.assertEqual(record["path"], str(self.project))
        self.fella("enter", "race", "--", "/usr/bin/true")

    def test_concurrent_identity_creation_preserves_the_winner(self):
        def create(_):
            return subprocess.run(
                [BINARY, "identity", "create", "race"],
                env=self.env, capture_output=True, timeout=20,
            ).returncode
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(create, range(2))), [0, 1])
        identity = Path(self.fella("identity", "path", "race").stdout.strip())
        self.assertTrue((identity.parent / "ready").is_file())
        self.assertTrue((identity.parent / "etc/passwd").is_file())
        self.assertEqual(self.fella("identity", "list").stdout.splitlines(), ["personal", "race", "work"])

    def test_workspace_remove_keeps_all_user_data(self):
        (self.project / "keep").write_text("keep")
        identity = Path(self.fella("identity", "path", "work").stdout.strip())
        (identity / "keep").write_text("keep")
        self.fella("workspace", "remove", "project")
        self.fella("enter", "project", "--", "/usr/bin/true", code=1)
        self.assertEqual((self.project / "keep").read_text(), "keep")
        self.assertEqual((identity / "keep").read_text(), "keep")

    def test_bad_grants_and_metadata_fail_closed(self):
        link = self.root / "home-link"
        link.symlink_to(self.home)
        for path in ["/", str(self.home), str(self.data), str(link), str(self.data / "fella")]:
            self.fella("workspace", "add", "unsafe", "--identity", "work", "--path", path, code=1)
        self.fella("workspace", "add", "missing", "--identity", "unknown", "--path", str(self.project), code=1)
        record = self.data / "fella/workspaces/project.json"
        record.write_text('{"version":99,"identity":"work","path":"/"}')
        self.fella("enter", "project", "--", "/usr/bin/true", code=1)
        record.write_text("not json")
        self.fella("enter", "project", "--", "/usr/bin/true", code=1)

    def test_retargeted_project_is_revalidated(self):
        # A previously selected path must not become a grant of the whole home.
        self.project.rmdir()
        self.project.symlink_to(self.home)
        self.fella("enter", "project", "--", "/usr/bin/true", code=1)

    def test_incomplete_identity_is_not_launchable(self):
        (self.data / "fella/identities/work/ready").unlink()
        self.fella("enter", "project", "--", "/usr/bin/true", code=1)

    def test_interrupted_identity_staging_does_not_block_retry(self):
        stage = self.data / "fella/identities/.creating-interrupted"
        stage.mkdir()
        (stage / "home").mkdir()
        self.fella("identity", "create", "retry")
        names = self.fella("identity", "list").stdout.splitlines()
        self.assertEqual(names, ["personal", "retry", "work"])
        self.assertTrue(stage.exists())  # No opportunistic deletion of unknown state.

    def test_insecure_store_is_rejected_without_silently_chmodding_it(self):
        root = self.data / "fella"
        root.chmod(0o755)
        self.fella("identity", "list", code=1)
        self.fella("identity", "create", "another", code=1)
        self.fella("enter", "project", "--", "/usr/bin/true", code=1)
        self.assertEqual(root.stat().st_mode & 0o777, 0o755)

    def test_inherited_host_file_descriptors_are_closed(self):
        with (self.home / "host-secret").open() as secret:
            fd = secret.fileno()
            stat = os.fstat(fd)
            script = (
                "import os; "
                f"exec('try:\\n s=os.fstat({fd})\\nexcept OSError:\\n pass\\nelse:\\n"
                f" assert (s.st_dev,s.st_ino) != ({stat.st_dev},{stat.st_ino}), \"host secret fd inherited\"')"
            )
            result = subprocess.run(
                [BINARY, "enter", "project", "--", "/usr/bin/python3", "-c", script],
                env=self.env, pass_fds=(fd,), capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unavailable_namespaces_do_not_fall_back_to_a_host_command(self):
        result = subprocess.run(
            [
                shutil.which("bwrap"), "--unshare-user", "--uid", "1000", "--gid", "1000",
                "--disable-userns", "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
                "--", "/bin/sh", "-c", 'echo NAMESPACE-RESTRICTED >&2; exec "$@"', "sh",
                BINARY, "enter", "project", "--", "/bin/sh", "-c",
                "echo UNSANDBOXED-FALLBACK",
            ],
            env=self.env, capture_output=True, text=True, timeout=20,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("NAMESPACE-RESTRICTED", result.stderr)
        self.assertIn("bwrap:", result.stderr)
        self.assertNotIn("UNSANDBOXED-FALLBACK", result.stdout)

    def test_shell_is_interactive_and_interruptible(self):
        session = PtySession(["enter", "project"], self.env)
        self.addCleanup(session.close)
        prompt = b"[fella:work/project] /workspace $ "
        session.read_until(prompt)
        # Readiness must come from the foreground child after job-control
        # handoff, not from a preceding shell builtin.
        session.send(
            b"python3 -c 'import time; print(\"interrupt-ready\", flush=True); time.sleep(30)'\n"
        )
        session.read_until(b"interrupt-ready\r\n")
        session.send(b"\x03")
        session.read_until(prompt)
        session.send(b"printf 'shell-%s\\n' \"$FELLA_IDENTITY\"\n")
        session.read_until(b"shell-work\r\n")
        session.read_until(prompt)
        session.send(b"exit 23\n")
        self.assertEqual(session.wait(), 23, session.transcript)
        self.assertNotIn(b"no job control", session.transcript)

    def test_direct_command_ctrl_c_ends_the_session(self):
        session = PtySession(
            ["enter", "project", "--", "/bin/sh", "-c", "echo direct-ready; sleep 30"],
            self.env,
        )
        self.addCleanup(session.close)
        session.read_until(b"direct-ready\r\n")
        session.send(b"\x03")
        self.assertNotEqual(session.wait(), 0)


class Diagnostics(unittest.TestCase):
    def test_doctor_checks_real_namespaces(self):
        result = subprocess.run([BINARY, "doctor"], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reads_do_not_initialize_storage(self):
        with tempfile.TemporaryDirectory(prefix="fella-read-") as temp:
            data = Path(temp) / "data"
            env = {**os.environ, "XDG_DATA_HOME": str(data)}
            for kind in ["identity", "workspace"]:
                result = subprocess.run([BINARY, kind, "list"], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
            self.assertFalse(data.exists())

    def test_host_identity_is_unchanged(self):
        paths = [Path("/etc/hostname"), Path("/etc/machine-id")]
        before = [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]
        subprocess.run([BINARY, "doctor"], check=True, stdout=subprocess.DEVNULL)
        self.assertEqual(before, [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths])


if __name__ == "__main__":
    if sys.platform != "linux" or os.geteuid() == 0:
        sys.exit("Run integration tests on Linux as a normal user, not sudo.")
    unittest.main(verbosity=2)
