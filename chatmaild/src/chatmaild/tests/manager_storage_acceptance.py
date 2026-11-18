"""Actual guarded Store/profile mount-loss acceptance, never a mock FUSE proof.

Run only as container root with an explicitly mounted private tmpfs test root,
real gocryptfs and the pinned RPC binary. Helpers and applications are separate
processes. Synthetic unlock material travels through a private pipe only.
The application drops to its nonroot UID, zero capabilities and NoNewPrivileges.
Only this harness deliberately detaches its own mount to exercise loss races.
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from chatmaild.backup import manager_transport
from chatmaild.backup.manager_profile import (
    Profile,
    StateGuard,
    mount_record,
    mount_state,
    no_core_dumps,
)
from chatmaild.backup.manager_transport import SDK, Transport
from chatmaild.backup.manager_transport import child as production_child
from chatmaild.backup.model import ArchiveError
from chatmaild.backup.store import Store

UID = 10001
GID = 10001
MODULE = "chatmaild.tests.manager_storage_acceptance"
BLOB_MARKER = b"manager-storage-blob-private-synthetic-v1"


def response_barrier_child(pipe, profile, server, checksum, initialize):
    """Actual core call with a deliberate test-only response barrier."""
    original = SDK.self_key

    def barrier(sdk, account):
        original(sdk, account)
        Path(profile, ".rpc-tmp", "response-barrier").write_bytes(b"ready")
        while True:
            time.sleep(1)

    SDK.self_key = barrier
    production_child(pipe, profile, server, checksum, initialize)


def owned_rpc_pid(transport, server):
    worker = transport.process
    assert worker is not None and worker.is_alive()
    children = (
        Path(f"/proc/{worker.pid}/task/{worker.pid}/children").read_text().split()
    )
    assert len(children) == 1
    pid = int(children[0])
    executable = os.stat(f"/proc/{pid}/exe")
    pinned = os.stat(server)
    assert (executable.st_dev, executable.st_ino) == (pinned.st_dev, pinned.st_ino)
    assert os.stat(f"/proc/{pid}").st_uid == UID
    return pid


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def reason(error):
    if isinstance(error, ArchiveError):
        return error.reason
    if isinstance(error, sqlite3.Error):
        return "sqlite_refused"
    if isinstance(error, OSError):
        return "filesystem_refused"
    return "acceptance_error"


def diagnostic(error):
    trace = error.__traceback__
    while trace is not None and trace.tb_next is not None:
        trace = trace.tb_next
    return {
        "exception": type(error).__name__,
        "reason": reason(error),
        "errno": getattr(error, "errno", None),
        "function": trace.tb_frame.f_code.co_name if trace else None,
        "line": trace.tb_lineno if trace else None,
    }


class AcceptanceFailure(RuntimeError):
    def __init__(self, action, outcome):
        self.detail = outcome
        super().__init__(
            "acceptance_" + action + "_" + outcome.get("reason", "refused")
        )


def set_nnp():
    # PR_SET_NO_NEW_PRIVS; no ambient secrets or filesystem changes in preexec.
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise OSError("no_new_privileges_failed")


def service():
    # Set this in the already exec'd trusted actor, before any configuration
    # or state access; never run Python callbacks in Popen's post-fork child.
    set_nnp()
    os.umask(0o077)
    config = json.loads(sys.stdin.readline())
    policy = config["policy"]
    mount = Path(policy["mount"])
    database = mount / "archive/state.sqlite"
    profile_path = mount / "bot"
    guard = store = profile = transport = held = lock = owner = None
    initialize_rpc = False
    status = Path("/proc/self/status").read_text()
    emit(
        {
            "ready": True,
            "uid": os.geteuid(),
            "gid": os.getegid(),
            "capabilities_zero": all(
                re.search(r"(?m)^" + name + r":\s*0+$", status)
                for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
            ),
            "no_new_privileges": bool(re.search(r"(?m)^NoNewPrivs:\s*1$", status)),
        }
    )
    try:
        for raw in sys.stdin:
            command = json.loads(raw)
            action = command["action"]
            try:
                if action == "stop":
                    emit({"ok": True})
                    return
                if action == "kernel_probe":
                    fd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        info = os.fstat(fd)
                        emit(
                            {
                                "ok": True,
                                "uid": info.st_uid,
                                "mode": stat.S_IMODE(info.st_mode),
                            }
                        )
                    finally:
                        os.close(fd)
                    continue
                if action == "guard":
                    StateGuard(command.get("policy", policy))
                elif action == "held_guard":
                    guard.check()
                elif action == "ciphertext":
                    os.listdir(policy["backing"])
                elif action == "create_attributes":
                    # Immediate create results, without cache sleeps/retries.
                    child = mount / "immediate-private-child"
                    child.mkdir(mode=0o700)
                    info = child.stat()
                    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
                        UID,
                        GID,
                        0o700,
                    )
                    first = child / "first"
                    first.write_bytes(BLOB_MARKER)
                    first.chmod(0o600)
                    os.link(first, child / "second")
                    assert first.stat().st_ino == (child / "second").stat().st_ino
                    assert first.stat().st_uid == UID
                elif action in ("enroll", "open"):
                    guard = StateGuard(policy)
                    store = Store(database, guard=guard, create=action == "enroll")
                    if action == "enroll":
                        with store.connect() as db:
                            assert (
                                db.execute("PRAGMA journal_mode=" + command["journal"])
                                .fetchone()[0]
                                .upper()
                                == command["journal"]
                            )
                            db.execute(
                                "CREATE TABLE IF NOT EXISTS acceptance_probe (key TEXT PRIMARY KEY,value TEXT NOT NULL)"
                            )
                            db.execute(
                                "INSERT OR REPLACE INTO acceptance_probe VALUES('committed','pre-detach-committed')"
                            )
                        with guard.parent(profile_path / ".enrollment", create=True):
                            pass
                    profile = Profile(profile_path, state=guard)
                    profile.initialize() if action == "enroll" else profile.check()
                    initialize_rpc = action == "enroll"
                elif action == "check_committed":
                    with store.connect() as db:
                        assert db.execute(
                            "SELECT value FROM acceptance_probe WHERE key='committed'"
                        ).fetchone() == ("pre-detach-committed",)
                        if config.get("journal") == "WAL":
                            assert (
                                db.execute(
                                    "PRAGMA wal_checkpoint(TRUNCATE)"
                                ).fetchone()[0]
                                == 0
                            )
                elif action == "blob":
                    transport.close()
                    probe = subprocess.Popen(
                        [sys.executable, "-m", MODULE, "--internal", "blob"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                        start_new_session=True,
                    )
                    try:
                        stdout, _stderr = probe.communicate(
                            json.dumps({**config, "profile": str(profile_path)}) + "\n",
                            timeout=30,
                        )
                    except subprocess.TimeoutExpired:
                        os.killpg(probe.pid, signal.SIGKILL)
                        probe.wait(timeout=5)
                        raise ArchiveError("acceptance_blob_stall") from None
                    outcome = json.loads(stdout)
                    if probe.returncode != 0 or outcome != {"ok": True}:
                        error = ArchiveError(
                            "acceptance_blob_"
                            + outcome.get("phase", "unknown")
                            + "_"
                            + outcome.get("kind", "refused")
                        )
                        error.acceptance_detail = outcome
                        raise error
                elif action == "check_blob":
                    metadata = json.loads(
                        (profile_path / "blob-probe.json").read_text()
                    )
                    path = Path(metadata["path"])
                    assert (
                        profile.accounts_path() in path.parents
                        and path.read_bytes() == BLOB_MARKER
                    )
                elif action in ("rpc_death", "rpc_busy_close"):
                    transport.close()
                    metadata = json.loads(
                        (profile_path / "blob-probe.json").read_text()
                    )
                    marker = profile_path / ".rpc-tmp" / "response-barrier"
                    if marker.exists():
                        marker.unlink()
                    original = manager_transport.child
                    manager_transport.child = response_barrier_child
                    try:
                        transport.start()
                    finally:
                        manager_transport.child = original
                    failures = []

                    def request():
                        try:
                            transport.call("self_key", metadata["account"])
                        except ArchiveError as error:
                            failures.append(error.reason)

                    pending = threading.Thread(target=request, daemon=True)
                    pending.start()
                    deadline = time.monotonic() + 10
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    assert marker.exists()
                    worker = transport.process
                    pid = owned_rpc_pid(transport, config["rpc_server"])
                    began = time.monotonic()
                    if action == "rpc_death":
                        os.kill(
                            pid, signal.SIGKILL
                        )  # Exact owned/pinned test child only.
                    else:
                        transport.close()  # Worker must reap before parent escalation.
                    pending.join(5)
                    assert (
                        not pending.is_alive()
                        and len(failures) == 1
                        and failures[0]
                        in (
                            "manager_transport_child_exit",
                            "manager_transport_unavailable",
                        )
                    )
                    assert time.monotonic() - began < 5 and worker.exitcode is not None
                    assert not Path(f"/proc/{pid}").exists()
                    transport.start()
                    assert (
                        transport.call("self_key", metadata["account"])
                        == metadata["key_digest"]
                    )
                    assert Path(metadata["path"]).read_bytes() == BLOB_MARKER
                elif action == "hold":
                    held = store.transaction()
                    db = held.__enter__()
                    db.execute(
                        "INSERT OR REPLACE INTO acceptance_probe VALUES('inflight','not-promised-durable')"
                    )
                    lock = store.operation("a" * 32)
                    lock.__enter__()
                elif action == "finish":
                    current, held = held, None
                    try:
                        current.__exit__(None, None, None)
                    finally:
                        if lock is not None:
                            current_lock, lock = lock, None
                            current_lock.__exit__(None, None, None)
                elif action == "new_store":
                    Store(database, guard=guard, create=False)
                elif action == "new_lock":
                    with store.operation("b" * 32):
                        pass
                elif action == "new_profile":
                    Profile(profile_path, state=guard).check()
                elif action == "new_owner":
                    with profile.owner():
                        pass
                elif action == "restart_rpc":
                    if owner is None:
                        owner = profile.owner()
                        owner.__enter__()
                    if transport is not None:
                        previous_pid = (
                            owned_rpc_pid(transport, config["rpc_server"])
                            if transport.process is not None
                            else None
                        )
                        transport.close()
                        assert (
                            previous_pid is None
                            or not Path(f"/proc/{previous_pid}").exists()
                        )
                    else:
                        transport = Transport(
                            profile,
                            config["rpc_server"],
                            config["rpc_sha256"],
                            timeout=20,
                            initialize=initialize_rpc,
                        )
                    transport.start()
                    initialize_rpc = False
                    assert transport.process.is_alive()
                    emit({"ok": True, "rpc_started": True})
                    continue
                elif action == "missing_accounts":
                    transport.close()
                    accounts = profile.accounts_path()
                    assert (
                        accounts.parent == profile_path and accounts.name == "accounts"
                    )
                    saved = accounts.with_name("accounts.acceptance-held")
                    accounts.rename(saved)
                    refused = False
                    try:
                        try:
                            transport.start()
                        except (ArchiveError, OSError):
                            refused = True
                        assert refused and not accounts.exists(), (
                            "normal startup recreated a missing accounts identity"
                        )
                    finally:
                        if not accounts.exists():
                            saved.rename(accounts)
                elif action == "race":
                    Profile(profile_path, state=guard).check()
                    # Baseline Store/profile opens were proven before the
                    # other actor held its writer. Announce before potentially
                    # contended I/O so the parent can detach during real opens.
                    emit({"racing": True})
                    events = []
                    deadline = time.monotonic() + 1.5
                    while (time.monotonic() < deadline or len(events) < 12) and len(
                        events
                    ) < 300:
                        for operation in ("new_store", "new_lock", "new_profile"):
                            began = time.monotonic()
                            try:
                                if operation == "new_store":
                                    candidate = Store(
                                        database, guard=guard, create=False
                                    )
                                    with candidate.connect() as reader:
                                        assert reader.execute(
                                            "SELECT value FROM acceptance_probe WHERE key='committed'"
                                        ).fetchone() == ("pre-detach-committed",)
                                elif operation == "new_lock":
                                    with store.operation("c" * 32):
                                        pass
                                else:
                                    Profile(profile_path, state=guard).check()
                                events.append([operation, began, True])
                            except (ArchiveError, OSError, sqlite3.Error):
                                events.append([operation, began, False])
                        time.sleep(0.005)
                    emit({"ok": True, "events": events})
                    continue
                else:
                    raise ArchiveError("acceptance_action_invalid")
                emit({"ok": True})
            except (ArchiveError, OSError, sqlite3.Error, AssertionError) as error:
                emit(
                    {
                        "ok": False,
                        "phase": action,
                        **diagnostic(error),
                        "reason": reason(error),
                        "errno": getattr(error, "errno", None),
                        "rpc_spawned": bool(
                            transport is not None
                            and transport.process is not None
                            and transport.process.is_alive()
                        ),
                        "child": getattr(error, "acceptance_detail", None),
                    }
                )
    finally:
        if held is not None:
            try:
                held.__exit__(RuntimeError, RuntimeError("acceptance_abort"), None)
            except (ArchiveError, OSError, sqlite3.Error):
                pass
        if lock is not None:
            lock.__exit__(None, None, None)
        if transport is not None:
            transport.close()
        if owner is not None:
            owner.__exit__(None, None, None)


def helper(secret_fd):
    config = json.loads(sys.stdin.readline())
    try:
        secret = os.read(secret_fd, 1025).decode("ascii")
    finally:
        os.close(secret_fd)

    class MemoryBroker:
        def get(self, _reference):
            if config.get("unavailable"):
                raise ArchiveError("manager_mount_key_unavailable")
            return {"gocryptfs_passphrase": secret}

    try:
        mount_state(
            config["policy"],
            MemoryBroker(),
            "synthetic-memory-only",
            initialize=config["initialize"],
        )
        emit({"ok": True})
        return 0
    except (ArchiveError, OSError, ValueError) as error:
        emit({"ok": False, "reason": reason(error)})
        return 1


def blob():
    """A bounded test child, not an added production transport operation."""
    config = json.loads(sys.stdin.readline())
    profile = Path(config["profile"])
    guard = StateGuard(config["policy"])
    Profile(profile, state=guard).check()
    sdk = None
    phase = "sdk_start"
    failure = None
    try:
        sdk = SDK(profile, config["rpc_server"], config["rpc_sha256"])
        phase = "add_account"
        account = sdk.rpc.add_account()
        # Pinned core's supported offline-test transport initializes the
        # account identity without an IMAP/SMTP connection or credentials.
        # A bare, unconfigured add_account has no usable SELF vCard yet.
        phase = "offline_identity"
        sdk.rpc.add_pseudo_transport(account, "storage-fixture@example.invalid")
        phase = "input_write"
        source = profile / ".rpc-tmp" / "blob-probe-input"
        source.write_bytes(BLOB_MARKER)
        phase = "blob_copy"
        path = Path(sdk.rpc.copy_to_blob_dir(account, str(source)))
        phase = "path_validate"
        assert profile / "accounts" in path.parents and path.read_bytes() == BLOB_MARKER
        phase = "self_key"
        (profile / "blob-probe.json").write_text(
            json.dumps(
                {
                    "path": str(path),
                    "account": account,
                    "key_digest": sdk.self_key(account),
                }
            )
        )
        source.unlink()
        guard.check()
    except Exception as error:
        failure = {
            "ok": False,
            "phase": phase,
            "kind": error.reason
            if isinstance(error, ArchiveError)
            else type(error).__name__,
            **diagnostic(error),
        }
    finally:
        if sdk is not None:
            try:
                sdk.close()
                assert (
                    sdk.rpc.process.returncode is not None
                    and not Path(f"/proc/{sdk.rpc.process.pid}").exists()
                )
            except Exception:
                failure = failure or {
                    "ok": False,
                    "phase": "sdk_close",
                    "kind": "refused",
                }
    emit(failure or {"ok": True})
    return 1 if failure else 0


class Actor:
    def __init__(self, config, *, uid=UID):
        self.process = subprocess.Popen(
            [sys.executable, "-m", MODULE, "--internal", "service"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            user=uid,
            group=GID,
            extra_groups=[],
            start_new_session=True,
        )
        self.send(config)
        ready = self.read()
        assert (
            ready["ready"]
            and ready["uid"] == uid
            and ready["capabilities_zero"]
            and ready["no_new_privileges"]
        )

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def read(self, timeout=40):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout):
                raise RuntimeError("acceptance_actor_stall")
        raw = self.process.stdout.readline(65537)
        if not raw or len(raw) > 65536:
            raise RuntimeError("acceptance_actor_response_invalid")
        return json.loads(raw)

    def call(self, action, **values):
        self.send({"action": action, **values})
        return self.read()

    def close(self):
        if self.process.poll() is None:
            try:
                self.call("stop")
                self.process.wait(timeout=8)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=5)


def start_helper(policy, secret, *, initialize, unavailable=False):
    read, write = os.pipe()
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                MODULE,
                "--internal",
                "helper",
                "--secret-fd",
                str(read),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            pass_fds=(read,),
            start_new_session=True,
        )
        os.write(write, secret.encode("ascii"))
        process.stdin.write(
            json.dumps(
                {"policy": policy, "initialize": initialize, "unavailable": unavailable}
            )
            + "\n"
        )
        process.stdin.flush()
        process.stdin.close()
        return process
    finally:
        os.close(read)
        os.close(write)


def wait_mounted(policy, process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            result = json.loads(process.stdout.readline())
            raise RuntimeError(result.get("reason", "acceptance_mount_failed"))
        if (
            Path(policy["attestation"]).is_file()
            and mount_record(policy["mount"])[1] == "fuse.gocryptfs"
        ):
            return
        time.sleep(0.05)
    raise RuntimeError("acceptance_mount_stall")


def finish_helper(process):
    try:
        return process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            return process.wait(timeout=5)


def success(actor, action, **kwargs):
    result = actor.call(action, **kwargs)
    if not result.get("ok"):
        raise AcceptanceFailure(action, result)
    return result


def denied(actor, action, **kwargs):
    result = actor.call(action, **kwargs)
    assert result.get("ok") is False, "guarded operation unexpectedly succeeded"
    return result


def run_case(root, journal, args, checks):
    case = root / journal.lower()
    case.mkdir(mode=0o755)
    os.chmod(case, 0o755)
    mount, ciphertext, runtime = case / "mount", case / "ciphertext", case / "runtime"
    ciphertext.mkdir(mode=0o700)
    backing = ciphertext / "backing"
    mount.mkdir(mode=0)
    backing.mkdir(mode=0o700)
    os.chown(backing, UID, GID)
    runtime.mkdir(mode=0o755)
    policy = {
        "mount": str(mount),
        "backing": str(backing),
        "attestation": str(runtime / "attestation.json"),
        "epoch": secrets.token_hex(16),
        "uid": UID,
        "gid": GID,
        "gocryptfs": args.gocryptfs,
        "gocryptfs_sha256": args.gocryptfs_sha256,
    }
    config = {
        "policy": policy,
        "rpc_server": args.rpc_server,
        "rpc_sha256": args.rpc_sha256,
        "journal": journal,
    }
    secret = secrets.token_urlsafe(48)
    underlay = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    actors, process = [], None
    original_attestation = None

    def empty_underlay():
        info = os.fstat(underlay)
        assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0
        assert os.listdir(underlay) == [], (
            "plaintext files appeared in the inaccessible underlay"
        )

    try:
        unavailable = start_helper(policy, secret, initialize=True, unavailable=True)
        assert unavailable.wait(timeout=20) != 0
        assert (
            json.loads(unavailable.stdout.readline())["reason"]
            == "manager_mount_key_unavailable"
        )
        assert not Path(policy["attestation"]).exists() and not list(backing.iterdir())
        empty_underlay()
        checks.append(
            journal + ": unavailable wallet refuses initialization without state files"
        )

        process = start_helper(policy, secret, initialize=True)
        wait_mounted(policy, process)
        original_attestation = Path(policy["attestation"]).read_bytes()
        app = Actor(config)
        actors.append(app)
        probe = app.call("kernel_probe")
        if not probe.get("ok"):
            raise RuntimeError(
                "acceptance_unprivileged_fuse_access_"
                + probe.get("reason", "denied")
                + "_"
                + str(probe.get("errno"))
            )
        assert probe["uid"] == UID and probe["mode"] == 0o700
        success(app, "create_attributes")
        denied(app, "ciphertext")
        success(app, "enroll", journal=journal)
        success(app, "check_committed")
        success(app, "restart_rpc")
        success(app, "blob")
        success(app, "check_blob")
        success(app, "rpc_death")
        success(app, "rpc_busy_close")
        count = total = 0
        for current, directories, files in os.walk(backing):
            count += len(directories) + len(files)
            assert count < 4096
            assert not {"accounts.toml", "archive.sqlite", "blob-probe.json"} & set(
                files
            )
            for name in files:
                raw = (Path(current) / name).read_bytes()
                total += len(raw)
                assert total < 64 * 1024 * 1024
                assert BLOB_MARKER not in raw and b"pre-detach-committed" not in raw
        success(app, "missing_accounts")
        mounted_id = mount_record(mount)
        success(app, "restart_rpc")
        assert process.poll() is None and mount_record(mount) == mounted_id
        checks.append(
            journal
            + ": actual RPC restart preserves the independent encrypted state mount"
        )
        checks.append(
            journal
            + ": ordinary RPC startup refuses missing accounts identity without recreation"
        )
        checks.append(
            journal
            + ": immediate service create attributes/hardlinks and actual core blob IO are private; direct ciphertext access denied"
        )
        checks.append(
            journal
            + ": exact pinned core death during a response barrier promptly fails/reaps the waiter; explicit restart retains account/key/blob"
        )
        checks.append(
            journal
            + ": busy close during an actual core response barrier reaps the exact owned core PID before explicit restart"
        )

        wrong_uid = Actor(config, uid=UID + 1)
        actors.append(wrong_uid)
        denied(wrong_uid, "guard")
        denied(
            app,
            "guard",
            policy={
                **policy,
                "epoch": "f" * 32 if policy["epoch"] != "f" * 32 else "e" * 32,
            },
        )
        invalid = json.loads(original_attestation)
        invalid["mount_id_unique"] += 1
        Path(policy["attestation"]).write_text(json.dumps(invalid))
        denied(app, "guard")
        invalid["version"] = 1
        invalid.pop("mount_id_unique")
        Path(policy["attestation"]).write_text(json.dumps(invalid))
        denied(app, "guard")
        Path(policy["attestation"]).write_bytes(original_attestation)
        runtime.chmod(0o777)
        denied(app, "guard")
        runtime.chmod(0o755)
        success(app, "guard")
        checks.append(
            journal + ": wrong UID, epoch, attestation and writable ancestor all refuse"
        )

        racer = Actor(config)
        actors.append(racer)
        success(racer, "open")
        success(app, "hold")
        racer.send({"action": "race"})
        started = racer.read()
        if started.get("racing") is not True:
            raise AcceptanceFailure("race_start", started)
        # Deliberate fault injection on this newly created test mount only.
        subprocess.run(
            [args.fusermount, "-u", "-z", str(mount)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        detached_at = time.monotonic()
        events = racer.read()["events"]
        for operation in ("new_store", "new_lock", "new_profile"):
            after = [
                event
                for event in events
                if event[0] == operation and event[1] >= detached_at
            ]
            assert after and not any(event[2] for event in after), (
                "post-detach open bypassed its guard"
            )
        denied(app, "finish")
        for operation in ("new_store", "new_lock", "new_profile"):
            denied(app, operation)
        denied(app, "new_owner")
        restart = denied(app, "restart_rpc")
        assert restart["rpc_spawned"] is False
        empty_underlay()
        checks.append(
            journal
            + ": held transaction and raced Store/lock/profile opens refuse after actual detach"
        )
        checks.append(
            journal
            + ": actual RPC restart is blocked with mount absent; underlay contains zero files"
        )
        for actor in actors[1:]:
            actor.close()
        actors[:] = [app]  # Retain one guard across the actual detach/remount.
        finish_helper(process)
        process = None

        Path(policy["attestation"]).unlink()
        wrong_key = start_helper(policy, secrets.token_urlsafe(48), initialize=False)
        assert wrong_key.wait(timeout=25) != 0
        assert not Path(policy["attestation"]).exists()
        empty_underlay()
        checks.append(
            journal + ": wrong wallet key cannot mount or create plaintext fallback"
        )

        process = start_helper(policy, secret, initialize=False)
        wait_mounted(policy, process)
        current_attestation = Path(policy["attestation"]).read_bytes()
        assert (
            json.loads(current_attestation)["mount_id_unique"]
            != json.loads(original_attestation)["mount_id_unique"]
        )
        denied(app, "held_guard")
        app.close()
        actors.clear()
        app = Actor(config)
        actors.append(app)
        Path(policy["attestation"]).write_bytes(original_attestation)
        denied(app, "guard")
        Path(policy["attestation"]).write_bytes(current_attestation)
        success(app, "open")
        success(app, "check_committed")
        success(app, "check_blob")
        success(app, "restart_rpc")
        empty_underlay()
        checks.append(
            journal
            + ": stale attestation refuses; legitimate remount preserves pre-detach committed data and RPC startup"
        )
    finally:
        for actor in actors:
            actor.close()
        if process is not None:
            if mount_record(mount)[1] == "fuse.gocryptfs":
                subprocess.run(
                    [args.fusermount, "-u", str(mount)],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            finish_helper(process)
        os.close(underlay)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--internal", choices=("service", "helper", "blob"), help=argparse.SUPPRESS
    )
    parser.add_argument("--secret-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--root")
    parser.add_argument("--output")
    parser.add_argument("--rpc-server")
    parser.add_argument("--rpc-sha256")
    parser.add_argument("--gocryptfs", default="/usr/bin/gocryptfs")
    parser.add_argument("--gocryptfs-sha256")
    parser.add_argument("--fusermount", default="/usr/bin/fusermount3")
    args = parser.parse_args(argv)
    no_core_dumps()
    if args.internal == "service":
        service()
        return 0
    if args.internal == "helper":
        return helper(args.secret_fd)
    if args.internal == "blob":
        return blob()
    assert os.geteuid() == 0 and os.environ.get("CHATMAIL_ISOLATED_STORAGE_LAB") == "1"
    assert Path("/run/.containerenv").exists() or Path("/.dockerenv").exists()
    root = Path(args.root).absolute()
    assert str(root).startswith("/var/lib/") and root.parent.resolve() == root.parent
    assert mount_record(root.parent)[1] == "tmpfs", (
        "test state and private material must stay in container tmpfs"
    )
    root.mkdir(mode=0o755)
    os.chmod(root, 0o755)
    checks = []
    result = {
        "synthetic_only": True,
        "real_fuse": True,
        "network_used": False,
        "inflight_write_durability": "not promised",
        "passed": 0,
    }
    try:
        for journal in ("DELETE", "WAL"):
            run_case(root, journal, args, checks)
        result.update(
            state="passed", checks=checks, passed=len(checks), underlay_files=0
        )
    except BaseException as error:
        result.update(
            state="failed",
            checks=checks,
            passed=len(checks),
            reason="interrupted"
            if isinstance(error, KeyboardInterrupt)
            else str(error)
            if isinstance(error, RuntimeError)
            else reason(error),
            failure=getattr(error, "detail", diagnostic(error)),
        )
        raise
    finally:
        result["harness_sha256"] = hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest()
        Path(args.output).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n"
        )
        emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
