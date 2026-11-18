"""Automatic issuance reserves authority before I/O and never replays ambiguity."""

import json
import multiprocessing
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from chatmaild.backup import cli, manager_transport
from chatmaild.backup import manager as implementation
from chatmaild.backup import store as store_module
from chatmaild.backup.manager import Context, IssuanceWorker
from chatmaild.backup.manager_store import ManagerStore, row
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_backend import setup as manager_setup


@pytest.fixture
def context(tmp_path):
    context = manager_setup.__wrapped__(tmp_path)
    manager = context.manager

    class Issuing:
        def __init__(self):
            self.sent = []
            self.fail = False
            self.key = "a" * 64
            self.self_key = "c" * 64
            self.after_send = None

        def call(self, method, *args):
            with manager.store.transaction() as db:
                # Any SDK call for issuance must follow its durable reservation;
                # the test can also acquire this writer because no SQL spans I/O.
                claim = row(db, "SELECT * FROM manager_issuance WHERE state='issuing'")
                assert claim is not None and claim["instance"] and claim["claim_token"]
            peer = {
                "account": 1,
                "chat": 20,
                "contact": 10,
                "key_digest": self.key,
                "self_key_digest": self.self_key,
            }
            if method == "peer":
                return peer
            assert method == "issue"
            assert args[3] == {"key_digest": self.key, "self_key_digest": self.self_key}
            assert Path(args[2]).is_file()
            self.sent.append(claim["instance"])
            if self.fail:
                raise ArchiveError("manager_transport_stall")
            if self.after_send is not None:
                self.after_send()
            return {**peer, "message": 1000 + len(self.sent)}

        def attest(self, registered):
            return Context(
                **{key: registered[key] for key in Context.__dataclass_fields__}
            )

        def close(self):
            pass

    context.transport = Issuing()
    manager.transport = context.transport
    return context


def current(context):
    with context.scenario.store.connect() as db:
        return row(
            db,
            "SELECT * FROM manager_issuance WHERE contact=10 ORDER BY created LIMIT 1",
        )


def test_duplicate_securejoin_issues_once_without_inheriting_owner_links(context):
    manager = context.manager
    epoch = manager.profile.check()
    for _ in range(3):
        manager.db.securejoin(epoch, 1, 10, "a" * 64)
    worker = IssuanceWorker(manager, 1)
    assert worker.tick()
    assert current(context)["state"] == "issued"
    assert not worker.tick()
    manager.db.securejoin(epoch, 1, 10, "a" * 64)
    assert not worker.tick() and len(context.transport.sent) == 1
    with manager.store.connect() as db:
        issued = db.execute(
            "SELECT count(*) FROM manager_instances WHERE id=?",
            (context.transport.sent[0],),
        ).fetchone()[0]
        links = db.execute(
            "SELECT count(*) FROM manager_links WHERE instance=?",
            (context.transport.sent[0],),
        ).fetchone()[0]
    assert issued == 1 and links == 0
    assert manager.store.metrics()["manager_issuance_issued"] == 1


def test_two_workers_cannot_claim_the_same_pending_issuance(context):
    barrier = threading.Barrier(3)
    claims = []

    def claim():
        barrier.wait()
        claims.append(
            context.manager.db.claim_issuance(context.manager.profile.check(), 1)
        )

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert sum(value is not None for value in claims) == 1
    assert context.transport.sent == []


def test_interrupted_reserved_job_becomes_uncertain_only_under_owner_recovery(context):
    manager = context.manager
    epoch = manager.profile.check()
    claim = manager.db.claim_issuance(epoch, 1)
    assert claim["instance"] and context.transport.sent == []
    ManagerStore(manager.store)  # A portal opener must not retire a live claim.
    assert current(context)["state"] == "issuing"
    with manager.profile.owner():
        assert manager.db.recover_issuance(epoch) == 1
    manager.db.securejoin(epoch, 1, 10, "a" * 64)
    assert current(context)["state"] == "uncertain"
    assert not IssuanceWorker(manager, 1).tick()
    assert context.transport.sent == []


def test_lost_reply_after_acceptance_requires_explicit_replacement_and_keeps_history(
    context,
):
    manager = context.manager
    context.transport.fail = True
    with pytest.raises(ArchiveError, match="manager_issue_uncertain"):
        IssuanceWorker(manager, 1).tick()
    abandoned = current(context)
    assert abandoned["state"] == "uncertain" and len(context.transport.sent) == 1
    assert not IssuanceWorker(manager, 1).tick()
    context.transport.fail = False
    issued = manager.issue_app(1, 10, replacement=abandoned["id"])
    assert issued != abandoned["instance"] and len(context.transport.sent) == 2
    with manager.store.connect() as db:
        history = row(
            db,
            "SELECT * FROM manager_issuance_history WHERE issuance=?",
            (abandoned["id"],),
        )
        orphan = db.execute(
            "SELECT count(*) FROM manager_instances WHERE id=?",
            (abandoned["instance"],),
        ).fetchone()[0]
    assert (
        history["instance"] == abandoned["instance"] and history["state"] == "uncertain"
    )
    assert history["replacement_instance"] == issued and orphan == 0


def test_peer_change_cancels_pending_old_key_and_new_app_has_no_old_links(context):
    manager = context.manager
    epoch = manager.profile.check()
    manager.db.securejoin(epoch, 1, 10, "d" * 64)
    context.transport.key = "d" * 64
    assert current(context)["state"] == "cancelled"
    assert IssuanceWorker(manager, 1).tick()
    with manager.store.connect() as db:
        issued = row(
            db, "SELECT * FROM manager_issuance WHERE key_digest=?", ("d" * 64,)
        )
        links = db.execute(
            "SELECT count(*) FROM manager_links WHERE instance=?", (issued["instance"],)
        ).fetchone()[0]
    assert issued["state"] == "issued" and links == 0


def test_account_key_change_before_sdk_send_fails_without_issuing(context):
    with context.manager.store.transaction() as db:
        db.execute("UPDATE manager_accounts SET self_key_digest=?", ("d" * 64,))
    with pytest.raises(ArchiveError, match="manager_issue_preparation_failed"):
        IssuanceWorker(context.manager, 1).tick()
    assert current(context)["state"] == "failed" and context.transport.sent == []


@pytest.mark.parametrize("race", ["claim", "account", "peer"])
def test_registration_fences_send_races_and_never_registers_orphan(context, race):
    manager = context.manager

    def change():
        with manager.store.transaction() as db:
            if race == "claim":
                db.execute(
                    "UPDATE manager_issuance SET claim_token=?",
                    (secrets.token_hex(32),),
                )
            elif race == "account":
                db.execute("UPDATE manager_accounts SET self_key_digest=?", ("d" * 64,))
            else:
                db.execute("UPDATE manager_peers SET key_digest=?", ("d" * 64,))

    context.transport.after_send = change
    with pytest.raises(ArchiveError, match="manager_issue_uncertain"):
        IssuanceWorker(manager, 1).tick()
    with manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM manager_instances WHERE id=?",
                (context.transport.sent[0],),
            ).fetchone()[0]
            == 0
        )
        assert db.execute(
            "SELECT count(*) FROM ledger WHERE reason='manager_issue_stale_outcome'"
        ).fetchone()[0] == (1 if race == "claim" else 0)


def test_registration_and_issued_transition_roll_back_together(context, monkeypatch):
    manager = context.manager
    original = manager.store._ledger

    def failure(db, reason, *args, **kwargs):
        if reason == "manager_instance_registered":
            raise ArchiveError("manager_test_registration_rollback")
        return original(db, reason, *args, **kwargs)

    monkeypatch.setattr(manager.store, "_ledger", failure)
    with pytest.raises(ArchiveError, match="manager_issue_uncertain"):
        IssuanceWorker(manager, 1).tick()
    assert current(context)["state"] == "uncertain"
    with manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM manager_instances WHERE id=?",
                (context.transport.sent[0],),
            ).fetchone()[0]
            == 0
        )


def test_pending_saturation_retains_durable_unique_refusal(context):
    manager = context.manager
    epoch = manager.profile.check()
    manager.db.securejoin(epoch, 1, 11, "d" * 64, max_pending=1)
    manager.db.securejoin(epoch, 1, 11, "d" * 64, max_pending=1)
    with manager.store.connect() as db:
        rows = db.execute(
            "SELECT state,reason FROM manager_issuance WHERE contact=11"
        ).fetchall()
    assert rows == [("held", "manager_issue_saturated")]
    assert manager.store.metrics()["manager_issuance_held"] == 1


def test_profile_owner_excludes_cli_before_any_sdk_open(context, monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "load",
        lambda _path: ({"manager": {"account_id": 1}}, context.manager.store, None),
    )
    monkeypatch.setattr(
        implementation, "load_manager", lambda *_args, **_kwargs: context.manager
    )
    with context.manager.profile.owner():
        assert implementation.main(["--config", "unused", "serve"]) == 1
    assert "manager_profile_busy" in capsys.readouterr().err
    assert context.transport.sent == []


def clean_spawn_child(pipe, profile, _server, _checksum, _initialize):
    os.setsid()
    assert multiprocessing.get_start_method() == "spawn"
    Path(profile, "accounts", "accounts.toml").write_text("# synthetic\n")
    manager_transport.write_private_frame(pipe, {"ok": True, "value": None})
    assert manager_transport.read_private_frame(pipe, 65536) is None
    Path(profile, "clean-shutdown").write_bytes(b"closed")


def test_transport_uses_clean_spawn_and_idle_shutdown_before_signal(
    context, monkeypatch
):
    monkeypatch.setattr(manager_transport, "child", clean_spawn_child)
    adapter = manager_transport.Transport(
        context.manager.profile, "unused", "0" * 64, timeout=5, initialize=True
    )
    adapter.start()
    worker = adapter.process
    adapter.close()
    assert worker.exitcode == 0
    assert (context.manager.profile.mount / "clean-shutdown").read_bytes() == b"closed"


def busy_spawn_child(pipe, profile, _server, _checksum, _initialize):
    os.setsid()
    Path(profile, "accounts", "accounts.toml").write_text("# synthetic\n")
    manager_transport.write_private_frame(pipe, {"ok": True, "value": None})
    manager_transport.read_private_frame(pipe, 65536)
    Path(profile, "request-inflight").write_bytes(b"ready")
    while True:
        time.sleep(1)


def test_busy_close_fails_pending_request_and_reaps_owned_worker(context, monkeypatch):
    monkeypatch.setattr(manager_transport, "child", busy_spawn_child)
    adapter = manager_transport.Transport(
        context.manager.profile, "unused", "0" * 64, timeout=5, initialize=True
    )
    adapter.start()
    worker = adapter.process
    failures = []

    def request():
        try:
            adapter.call("self_key", 1)
        except ArchiveError as error:
            failures.append(error.reason)

    pending = threading.Thread(target=request)
    pending.start()
    marker = context.manager.profile.mount / "request-inflight"
    deadline = time.monotonic() + 5
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert marker.exists()
    adapter.close()
    pending.join(5)
    assert not pending.is_alive() and worker.exitcode is not None
    assert failures and failures[0] in (
        "manager_transport_child_exit",
        "manager_transport_unavailable",
    )


def test_sdk_close_reaps_core_before_unbounded_official_cleanup_can_strand_it():
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    sdk = manager_transport.SDK.__new__(manager_transport.SDK)
    sdk.stopped = threading.Event()
    blocked = threading.Event()

    class Client:
        def close(self):
            blocked.wait(10)

    sdk.rpc = Client()
    sdk.rpc.process = process
    began = time.monotonic()
    try:
        sdk.close()
        assert time.monotonic() - began < 2
        assert (
            process.returncode is not None and not Path(f"/proc/{process.pid}").exists()
        )
    finally:
        blocked.set()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)


def test_sdk_watchdog_ignores_dynamic_method_placeholder_before_popen_exists():
    class Client:
        def __getattr__(self, _name):
            return object()

    sdk = manager_transport.SDK.__new__(manager_transport.SDK)
    sdk.rpc = Client()
    sdk.stopped = threading.Event()
    sdk.started = threading.Event()
    watcher = threading.Thread(target=sdk._watch_owned_process, daemon=True)
    watcher.start()
    time.sleep(0.05)
    assert watcher.is_alive()
    sdk.stopped.set()
    watcher.join(1)
    assert not watcher.is_alive()


@pytest.mark.parametrize("kind", ["oversized_first", "unicode_expansion"])
def test_oversized_first_history_update_quarantines_without_advancing_cursor(
    context, kind
):
    padding = (
        "x" * manager_transport.MAX_IPC
        if kind == "oversized_first"
        else "\U0001f600" * (manager_transport.MAX_IPC // 12)
    )
    values = [{"serial": 1, "payload": {"padding": padding}}]
    raw = json.dumps(values, ensure_ascii=False)
    assert len(raw) < 16 * 1024 * 1024
    sdk = manager_transport.SDK.__new__(manager_transport.SDK)
    sdk.rpc = SimpleNamespace(get_webxdc_status_updates=lambda *_args: raw)
    sdk.attest = context.transport.attest
    context.transport.updates = sdk.updates
    manager_transport.reconcile(context.manager)
    with context.manager.store.connect() as db:
        state, serial = db.execute(
            "SELECT state,serial FROM manager_instances WHERE id=?", (context.instance,)
        ).fetchone()
        refused = db.execute(
            "SELECT count(*) FROM ledger WHERE reason='manager_history_quarantined'"
        ).fetchone()[0]
    assert state == "quarantined" and serial == 0 and refused == 1


def test_storage_refusal_flush_restores_batch_after_failed_commit(context, monkeypatch):
    store = context.manager.store
    guard = store.guard
    guard.record_refusal(3)
    connect = store_module.sqlite3.connect

    class FailedCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("synthetic_commit_failure")

    def failing(*args, **kwargs):
        return connect(*args, **kwargs, factory=FailedCommit)

    with monkeypatch.context() as patch:
        patch.setattr(store_module.sqlite3, "connect", failing)
        with pytest.raises(sqlite3.OperationalError, match="synthetic_commit_failure"):
            with store.connect():
                pass
    assert guard.refusals == 3
    with store.connect():
        pass
    assert guard.refusals == 0
    with store.connect() as db:
        assert (
            db.execute(
                "SELECT sum(amount) FROM ledger WHERE reason='manager_storage_refused'"
            ).fetchone()[0]
            == 3
        )


def test_storage_refusal_flush_preserves_concurrent_increments(context, monkeypatch):
    store = context.manager.store
    guard = store.guard
    guard.record_refusal(3)
    taken = threading.Event()
    release = threading.Event()
    original = store._ledger
    failures = []

    def ledger(db, reason, *args, **kwargs):
        if reason == "manager_storage_refused":
            taken.set()
            assert release.wait(5)
        return original(db, reason, *args, **kwargs)

    monkeypatch.setattr(store, "_ledger", ledger)

    def flush():
        try:
            with store.connect():
                pass
        except Exception:
            failures.append(True)

    worker = threading.Thread(target=flush)
    worker.start()
    assert taken.wait(5)
    guard.record_refusal(5)
    release.set()
    worker.join(5)
    assert not worker.is_alive() and not failures and guard.refusals == 5
    with store.connect():
        pass
    with store.connect() as db:
        assert (
            db.execute(
                "SELECT sum(amount) FROM ledger WHERE reason='manager_storage_refused'"
            ).fetchone()[0]
            == 8
        )
    assert guard.refusals == 0
