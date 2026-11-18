"""Deterministic ownership races at archive operation/transaction boundaries."""

import hashlib
import json
import os
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from chatmaild.backup import cli
from chatmaild.backup.drive import Drive
from chatmaild.backup.incarnation import Mailbox
from chatmaild.backup.jobs import Worker
from chatmaild.backup.model import ArchiveError, Receipt, subject
from chatmaild.backup.store import Store
from chatmaild.tests.test_backup import (
    FakeSession,
    Response,
    flow,
    mailbox,
    portal,
    remote_metadata,
    signin,
)
from chatmaild.tests.test_backup_review import operator_setup


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state" / "archive.sqlite")


def environment(tmp_path, make_config, store):
    relay = make_config("example.org")
    root, box = mailbox(tmp_path, root=relay.mailboxes_dir)
    with Mailbox(root, box.name) as source:
        incarnation = source.ensure_marker()
    b = store.bind(
        subject("accounts.google.com", "one"), box.name, incarnation=incarnation
    )
    assert store.consent(
        b.id,
        b.owner,
        b.generation,
        "principal-one",
        "credential-A",
        "key-one",
        "age1synthetic",
        "folder-one",
        expected_ref=None,
    )
    b = store.get(b.id)
    spool = tmp_path / "spool"
    spool.mkdir(mode=0o700)
    config = {"chatmail_ini": str(relay._inipath), "spool": str(spool)}
    return store.get(b.id), root, spool, config


def renew(store, b, reference):
    assert store.consent(
        b.id,
        b.owner,
        b.generation,
        b.permission_id,
        reference,
        b.key_ref,
        b.recipient,
        b.folder_id,
        expected_ref=b.credential_ref,
    )
    return store.get(b.id)


def prepared(store, b, spool, *, cursor=7, file_id=True, resolved=()):
    job = store.enqueue(b.id)
    store.start_attempt(job)
    store.capture_start(job, credential_ref=b.credential_ref)
    payload = b"synthetic-ciphertext-" + job.encode()
    (spool / (job + ".age")).write_bytes(payload)
    fields = {
        "spool": job + ".age",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "message_ids": json.dumps(["content-" + job]),
        "capture_cursor": cursor,
        "capture_resolved": json.dumps(list(resolved)),
    }
    if file_id:
        fields["file_id"] = "remote-" + job
    store.update_job(job, "prepared", **fields)
    return job, payload


def start(target):
    errors = []

    def run():
        try:
            target()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    return thread, errors


def finish(thread, errors):
    thread.join(10)
    assert not thread.is_alive()
    assert not errors


def immutable(job):
    return tuple(
        job[key]
        for key in (
            "file_id",
            "spool",
            "sha256",
            "size",
            "message_ids",
            "key_ref",
            "recipient",
            "folder_id",
            "permission_id",
            "incarnation",
            "capture_revision",
            "capture_scan",
        )
    )


@pytest.mark.parametrize("first", ["worker", "verify"])
def test_cli_verify_worker_failure_and_retry_share_one_guard(
    tmp_path, make_config, store, monkeypatch, first
):
    b, root, spool, config = environment(tmp_path, make_config, store)
    job, payload = prepared(store, b, spool)
    pins = immutable(store.job(job))
    entered, release = threading.Event(), threading.Event()
    results = []
    credentials = SimpleNamespace(access=lambda _b: "synthetic")
    network = []

    class VerifyDrive:
        def __init__(self, _token, checkpoint):
            self.checkpoint = checkpoint

        def principal(self):
            return b.permission_id

        def verify(self, object_id, data):
            assert object_id == "remote-" + job and data == payload
            network.append(object_id)
            self.checkpoint()
            if first == "verify":
                entered.set()
                assert release.wait(10)
            return Receipt(object_id, len(data), hashlib.sha256(data).hexdigest())

    class FailingWorker(Worker):
        def _run(self, _job, _binding):
            raise ArchiveError("drive_transport", retryable=True, uncertain=True)

    original = store.fail

    def failed(*args, **kwargs):
        if first == "worker":
            entered.set()
            assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "fail", failed)
    monkeypatch.setattr(cli, "load", lambda _path: (config, store, credentials))
    monkeypatch.setattr(cli, "Drive", VerifyDrive)

    def verify_cli():
        results.append(
            cli.main(["--config", "/unused-synthetic-config", "verify", job])
        )

    worker = FailingWorker(store, credentials, root, spool)
    target = (lambda: worker.run(job)) if first == "worker" else verify_cli
    thread, errors = start(target)
    assert entered.wait(10)
    try:
        if first == "worker":
            verify_cli()
            assert results == [1] and not network
        else:
            worker.run(job)
        with pytest.raises(ArchiveError, match="operation_busy"):
            store.retry(job)
        assert immutable(store.job(job)) == pins
    finally:
        release.set()
    finish(thread, errors)
    if first == "worker":
        assert store.job(job)["state"] == "uncertain"
        verify_cli()
        assert results == [1, 0]
    else:
        assert results == [0]
    verified = store.job(job)
    assert verified["state"] == "verified" and immutable(verified) == pins
    assert (
        store.fail(
            job,
            ArchiveError("late_failure", retryable=True),
            credential_ref=b.credential_ref,
            max_attempts=8,
        )
        == "verified"
    )
    assert (
        store.update_job(job, "prepared", attempt=99, message_ids='["corrupt"]')
        is False
    )
    with pytest.raises(ArchiveError, match="job_already_verified"):
        store.retry(job)
    assert store.job(job) == verified and store.capture_cursor(b.id) == 7
    assert store.metrics()["events_job_verified"] == 1


def test_old_refresh_failure_cannot_pause_renewed_consent_and_reconciles_same_id(
    tmp_path, make_config, store
):
    b, root, spool, _config = environment(tmp_path, make_config, store)
    job, payload = prepared(store, b, spool)
    pins = immutable(store.job(job))
    entered, release = threading.Event(), threading.Event()
    observed = []

    def expired(binding):
        observed.append(binding.credential_ref)
        entered.set()
        assert release.wait(10)
        raise ArchiveError("reconnect")

    worker = Worker(store, SimpleNamespace(access=expired), root, spool)
    thread, errors = start(lambda: worker.run(job))
    assert entered.wait(10)
    fresh = renew(store, b, "credential-B")
    release.set()
    finish(thread, errors)
    assert observed == [b.credential_ref]
    assert store.get(b.id) == fresh and fresh.consent == "active"
    assert store.job(job)["state"] == "uncertain" and immutable(store.job(job)) == pins
    assert store.metrics()["events_stale_credential_outcome"] == 1
    fake = FakeSession(
        [
            Response(data={"user": {"permissionId": b.permission_id}}),
            Response(data=remote_metadata(payload)),
            Response(data=remote_metadata(payload)),
            Response(body=payload),
        ]
    )
    used = []

    def access(binding):
        used.append(binding.credential_ref)
        return "synthetic-B"

    Worker(
        store,
        SimpleNamespace(access=access),
        root,
        spool,
        drive_factory=lambda token, **kwargs: Drive(token, session=fake, **kwargs),
    ).run(job)
    assert used == [fresh.credential_ref]
    assert store.job(job)["state"] == "verified" and immutable(store.job(job)) == pins
    assert all(method == "GET" for method, _url, _kw in fake.calls)
    assert len(fake.calls) == 4 and store.seen(b.id) == {"content-" + job}


@pytest.mark.parametrize("action", ["optout", "retire", "operator-revoke"])
def test_inflight_uncertain_failure_cannot_undo_short_authority_transaction(
    tmp_path, make_config, store, action
):
    if action == "operator-revoke":
        _cfg, _path, b, root, _box = operator_setup(tmp_path, make_config, store)
        spool = tmp_path / "spool"
        spool.mkdir(mode=0o700)
    else:
        b, root, spool, _config = environment(tmp_path, make_config, store)
    job, _payload = prepared(store, b, spool)
    pins = immutable(store.job(job))
    entered, release = threading.Event(), threading.Event()

    class WorkerA(Worker):
        def _run(self, _job, _binding):
            entered.set()
            assert release.wait(10)
            raise ArchiveError("drive_transport", retryable=True, uncertain=True)

    thread, errors = start(lambda: WorkerA(store, None, root, spool).run(job))
    assert entered.wait(10)
    if action == "optout":
        store.optout(b.id, b.owner)
    elif action == "retire":
        store.invalidate_incarnation(b.id)
    else:
        store.revoke_operator(b.id)
    changed = store.get(b.id)
    release.set()
    finish(thread, errors)
    assert store.get(b.id) == changed and not changed.enabled
    assert store.job(job)["state"] == "paused" and immutable(store.job(job)) == pins
    assert not store.seen(b.id) and store.capture_cursor(b.id) == 0
    assert store.metrics()["events_stale_generation_outcome"] == 1


@pytest.mark.parametrize("action", ["consent", "optout", "retire", "operator-revoke"])
def test_verified_receipts_remain_terminal_under_all_binding_transitions(
    tmp_path, make_config, store, action
):
    if action == "operator-revoke":
        _cfg, _path, b, _root, _box = operator_setup(tmp_path, make_config, store)
        spool = tmp_path / "spool"
        spool.mkdir(mode=0o700)
    else:
        b, _root, spool, _config = environment(tmp_path, make_config, store)
    job, _payload = prepared(store, b, spool)
    with store.operation(b.id, job):
        assert store.verified(job, credential_ref=b.credential_ref)
    before = store.job(job)
    if action == "consent":
        renew(store, b, "credential-B")
    elif action == "optout":
        store.optout(b.id, b.owner)
    elif action == "retire":
        store.invalidate_incarnation(b.id)
    else:
        store.revoke_operator(b.id)
    assert store.job(job) == before
    assert not store.verified(job, credential_ref=None)
    assert (
        store.fail(job, ArchiveError("reconnect"), credential_ref=None, max_attempts=8)
        == "verified"
    )
    assert store.update_job(job, "failed", last_reason="late") == False
    assert store.job(job) == before and store.metrics()["events_job_verified"] == 1


def test_double_verify_and_late_first_verification_preserve_cursor_wrap_and_newer_issues(
    tmp_path, make_config, store
):
    b, _root, spool, _config = environment(tmp_path, make_config, store)
    old, _ = prepared(store, b, spool, cursor=3, file_id=False, resolved=["entry"])
    store.update_job(old, "failed")
    newer, _ = prepared(store, b, spool, cursor=9, resolved=[])
    store.record_unresolved(b.id, newer, [("entry", "newer_source_failure")])
    assert store.verified(newer, credential_ref=b.credential_ref)
    store.retry(old)
    store.update_job(old, "prepared", file_id="old-remote")
    assert store.verified(old, credential_ref=b.credential_ref)
    assert (
        store.capture_cursor(b.id) == 9
        and store.unresolved(b.id)[0][1] == "newer_source_failure"
    )
    wrap, _ = prepared(store, b, spool, cursor=0)
    assert store.verified(wrap, credential_ref=b.credential_ref)
    assert store.capture_cursor(b.id) == 0
    assert not store.verified(old, credential_ref=b.credential_ref)
    assert store.capture_cursor(b.id) == 0
    assert store.unresolved(b.id)[0][1] == "newer_source_failure"
    assert store.metrics()["events_job_verified"] == 3
    assert store.metrics()["events_stale_cursor_outcome"] == 1


def test_newer_unresolved_observation_survives_old_scan_even_with_same_cursor_revision(
    tmp_path, make_config, store
):
    b, _root, spool, _config = environment(tmp_path, make_config, store)
    old, _ = prepared(store, b, spool, cursor=3, file_id=False, resolved=["entry"])
    store.update_job(old, "failed")
    newer, _ = prepared(store, b, spool, cursor=9, resolved=[])
    store.record_unresolved(b.id, newer, [("entry", "newer_failure")])
    store.retry(old)
    store.update_job(old, "prepared", file_id="old-remote")
    assert store.verified(old, credential_ref=b.credential_ref)
    assert (
        store.capture_cursor(b.id) == 3
        and store.unresolved(b.id)[0][1] == "newer_failure"
    )
    store.record_unresolved(b.id, old, [("entry", "stale_failure")])
    assert store.unresolved(b.id)[0][1] == "newer_failure"
    assert store.metrics()["events_stale_source_outcome"] == 1


@pytest.mark.parametrize("baseline", [None, "existing"])
@pytest.mark.parametrize("outcome", ["declined", "missing", "success"])
def test_stale_oauth_outcomes_cannot_pause_or_replace_fresh_consent(
    store, baseline, outcome
):
    p = portal(store)
    one, two = signin(p), signin(p)
    b = store.bind(one["owner"], "owner@example.org")
    if baseline:
        p.callback(one, flow(p, one, "drive", b.id))
    old = flow(p, one, "drive", b.id)
    new = flow(p, two, "drive", b.id)
    p.callback(two, new)
    active = store.get(b.id)
    if outcome == "declined":
        old.pop("code")
        old["error"] = "access_denied"
    elif outcome == "missing":
        p.credentials.exchange = lambda *_args: {
            "id_token": "synthetic",
            "access_token": "synthetic",
            "scope": "openid",
        }
    if outcome == "success":
        with pytest.raises(ArchiveError, match="stale_credential_outcome"):
            p.callback(one, old)
    else:
        p.callback(one, old)
    assert store.get(b.id) == active and active.consent == "active"
    assert store.metrics()["events_stale_credential_outcome"] == 1
    if outcome == "success":
        assert store.metrics()["events_unused_credential_ref"] == 1


def test_credential_reference_cas_is_explicit_and_versions_cannot_be_reused(
    tmp_path, make_config, store
):
    b, _root, _spool, _config = environment(tmp_path, make_config, store)
    fresh = renew(store, b, "credential-B")
    assert not store.consent(
        b.id,
        b.owner,
        b.generation,
        b.permission_id,
        "credential-C",
        b.key_ref,
        b.recipient,
        b.folder_id,
        expected_ref=None,
    )
    assert store.get(b.id) == fresh
    with pytest.raises(ArchiveError, match="credential_ref_reused"):
        store.consent(
            b.id,
            b.owner,
            b.generation,
            b.permission_id,
            b.credential_ref,
            b.key_ref,
            b.recipient,
            b.folder_id,
            expected_ref=fresh.credential_ref,
        )
    assert store.get(b.id) == fresh


def test_private_state_owner_contract_for_cli_first_and_worker_first(
    tmp_path, make_config, store, monkeypatch
):
    b, root, spool, _config = environment(tmp_path, make_config, store)
    job = store.enqueue(b.id)
    path = store.operation_path(b.id)
    uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: uid + 1)
    with pytest.raises(ArchiveError, match="state_owner_mismatch"):
        Store(store.path)
    with pytest.raises(ArchiveError, match="state_owner_mismatch"):
        store.retry(job)
    assert not path.exists()
    monkeypatch.setattr(os, "geteuid", lambda: uid)
    store.retry(job)  # The CLI is the first legitimate lock creator.
    assert path.stat().st_uid == uid and path.stat().st_mode & 0o777 == 0o600
    worker = Worker(store, None, root, spool)
    with store.operation(b.id, job):
        worker.run(job)
        with pytest.raises(ArchiveError, match="operation_busy"):
            store.retry(job)
    assert store.job(job)["state"] == "queued"
    assert store.operations.stat().st_mode & 0o777 == 0o700


def test_v2_migration_preserves_history_but_invalidates_unprovable_drive_state(
    tmp_path, make_config, store
):
    b, _root, spool, _config = environment(tmp_path, make_config, store)
    job, _payload = prepared(store, b, spool, cursor=7, resolved=["entry"])
    pins = immutable(store.job(job))[:10]
    p = portal(store)
    drive_raw, drive_session = p.session()
    with store.connect() as db:
        db.execute(
            "UPDATE sessions SET owner=? WHERE id_hash=?",
            (b.owner, drive_session["id_hash"]),
        )
    drive_session = p.session(drive_raw)[1]
    flow(p, drive_session, "drive", b.id)
    login_raw, login_session = p.session()
    login = flow(p, login_session)
    with sqlite3.connect(store.path) as db:
        for column in ("attempt_credential_ref", "capture_revision", "capture_scan"):
            db.execute("ALTER TABLE jobs DROP COLUMN " + column)
        db.execute("ALTER TABLE sessions DROP COLUMN binding_credential_ref")
        db.execute("ALTER TABLE unresolved DROP COLUMN scan_revision")
        db.execute("UPDATE version SET number=2")
    migrated = Store(store.path)
    assert immutable(migrated.job(job))[:10] == pins
    assert migrated.job(job)["capture_revision"] is None
    assert migrated.job(job)["attempt_credential_ref"] is None
    assert (
        p.session(drive_raw)[1]["owner"] == b.owner
        and p.session(drive_raw)[1]["state_hash"] is None
    )
    p.callback(login_session, login)
    assert p.session(login_raw)[1]["owner"] == subject("accounts.google.com", "one")
    with migrated.connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO metadata VALUES(?,?)",
            ("capture_cursor:" + b.id, "21"),
        )
        db.execute(
            "INSERT OR REPLACE INTO metadata VALUES(?,?)",
            ("capture_revision:" + b.id, "4"),
        )
    migrated.start_attempt(job, verify=True)
    assert migrated.verified(job, credential_ref=b.credential_ref)
    assert migrated.capture_cursor(b.id) == 21
    assert migrated.metrics()["events_oauth_baseline_migration_invalidated"] == 1
