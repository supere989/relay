"""Offline archive contract tests: synthetic mail, keys and Google transports."""

import gzip
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import tarfile
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from chatmaild.backup import bundle
from chatmaild.backup.cli import operator_binding, quarantine_destination
from chatmaild.backup.credentials import Credentials, Wallet
from chatmaild.backup.drive import CHUNK, Drive
from chatmaild.backup.incarnation import Mailbox
from chatmaild.backup.jobs import Worker
from chatmaild.backup.model import DRIVE_SCOPE, ArchiveError, Message, Receipt, subject
from chatmaild.backup.sources import capture, legacy_manifest
from chatmaild.backup.store import Store
from chatmaild.backup.web import Portal, prove_existing


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state" / "archive.sqlite")


def binding(store, owner="one", mailbox="owner@example.org"):
    root = store.path.parent.parent / "mail"
    incarnation = None
    if (root / mailbox / "password").is_file():
        with Mailbox(root, mailbox) as source:
            incarnation = source.ensure_marker()
    b = store.bind(
        subject("https://accounts.google.com", owner), mailbox, incarnation=incarnation
    )
    store.consent(
        b.id,
        b.owner,
        b.generation,
        "principal-one",
        "ref-" + b.id,
        "key-one",
        "age1synthetic",
        "folder-one",
        expected_ref=b.credential_ref,
    )
    return store.get(b.id)


def mailbox(tmp_path, *, root=None):
    root = root if root is not None else tmp_path / "mail"
    box = root / "owner@example.org"
    for directory in ("cur", "new", "tmp"):
        (box / directory).mkdir(parents=True)
    (box / "cur" / "old:2,S").write_bytes(gzip.compress(b"old synthetic message"))
    (box / "new" / "fresh").write_bytes(b"new synthetic message")
    (box / "tmp" / "not-ready").write_bytes(b"ignore")
    (box / "password").write_bytes(b"SYNTHETIC_TEST_PASSWORD_VERIFIER")
    return root, box


def test_identity_and_ownership_are_not_email(store):
    b = store.bind(subject("accounts.google.com", "one"), "owner@example.org")
    assert b.enabled and b.consent == "pending" and b.permission_id is None
    assert subject("accounts.google.com", "one") == subject(
        "https://accounts.google.com", "one"
    )
    with pytest.raises(ArchiveError, match="mailbox_already_bound"):
        store.bind(subject("accounts.google.com", "two"), b.mailbox)
    with pytest.raises(ArchiveError, match="binding_denied"):
        store.get(b.id, owner=subject("accounts.google.com", "two"))
    with pytest.raises(ArchiveError, match="invalid_identity"):
        subject("https://attacker.invalid", "one")


def test_generation_optout_and_principal_are_immutable(store):
    b = binding(store)
    with pytest.raises(ArchiveError, match="drive_principal_changed"):
        store.consent(
            b.id,
            b.owner,
            b.generation,
            "different",
            "r",
            "k",
            "age1x",
            "f",
            expected_ref=b.credential_ref,
        )
    store.optout(b.id, b.owner)
    assert not store.get(b.id).enabled
    assert store.get(b.id).generation == b.generation + 1
    with pytest.raises(ArchiveError, match="binding_inactive"):
        store.active(b.id, b.generation)
    store.enable(b.id, b.owner)
    assert store.get(b.id).consent == "pending"
    assert not store.pause(
        b.id, "reconnect", generation=b.generation, expected_ref=b.credential_ref
    )
    assert store.get(b.id).consent == "pending"


def test_queue_bound_and_durable_retry(store):
    b = binding(store)
    job = store.enqueue(b.id, max_pending=1)
    assert store.enqueue(b.id, max_pending=1) == job
    other = binding(store, "two", "other@example.org")
    with pytest.raises(ArchiveError, match="queue_saturated"):
        store.enqueue(other.id, max_pending=1)
    reopened = Store(store.path)
    assert reopened.due() == [job]
    assert reopened.job(job)["state"] == "queued"


def test_capture_all_cur_new_and_incremental(tmp_path):
    root, box = mailbox(tmp_path)
    first = capture(root, box.name, "binding-one")
    assert {m.path for m in first} == {"cur/old:2,S", "new/fresh"}
    assert (
        gzip.decompress(next(m.data for m in first if m.path.startswith("cur/")))
        == b"old synthetic message"
    )
    (box / "new" / "later").write_bytes(b"later")
    later = capture(root, box.name, "binding-one", {m.id for m in first})
    assert [m.path for m in later] == ["new/later"]
    assert capture(root, box.name, "other-binding")[0].id != first[0].id


@pytest.mark.parametrize("target", ["../outside", "/absolute", "a/b"])
def test_capture_mailbox_confinement(tmp_path, target):
    with pytest.raises(ArchiveError):
        capture(tmp_path, target, "b")


def test_capture_rejects_links_and_bounds(tmp_path):
    root, box = mailbox(tmp_path)
    (box / "new" / "link").symlink_to(box / "cur" / "old:2,S")
    snapshot = capture(root, box.name, "b")
    assert any(reason == "source_unavailable" for _entry, reason in snapshot.unresolved)
    assert all(m.path != "new/link" for m in snapshot)
    (box / "new" / "link").unlink()
    first = capture(root, box.name, "b", max_files=1)
    assert len(first) == 1 and first.cursor == 1
    second = capture(root, box.name, "b", max_files=1, after=first.cursor)
    assert len(second) == 1 and second.cursor == 0 and second[0].id != first[0].id
    assert len(capture(root, box.name, "b", max_batch=1)) == 1


def test_changed_source_never_advances(tmp_path, monkeypatch):
    root, box = mailbox(tmp_path)
    original = os.read
    changed = False

    def read(fd, size):
        nonlocal changed
        data = original(fd, size)
        if data and not changed:
            changed = True
            with (box / "cur" / "old:2,S").open("ab") as stream:
                stream.write(b"raced")
        return data

    monkeypatch.setattr(os, "read", read)
    snapshot = capture(root, box.name, "b")
    assert any(reason == "source_changed" for _entry, reason in snapshot.unresolved)
    assert "cur/old:2,S" not in {m.path for m in snapshot}


def test_strict_legacy_subset():
    checksum = "a" * 64
    result = legacy_manifest(f"5\t{checksum}\tdomain/user/cur/msg\t/untrusted/absolute")
    assert result[0]["coverage"] == "legacy-selected-subset"
    assert "absolute" not in json.dumps(result)
    for path in ("../escape", "/absolute", "a/../b"):
        with pytest.raises(ArchiveError):
            legacy_manifest(f"5\t{checksum}\t{path}\t/ignored")
    with pytest.raises(ArchiveError):
        legacy_manifest("summary\tnot-a-manifest")


def age_key():
    if not shutil.which("age-keygen") or not shutil.which("age"):
        pytest.fail("genuine age executable required for archive acceptance")
    identity = subprocess.run(
        ["/usr/bin/age-keygen"], capture_output=True, check=True
    ).stdout.decode()
    recipient = next(
        line.split(": ", 1)[1]
        for line in identity.splitlines()
        if line.startswith("# public key: ")
    )
    return identity, recipient


def test_real_age_roundtrip_wrong_key_and_truncation(tmp_path):
    identity, recipient = age_key()
    wrong, _ = age_key()
    raw = gzip.compress(b"synthetic gzip payload")
    m = Message("cur/message", raw, hashlib.sha256(raw).hexdigest(), "id")
    encrypted = bundle.encrypt([m], recipient, "run")
    assert encrypted.startswith(b"age-encryption.org/v1\n")
    assert raw not in encrypted and b"manifest.json" not in encrypted
    target = tmp_path / "quarantine"
    result = bundle.restore(encrypted, identity, target)
    assert result["consistency"] == "capture-window-per-message"
    assert (target / "cur" / "message").read_bytes() == raw
    assert target.stat().st_mode & 0o777 == 0o700
    for payload, key in ((encrypted, wrong), (encrypted[:-10], identity)):
        rejected = tmp_path / "rejected"
        with pytest.raises(ArchiveError):
            bundle.restore(payload, key, rejected)
        assert not rejected.exists()
    with pytest.raises(ArchiveError, match="restore_requires_new_directory"):
        bundle.restore(encrypted, identity, target)


def test_all_folder_messages_real_age_restore_and_new_folder_incremental(tmp_path):
    root, box = mailbox(tmp_path)
    sent = box / ".Sent" / "cur"
    sent.mkdir(parents=True)
    # Dovecot COPY can legitimately share inodes. The destination path is a
    # distinct archived message even though its original bytes are identical.
    os.link(box / "cur" / "old:2,S", sent / "copied:2,S")
    nested = box / "Archive" / "2026" / "new"
    nested.mkdir(parents=True)
    (nested / "nested-message").write_bytes(b"nested synthetic message")
    (box / ".Sent" / "tmp").mkdir()
    (box / ".Sent" / "tmp" / "unfinished").write_bytes(b"not ready")
    first = capture(root, box.name, "binding")
    assert {m.path for m in first} == {
        "cur/old:2,S",
        "new/fresh",
        ".Sent/cur/copied:2,S",
        "Archive/2026/new/nested-message",
    }
    identity, recipient = age_key()
    ciphertext = bundle.encrypt(first, recipient, "folder-run")
    destination = tmp_path / "folder-quarantine"
    bundle.restore(ciphertext, identity, destination)
    for message in first:
        assert (destination / message.path).read_bytes() == message.data
    assert (destination / ".Sent").stat().st_mode & 0o777 == 0o700
    later = box / ".Archive.2027" / "new"
    later.mkdir(parents=True)
    (later / "arrived-later").write_bytes(b"new folder synthetic")
    incremental = capture(root, box.name, "binding", {m.id for m in first})
    assert [m.path for m in incremental] == [".Archive.2027/new/arrived-later"]
    second = tmp_path / "incremental-quarantine"
    bundle.restore(
        bundle.encrypt(incremental, recipient, "later-run"), identity, second
    )
    assert (
        second / ".Archive.2027" / "new" / "arrived-later"
    ).read_bytes() == b"new folder synthetic"


def test_folder_walk_rejects_links_and_depth(tmp_path):
    root, box = mailbox(tmp_path)
    (box / ".Escape").symlink_to(tmp_path, target_is_directory=True)
    snapshot = capture(root, box.name, "binding")
    assert any(
        reason == "source_folder_unavailable" for _entry, reason in snapshot.unresolved
    )
    (box / ".Escape").unlink()
    nested = box
    for _ in range(17):
        nested = nested / "folder"
        nested.mkdir()
    snapshot = capture(root, box.name, "binding")
    assert any(
        reason == "source_folder_limit" for _entry, reason in snapshot.unresolved
    )


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", "file"),
        ("/absolute", "file"),
        ("messages/new/link", "symlink"),
        ("messages/new/device", "device"),
    ],
)
def test_restore_rejects_malicious_tar(name, kind):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        item = tarfile.TarInfo(name)
        if kind == "symlink":
            item.type, item.linkname = tarfile.SYMTYPE, "/etc/passwd"
        elif kind == "device":
            item.type = tarfile.CHRTYPE
        tar.addfile(item, io.BytesIO(b""))
    with pytest.raises(ArchiveError):
        bundle.verify_clear(output.getvalue())


class MemoryBroker:
    def __init__(self):
        self.values = {}

    def put(self, value):
        ref = "ref-" + secrets.token_hex(16)
        self.values[ref] = value
        return ref

    def get(self, ref):
        return self.values[ref]

    def key(self):
        return {"ref": "key", "recipient": "age1synthetic"}


def test_credential_envelope_rejects_owner_and_generation_swaps(store):
    b = binding(store)
    broker = MemoryBroker()
    c = Credentials(broker, "client", "client-secret")
    tokens = {"scope": DRIVE_SCOPE, "refresh_token": "SYNTHETIC_REFRESH_DO_NOT_LOG"}
    ref = c.persist(b, b.permission_id, tokens)
    for changed in (
        replace(b, owner="different", credential_ref=ref),
        replace(b, generation=2, credential_ref=ref),
    ):
        with pytest.raises(ArchiveError, match="credential_binding_mismatch"):
            c.access(changed)
    with pytest.raises(ArchiveError, match="drive_consent_missing"):
        c.persist(b, b.permission_id, {"scope": "openid", "refresh_token": "synthetic"})
    assert b"SYNTHETIC_REFRESH" not in store.path.read_bytes()


def portal(store, config=None):
    broker = MemoryBroker()
    c = SimpleNamespace(
        client_id="client",
        broker=broker,
        exchange=lambda *_: {
            "id_token": "SYNTHETIC_ID",
            "access_token": "synthetic",
            "scope": DRIVE_SCOPE,
            "refresh_token": "synthetic",
        },
        persist=lambda *_: broker.put({"synthetic": True}),
    )
    drive = SimpleNamespace(
        principal=lambda: "principal-one", folder=lambda: "folder-one"
    )
    p = Portal(
        store,
        config,
        c,
        "https://archive.example.org",
        verify=lambda *_: subject("accounts.google.com", "one"),
        drive_factory=lambda *_: drive,
    )
    if config is None:
        # Pure OAuth state-machine tests have no filesystem. Separate tests
        # below exercise the real proof/incarnation seam with synthetic Maildirs.
        p.check_binding = lambda _binding: None
    return p


def flow(p, session, purpose="login", b=None):
    url = p.begin(session, purpose, b)
    state = parse_qs(urlsplit(url).query)["state"][0]
    return {"state": state, "code": "synthetic-code"}


def test_portal_csrf_state_nonce_replay_and_signin(store):
    p = portal(store)
    raw, s = p.session()
    csrf = p.csrf(s)
    _, s = p.session(raw)
    p.mutation(s, {"csrf": csrf})
    with pytest.raises(ArchiveError, match="csrf_denied"):
        p.mutation(s, {"csrf": "wrong"})
    query = flow(p, s)
    called = []
    p.verify = lambda token, audience, nonce: (
        called.append((audience, nonce)) or subject("accounts.google.com", "one")
    )
    with pytest.raises(ArchiveError, match="oauth_state_denied"):
        p.callback(s, {"state": "wrong", "code": "x"})
    p.callback(s, query)
    assert called[0][0] == "client" and len(called[0][1]) > 30
    assert p.session(raw)[1]["owner"] == subject("accounts.google.com", "one")
    with pytest.raises(ArchiveError, match="oauth_state_denied"):
        p.callback(s, query)


def signin(p):
    raw, s = p.session()
    p.callback(s, flow(p, s))
    return p.session(raw)[1]


def test_drive_decline_missing_grant_and_default_pending_leave_login(store):
    p = portal(store)
    s = signin(p)
    b = store.bind(s["owner"], "owner@example.org")
    assert b.enabled and b.consent == "pending"
    query = flow(p, s, "drive", b.id)
    query.pop("code")
    query["error"] = "access_denied"
    p.callback(s, query)
    assert store.get(b.id).consent == "declined"
    assert store.owned(s["owner"])
    p.credentials.exchange = lambda *_: {
        "id_token": "synthetic",
        "access_token": "synthetic",
        "scope": "openid",
    }
    p.callback(s, flow(p, s, "drive", b.id))
    assert store.get(b.id).consent == "pending"
    assert store.owned(s["owner"])


def test_drive_same_google_account_required_then_enqueues(store):
    p = portal(store)
    s = signin(p)
    b = store.bind(s["owner"], "owner@example.org")
    p.verify = lambda *_: subject("accounts.google.com", "two")
    with pytest.raises(ArchiveError, match="google_account_mismatch"):
        p.callback(s, flow(p, s, "drive", b.id))
    assert store.get(b.id).consent == "pending"
    p.verify = lambda *_: s["owner"]
    p.callback(s, flow(p, s, "drive", b.id))
    assert store.get(b.id).consent == "active" and len(store.due()) == 1


def test_unknown_mailbox_proof_never_provisions(tmp_path):
    class Config:
        mail_domain = "example.org"
        mailboxes_dir = tmp_path

        def get_user(self, address):
            return SimpleNamespace(get_password_hash=lambda: None)

    assert not prove_existing(Config(), "unknown@example.org", "not-created")
    assert list(tmp_path.iterdir()) == []


def test_operator_role_separate_os_authority_and_allowlist(store, make_config):
    relay = make_config("example.org")
    relay.get_user("selected@example.org").set_password("SYNTHETIC_VERIFIER")
    cfg = {
        "chatmail_ini": str(relay._inipath),
        "operator": {
            "uid": os.getuid(),
            "identity": "trusted-admin",
            "google_sub": "one",
            "mailboxes": ["selected@example.org"],
        },
    }
    for identity, mailbox_name in (
        ("ordinary-google-owner", "selected@example.org"),
        ("trusted-admin", "unselected@example.org"),
    ):
        with pytest.raises(ArchiveError, match="operator_authority_denied"):
            operator_binding(cfg, store, identity, mailbox_name)
    b = operator_binding(cfg, store, "trusted-admin", "selected@example.org")
    assert b.mode == "operator" and b.consent == "pending"
    with pytest.raises(ArchiveError, match="binding_denied"):
        portal(store).begin({"owner": b.owner, "id_hash": "synthetic"}, "drive", b.id)
    with pytest.raises(ArchiveError, match="binding_denied"):
        portal(store).personal_binding(b.id, b.owner)


def test_personal_and_operator_same_mailbox_are_isolated(store):
    personal = binding(store)
    operator = store.bind(
        subject("accounts.google.com", "operator"),
        personal.mailbox,
        mode="operator",
        allowlist=[personal.mailbox],
    )
    store.consent(
        operator.id,
        operator.owner,
        operator.generation,
        "operator-principal",
        "operator-ref",
        "operator-key",
        "age1operator",
        "operator-folder",
        expected_ref=operator.credential_ref,
    )
    operator = store.get(operator.id)
    assert (
        operator.id != personal.id
        and operator.credential_ref != personal.credential_ref
    )
    job = store.enqueue(personal.id)
    store.update_job(job, "prepared", message_ids='["personal-message"]')
    store.start_attempt(job, verify=True)
    store.verified(job, credential_ref=personal.credential_ref)
    assert store.seen(personal.id) == {"personal-message"}
    assert not store.seen(operator.id)
    store.optout(personal.id, personal.owner)
    assert store.active(operator.id, operator.generation).enabled


def test_delayed_consent_cannot_reactivate_after_optout(store):
    p = portal(store)
    session_a, session_b = signin(p), signin(p)
    b = store.bind(session_a["owner"], "owner@example.org")
    delayed = flow(p, session_a, "drive", b.id)
    store.optout(b.id, session_b["owner"])
    store.enable(b.id, session_b["owner"])
    p.callback(session_b, flow(p, session_b, "drive", b.id))
    active = store.get(b.id)
    with pytest.raises(ArchiveError, match="stale_generation"):
        p.callback(session_a, delayed)
    assert store.get(b.id) == active


def test_reconcile_pages_durably_without_starving_owner_129(
    tmp_path, store, monkeypatch
):
    ids = {binding(store, str(i), f"owner-{i}@example.org").id for i in range(130)}
    visited = []
    monkeypatch.setattr(store, "enqueue", visited.append)
    worker = Worker(store, None, tmp_path, tmp_path / "spool")
    worker.reconcile()
    assert len(visited) == 128
    # A fresh worker uses the durable cursor, not process-local ordering.
    Worker(store, None, tmp_path, tmp_path / "spool").reconcile()
    assert set(visited) == ids


def test_sqlite_connections_close_after_context(store):
    import sqlite3

    with store.connect() as db:
        assert db.execute("SELECT 1").fetchone() == (1,)
    with pytest.raises(sqlite3.ProgrammingError):
        db.execute("SELECT 1")


def test_default_google_verifier_checks_nonce_expiry_issuer(monkeypatch):
    import time

    from google.oauth2 import id_token

    from chatmaild.backup.web import verify_google

    claims = {
        "iss": "https://accounts.google.com",
        "sub": "one",
        "exp": time.time() + 60,
        "nonce": "expected",
    }
    monkeypatch.setattr(
        id_token, "verify_oauth2_token", lambda *_args, **_kwargs: claims
    )
    assert verify_google("synthetic", "client", "expected") == subject(
        claims["iss"], claims["sub"]
    )
    with pytest.raises(ArchiveError, match="invalid_identity"):
        verify_google("synthetic", "client", "wrong")
    claims["exp"] = 0
    with pytest.raises(ArchiveError, match="invalid_identity"):
        verify_google("synthetic", "client", "expected")


def test_oidc_certificate_fetch_has_explicit_timeout(monkeypatch):
    import time

    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    from chatmaild.backup.web import verify_google

    observed = []

    def request(*_args, **kwargs):
        observed.append(kwargs["timeout"])
        return None

    monkeypatch.setattr(google_requests, "Request", lambda: request)

    def verified(_token, transport, **_kwargs):
        transport("https://synthetic.invalid/certs", timeout=999)
        return {
            "iss": "https://accounts.google.com",
            "sub": "one",
            "exp": time.time() + 60,
            "nonce": "nonce",
        }

    monkeypatch.setattr(id_token, "verify_oauth2_token", verified)
    verify_google("synthetic", "client", "nonce")
    assert observed == [20]


def test_oauth_transaction_expires_before_session(store):
    p = portal(store)
    raw, s = p.session()
    query = flow(p, s)
    with store.connect() as db:
        db.execute(
            "UPDATE sessions SET oauth_expires=0 WHERE id_hash=?", (s["id_hash"],)
        )
    with pytest.raises(ArchiveError, match="oauth_transaction_expired"):
        p.callback(s, query)
    assert p.session(raw)[1]["owner"] is None


def test_mailbox_proof_rejects_foreign_or_noncanonical_domain():
    def forbidden(_address):
        pytest.fail("foreign mailbox must not be read")

    config = SimpleNamespace(mail_domain="example.org", get_user=forbidden)
    for address in (
        "person@foreign.org",
        "person@EXAMPLE.ORG",
        "../person@example.org",
        "person@example.org@evil.org",
    ):
        assert not prove_existing(config, address, "synthetic")


def test_broker_put_uses_stdin_and_verifies_without_secret_argv(monkeypatch):
    calls = []

    def run(argv, data=None):
        calls.append((argv, data))
        return b""

    monkeypatch.setattr(Wallet, "_run", staticmethod(run))
    Wallet().call(
        "put", ref="archive-synthetic", value={"refresh_token": "SYNTHETIC_ONLY"}
    )
    assert len(calls) == 2 and "--stdin" in calls[0][0] and "verify" in calls[1][0]
    assert "SYNTHETIC_ONLY" not in repr([argv for argv, _data in calls])
    assert b"SYNTHETIC_ONLY" in calls[0][1]


def test_restore_cli_is_confined_to_private_quarantine(tmp_path):
    root = tmp_path / "quarantine"
    root.mkdir(mode=0o700)
    live = tmp_path / "mail"
    live.mkdir()
    cfg = {"database": str(tmp_path / "state.sqlite"), "quarantine_root": str(root)}
    relay = SimpleNamespace(mailboxes_dir=live)
    assert quarantine_destination(cfg, relay, str(root / "run")) == root / "run"
    for destination in (live / "new-owner", tmp_path / "outside", root):
        with pytest.raises(ArchiveError):
            quarantine_destination(cfg, relay, str(destination))


def test_conflict_not_visible_is_uncertain():
    fake = FakeSession([Response(404), Response(409), Response(404)])
    with pytest.raises(ArchiveError, match="drive_commit_not_visible") as error:
        Drive("synthetic", session=fake).upload(
            "same-id", "folder", b"ciphertext", "run"
        )
    assert error.value.uncertain and error.value.retryable


def test_exhausted_job_never_replaced_with_new_drive_id(store):
    b = binding(store)
    job = store.enqueue(b.id)
    store.update_job(
        job, "failed", file_id="fixed-drive-id", spool=job + ".age", attempt=8
    )
    assert store.enqueue(b.id) == job
    assert store.due() == []
    store.retry(job)
    assert store.job(job)["file_id"] == "fixed-drive-id"
    assert store.job(job)["attempt"] == 0 and store.due() == [job]
    store.update_job(job, "paused")
    store.pause(
        b.id, "reconnect", generation=b.generation, expected_ref=b.credential_ref
    )
    store.consent(
        b.id,
        b.owner,
        b.generation,
        b.permission_id,
        "new-ref",
        b.key_ref,
        b.recipient,
        b.folder_id,
        expected_ref=b.credential_ref,
    )
    assert store.enqueue(b.id) == job and store.job(job)["file_id"] == "fixed-drive-id"


def test_commit_is_recorded_before_download_verification():
    payload = b"ciphertext"
    fake = FakeSession(
        [
            Response(404),
            Response(headers={"Location": "https://www.googleapis.com/upload/session"}),
            Response(200),
            Response(data=remote_metadata(payload)),
            Response(body=b"wrong"),
        ]
    )
    drive = Drive("synthetic", session=fake)
    committed = []
    drive.on_commit = lambda: committed.append(True)
    with pytest.raises(ArchiveError, match="drive_checksum_mismatch"):
        drive.upload("file", "folder", payload, "run")
    assert committed == [True]


def test_post_commit_permission_failure_keeps_uncertain_job(tmp_path, store):
    root, _box = mailbox(tmp_path)
    b = binding(store)

    class FakeDrive:
        def __init__(self, *_args, **_kwargs):
            pass

        def principal(self):
            return b.permission_id

        def allocate(self):
            return "fixed-drive-id"

        def upload(self, *_args):
            self.on_commit()
            raise ArchiveError("drive_403_denied")

    worker = Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        drive_factory=FakeDrive,
        encrypt=lambda *_: b"ciphertext",
        max_attempts=1,
    )
    job = store.enqueue(b.id)
    worker.run(job)
    assert store.job(job)["state"] == "failed"
    assert store.enqueue(b.id) == job and not store.seen(b.id)


def test_worker_stop_and_retry_budget_are_bounded(tmp_path, store):
    import threading

    b = binding(store)
    worker = Worker(store, None, tmp_path, tmp_path / "spool", max_attempts=2)
    worker.stop = threading.Event()
    worker.stop.set()
    with pytest.raises(ArchiveError, match="worker_shutdown"):
        worker.checkpoint(b.id, b.generation)
    job = store.enqueue(b.id)
    error = ArchiveError("drive_http_503", retryable=True, uncertain=True)
    with store.operation(b.id, job):
        store.start_attempt(job)
        worker._failed(store.job(job), error, credential_ref=b.credential_ref)
        assert store.job(job)["state"] == "uncertain"
        store.start_attempt(job)
        worker._failed(store.job(job), error, credential_ref=b.credential_ref)
    assert store.job(job)["state"] == "failed" and store.job(job)["attempt"] == 2


def test_worker_lock_stalls_are_ledgered(tmp_path, store):
    b = binding(store)
    worker = Worker(store, None, tmp_path, tmp_path / "spool")
    job = store.enqueue(b.id)
    with store.operation(b.id, job):
        worker.run(job)
    assert store.job(job)["state"] == "queued"
    assert store.metrics()["events_worker_lock_stall"] == 1


def test_capture_cursor_advances_only_with_verified_receipt(
    tmp_path, store, monkeypatch
):
    from functools import partial

    from chatmaild.backup import jobs

    root, box = mailbox(tmp_path)
    b = binding(store)
    monkeypatch.setattr(jobs, "capture", partial(capture, max_files=1, max_batch=1))
    fail = [True]

    class FakeDrive:
        def __init__(self, *_args, **_kwargs):
            pass

        def principal(self):
            return b.permission_id

        def allocate(self):
            return "file-one"

        def upload(self, object_id, _folder, data, _run):
            if fail[0]:
                raise ArchiveError("drive_transport", retryable=True, uncertain=True)
            return Receipt(object_id, len(data), hashlib.sha256(data).hexdigest())

    worker = Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        drive_factory=FakeDrive,
        encrypt=lambda *_: b"ciphertext",
    )
    job = store.enqueue(b.id)
    worker.run(job)
    assert store.capture_cursor(b.id) == 0 and not store.seen(b.id)
    fail[0] = False
    # Recovery uses the durable prepared ciphertext, not a fresh source capture.
    worker.run(job)
    assert store.capture_cursor(b.id) == 1 and len(store.seen(b.id)) == 1
    second = store.enqueue(b.id)
    worker.run(second)
    assert store.capture_cursor(b.id) == 0 and len(store.seen(b.id)) == 2
    assert (box / "new" / "fresh").exists()


def test_http_portal_secure_cookie_csrf_bounds_and_no_code_logs(store, caplog):
    import threading
    from http.client import HTTPConnection
    from http.cookies import SimpleCookie

    from chatmaild.backup.web import Server

    p = portal(store)
    server = Server(("127.0.0.1", 0), p, workers=2)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()

    def request(method, path, body=None, headers=None):
        conn = HTTPConnection(*server.server_address, timeout=3)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    try:
        status, headers, _ = request("GET", "/archive/")
        assert status == 200 and "no-store" in headers["Cache-Control"]
        cookie = headers["Set-Cookie"]
        assert all(
            flag in cookie for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/")
        )
        parsed = SimpleCookie(cookie)
        raw = next(iter(parsed.values())).value
        _, session = p.session(raw)
        cookie_header = {
            "Cookie": cookie.split(";", 1)[0],
            "Content-Type": "application/x-www-form-urlencoded",
        }
        status, _, _ = request("POST", "/archive/login", "csrf=invalid", cookie_header)
        assert status == 400
        status, _, _ = request("POST", "/archive/login", "x" * 4097, cookie_header)
        assert status == 400
        status, _, _ = request(
            "GET",
            "/archive/callback?state=wrong&code=SYNTHETIC_CODE_DO_NOT_LOG",
            headers=cookie_header,
        )
        assert status == 400
        assert "SYNTHETIC_CODE_DO_NOT_LOG" not in caplog.text
        assert raw.encode() not in store.path.read_bytes()
        assert session["owner"] is None
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_empty_capture_optout_does_not_verify_stale_job(tmp_path, store, monkeypatch):
    from chatmaild.backup import jobs

    root, _box = mailbox(tmp_path)
    b = binding(store)
    job = store.enqueue(b.id)

    def cancelled(*_args, **_kwargs):
        store.optout(b.id, b.owner)
        return []

    monkeypatch.setattr(jobs, "capture", cancelled)
    drive = lambda *_args, **_kwargs: SimpleNamespace(principal=lambda: b.permission_id)
    worker = Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        drive_factory=drive,
    )
    worker.run(job)
    assert store.job(job)["state"] == "paused" and not store.seen(b.id)


class Response:
    def __init__(self, status=200, data=None, headers=None, body=b""):
        self.status_code, self.data, self.headers, self.body = (
            status,
            data,
            headers or {},
            body,
        )

    def json(self):
        return self.data

    def iter_content(self, size):
        for offset in range(0, len(self.body), size):
            yield self.body[offset : offset + size]

    def close(self):
        pass


class FakeSession:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def remote_metadata(payload):
    return {
        "size": str(len(payload)),
        "md5Checksum": hashlib.md5(payload).hexdigest(),
        "appProperties": {"sha256": hashlib.sha256(payload).hexdigest()},
    }


def test_drive_resumable_308_and_verified_download():
    payload = b"a" * (CHUNK + 3)
    fake = FakeSession(
        [
            Response(404),
            Response(headers={"Location": "https://www.googleapis.com/upload/session"}),
            Response(308, headers={"Range": f"bytes=0-{CHUNK - 1}"}),
            Response(200),
            Response(data=remote_metadata(payload)),
            Response(body=payload),
        ]
    )
    receipt = Drive("synthetic", session=fake).upload(
        "file-one", "folder-one", payload, "run"
    )
    assert receipt.size == len(payload)
    chunks = [
        kw["headers"]["Content-Range"]
        for method, _, kw in fake.calls
        if method == "PUT"
    ]
    assert chunks == [
        f"bytes 0-{CHUNK - 1}/{len(payload)}",
        f"bytes {CHUNK}-{CHUNK + 2}/{len(payload)}",
    ]


def test_drive_uncertain_commit_and_conflict_reconcile_same_id():
    payload = b"ciphertext"
    initial = FakeSession(
        [
            Response(404),
            Response(headers={"Location": "https://www.googleapis.com/upload/session"}),
            requests.Timeout(),
        ]
    )
    with pytest.raises(ArchiveError) as error:
        Drive("synthetic", session=initial).upload("same-id", "folder", payload, "run")
    assert error.value.uncertain
    retry = FakeSession(
        [
            Response(404),
            Response(409),
            Response(data=remote_metadata(payload)),
            Response(body=payload),
        ]
    )
    assert (
        Drive("synthetic", session=retry)
        .upload("same-id", "folder", payload, "run")
        .file_id
        == "same-id"
    )


@pytest.mark.parametrize(
    "response,reason",
    [
        (Response(308, headers={"Range": "bytes=0-9999"}), "upload_range_mismatch"),
        (Response(410), "upload_session_expired"),
        (Response(401), "reconnect"),
        (
            Response(
                403, data={"error": {"errors": [{"reason": "storageQuotaExceeded"}]}}
            ),
            "drive_403_storageQuotaExceeded",
        ),
        (Response(429), "drive_http_429"),
    ],
)
def test_drive_failures_are_explicit(response, reason):
    fake = FakeSession(
        [
            Response(404),
            Response(headers={"Location": "https://www.googleapis.com/upload/session"}),
            response,
        ]
    )
    with pytest.raises(ArchiveError, match=reason):
        Drive("synthetic", session=fake).upload("file", "folder", b"ciphertext", "run")


def test_drive_checksum_mismatch_and_host_confinement():
    fake = FakeSession(
        [Response(data=remote_metadata(b"ciphertext")), Response(body=b"wrong")]
    )
    with pytest.raises(ArchiveError, match="drive_checksum_mismatch"):
        Drive("synthetic", session=fake).verify("file", b"ciphertext")
    fake = FakeSession(
        [
            Response(404),
            Response(headers={"Location": "https://attacker.invalid/session"}),
        ]
    )
    with pytest.raises(ArchiveError, match="unsafe_upload_uri"):
        Drive("synthetic", session=fake).upload("file", "folder", b"ciphertext", "run")


def test_worker_initial_incremental_receipts_and_optout(tmp_path, store):
    root, box = mailbox(tmp_path)
    b = binding(store)
    calls = []

    class FakeDrive:
        def __init__(self, token, checkpoint):
            self.checkpoint = checkpoint

        def principal(self):
            return "principal-one"

        def allocate(self):
            return "file-" + str(len(calls))

        def upload(self, object_id, folder, data, run):
            self.checkpoint()
            calls.append(object_id)
            return Receipt(object_id, len(data), hashlib.sha256(data).hexdigest())

    worker = Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        drive_factory=FakeDrive,
        encrypt=lambda *_: b"synthetic-ciphertext",
    )
    job = store.enqueue(b.id)
    worker.run(job)
    assert store.job(job)["state"] == "verified" and len(store.seen(b.id)) == 2
    assert (
        b"old synthetic message"
        not in (tmp_path / "spool" / (job + ".age")).read_bytes()
    )
    (box / "new" / "later").write_bytes(b"later")
    later = store.enqueue(b.id)
    worker.run(later)
    assert len(store.seen(b.id)) == 3 and len(calls) == 2
    pending = store.enqueue(b.id)
    store.optout(b.id, b.owner)
    worker.run(pending)
    assert store.job(pending)["state"] == "paused" and len(calls) == 2
    assert (box / "cur" / "old:2,S").exists()


def test_worker_retries_bounded_and_revoke_pauses(tmp_path, store):
    root, _box = mailbox(tmp_path)
    b = binding(store)

    def unavailable(_binding):
        raise ArchiveError("reconnect")

    worker = Worker(
        store, SimpleNamespace(access=unavailable), root, tmp_path / "spool"
    )
    job = store.enqueue(b.id)
    worker.run(job)
    assert (
        store.job(job)["state"] == "paused" and store.get(b.id).consent == "reconnect"
    )
    assert store.metrics()["events_reconnect"] >= 1


def test_metrics_reuse_fsreport_surface(tmp_path, store):
    from chatmaild.fsreport import Report

    store.event("worker_lock_stall", amount=3)
    report = Report(0, 0, None, archive_metrics=store.metrics())
    path = tmp_path / "metrics.prom"
    report.dump_textfile(path)
    text = path.read_text()
    assert "chatmail_archive_events_worker_lock_stall 3" in text
    assert "@" not in text and "credential" not in text
