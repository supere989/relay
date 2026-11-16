"""Adversarial reproductions for mailbox authority and archive recovery."""

import io
import json
import os
import tarfile
import threading
from functools import partial
from types import SimpleNamespace

import pytest

from chatmaild.backup import bundle, jobs
from chatmaild.backup.cli import main, operator_binding, read_policy
from chatmaild.backup.drive import CHUNK, Drive
from chatmaild.backup.incarnation import MARKER, Mailbox
from chatmaild.backup.jobs import Worker
from chatmaild.backup.model import ArchiveError, Receipt, subject
from chatmaild.backup.sources import capture
from chatmaild.backup.store import Store
from chatmaild.backup.web import Server
from chatmaild.doveauth import encrypt_password
from chatmaild.tests.test_backup import (
    FakeSession,
    Response,
    age_key,
    binding,
    flow,
    mailbox,
    portal,
    signin,
)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state" / "archive.sqlite")


def owner_portal(tmp_path, make_config, store):
    relay = make_config("example.org")
    root, box = mailbox(tmp_path, root=relay.mailboxes_dir)
    relay.get_user(box.name).set_password(encrypt_password("old-synthetic-proof"))
    p = portal(store, relay)
    session = signin(p)
    b = p.link(session, {"mailbox": box.name, "password": "old-synthetic-proof"})
    return p, session, b, root, box


def activate(store, b):
    store.consent(
        b.id,
        b.owner,
        b.generation,
        "principal-one",
        "credential",
        "key",
        "age1synthetic",
        "folder",
        expected_ref=b.credential_ref,
    )
    return store.get(b.id)


def recreate(relay, box, old_location):
    box.rename(old_location)
    (box / "cur").mkdir(parents=True)
    (box / "new").mkdir()
    relay.get_user(box.name).set_password(encrypt_password("new-synthetic-proof"))
    (box / "new" / "new-owner-private").write_bytes(b"NEW_OWNER_PRIVATE_BODY")


def test_address_recreation_invalidates_old_owner_and_retains_history(
    tmp_path, make_config, store
):
    p, session, b, root, box = owner_portal(tmp_path, make_config, store)
    b = activate(store, b)
    job = store.enqueue(b.id)
    old_key = b.key_ref
    assert (box / MARKER).is_file()
    recreate(p.config, box, tmp_path / "old-mailbox")
    calls = []
    worker = Worker(
        store,
        SimpleNamespace(access=lambda _: calls.append("credential")),
        root,
        tmp_path / "spool",
    )
    worker.run(job)
    old = store.get(b.id)
    assert (
        old.retired
        and not old.enabled
        and old.owner == b.owner
        and old.key_ref == old_key
    )
    assert store.job(job)["state"] == "paused" and not calls
    assert not (box / MARKER).exists()  # Workers never create or repair markers.
    with pytest.raises(ArchiveError):
        p.begin(session, "drive", b.id)
    with pytest.raises(ArchiveError):
        store.enable(b.id, b.owner)
    p.verify = lambda *_: subject("accounts.google.com", "two")
    second_session = signin(p)
    fresh = p.link(
        second_session, {"mailbox": box.name, "password": "new-synthetic-proof"}
    )
    assert fresh.id != b.id and fresh.owner != b.owner and fresh.consent == "pending"
    assert store.get(b.id).key_ref == old_key
    with pytest.raises(ArchiveError, match="binding_denied"):
        store.get(b.id, owner=fresh.owner)
    with pytest.raises(ArchiveError, match="binding_denied"):
        store.get(fresh.id, owner=b.owner)


def test_normal_timestamp_and_folder_creation_preserve_incarnation(
    tmp_path, make_config, store
):
    p, _session, b, root, box = owner_portal(tmp_path, make_config, store)
    os.utime(box / "password", (0, 0))
    (box / ".Sent" / "new").mkdir(parents=True)
    (box / ".Sent" / "new" / "message").write_bytes(b"synthetic")
    (box / "dovecot-index").write_bytes(b"normal control")
    p.check_binding(b)
    with Mailbox(root, box.name) as source:
        source.check(b.incarnation)
    verifier = p.config.get_user(box.name).get_password_hash().encode()
    assert verifier not in store.path.read_bytes()


@pytest.mark.parametrize("change", ["password", "marker"])
def test_password_rotation_or_marker_loss_requires_fresh_proof(
    tmp_path, make_config, store, change
):
    p, session, b, _root, box = owner_portal(tmp_path, make_config, store)
    if change == "password":
        p.config.get_user(box.name).set_password(
            encrypt_password("rotated-synthetic-proof")
        )
    else:
        (box / MARKER).unlink()
    with pytest.raises(ArchiveError, match="mailbox_incarnation_changed"):
        p.begin(session, "drive", b.id)
    assert store.get(b.id).retired
    fresh = p.link(
        session,
        {
            "mailbox": box.name,
            "password": "rotated-synthetic-proof"
            if change == "password"
            else "old-synthetic-proof",
        },
    )
    assert fresh.id != b.id and fresh.incarnation != b.incarnation


def test_swap_between_password_proof_and_marker_bind_is_rejected(
    tmp_path, make_config, store, monkeypatch
):
    relay = make_config("example.org")
    root, box = mailbox(tmp_path, root=relay.mailboxes_dir)
    relay.get_user(box.name).set_password(encrypt_password("old-synthetic-proof"))
    p = portal(store, relay)
    session = signin(p)
    original = Mailbox.ensure_marker

    def swapped(source):
        result = original(source)
        recreate(relay, box, tmp_path / "retired-during-proof")
        return result

    monkeypatch.setattr(Mailbox, "ensure_marker", swapped)
    with pytest.raises(ArchiveError, match="mailbox_incarnation_changed"):
        p.link(session, {"mailbox": box.name, "password": "old-synthetic-proof"})
    assert not store.owned(session["owner"]) and not (box / MARKER).exists()


def test_held_capture_fd_rejects_namespace_swap_before_upload(
    tmp_path, make_config, store, monkeypatch
):
    p, _session, b, root, box = owner_portal(tmp_path, make_config, store)
    b = activate(store, b)
    job = store.enqueue(b.id)
    original = os.read
    swapped = []
    read_bytes = []

    def raced(fd, size):
        data = original(fd, size)
        read_bytes.append(data)
        if data and not swapped:
            swapped.append(True)
            recreate(p.config, box, tmp_path / "retired-during-read")
        return data

    monkeypatch.setattr(os, "read", raced)
    uploads = []

    class FakeDrive:
        def __init__(self, *_args, **_kwargs):
            pass

        def principal(self):
            return "principal-one"

        def upload(self, *_args):
            uploads.append(True)

    Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        drive_factory=FakeDrive,
    ).run(job)
    assert store.get(b.id).retired and not uploads
    assert swapped
    assert b"NEW_OWNER_PRIVATE_BODY" not in b"".join(read_bytes)


def test_two_consent_callbacks_keep_first_destination_and_pinned_recovery(
    tmp_path, make_config, store
):
    p, session_a, b, root, _box = owner_portal(tmp_path, make_config, store)
    session_b = signin(p)
    query_a, query_b = (
        flow(p, session_a, "drive", b.id),
        flow(p, session_b, "drive", b.id),
    )
    identities = {}
    recipients = {}
    for name in ("consent-A", "consent-B"):
        identities[name], recipients[name] = age_key()
    barrier = threading.Barrier(2)
    finished = threading.Event()
    uploads = []
    failures = []

    def key():
        name = threading.current_thread().name
        barrier.wait(timeout=5)
        return {"ref": "key-" + name, "recipient": recipients[name]}

    p.credentials.broker.key = key
    p.credentials.persist = lambda *_args: (
        "credential-" + threading.current_thread().name
    )

    class ConsentDrive:
        def __init__(self, *_args):
            pass

        def principal(self):
            return "principal-one"

        def folder(self):
            return "folder-" + threading.current_thread().name

    class UploadDrive:
        def __init__(self, *_args, **kwargs):
            self.checkpoint = kwargs["checkpoint"]

        def principal(self):
            return "principal-one"

        def allocate(self):
            return "file-one"

        def upload(self, object_id, folder, payload, _run):
            import hashlib

            self.checkpoint()
            uploads.append((folder, payload))
            return Receipt(object_id, len(payload), hashlib.sha256(payload).hexdigest())

    p.drive_factory = ConsentDrive
    original = store.consent

    def interleaved(*args, **kwargs):
        if threading.current_thread().name == "consent-B":
            assert finished.wait(10)
            return original(*args, **kwargs)
        result = original(*args, **kwargs)
        job = store.enqueue(b.id)
        Worker(
            store,
            SimpleNamespace(access=lambda _: "synthetic"),
            root,
            tmp_path / "spool",
            drive_factory=UploadDrive,
        ).run(job)
        finished.set()
        return result

    store.consent = interleaved

    def callback(session, query):
        try:
            p.callback(session, query)
        except ArchiveError as exc:
            failures.append(exc.reason)

    threads = [
        threading.Thread(name=name, target=callback, args=args)
        for name, args in (
            ("consent-A", (session_a, query_a)),
            ("consent-B", (session_b, query_b)),
        )
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(15)
        assert not thread.is_alive()
    assert failures == ["destination_initialization_conflict"]
    active = store.get(b.id)
    assert active.key_ref == "key-consent-A" and active.folder_id == "folder-consent-A"
    with store.connect() as db:
        job_id = db.execute("SELECT id FROM jobs WHERE state='verified'").fetchone()[0]
    receipt = store.job(job_id)
    assert (receipt["key_ref"], receipt["recipient"], receipt["folder_id"]) == (
        active.key_ref,
        active.recipient,
        active.folder_id,
    )
    assert uploads[0][0] == active.folder_id
    with store.connect() as db:
        unused = set(
            db.execute("SELECT kind,reference FROM artifacts WHERE state='unused'")
        )
    assert unused == {
        ("credential_ref", "credential-consent-B"),
        ("key_ref", "key-consent-B"),
        ("drive_folder", "folder-consent-B"),
    }
    assert store.metrics()["events_unused_key_ref"] == 1
    assert store.metrics()["events_unused_drive_folder"] == 1
    assert (
        len(
            bundle.verify_clear(bundle.decrypt(uploads[0][1], identities["consent-A"]))[
                1
            ]
        )
        == 2
    )
    with pytest.raises(ArchiveError):
        bundle.decrypt(uploads[0][1], identities["consent-B"])


def test_uncertain_folder_creation_ledgers_unused_wallet_candidates(store):
    p = portal(store)
    session = signin(p)
    b = store.bind(session["owner"], "owner@example.org")

    def folder():
        raise ArchiveError("drive_transport", retryable=True, uncertain=True)

    p.drive_factory = lambda *_args: SimpleNamespace(
        principal=lambda: "principal-one", folder=folder
    )
    with pytest.raises(ArchiveError, match="drive_transport"):
        p.callback(session, flow(p, session, "drive", b.id))
    assert store.get(b.id).key_ref is None
    assert store.metrics()["events_drive_folder_creation_uncertain"] == 1
    assert store.metrics()["artifacts_unused"] == 2


def operator_setup(tmp_path, make_config, store):
    relay = make_config("example.org")
    root, box = mailbox(tmp_path, root=relay.mailboxes_dir)
    cfg = {
        "database": str(store.path),
        "spool": str(tmp_path / "spool"),
        "chatmail_ini": str(relay._inipath),
        "google_client_id": "synthetic-client",
        "google_client_secret_ref": "archive-client",
        "broker_argv": ["/unused-synthetic-broker"],
        "operator": {
            "uid": os.getuid(),
            "identity": "trusted-admin",
            "google_sub": "operator-sub",
            "mailboxes": [box.name],
        },
    }
    path = tmp_path / "archive.json"
    path.write_text(json.dumps(cfg))
    b = operator_binding(cfg, store, "trusted-admin", box.name)
    return cfg, path, activate(store, b), root, box


def test_operator_policy_removal_prevents_credentials_or_capture(
    tmp_path, make_config, store
):
    cfg, path, b, root, _box = operator_setup(tmp_path, make_config, store)
    job = store.enqueue(b.id)
    cfg.pop("operator")
    path.write_text(json.dumps(cfg))
    calls = []
    Worker(
        store,
        SimpleNamespace(access=lambda _: calls.append(True)),
        root,
        tmp_path / "spool",
        policy_loader=lambda: read_policy(path),
    ).run(job)
    assert not calls and not store.get(b.id).enabled
    assert store.get(b.id).consent == "operator_policy_removed"
    assert store.job(job)["state"] == "paused"


def test_operator_allowlist_rechecked_between_resumable_chunks(
    tmp_path, make_config, store
):
    cfg, path, b, root, _box = operator_setup(tmp_path, make_config, store)
    job = store.enqueue(b.id)

    class Session(FakeSession):
        def request(self, method, url, **kwargs):
            result = super().request(method, url, **kwargs)
            if method == "PUT":
                cfg["operator"]["mailboxes"] = []
                path.write_text(json.dumps(cfg))
            return result

    fake = Session(
        [
            Response(data={"user": {"permissionId": "principal-one"}}),
            Response(data={"ids": ["file-one"]}),
            Response(404),
            Response(headers={"Location": "https://www.googleapis.com/upload/session"}),
            Response(308, headers={"Range": f"bytes=0-{CHUNK - 1}"}),
        ]
    )
    Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        policy_loader=lambda: read_policy(path),
        drive_factory=lambda token, **kwargs: Drive(token, session=fake, **kwargs),
        encrypt=lambda *_: b"x" * (CHUNK + 1),
    ).run(job)
    assert len([c for c in fake.calls if c[0] == "PUT"]) == 1
    assert not store.get(b.id).enabled and store.job(job)["state"] == "paused"


def test_explicit_operator_revoke_is_separate_from_owner_routes(
    tmp_path, make_config, store
):
    _cfg, path, b, _root, _box = operator_setup(tmp_path, make_config, store)
    with pytest.raises(ArchiveError, match="binding_denied"):
        portal(store).personal_binding(b.id, b.owner)
    assert (
        main(
            [
                "--config",
                str(path),
                "operator-revoke",
                "--identity",
                "trusted-admin",
                "--mailbox",
                b.mailbox,
            ]
        )
        == 0
    )
    assert not store.get(b.id).enabled


@pytest.mark.parametrize("kind", ["pax", "gnu"])
def test_sparse_tar_rejected_before_extract_or_expansion(kind, monkeypatch):
    if kind == "pax":
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for index in range(3):
                item = tarfile.TarInfo(f"messages/cur/sparse-{index}")
                item.size = 1
                item.pax_headers = {
                    "GNU.sparse.map": "0,1",
                    "GNU.sparse.size": str(32 * 1024 * 1024),
                }
                tar.addfile(item, io.BytesIO(b"x"))
        clear = output.getvalue()
    else:
        item = tarfile.TarInfo("messages/cur/sparse")
        item.type = tarfile.GNUTYPE_SPARSE
        clear = item.tobuf(format=tarfile.GNU_FORMAT) + b"\0" * 1024
    monkeypatch.setattr(
        tarfile.TarFile,
        "extractfile",
        lambda *_args: pytest.fail("sparse body must not be materialized"),
    )
    with pytest.raises(ArchiveError, match="unsafe_tar_member"):
        bundle.verify_clear(clear)
    assert len(clear) < 20000


def test_many_small_members_are_stream_bounded(monkeypatch):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for index in range(1000):
            tar.addfile(tarfile.TarInfo(f"messages/cur/{index}"), io.BytesIO(b""))
    monkeypatch.setattr(
        tarfile.TarFile,
        "getmembers",
        lambda *_args: pytest.fail("unbounded member listing forbidden"),
    )
    with pytest.raises(ArchiveError, match="manifest_count"):
        bundle.verify_clear(output.getvalue())


def test_partial_capture_progress_unresolved_visibility_and_bounded_retry(
    tmp_path, store, monkeypatch
):
    import hashlib

    root, box = mailbox(tmp_path)
    (box / "cur" / "blocked-large").write_bytes(b"x" * 128)
    (box / "new" / "blocked-fifo").parent.mkdir(exist_ok=True)
    os.mkfifo(box / "new" / "blocked-fifo")
    b = binding(store)
    monkeypatch.setattr(
        jobs, "capture", partial(capture, max_files=1, max_batch=1, max_message=64)
    )
    archived = []

    class FakeDrive:
        def __init__(self, *_args, **_kwargs):
            pass

        def principal(self):
            return "principal-one"

        def allocate(self):
            return "file-one"

        def upload(self, object_id, _folder, payload, _run):
            return Receipt(object_id, len(payload), hashlib.sha256(payload).hexdigest())

    def encrypt(messages, *_args):
        archived.extend(message.path for message in messages)
        return b"synthetic-ciphertext"

    worker = Worker(
        store,
        SimpleNamespace(access=lambda _: "synthetic"),
        root,
        tmp_path / "spool",
        drive_factory=FakeDrive,
        encrypt=encrypt,
    )
    for _ in range(40):
        worker.run(store.enqueue(b.id))
    assert {"cur/old:2,S", "new/fresh"}.issubset(archived)
    assert "cur/blocked-large" not in archived and "new/blocked-fifo" not in archived
    assert len(store.unresolved(b.id)) == 2
    assert all(row[2] == 8 for row in store.unresolved(b.id))
    assert store.metrics()["unresolved_entries"] == 2
    assert b"INCOMPLETE" in portal(store).page(
        {"owner": b.owner, "id_hash": signin(portal(store))["id_hash"]}
    )
    (box / "cur" / "blocked-large").write_bytes(b"fixed")
    (box / "new" / "blocked-fifo").unlink()
    (box / "new" / "blocked-fifo").write_bytes(b"fixed too")
    store.retry_sources(b.id)
    for _ in range(12):
        worker.run(store.enqueue(b.id))
    assert not store.unresolved(b.id)
    assert {"cur/blocked-large", "new/blocked-fifo"}.issubset(archived)


def test_proxy_client_and_owner_quotas_are_independent_and_spoof_safe(store):
    server = Server(("127.0.0.1", 0), portal(store))
    try:
        one = server.client_key("127.0.0.1", ["192.0.2.1"])
        two = server.client_key("127.0.0.1", ["192.0.2.2"])
        assert all(server.admit(one) for _ in range(60)) and not server.admit(one)
        assert server.admit(two)
        assert server.client_key("192.0.2.99", ["192.0.2.1"]) == "ip:192.0.2.99"
        assert server.admit(one, owner="owner-one") and server.admit(
            one, owner="owner-two"
        )
        for value in (
            ["192.0.2.1, 192.0.2.2"],
            [" 192.0.2.1"],
            ["192.0.2.1", "192.0.2.2"],
        ):
            with pytest.raises(ArchiveError, match="proxy_client_header_denied"):
                server.client_key("127.0.0.1", value)
    finally:
        server.server_close()
