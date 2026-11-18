"""Authority linearization, partial delivery, and hostile archive regressions."""

import hashlib
import io
import json
import stat
import subprocess
import tarfile
import threading
import zipfile
from types import SimpleNamespace

import pytest

from chatmaild.backup import FORMAT, bundle
from chatmaild.backup import recovery_tool as tool
from chatmaild.backup.drive import Drive
from chatmaild.backup.recovery import Recovery
from chatmaild.backup.sources import capture
from chatmaild.backup.web import Handler
from chatmaild.doveauth import encrypt_password
from chatmaild.tests.recovery_fixture import PrivateBytes, Scenario
from chatmaild.tests.test_backup import FakeSession, Response, remote_metadata


def kit(scenario):
    scenario.capture()
    status, _headers, data = scenario.http_download()
    if status != 200:
        raise RuntimeError("synthetic_export_failed")
    return data


@pytest.mark.parametrize(
    "change",
    ["csrf", "password", "operator", "retired", "unknown-field", "other-owner", "get"],
)
def test_http_recovery_authority_denials(tmp_path, change):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    fields = {}
    raw = None
    method = "POST"
    if change == "csrf":
        fields["csrf"] = "wrong"
    elif change == "password":
        fields["password"] = "wrong"
    elif change == "operator":
        b = scenario.binding
        scenario.binding = scenario.store.bind(
            b.owner,
            b.mailbox,
            mode="operator",
            allowlist=[b.mailbox],
            incarnation=b.incarnation,
            operator_authority="synthetic-delegation",
        )
    elif change == "retired":
        scenario.store.invalidate_incarnation(scenario.binding.id)
    elif change == "unknown-field":
        fields["key_ref"] = "archive-key-a"
    elif change == "other-owner":
        raw, session = scenario.portal.session()
        with scenario.store.connect() as db:
            db.execute(
                "UPDATE sessions SET owner=? WHERE id_hash=?",
                ("2" * 64, session["id_hash"]),
            )
    else:
        method = "GET"
    scenario.broker.gets.clear()
    status, headers, _data = scenario.http_download(
        fields=fields, raw=raw, method=method
    )
    assert status != 200 and headers["Content-Type"] != "application/zip"
    assert not scenario.broker.gets


@pytest.mark.parametrize("stage", ["broker", "final"])
@pytest.mark.parametrize("action", ["logout", "optout", "retire", "renew"])
def test_http_export_authority_barriers_and_ordinary_renewal(
    tmp_path, monkeypatch, stage, action
):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    entered, release = threading.Event(), threading.Event()
    if stage == "broker":
        original = scenario.broker.recovery_key

        def blocked(*args):
            result = original(*args)
            entered.set()
            assert release.wait(10)
            return result

        monkeypatch.setattr(scenario.broker, "recovery_key", blocked)
    else:
        original = Recovery.authorize

        def blocked(self, *args):
            entered.set()
            assert release.wait(10)
            return original(self, *args)

        monkeypatch.setattr(Recovery, "authorize", blocked)
    results, errors = [], []

    def request():
        try:
            results.append(scenario.http_download())
        except BaseException as exc:
            errors.append(type(exc).__name__)

    thread = threading.Thread(target=request)
    thread.start()
    assert entered.wait(10)
    if action == "logout":
        with scenario.store.connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE id_hash=?", (scenario.session["id_hash"],)
            )
    elif action == "optout":
        scenario.store.optout(scenario.binding.id, scenario.binding.owner)
    elif action == "retire":
        scenario.store.invalidate_incarnation(scenario.binding.id)
    else:
        scenario.renew()
    release.set()
    thread.join(15)
    assert not thread.is_alive() and not errors
    status, headers, _data = results[0]
    assert status == (200 if action == "renew" else 400)
    assert (headers["Content-Type"] == "application/zip") == (action == "renew")
    if action == "optout":
        status, _headers, _data = scenario.http_download()
        assert status == 200  # A fresh proof at the NEW generation remains valid.


def test_namespace_change_during_broker_denies_and_reassigned_owner_gets_no_old_history(
    tmp_path, monkeypatch
):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    old = scenario.binding
    original = scenario.broker.recovery_key
    changed = []

    def replaced(*args):
        result = original(*args)
        if not changed:
            changed.append(True)
            scenario.user.maildir.rename(scenario.directory / "retired-instance")
            scenario.user.set_password(encrypt_password("new-synthetic-proof"))
        return result

    monkeypatch.setattr(scenario.broker, "recovery_key", replaced)
    status, _headers, _body = scenario.http_download()
    assert status == 400 and changed
    monkeypatch.setattr(scenario.broker, "recovery_key", original)
    scenario.store.invalidate_incarnation(old.id)
    raw, session = scenario.portal.session()
    with scenario.store.connect() as db:
        db.execute(
            "UPDATE sessions SET owner=? WHERE id_hash=?",
            ("2" * 64, session["id_hash"]),
        )
    session = scenario.portal.session(raw)[1]
    fresh = scenario.portal.link(
        session, {"mailbox": scenario.address, "password": "new-synthetic-proof"}
    )
    scenario.store.consent(
        fresh.id,
        fresh.owner,
        fresh.generation,
        "principal-two",
        "new-credential",
        "archive-key-b",
        scenario.recipients["archive-key-b"],
        "folder-two",
        expected_ref=None,
    )
    scenario.binding = scenario.store.get(fresh.id)
    scenario.raw, scenario.session, scenario.password = (
        raw,
        session,
        "new-synthetic-proof",
    )
    status, _headers, data = scenario.http_download()
    assert status == 200 and fresh.id != old.id
    metadata = tool.json_object(
        tool.zip_components(data)["recovery.json"], tool.MAX_KIT
    )
    receipt_count = len(metadata["receipts"])
    identifiers = [row["id"] for row in metadata["keys"]]
    assert receipt_count == 0 and identifiers == [
        tool.key_id(scenario.recipients["archive-key-b"])
    ]


@pytest.mark.parametrize(
    "broken", ["missing-key", "wrong-recipient", "missing-receipt"]
)
def test_missing_or_conflicting_history_fails_entire_export(tmp_path, broken):
    scenario = Scenario(tmp_path / "server")
    row = scenario.capture()
    if broken == "missing-key":
        scenario.broker.values.pop("archive-key-a")
    elif broken == "wrong-recipient":
        scenario.broker.values["archive-key-a"] = scenario.broker.values[
            "archive-key-b"
        ]
    else:
        with scenario.store.connect() as db:
            db.execute("UPDATE jobs SET sha256=NULL WHERE id=?", (row["id"],))
    status, _headers, _body = scenario.http_download()
    assert status == 400
    assert scenario.store.metrics()["events_recovery_denied"] == 1


def test_logout_after_final_authorization_does_not_retract_authorized_response(
    tmp_path, monkeypatch
):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    original = Recovery.authorize

    def authorized_then_logout(self, *args):
        result = original(self, *args)
        with self.store.connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE id_hash=?", (scenario.session["id_hash"],)
            )
        return result

    monkeypatch.setattr(Recovery, "authorize", authorized_then_logout)
    status, headers, _body = scenario.http_download()
    assert status == 200 and headers["Content-Type"] == "application/zip"
    assert scenario.store.metrics()["events_recovery_authorized"] == 1


def test_response_abort_is_not_authorization_denial_or_browser_save_claim(tmp_path):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    csrf = scenario.portal.csrf(scenario.session)
    download = Recovery(scenario.store, scenario.config, scenario.broker).export(
        scenario.session,
        {"binding": scenario.binding.id, "password": scenario.password, "csrf": csrf},
    )
    handler = object.__new__(Handler)
    handler.server = SimpleNamespace(portal=scenario.portal)
    handler.send_response = lambda *_args: None
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None

    def interrupted(_data):
        raise BrokenPipeError()

    handler.wfile = SimpleNamespace(write=interrupted, flush=lambda: None)
    handler.recovery_reply(None, download)
    metrics = scenario.store.metrics()
    assert (
        metrics["events_recovery_authorized"] == 1
        and metrics["events_recovery_response_aborted"] == 1
    )
    assert metrics.get("events_recovery_denied", 0) == 0


def public_encrypt(clear, recipient):
    result = subprocess.run(
        ["/usr/bin/age", "--encrypt", "--recipient", recipient],
        input=clear,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return result.stdout


def tar_bytes(manifest, tag, messages):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:

        def add(name, data):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))

        add("manifest.json", tool.canonical(manifest))
        if tag is not None:
            add("manifest.hmac", tag)
        for path, data in messages:
            add("messages/" + path, data)
    return output.getvalue()


@pytest.mark.parametrize(
    "attack",
    [
        "bad-mac",
        "changed-manifest",
        "changed-message",
        "wrong-binding",
        "stripped-tag",
        "legacy-unlisted",
        "truncated",
        "conflicting-run",
        "rotated-key",
    ],
)
def test_hostile_publicly_encrypted_or_corrupt_archives_never_complete(
    tmp_path, attack
):
    scenario = Scenario(tmp_path / "server")
    data = kit(scenario)
    original = scenario.archives[0][1]
    identity = scenario.broker.recovery_key(
        "archive-key-a", scenario.recipients["archive-key-a"]
    )
    parts = tool.tar_components(tool.decrypt(original, identity))
    manifest = tool.json_object(parts["manifest.json"])
    messages = [
        (entry["path"], parts["messages/" + entry["path"]])
        for entry in manifest["messages"]
    ]
    tag = parts["manifest.hmac"]
    inputs = []
    if attack == "bad-mac":
        tag = b"\0" * 32
    elif attack == "changed-manifest":
        manifest["unresolved_count"] += 1
    elif attack == "changed-message":
        messages[0] = (messages[0][0], b"forged content")
    elif attack == "wrong-binding":
        manifest["binding"] = "f" * 32
        tag = tool.manifest_mac(
            tool.canonical(manifest),
            tool.mac_key(identity, manifest["binding"], manifest["recipient"]),
        )
    elif attack == "stripped-tag":
        tag = None
    elif attack == "legacy-unlisted":
        manifest.pop("binding")
        manifest.pop("recipient")
        manifest["format"] = tool.V1
        tag = None
    elif attack == "conflicting-run":
        inputs.append(original)
        manifest["coverage"] = "incomplete"
        tag = tool.manifest_mac(
            tool.canonical(manifest),
            tool.mac_key(identity, scenario.binding.id, manifest["recipient"]),
        )
    elif attack == "rotated-key":
        manifest["recipient"] = scenario.recipients["archive-key-b"]
        rotated = scenario.broker.recovery_key("archive-key-b", manifest["recipient"])
        tag = tool.manifest_mac(
            tool.canonical(manifest),
            tool.mac_key(rotated, scenario.binding.id, manifest["recipient"]),
        )
    recipient = scenario.recipients[
        "archive-key-b" if attack == "rotated-key" else "archive-key-a"
    ]
    corrupted = (
        original[:-10]
        if attack == "truncated"
        else public_encrypt(tar_bytes(manifest, tag, messages), recipient)
    )
    inputs.append(corrupted)
    client = tmp_path / "client"
    client.mkdir(mode=0o700)
    output = client / "quarantine"
    with pytest.raises(tool.RecoveryError):
        tool.restore_archives(data, inputs, str(output))
    assert (
        not (output / "completion.json").exists() and (output / ".incomplete").exists()
    )


def test_retained_legacy_spool_retries_unchanged_and_requires_exact_exported_pin(
    tmp_path,
):
    scenario = Scenario(tmp_path / "server")
    b = scenario.binding
    job = scenario.store.enqueue(b.id)
    messages = capture(scenario.config.mailboxes_dir, b.mailbox, b.id)
    legacy = bundle.encrypt_legacy(messages, b.recipient, job)
    path = scenario.directory / "spool" / (job + ".age")
    path.write_bytes(legacy)
    scenario.store.update_job(
        job,
        "prepared",
        spool=path.name,
        size=len(legacy),
        sha256=hashlib.sha256(legacy).hexdigest(),
        message_ids=json.dumps([m.id for m in messages]),
    )
    status, _headers, data = scenario.http_download()
    assert status == 200
    parsed, keys, receipts = tool.load_kit(data)
    assert next(iter(receipts.values()))["file_id"] is None
    fake = FakeSession(
        [
            Response(data={"user": {"permissionId": "principal-one"}}),
            Response(data={"ids": ["legacy-file"]}),
            Response(404),
            Response(headers={"Location": "https://www.googleapis.com/upload/session"}),
            Response(200),
            Response(data=remote_metadata(legacy)),
            Response(body=legacy),
        ]
    )
    scenario.worker.drive_factory = lambda token, **kwargs: Drive(
        token, session=fake, **kwargs
    )

    def no_new_mac(*_args):
        pytest.fail("legacy retry must not produce a new manifest")

    scenario.broker.manifest_key = no_new_mac
    scenario.worker.run(job)
    unchanged = path.read_bytes() == legacy
    sent = next(
        kwargs["data"] for method, _url, kwargs in fake.calls if method == "PUT"
    )
    same_upload = sent == legacy
    hint = next(
        kwargs["json"]["appProperties"]["format"]
        for method, _url, kwargs in fake.calls
        if method == "POST"
    )
    assert unchanged and same_upload and hint == FORMAT
    _digest, manifest, _messages = tool.authenticate_archive(
        legacy, parsed, keys, receipts
    )
    assert manifest["format"] == tool.V1
    client = tmp_path / "client"
    client.mkdir(mode=0o700)
    tool.restore_archives(data, [legacy], str(client / "restored"))
    assert (
        client / "restored" / job / "cur" / "shared:2,S"
    ).read_bytes() == b"version-one"
    with pytest.raises(tool.RecoveryError, match="untrusted_archive_format"):
        tool.authenticate_archive(legacy, parsed, keys, {})


@pytest.mark.parametrize(
    "attack", ["checksum", "zip-link", "zip-traversal", "wrong-key", "receipt-key-type"]
)
def test_malformed_private_kit_rejected_before_any_output(tmp_path, attack):
    scenario = Scenario(tmp_path / "server")
    data = kit(scenario)
    parts = tool.zip_components(data)
    if attack == "checksum":
        parts["README.txt"] += b"corrupt"
    elif attack in ("wrong-key", "receipt-key-type"):
        metadata = tool.json_object(parts["recovery.json"], tool.MAX_KIT)
        if attack == "wrong-key":
            metadata["keys"][0]["identity"] = scenario.broker.values["archive-key-b"][
                "identity"
            ]
        else:
            metadata["receipts"][0]["key"] = []
        parts["recovery.json"] = tool.canonical(metadata)
        parts["checksums.json"] = tool.canonical(
            {
                "version": 1,
                "files": {
                    name: hashlib.sha256(value).hexdigest()
                    for name, value in parts.items()
                    if name != "checksums.json"
                },
            }
        )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, value in parts.items():
            item = zipfile.ZipInfo(
                "../escape"
                if attack == "zip-traversal" and name == "README.txt"
                else name
            )
            item.external_attr = (
                (stat.S_IFLNK if attack == "zip-link" else stat.S_IFREG) | 0o600
            ) << 16
            archive.writestr(item, value)
    bad = PrivateBytes(output.getvalue())
    client = tmp_path / "client"
    client.mkdir(mode=0o700)
    with pytest.raises(tool.RecoveryError):
        tool.restore_archives(bad, [scenario.archives[0][1]], str(client / "new"))
    assert not (client / "new").exists()
