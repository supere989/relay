"""Stable bounded receipt pages never impose a lifetime v2 key-export limit."""

import hashlib
import io
import stat
import zipfile
from itertools import permutations

import pytest

from chatmaild.backup import bundle
from chatmaild.backup import recovery_tool as tool
from chatmaild.backup.sources import capture
from chatmaild.backup.store import Store
from chatmaild.tests.recovery_fixture import PrivateBytes, Scenario


def metadata(data):
    return tool.json_object(tool.zip_components(data)["recovery.json"], tool.MAX_KIT)


def test_more_than_4096_jobs_keys_available_and_all_receipts_stable_once(tmp_path):
    scenario = Scenario(tmp_path / "server")
    b = scenario.binding
    count = tool.MAX_ARCHIVES + 3
    with scenario.store.transaction() as db:
        db.executemany(
            "INSERT INTO jobs(id,binding_id,generation,state,due,updated,key_ref,recipient,folder_id,permission_id,incarnation,size,sha256,file_id) VALUES(?,?,?,'verified',0,0,?,?,?,?,?,1,?,?)",
            [
                (
                    f"{n:032x}",
                    b.id,
                    b.generation,
                    b.key_ref,
                    b.recipient,
                    b.folder_id,
                    b.permission_id,
                    b.incarnation,
                    hashlib.sha256(str(n).encode()).hexdigest(),
                    "file-" + str(n),
                )
                for n in range(1, count + 1)
            ],
        )
    status, _headers, key_kit = scenario.http_download(fields={"mode": "keys"})
    assert status == 200 and metadata(key_kit)["receipt_coverage"] == {"kind": "none"}
    status, _headers, first = scenario.http_download()
    assert status == 200
    one = metadata(first)
    coverage = one["receipt_coverage"]
    assert (
        coverage["total"] == count
        and coverage["parts"] == 2
        and not coverage["complete"]
    )
    scenario.capture()  # This later real upload cannot move the snapshot range.
    status, _headers, second = scenario.http_download(
        fields={"snapshot": coverage["snapshot"], "part": "2"}
    )
    assert status == 200
    two = metadata(second)
    runs = [row["run"] for part in (one, two) for row in part["receipts"]]
    assert len(runs) == len(set(runs)) == count
    assert two["receipt_coverage"]["cutoff"] == coverage["cutoff"]
    assert two["receipt_coverage"]["total"] == count
    _kit, _keys, union = tool.load_kits([first, second])
    assert len(union) == count
    with scenario.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM recovery_receipts WHERE binding_id=?", (b.id,)
            ).fetchone()[0]
            == count + 1
        )


def test_legacy_missing_page_refused_and_combined_parts_restore(tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "MAX_ARCHIVES", 1)
    scenario = Scenario(tmp_path / "server")
    payloads = {}
    for index in range(2):
        (scenario.user.maildir / "cur" / "shared:2,S").write_bytes(
            b"version-" + str(index).encode()
        )
        job = scenario.store.enqueue(scenario.binding.id)
        messages = capture(
            scenario.config.mailboxes_dir, scenario.address, scenario.binding.id
        )
        ciphertext = bundle.encrypt_legacy(messages, scenario.binding.recipient, job)
        scenario.store.update_job(
            job,
            "prepared",
            spool=job + ".age",
            size=len(ciphertext),
            sha256=hashlib.sha256(ciphertext).hexdigest(),
        )
        scenario.store.update_job(job, "failed", last_reason="synthetic_retained_spool")
        payloads[job] = ciphertext
    status, _headers, first = scenario.http_download()
    assert status == 200
    meta = metadata(first)
    status, _headers, second = scenario.http_download(
        fields={"snapshot": meta["receipt_coverage"]["snapshot"], "part": "2"}
    )
    assert status == 200
    missing = metadata(second)["receipts"][0]["run"]
    parsed, keys, receipts = tool.load_kit(first)
    with pytest.raises(tool.RecoveryError, match="untrusted_archive_format"):
        tool.authenticate_archive(payloads[missing], parsed, keys, receipts)
    # Process one input at a time under this fixture's one-receipt page bound.
    client = tmp_path / "client"
    client.mkdir(mode=0o700)
    for index, (run, payload) in enumerate(payloads.items()):
        summary = tool.restore_archives(
            [first, second], [payload], str(client / str(index))
        )
        assert summary["runs"][0]["run"] == run


@pytest.mark.parametrize(
    "change", ["forged", "other-owner", "generation", "retired", "expired", "part"]
)
def test_receipt_selector_is_scoped_to_current_authority(tmp_path, change):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    status, _headers, first = scenario.http_download()
    assert status == 200
    selector = metadata(first)["receipt_coverage"]["snapshot"]
    part = "1"
    if change == "forged":
        selector = "f" * 32
    elif change == "other-owner":
        with scenario.store.connect() as db:
            db.execute(
                "UPDATE recovery_snapshots SET owner=? WHERE id=?", ("2" * 64, selector)
            )
    elif change == "generation":
        scenario.store.optout(scenario.binding.id, scenario.binding.owner)
    elif change == "retired":
        scenario.store.invalidate_incarnation(scenario.binding.id)
    elif change == "expired":
        with scenario.store.connect() as db:
            db.execute(
                "UPDATE recovery_snapshots SET expires=0 WHERE id=?", (selector,)
            )
    else:
        part = "2"
    scenario.broker.gets.clear()
    status, _headers, _body = scenario.http_download(
        fields={"snapshot": selector, "part": part}
    )
    assert status == 400 and not scenario.broker.gets


def test_catalog_conflicting_pin_and_combined_kit_conflict_fail(tmp_path):
    scenario = Scenario(tmp_path / "server")
    row = scenario.capture()
    status, _headers, first = scenario.http_download()
    assert status == 200
    with scenario.store.connect() as db:
        db.execute("UPDATE jobs SET sha256=? WHERE id=?", ("f" * 64, row["id"]))
    status, _headers, _body = scenario.http_download()
    assert status == 400
    other = Scenario(tmp_path / "other")
    status, _headers, second = other.http_download(fields={"mode": "keys"})
    assert status == 200
    with pytest.raises(tool.RecoveryError, match="conflicting_kit_binding"):
        tool.load_kits([first, second])


def test_existing_v3_state_gets_additive_recovery_tables_without_changing_authority(
    tmp_path,
):
    scenario = Scenario(tmp_path / "server")
    before = scenario.store.get(scenario.binding.id)
    with scenario.store.connect() as db:
        db.execute("DROP TABLE recovery_snapshots")
        db.execute("DROP TABLE recovery_receipts")
    reopened = Store(scenario.store.path)
    assert reopened.get(before.id) == before
    with reopened.connect() as db:
        assert db.execute("SELECT number FROM version").fetchall() == [(3,)]
        assert db.execute("SELECT count(*) FROM recovery_snapshots").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM recovery_receipts").fetchone()[0] == 0


def test_combined_parts_reject_conflicting_duplicate_core_pins(tmp_path):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    status, _headers, first = scenario.http_download()
    assert status == 200
    parts = tool.zip_components(first)
    data = metadata(first)
    data["receipts"][0]["generation"] += 1
    parts["recovery.json"] = tool.canonical(data)
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
            item = zipfile.ZipInfo(name)
            item.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(item, value)
    conflicting = PrivateBytes(output.getvalue())
    with pytest.raises(tool.RecoveryError, match="conflicting_kit_receipt"):
        tool.load_kits([first, conflicting])


@pytest.mark.parametrize(
    "file_ids,conflict",
    [(order, True) for order in permutations((None, "file-a", "file-b"))]
    + [
        (order, False)
        for order in dict.fromkeys(permutations((None, "file-a", "file-a")))
    ]
    + [(order, False) for order in permutations((None, "file-a"))],
)
def test_nullable_discovery_ids_merge_or_conflict_independent_of_part_order(
    tmp_path, file_ids, conflict
):
    scenario = Scenario(tmp_path / "server")
    scenario.capture()
    status, _headers, first = scenario.http_download()
    assert status == 200
    kits = []
    for file_id in file_ids:
        parts = tool.zip_components(first)
        data = metadata(first)
        data["receipts"][0]["file_id"] = file_id
        parts["recovery.json"] = tool.canonical(data)
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
                item = zipfile.ZipInfo(name)
                item.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(item, value)
        kits.append(PrivateBytes(output.getvalue()))
    if conflict:
        with pytest.raises(tool.RecoveryError, match="conflicting_kit_receipt"):
            tool.load_kits(kits)
    else:
        _kit, _keys, receipts = tool.load_kits(kits)
        assert len(receipts) == 1
        assert next(iter(receipts.values()))["file_id"] == "file-a"
