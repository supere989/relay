import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from cmdeploy.runtime_bundle import CONTRACTS, check, verify
from cmdeploy.runtime_security import load_lock

ID = "upstream-2.4.5-alma10-x86_64"
NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


def setup_bundle(tmp_path):
    profile = deepcopy(load_lock()["profiles"][ID])
    runtime = profile["runtime"]
    rpm = tmp_path / "synthetic.rpm"
    rpm.write_bytes(b"synthetic candidate payload")
    manifest = {
        "profile": ID,
        "version": runtime["version"],
        "prefix": runtime["prefix"],
        "source_archives": runtime["source_archives"],
        "source_signer": runtime["source_signer"],
        "config_version": runtime["config_version"],
        "storage_version": runtime["storage_version"],
        "source_revision": "a" * 40,
        "source_files": {"recipe.py": "b" * 64},
        "native_tests": {"core": "passed", "pigeonhole": "passed"},
        "modules": {name: "private/" + name for name in profile["required_modules"]},
        "rpm": {
            "name": rpm.name,
            "sha256": hashlib.sha256(rpm.read_bytes()).hexdigest(),
            "signed": False,
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    return profile, path, rpm, manifest


def facts(profile):
    runtime = profile["runtime"]
    return {
        "profile": ID,
        "_file_sha256": profile["source_dispositions_sha256"],
        "checked_at": "2026-11-16",
        "fetch_status": "ok",
        "source_archives": runtime["source_archives"],
        "source_signer": runtime["source_signer"],
        "required_config": {
            "dovecot_config_version": "2.4.5",
            "dovecot_storage_version": "2.4.5",
        },
        "sources": [{"url": "https://publisher.test/advisory"}],
        "inventory": {"package": "dovecot", "required_ids": ["CVE-2026-40017"]},
        "advisories": [
            {
                "id": "CVE-2026-40017",
                "claim": "fixed",
                "component": "core",
                "reason": "reviewed publisher/source disposition",
                "source_evidence": [
                    {
                        "url": "https://publisher.test/advisory",
                        "path_or_boundary": "/fixed",
                    }
                ],
            }
        ],
    }


def test_source_dispositions_alone_cannot_qualify_binary(tmp_path):
    profile, _, _, _ = setup_bundle(tmp_path)
    report = check(profile, facts(profile), NOW)
    assert report["security_counts"]["unknown"] == 1
    assert not report["security_qualified"]


def test_native_source_linkage_without_storage_runtime_proof_is_not_full_security(
    tmp_path,
):
    profile, path, rpm, _ = setup_bundle(tmp_path)
    source = facts(profile)
    source["build_evidence"] = verify(profile, path, rpm)
    report = check(profile, source, NOW)
    assert report["security_counts"]["fixed"] == 1
    assert report["source_security_qualified"]
    assert not report["security_qualified"]
    assert not report["runtime_qualified"] and not report["deployable"]
    assert "candidate runtime package is unsigned" in report["unresolved"]


def test_runtime_requires_exact_build_hash_and_all_contracts(tmp_path):
    profile, path, rpm, _ = setup_bundle(tmp_path)
    regression = tmp_path / "regression.json"
    result = {
        "profile": ID,
        "build_manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "passed": 20,
        "synthetic_only": True,
        "external_network": False,
        "contracts": dict.fromkeys(CONTRACTS, True),
    }
    regression.write_text(json.dumps(result))
    evidence = verify(profile, path, rpm, regression)
    assert evidence["runtime_qualified"]
    source = facts(profile)
    source["build_evidence"] = evidence
    report = check(profile, source, NOW)
    assert report["source_security_qualified"] and report["security_qualified"]
    assert not report["deployable"]
    for key, value in (
        ("build_manifest_sha256", "wrong"),
        ("contracts", {}),
        ("failed", 1),
    ):
        changed = {**result, key: value}
        regression.write_text(json.dumps(changed))
        with pytest.raises(ValueError, match="regression"):
            verify(profile, path, rpm, regression)


def test_changed_rpm_missing_module_storage_and_signer_rejected(tmp_path):
    profile, path, rpm, manifest = setup_bundle(tmp_path)
    for key, value in (
        ("modules", {}),
        ("storage_version", "2.4.0"),
        ("source_signer", "wrong"),
    ):
        path.write_text(json.dumps({**manifest, key: value}))
        with pytest.raises(ValueError):
            verify(profile, path, rpm)
    path.write_text(json.dumps(manifest))
    rpm.write_bytes(b"changed payload")
    with pytest.raises(ValueError, match="RPM bytes"):
        verify(profile, path, rpm)


def test_stale_failed_missing_inventory_or_changed_fact_receipt_is_unknown(tmp_path):
    profile, path, rpm, _ = setup_bundle(tmp_path)
    original = facts(profile)
    original["build_evidence"] = verify(profile, path, rpm)
    for key, value in (
        ("fetch_status", "network-failed"),
        ("checked_at", "2026-01-01"),
        ("_file_sha256", "0" * 64),
        ("inventory", {}),
    ):
        changed = {**original, key: value}
        assert check(profile, changed, NOW)["security_counts"]["unknown"] >= 1
