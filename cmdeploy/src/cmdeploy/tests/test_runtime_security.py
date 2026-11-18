import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from cmdeploy.platforms import ALMA10, DEBIAN, package_plan, select_platform
from cmdeploy.runtime_security import (
    check,
    load_lock,
    require_promoted,
    verify_addon_manifest,
)

NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)
PROFILE = "alma10-relay113-candidate"


def captured():
    return deepcopy(load_lock())


def test_known_platforms_and_unknown_rejection():
    assert select_platform({"name": "AlmaLinux", "major": "10"}) == ALMA10
    assert select_platform({"name": "Debian", "major": "12"}) == DEBIAN
    assert select_platform({"name": "Ubuntu", "major": "24"}) == DEBIAN
    for distribution in (
        {"name": "Fedora", "major": "43"},
        {"name": "AlmaLinux", "major": "9"},
        {},
        None,
    ):
        with pytest.raises(ValueError):
            select_platform(distribution)


def test_package_mapping_does_not_invent_dovecot_lua_or_acmetool():
    assert package_plan(ALMA10, "postfix") == ["postfix", "postfix-pcre"]
    with pytest.raises(ValueError):
        package_plan(ALMA10, "acmetool")


def test_fixed_needs_exact_binary_and_source_linkage():
    lock = captured()
    report = check(lock, PROFILE, now=NOW)
    assert report["security_counts"]["fixed"] >= 1
    lock["captured_facts"]["advisories"][0]["binary"].pop("sha256")
    assert check(lock, PROFILE, now=NOW)["security_counts"]["unknown"] >= 1


def test_source_fix_alone_remains_unknown():
    lock = captured()
    lock["captured_facts"]["advisories"][0]["binary"] = {}
    assert check(lock, PROFILE, now=NOW)["security_counts"]["fixed"] == 0


def test_failed_and_stale_evidence_is_unknown():
    lock = captured()
    lock["captured_facts"]["advisories"][0]["evidence"]["fetch_status"] = (
        "network-failed"
    )
    assert check(lock, PROFILE, now=NOW)["security_counts"]["unknown"]
    lock = captured()
    report = check(lock, PROFILE, now=datetime(2026, 12, 1, tzinfo=timezone.utc))
    assert report["security_counts"]["unknown"] >= 1
    assert not report["deployable"]


def test_exact_core_addon_mismatch_and_missing_authdb_module():
    lock = captured()
    lock["profiles"][PROFILE]["addon"]["core_nevra"] = "dovecot-1:2.3.21-16.el10.x86_64"
    report = check(lock, PROFILE, now=NOW)
    assert "core/addon identity mismatch" in report["unresolved"]
    assert any("authdb_lua" in reason for reason in report["unresolved"])


def test_latest_relay_cannot_use_legacy_dict_auth_profile():
    with pytest.raises(RuntimeError, match="contract"):
        require_promoted(
            load_lock(),
            "alma10-chatmail02-security-candidate",
            "relay113-lua-http-auth",
        )


def test_current_candidate_is_not_promoted():
    report = check(load_lock(), PROFILE, now=NOW)
    assert not report["deployable"]
    assert any("promotion" in reason for reason in report["unresolved"])


def test_old_debian_pin_does_not_inherit_alma_fix_evidence():
    report = check(load_lock(), "debian-relay113-upstream-pin", now=NOW)
    assert report["security_counts"]["unknown"] >= 1
    assert not report["security_qualified"]


def test_upstream_drift_is_distinct_from_backport_proof():
    report = check(load_lock(), PROFILE, now=NOW)
    channel = next(
        item for item in report["channels"] if item["project"] == "dovecot-ce"
    )
    assert channel["state"] == "drift"
    assert report["security_counts"]["fixed"] >= 1


def test_full_upstream_disclosure_does_not_disappear_behind_vendor_subset():
    report = check(load_lock(), PROFILE, now=NOW)
    assert len(report["findings"]) == 25
    assert any(
        item["id"] == "CVE-2026-33607" and item["state"] == "unknown"
        for item in report["findings"]
    )
    assert not report["security_qualified"]


def test_report_order_and_counts_are_deterministic():
    assert json.dumps(
        check(load_lock(), PROFILE, now=NOW), sort_keys=True
    ) == json.dumps(check(load_lock(), PROFILE, now=NOW), sort_keys=True)


def test_immutable_addon_manifest_mismatch(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"source_revision":"different"}')
    profile = deepcopy(load_lock()["profiles"][PROFILE])
    profile["addon"]["build_manifest_sha256"] = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="source/core"):
        verify_addon_manifest(profile, path)
    path.write_text("changed")
    with pytest.raises(ValueError, match="digest"):
        verify_addon_manifest(profile, path)
