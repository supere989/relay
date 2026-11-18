"""Offline source/binary security evidence and runtime-promotion contract.

Version strings alone never establish a fix. This module has no network or
deployment operations; callers preserve its JSON receipt in their existing CI
logs/artifacts. Captured evidence is reviewable input, not a cryptographic
attestation magically created by the checker.
"""

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}")
RESULTS = ("fixed", "not-applicable", "affected", "unknown")
PROMOTION_CHECKS = (
    "authentication",
    "notification",
    "metadata",
    "archive",
    "package_plan",
    "service_startup",
    "selinux",
    "rollback",
)


def _date(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def fresh(record, now, maximum_days):
    try:
        age = (now - _date(record["checked_at"])).total_seconds()
        return record.get("fetch_status") == "ok" and 0 <= age <= maximum_days * 86400
    except (KeyError, TypeError, ValueError):
        return False


def _sha(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def advisory_result(advisory, profile, now, maximum_days):
    evidence = advisory.get("evidence", {})
    if not fresh(evidence, now, maximum_days) or not evidence.get("url", "").startswith(
        "https://"
    ):
        return "unknown", "missing, stale or failed primary evidence"
    claim = advisory.get("claim")
    if claim == "not-applicable":
        applicable_profiles = advisory.get(
            "applicability_profiles", [advisory.get("applicability_profile")]
        )
        if (
            advisory.get("reason")
            and profile["id"] in applicable_profiles
            and advisory.get("source_srpm_sha256")
            == profile.get("core", {}).get("srpm_sha256")
            and _sha(advisory.get("source_srpm_sha256"))
        ):
            return claim, advisory["reason"]
        return "unknown", "applicability is not bound to this runtime profile"
    if claim == "affected":
        return claim, advisory.get(
            "reason", "primary evidence identifies affected runtime"
        )
    source, binary = advisory.get("source", {}), advisory.get("binary", {})
    core = profile.get("core", {})
    if claim != "fixed" or not source.get("patches"):
        return "unknown", "no reviewed source fix mapping"
    if not all(
        _sha(value)
        for value in (
            source.get("srpm_sha256"),
            binary.get("sha256"),
            core.get("sha256"),
        )
    ):
        return "unknown", "source or binary digest missing"
    if (
        source.get("srpm_sha256") != core.get("srpm_sha256")
        or binary.get("sha256") != core.get("sha256")
        or binary.get("nevra") != core.get("nevra")
        or binary.get("signer") != core.get("signer")
        or not binary.get("signature_verified")
        or not core.get("signature_verified")
    ):
        return "unknown", "source/binary identity or signer linkage differs"
    return "fixed", "reviewed source fix maps to the exact signed runtime binary"


def check(lock, profile_id, facts=None, now=None):
    now = now or datetime.now(timezone.utc)
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported runtime lock schema")
    profiles = lock.get("profiles", {})
    if profile_id not in profiles:
        raise ValueError("unknown runtime profile")
    profile = profiles[profile_id]
    if profile.get("id") != profile_id:
        raise ValueError("profile identity mismatch")
    if profile.get("runtime_kind") == "bundled-upstream":
        from .runtime_bundle import check as check_bundle

        return check_bundle(
            profile, facts or {}, now, lock["policy"]["maximum_evidence_age_days"]
        )
    findings = []
    source = facts if facts is not None else lock.get("captured_facts", {})
    maximum_days = lock["policy"]["maximum_evidence_age_days"]
    for advisory in source.get("advisories", []):
        result, reason = advisory_result(advisory, profile, now, maximum_days)
        for identifier in advisory.get(
            "covers", [advisory.get("id", "unidentified-advisory")]
        ):
            findings.append(
                {
                    "id": identifier,
                    "state": result,
                    "reason": reason,
                    "evidence_id": advisory.get("id"),
                }
            )
    if not findings:
        findings.append(
            {
                "id": "security-inventory",
                "state": "unknown",
                "reason": "no applicable advisory inventory",
            }
        )
    inventory = source.get("inventory", {})
    if not fresh(inventory, now, maximum_days) or inventory.get("package") != "dovecot":
        findings.append(
            {
                "id": "security-inventory",
                "state": "unknown",
                "reason": "advisory discovery is stale, failed or absent",
            }
        )
    assessed = {finding["id"] for finding in findings}
    for identifier in sorted(set(inventory.get("required_ids", [])) - assessed):
        findings.append(
            {
                "id": identifier,
                "state": "unknown",
                "reason": "upstream disclosure has no source/binary/applicability disposition",
            }
        )
    if not inventory.get("required_ids"):
        findings.append(
            {
                "id": "security-inventory-completeness",
                "state": "unknown",
                "reason": "full upstream vulnerability inventory is absent",
            }
        )
    counts = {name: 0 for name in RESULTS}
    counts.update(Counter(finding["state"] for finding in findings))
    unresolved = list(profile.get("unresolved", []))
    addon = profile.get("addon", {})
    if addon.get("core_nevra") != profile.get("core", {}).get("nevra"):
        unresolved.append("core/addon identity mismatch")
    if not _sha(addon.get("build_manifest_sha256")) or not re.fullmatch(
        r"[0-9a-f]{40}", str(addon.get("repository_oid", ""))
    ):
        unresolved.append("addon immutable build evidence is missing")
    missing = sorted(
        set(profile.get("required_modules", []))
        - set(addon.get("qualified_modules", []))
    )
    if missing:
        unresolved.append("unqualified modules: " + ", ".join(missing))
    promotion = profile.get("promotion", {})
    missing_checks = [
        name for name in PROMOTION_CHECKS if promotion.get(name) is not True
    ]
    if (
        promotion.get("approved") is not True
        or not _sha(promotion.get("reviewed_manifest_sha256"))
        or promotion.get("reviewed_manifest_sha256")
        != addon.get("build_manifest_sha256")
    ):
        unresolved.append("no promotion bound to this exact addon manifest")
    if missing_checks:
        unresolved.append(
            "unqualified promotion contracts: " + ", ".join(missing_checks)
        )
    channels = []
    for channel in source.get("channels", []):
        state = "current" if fresh(channel, now, maximum_days) else "unknown"
        if state == "current" and channel.get("selected") != channel.get("latest"):
            state = "drift"
        if state == "unknown":
            unresolved.append(
                "release discovery is unknown: "
                + str(channel.get("project", "unidentified"))
            )
        if channel.get("upstream_release_changed"):
            unresolved.append(
                "new upstream release requires source/security classification: "
                + str(channel.get("project"))
            )
        channels.append(
            {
                "project": channel.get("project"),
                "selected": channel.get("selected"),
                "latest": channel.get("latest"),
                "state": state,
                "note": "backport coverage is evaluated independently from upstream version drift",
            }
        )
    return {
        "schema_version": 1,
        "profile": profile_id,
        "core": profile.get("core", {}).get("nevra"),
        "security_counts": counts,
        "findings": sorted(findings, key=lambda item: item["id"]),
        "channels": sorted(channels, key=lambda item: item["project"] or ""),
        "unresolved": sorted(set(unresolved)),
        "security_qualified": counts["affected"] == 0 and counts["unknown"] == 0,
        "deployable": counts["affected"] == 0
        and counts["unknown"] == 0
        and not unresolved,
    }


def require_promoted(lock, profile_id, expected_contract):
    report = check(lock, profile_id)
    profile = lock["profiles"][profile_id]
    if profile.get("config_auth_contract") != expected_contract:
        raise RuntimeError(
            "runtime profile differs from the selected relay configuration/authentication contract"
        )
    if not report["deployable"]:
        raise RuntimeError(
            "EL10 runtime remains a candidate: "
            + "; ".join(report["unresolved"])
            + f"; security counts={report['security_counts']}"
        )
    return report


def load_lock(path=None):
    path = Path(path) if path else Path(__file__).with_name("runtime-lock.json")
    return json.loads(path.read_text())


def verify_addon_manifest(profile, path):
    data = Path(path).read_bytes()
    addon = profile["addon"]
    if hashlib.sha256(data).hexdigest() != addon.get("build_manifest_sha256"):
        raise ValueError("addon manifest digest mismatch")
    manifest = json.loads(data)
    if manifest.get("source_revision") != addon.get("repository_oid") or manifest.get(
        "target"
    ) != addon.get("core_nvr"):
        raise ValueError("addon manifest source/core mismatch")
    return manifest
