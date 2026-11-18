"""Offline linkage of signed source dispositions to the private native RPM.

Security qualification and production promotion are separate. Reading verified
candidate artifacts never edits a lock, signs a package or approves deployment.
"""

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CONTRACTS = (
    "authentication",
    "notification",
    "metadata",
    "storage_transition",
    "compression_reset",
    "quota",
    "standard_users",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(profile, manifest_path, rpm_path, regression_path=None):
    manifest = json.loads(Path(manifest_path).read_text())
    expected = profile["runtime"]
    if (
        manifest.get("profile") != profile["id"]
        or manifest.get("version") != expected["version"]
        or manifest.get("prefix") != expected["prefix"]
        or manifest.get("source_archives") != expected["source_archives"]
        or manifest.get("source_signer") != expected["source_signer"]
        or manifest.get("config_version") != expected["config_version"]
        or manifest.get("storage_version") != expected["storage_version"]
        or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("source_revision", ""))
        or not manifest.get("source_files")
    ):
        raise ValueError(
            "bundled runtime source, profile or storage provenance mismatch"
        )
    if sha(rpm_path) != manifest.get("rpm", {}).get("sha256") or Path(
        rpm_path
    ).name != manifest.get("rpm", {}).get("name"):
        raise ValueError("bundled runtime RPM bytes differ from build evidence")
    modules = set(manifest.get("modules", {}))
    if set(profile["required_modules"]) - modules:
        raise ValueError("bundled runtime is missing required native modules")
    if any(
        manifest.get("native_tests", {}).get(name) != "passed"
        for name in ("core", "pigeonhole")
    ):
        raise ValueError("bundled runtime native test evidence incomplete")
    result = {
        "manifest_sha256": sha(manifest_path),
        "rpm_sha256": sha(rpm_path),
        "source_archives": manifest["source_archives"],
        "source_signer": manifest["source_signer"],
        "source_revision": manifest["source_revision"],
        "native_tests": manifest["native_tests"],
        "config_version": manifest["config_version"],
        "storage_version": manifest["storage_version"],
        "runtime_qualified": False,
        "rpm_signed": manifest["rpm"].get("signed") is True,
    }
    if regression_path:
        regression = json.loads(Path(regression_path).read_text())
        if (
            regression.get("build_manifest_sha256") != result["manifest_sha256"]
            or regression.get("profile") != profile["id"]
            or regression.get("failed")
            or not regression.get("passed")
            or regression.get("synthetic_only") is not True
            or regression.get("external_network") is not False
            or any(
                regression.get("contracts", {}).get(name) is not True
                for name in CONTRACTS
            )
        ):
            raise ValueError(
                "runtime regression evidence is incomplete or belongs to another build"
            )
        result.update(
            runtime_qualified=True,
            regression_sha256=sha(regression_path),
            contracts=regression["contracts"],
        )
    return result


def check(profile, facts, now=None, maximum_days=7):
    from .runtime_security import fresh

    now = now or datetime.now(timezone.utc)
    findings, unresolved = [], list(profile.get("unresolved", []))
    runtime = profile["runtime"]
    evidence = facts.get("build_evidence", {})
    source_bound = (
        facts.get("_file_sha256") == profile.get("source_dispositions_sha256")
        and bool(profile.get("source_dispositions_sha256"))
        and facts.get("profile") == profile["id"]
        and facts.get("source_archives") == runtime["source_archives"]
        and facts.get("source_signer") == runtime["source_signer"]
        and facts.get("required_config")
        == {
            "dovecot_config_version": runtime["config_version"],
            "dovecot_storage_version": runtime["storage_version"],
        }
    )
    binary_bound = (
        evidence.get("source_archives") == runtime["source_archives"]
        and evidence.get("source_signer") == runtime["source_signer"]
        and all(
            re.fullmatch(r"[0-9a-f]{64}", str(evidence.get(key, "")))
            for key in ("manifest_sha256", "rpm_sha256")
        )
        and evidence.get("storage_version") == runtime["storage_version"]
        and evidence.get("config_version") == runtime["config_version"]
        and all(
            evidence.get("native_tests", {}).get(name) == "passed"
            for name in ("core", "pigeonhole")
        )
    )
    fresh_source = fresh(facts, now, maximum_days)
    for advisory in facts.get("advisories", []):
        reviewed = advisory.get("source_evidence", [])
        known_sources = {item.get("url") for item in facts.get("sources", [])}
        valid = (
            fresh_source
            and source_bound
            and binary_bound
            and advisory.get("reason")
            and advisory.get("component") in ("core", "pigeonhole")
            and reviewed
            and all(
                item.get("url") in known_sources and item.get("path_or_boundary")
                for item in reviewed
            )
        )
        claim = advisory.get("claim")
        result = (
            claim
            if valid and claim in ("fixed", "not-applicable", "affected")
            else "unknown"
        )
        findings.append(
            {
                "id": advisory.get("id", "unidentified"),
                "state": result,
                "reason": advisory.get("reason")
                if valid
                else "source disposition, freshness or exact artifact linkage incomplete",
            }
        )
    inventory = facts.get("inventory", {})
    expected_ids = set(inventory.get("required_ids", []))
    observed_ids = {row["id"] for row in findings}
    for identifier in sorted(expected_ids - observed_ids):
        findings.append(
            {
                "id": identifier,
                "state": "unknown",
                "reason": "required source disposition absent",
            }
        )
    if not expected_ids or inventory.get("package") != "dovecot":
        findings.append(
            {
                "id": "security-inventory",
                "state": "unknown",
                "reason": "full primary-source inventory absent",
            }
        )
    if len(observed_ids) != len(findings):
        unresolved.append("duplicate or incomplete advisory dispositions")
    if not binary_bound:
        unresolved.append("exact native build/RPM linkage missing")
    if evidence.get("runtime_qualified") is not True:
        unresolved.append(
            "real relay authentication/notification/storage qualification missing"
        )
    if not evidence.get("rpm_signed"):
        unresolved.append("candidate runtime package is unsigned")
    promotion = profile.get("promotion", {})
    if (
        promotion.get("approved") is not True
        or not promotion.get("reviewed_manifest_sha256")
        or promotion.get("reviewed_manifest_sha256") != evidence.get("manifest_sha256")
    ):
        unresolved.append(
            "production promotion is not bound to this exact native artifact"
        )
    counts = {state: 0 for state in ("fixed", "not-applicable", "affected", "unknown")}
    counts.update(Counter(row["state"] for row in findings))
    source_qualified = not counts["unknown"] and not counts["affected"]
    qualified = source_qualified and evidence.get("runtime_qualified") is True
    return {
        "schema_version": 1,
        "profile": profile["id"],
        "core": runtime["version"],
        "security_counts": counts,
        "findings": sorted(findings, key=lambda row: row["id"]),
        "channels": [],
        "unresolved": sorted(set(unresolved)),
        "build_evidence": evidence,
        "source_security_qualified": source_qualified,
        "security_qualified": qualified,
        "runtime_qualified": evidence.get("runtime_qualified") is True,
        "deployable": qualified and not unresolved,
    }
