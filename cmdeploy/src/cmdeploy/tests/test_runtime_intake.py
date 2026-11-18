import json
from datetime import datetime, timezone

from cmdeploy.runtime_intake import RELEASES, collect
from cmdeploy.runtime_security import check, load_lock


def test_new_disclosure_is_unknown_until_classified():
    lock = load_lock()
    inventory_url = lock["captured_facts"]["inventory"]["url"]
    original = lock["captured_facts"]["inventory"]["required_ids"]

    def fake(url):
        if url == inventory_url:
            return json.dumps(
                {
                    "document": {"tracking": {"id": "synthetic-CSAF"}},
                    "vulnerabilities": [
                        {"cve": cve} for cve in original + ["CVE-2026-99999"]
                    ],
                }
            ).encode()
        return json.dumps(
            {"tag_name": "2.4.5" if url == RELEASES["dovecot-ce"] else "1.13.0"}
        ).encode()

    now = datetime(2026, 11, 16, tzinfo=timezone.utc)
    facts = collect(lock, fake, now)
    report = check(lock, "alma10-relay113-candidate", facts, now)
    assert any(
        row["id"] == "CVE-2026-99999" and row["state"] == "unknown"
        for row in report["findings"]
    )
    assert lock["captured_facts"]["inventory"]["required_ids"] == original
    assert not report["deployable"]


def test_failed_fetch_is_not_renewed_success():
    def failed(url):
        raise OSError("synthetic network failure")

    now = datetime(2026, 11, 16, tzinfo=timezone.utc)
    facts = collect(load_lock(), failed, now)
    assert facts["inventory"]["fetch_status"] == "failed"
    assert all(row["result"] == "unknown" for row in facts["intake_ledger"])
    assert not check(load_lock(), "alma10-relay113-candidate", facts, now)[
        "security_qualified"
    ]
