"""Read-only upstream disclosure/release intake; never edits runtime pins."""

import argparse
import hashlib
import json
import re
import urllib.request
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from .runtime_security import load_lock

RELEASES = {
    "dovecot-ce": "https://api.github.com/repos/dovecot/core/releases/latest",
    "chatmail-relay": "https://api.github.com/repos/chatmail/relay/releases/latest",
}


def fetch(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "chatmail-runtime-intake/1"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("primary response exceeds the intake bound")
    return data


def collect(lock, fetcher=fetch, now=None):
    now = now or datetime.now(timezone.utc)
    checked_at = now.isoformat()
    facts = deepcopy(lock["captured_facts"])
    events = []
    inventory = facts["inventory"]
    inventory["checked_at"] = checked_at
    try:
        raw = fetcher(inventory["url"])
        document = json.loads(raw)
        identifiers = sorted({item["cve"] for item in document["vulnerabilities"]})
        if not identifiers or not all(
            re.fullmatch(r"CVE-\d{4}-\d{4,}", value) for value in identifiers
        ):
            raise ValueError("unrecognized CSAF vulnerability inventory")
        inventory.update(
            fetch_status="ok",
            required_ids=identifiers,
            document_sha256=hashlib.sha256(raw).hexdigest(),
            document_id=document["document"]["tracking"]["id"],
        )
        events.append(
            {"stage": "disclosure", "result": "ok", "count": len(identifiers)}
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        inventory["fetch_status"] = "failed"
        events.append(
            {"stage": "disclosure", "result": "unknown", "reason": type(error).__name__}
        )
    for channel in facts["channels"]:
        channel["checked_at"] = checked_at
        try:
            raw = fetcher(RELEASES[channel["project"]])
            document = json.loads(raw)
            latest = document["tag_name"].removeprefix("v")
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", latest):
                raise ValueError("release tag requires explicit review")
            channel.update(
                fetch_status="ok",
                latest=latest,
                document_sha256=hashlib.sha256(raw).hexdigest(),
                upstream_release_changed=latest != channel.get("latest"),
            )
            events.append(
                {"stage": "release", "project": channel["project"], "result": "ok"}
            )
        except (OSError, ValueError, KeyError, TypeError) as error:
            channel["fetch_status"] = "failed"
            events.append(
                {
                    "stage": "release",
                    "project": channel["project"],
                    "result": "unknown",
                    "reason": type(error).__name__,
                }
            )
    # Historical source/binary mappings remain dated evidence. Intake does not
    # silently renew their inspection dates or classify a new CVE as fixed.
    facts["intake_ledger"] = events
    return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    facts = collect(load_lock(args.lock))
    Path(args.output).write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n")
    return (
        1
        if any(event["result"] == "unknown" for event in facts["intake_ledger"])
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
