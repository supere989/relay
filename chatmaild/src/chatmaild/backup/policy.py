"""Current operator delegation, separate from ordinary Google owner identity."""

import hashlib
import json

from .model import ArchiveError, subject


def authority(config, mailbox):
    operator = config.get("operator", {})
    if (
        not operator
        or mailbox not in operator.get("mailboxes", [])
        or not isinstance(operator.get("uid"), int)
        or not operator.get("identity")
    ):
        raise ArchiveError("operator_policy_removed")
    owner = subject("https://accounts.google.com", operator.get("google_sub"))
    fingerprint = hashlib.sha256(
        json.dumps(
            (operator["uid"], operator["identity"], owner, mailbox),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return owner, fingerprint


def check(config, binding):
    owner, fingerprint = authority(config, binding.mailbox)
    if binding.owner != owner or binding.operator_authority != fingerprint:
        raise ArchiveError("operator_policy_changed")
