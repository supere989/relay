"""Public vCard key parsing follows the pinned core 2.69 wire format."""

import base64
import hashlib

import pytest

from chatmaild.backup.manager_transport import public_key_digest
from chatmaild.backup.model import ArchiveError

PUBLIC_KEY = bytes(range(64))
ENCODED_KEY = base64.b64encode(PUBLIC_KEY).decode("ascii")


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("separator", [",", "\\,"])
def test_current_and_legacy_core_vcards(newline, separator):
    card = newline.join(
        [
            "BEGIN:VCARD",
            "VERSION:4.0",
            "KEY:data:application/pgp-keys;base64" + separator + ENCODED_KEY,
            "END:VCARD",
            "",
        ]
    )
    assert public_key_digest(card) == hashlib.sha256(PUBLIC_KEY).hexdigest()


def test_folded_current_core_vcard():
    key = ENCODED_KEY[:40] + "\r\n " + ENCODED_KEY[40:]
    card = (
        "BEGIN:VCARD\r\nKEY:data:application/pgp-keys;base64\\,"
        + key
        + "\r\nEND:VCARD\r\n"
    )
    assert public_key_digest(card) == hashlib.sha256(PUBLIC_KEY).hexdigest()


@pytest.mark.parametrize(
    "value",
    [
        "data:application/pgp-keys;base64\\,not-base64!",
        "data:application/pgp-keys;base64\\\\," + ENCODED_KEY,
        "data:application/pgp-keys;base64\\,"
        + base64.b64encode(b"short").decode("ascii"),
        "data:application/pgp-keys;base64\\,"
        + base64.b64encode(b"x" * 65537).decode("ascii"),
    ],
)
def test_malformed_and_unbounded_keys_are_denied(value):
    with pytest.raises(ArchiveError, match="manager_peer_key_invalid"):
        public_key_digest("BEGIN:VCARD\r\nKEY:" + value + "\r\nEND:VCARD\r\n")


def test_duplicate_folded_properties_are_denied():
    card = "BEGIN:VCARD\r\nKEY:" + ENCODED_KEY[:40] + "\r\n " + ENCODED_KEY[40:]
    card += (
        "\r\nKEY:data:application/pgp-keys;base64\\,"
        + ENCODED_KEY
        + "\r\nEND:VCARD\r\n"
    )
    with pytest.raises(ArchiveError, match="manager_peer_key_missing"):
        public_key_digest(card)
