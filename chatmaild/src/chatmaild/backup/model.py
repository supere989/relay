"""Small explicit contracts shared by the portal and background worker."""

import hashlib
from dataclasses import dataclass

GOOGLE_ISSUER = "https://accounts.google.com"
DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"


class ArchiveError(Exception):
    """A safe reason code, never an upstream body or credential."""

    def __init__(self, reason, *, retryable=False, uncertain=False):
        super().__init__(reason)
        self.reason = reason
        self.retryable = retryable
        self.uncertain = uncertain


def subject(issuer, sub):
    if (
        issuer not in (GOOGLE_ISSUER, "accounts.google.com")
        or not isinstance(sub, str)
        or not 0 < len(sub) <= 255
    ):
        raise ArchiveError("invalid_identity")
    return hashlib.sha256((GOOGLE_ISSUER + "\0" + sub).encode()).hexdigest()


@dataclass(frozen=True)
class Binding:
    id: str
    owner: str
    mailbox: str
    mode: str
    generation: int
    enabled: bool
    consent: str
    permission_id: str | None
    credential_ref: str | None
    key_ref: str | None
    recipient: str | None
    folder_id: str | None
    incarnation: str | None
    retired: bool
    operator_authority: str | None


@dataclass(frozen=True)
class Message:
    path: str
    data: bytes
    sha256: str
    id: str


@dataclass(frozen=True)
class Receipt:
    file_id: str
    size: int
    sha256: str
