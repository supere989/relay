"""Bind archive authority to one existing mailbox and password incarnation.

The random marker is NOT a secret and is never part of an archive. Workers only
read it. A successful existing-password proof alone may create it atomically.
Normal last-login timestamp touches do not change this identity.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import stat

from .model import ArchiveError
from .sources import relative_path

MARKER = ".chatmail-archive-incarnation"


class Mailbox:
    def __init__(self, root, mailbox):
        self.root = root
        self.mailbox = mailbox
        self.root_fd = self.fd = self.password_fd = self.marker_fd = None
        if relative_path(mailbox).parts != (mailbox,):
            raise ArchiveError("mailbox_incarnation_changed")
        try:
            self.root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fd = os.open(
                mailbox,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=self.root_fd,
            )
            self.password_fd = os.open(
                "password", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd
            )
            self.password, self.password_identity = self._password(self.password_fd)
            self.box_identity = self._inode(os.fstat(self.fd))
        except Exception as exc:
            self.close()
            raise ArchiveError("mailbox_incarnation_changed") from exc

    @staticmethod
    def _inode(info):
        return (info.st_dev, info.st_ino)

    def _password(self, fd):
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 4096:
            raise ArchiveError("mailbox_incarnation_changed")
        data = os.pread(fd, 4097, 0)
        after = os.fstat(fd)
        if (
            self._inode(before) != self._inode(after)
            or len(data) != before.st_size
            or before.st_size != after.st_size
        ):
            raise ArchiveError("mailbox_incarnation_changed")
        return data, (*self._inode(after), hashlib.sha256(data).hexdigest())

    def ensure_marker(self):
        """Only the fresh-password proof path calls this method."""
        self.check_paths()
        try:
            fd = os.open(
                MARKER,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.fd,
            )
        except FileExistsError:
            pass
        else:
            try:
                os.write(fd, secrets.token_hex(32).encode())
                os.fsync(fd)
                os.fsync(self.fd)
            finally:
                os.close(fd)
        return self.fingerprint()

    def check_paths(self):
        try:
            # Fresh path reads and held descriptors must identify the same
            # namespace and credential before and after every protected seam.
            root = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                box = os.open(
                    self.mailbox,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root,
                )
                try:
                    if self._inode(os.fstat(box)) != self.box_identity:
                        raise ArchiveError("mailbox_incarnation_changed")
                    password = os.open(
                        "password",
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=box,
                    )
                    try:
                        if (
                            self._password(password)[1] != self.password_identity
                            or self._password(self.password_fd)[1]
                            != self.password_identity
                        ):
                            raise ArchiveError("mailbox_incarnation_changed")
                    finally:
                        os.close(password)
                finally:
                    os.close(box)
            finally:
                os.close(root)
        except OSError as exc:
            raise ArchiveError("mailbox_incarnation_changed") from exc

    def fingerprint(self):
        self.check_paths()
        try:
            current = os.open(
                MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd
            )
            try:
                info = os.fstat(current)
                value = os.pread(current, 65, 0)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077
                    or not re.fullmatch(b"[a-f0-9]{64}", value)
                ):
                    raise ArchiveError("mailbox_incarnation_changed")
                if self.marker_fd is None:
                    self.marker_fd = os.dup(current)
                if (
                    self._inode(os.fstat(self.marker_fd)) != self._inode(info)
                    or os.pread(self.marker_fd, 65, 0) != value
                ):
                    raise ArchiveError("mailbox_incarnation_changed")
                identity = (
                    self.box_identity,
                    self.password_identity,
                    self._inode(info),
                    value.decode(),
                )
                result = hashlib.sha256(
                    json.dumps(identity, separators=(",", ":")).encode()
                ).hexdigest()
            finally:
                os.close(current)
        except OSError as exc:
            raise ArchiveError("mailbox_incarnation_changed") from exc
        self.check_paths()
        return result

    def check(self, expected):
        if not expected or not hmac.compare_digest(self.fingerprint(), expected):
            raise ArchiveError("mailbox_incarnation_changed")

    def close(self):
        for attr in ("marker_fd", "password_fd", "fd", "root_fd"):
            fd = getattr(self, attr, None)
            if fd is not None:
                os.close(fd)
                setattr(self, attr, None)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
