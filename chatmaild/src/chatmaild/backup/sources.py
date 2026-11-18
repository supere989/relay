"""Read Maildir messages through directory descriptors; never follow links."""

import hashlib
import os
import stat
from contextlib import closing
from pathlib import PurePosixPath

from .model import ArchiveError, Message

MAX_FOLDER_DEPTH = 16
MAX_FOLDERS = 4096


def _control_directory(name):
    return name in (
        "cur",
        "new",
        "tmp",
        "password",
        "metadata",
        ".chatmail-archive-incarnation",
    ) or name.startswith("dovecot")


def relative_path(value):
    p = PurePosixPath(value)
    if (
        not value
        or p.is_absolute()
        or ".." in p.parts
        or str(p) != value
        or "\\" in value
        or "\0" in value
        or len(value.encode()) > 4096
        or any(len(part.encode()) > 255 for part in p.parts)
    ):
        raise ArchiveError("unsafe_manifest_path")
    return p


def message_path(value):
    path = relative_path(value)
    if (
        len(path.parts) < 2
        or len(path.parts) > MAX_FOLDER_DEPTH + 2
        or path.parts[-2] not in ("cur", "new")
        or any(_control_directory(part) for part in path.parts[:-2])
    ):
        raise ArchiveError("unsafe_message_path")
    return path


def _directory(parent, name):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


class Capture(list):
    def __init__(self, messages, cursor, unresolved=(), resolved=(), held=0):
        super().__init__(messages)
        self.cursor = cursor
        self.unresolved = list(unresolved)
        self.resolved = list(resolved)
        self.held = held


def _entries(
    box, checkpoint, prefix="", depth=0, folders=None, issue=None, resolve=None
):
    # Both flat Maildir++ (.Archive.2026/cur) and filesystem folder layouts are
    # supported. Every directory is opened relative to its parent without links.
    if folders is None:
        folders = [0]
    folders[0] += 1
    if depth > MAX_FOLDER_DEPTH or folders[0] > MAX_FOLDERS:
        issue(prefix, "source_folder_limit")
        return
    for folder in ("cur", "new"):
        try:
            directory = _directory(box, folder)
        except FileNotFoundError:
            continue
        except OSError:
            issue(prefix + folder, "source_folder_unavailable")
            continue
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    checkpoint()
                    yield prefix + folder, directory, entry.name
            resolve(prefix + folder)
        except OSError:
            issue(prefix + folder, "source_folder_unavailable")
        finally:
            os.close(directory)
    with os.scandir(box) as children:
        for entry in children:
            checkpoint()
            if folders[0] > MAX_FOLDERS:
                return
            if _control_directory(entry.name):
                continue
            try:
                info = os.stat(entry.name, dir_fd=box, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    folders[0] += 1
                    issue(prefix + entry.name, "source_folder_unavailable")
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    continue
                relative_path(entry.name)
                directory = _directory(box, entry.name)
            except (OSError, ArchiveError):
                folders[0] += 1
                issue(prefix + entry.name, "source_folder_unavailable")
                continue
            try:
                yield from _entries(
                    directory,
                    checkpoint,
                    prefix + entry.name + "/",
                    depth + 1,
                    folders,
                    issue,
                    resolve,
                )
            finally:
                os.close(directory)
    if prefix:
        resolve(prefix.rstrip("/"))


def capture(
    mailboxes_root,
    mailbox,
    binding_id,
    seen=(),
    *,
    max_files=1024,
    max_message=32 * 1024 * 1024,
    max_bytes=64 * 1024 * 1024,
    max_batch=256,
    checkpoint=lambda: None,
    after=0,
    mailbox_fd=None,
    retry_allowed=lambda _entry: True,
):
    """A bounded capture window, with per-message before/after consistency.

    Source mailbox is a single component under the configured root. A batch may
    be smaller than the mailbox; verified content IDs drive the next reconcile.
    Any unsafe, missing or changing entry fails the capture, with no new cursor.
    """
    if relative_path(mailbox).parts != (mailbox,):
        raise ArchiveError("unsafe_mailbox")
    if not isinstance(after, int) or after < 0:
        raise ArchiveError("source_cursor_invalid")
    result, total, scanned, held = [], 0, 0, 0
    issues, resolved = [], []

    def finish(cursor):
        return Capture(result, cursor, issues, resolved, held)

    def issue(path, reason):
        issues.append(
            (
                hashlib.sha256((binding_id + "\0folder\0" + path).encode()).hexdigest(),
                reason,
            )
        )

    def resolve(path):
        resolved.append(
            hashlib.sha256((binding_id + "\0folder\0" + path).encode()).hexdigest()
        )

    root = (
        os.open(mailboxes_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if mailbox_fd is None
        else None
    )
    try:
        box = _directory(root, mailbox) if mailbox_fd is None else os.dup(mailbox_fd)
        try:
            with closing(
                _entries(box, checkpoint, issue=issue, resolve=resolve)
            ) as entries:
                for index, (folder, directory, name) in enumerate(entries):
                    if index < after:
                        continue
                    if scanned >= max_files or len(result) >= max_batch:
                        return finish(index)
                    scanned += 1
                    path = f"{folder}/{name}"
                    entry_id = hashlib.sha256(
                        (binding_id + "\0" + path).encode()
                    ).hexdigest()
                    if not retry_allowed(entry_id):
                        held += 1
                        continue
                    try:
                        message_path(path)
                        data = _read_message(directory, name, max_message, checkpoint)
                    except ArchiveError as exc:
                        if exc.reason not in (
                            "source_changed",
                            "source_not_regular",
                            "source_message_limit",
                            "source_unavailable",
                            "unsafe_message_path",
                            "unsafe_manifest_path",
                        ):
                            raise
                        issues.append((entry_id, exc.reason))
                        continue
                    checksum = hashlib.sha256(data).hexdigest()
                    mid = hashlib.sha256(
                        (binding_id + "\0" + path + "\0" + checksum).encode()
                    ).hexdigest()
                    if mid in seen:
                        resolved.append(entry_id)
                        continue
                    if total + len(data) > max_bytes or len(result) >= max_batch:
                        if not result:
                            raise ArchiveError("source_batch_limit")
                        return finish(index)
                    total += len(data)
                    result.append(Message(path, data, checksum, mid))
                    resolved.append(entry_id)
        finally:
            os.close(box)
    except OSError as exc:
        raise ArchiveError("source_unavailable", retryable=True) from exc
    finally:
        if root is not None:
            os.close(root)
    # Directory enumeration is mutable. Reset after each sweep so inserts or
    # renames before a previous numeric cursor are found on the next sweep.
    # Cursor contains no message paths and advances only with verified receipts.
    return finish(0)


def _read_message(directory, name, max_message, checkpoint):
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ArchiveError("source_not_regular")
            if before.st_size > max_message:
                raise ArchiveError("source_message_limit")
            chunks, remaining = [], max_message + 1
            while remaining:
                checkpoint()
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)

            def signature(info):
                return (
                    info.st_dev,
                    info.st_ino,
                    info.st_size,
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                )

            if (
                len(data) != before.st_size
                or len(data) > max_message
                or signature(before) != signature(after)
                or signature(after) != signature(current)
            ):
                raise ArchiveError("source_changed", retryable=True)
            checkpoint()
            return data
        finally:
            os.close(fd)
    except OSError as exc:
        raise ArchiveError("source_unavailable", retryable=True) from exc


def legacy_manifest(text):
    """Strictly describe the legacy *subset*, ignoring all absolute columns.

    This reader grants no source authority and performs no restore or pruning.
    """
    entries, paths = [], set()
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise ArchiveError("legacy_manifest_invalid")
        size, checksum, path, _ignored_absolute = fields
        relative_path(path)
        if (
            not size.isdecimal()
            or len(checksum) != 64
            or any(c not in "0123456789abcdef" for c in checksum)
            or path in paths
        ):
            raise ArchiveError("legacy_manifest_invalid")
        paths.add(path)
        entries.append(
            {
                "path": path,
                "size": int(size),
                "sha256": checksum,
                "coverage": "legacy-selected-subset",
            }
        )
    return entries
