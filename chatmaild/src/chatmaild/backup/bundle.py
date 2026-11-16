"""Standard age v1 encryption, with plaintext held only in bounded memory."""

import hashlib
import io
import json
import os
import subprocess
import tarfile
from pathlib import Path

from . import FORMAT
from .model import ArchiveError
from .sources import message_path, relative_path

MAX_CLEAR = 70 * 1024 * 1024


def _run(argv, data, *, pass_fds=()):
    try:
        result = subprocess.run(
            argv,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ArchiveError("age_unavailable") from exc
    if result.returncode:
        raise ArchiveError("age_failed")
    return result.stdout


def encrypt(messages, recipient, run_id, *, age="/usr/bin/age"):
    if not recipient.startswith("age1") or len(recipient) > 128:
        raise ArchiveError("invalid_recipient")
    manifest = {
        "format": FORMAT,
        "run": run_id,
        "consistency": "capture-window-per-message",
        "coverage": "incomplete"
        if getattr(messages, "unresolved", ()) or getattr(messages, "held", 0)
        else "capture-window",
        "unresolved_count": len(getattr(messages, "unresolved", ())),
        "held_unresolved_count": getattr(messages, "held", 0),
        "messages": [
            {"path": m.path, "size": len(m.data), "sha256": m.sha256, "id": m.id}
            for m in messages
        ],
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:

        def add(name, data):
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), 0o600, 0
            tar.addfile(item, io.BytesIO(data))

        manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
        if len(manifest_bytes) > 1024 * 1024:
            raise ArchiveError("manifest_limit")
        add("manifest.json", manifest_bytes)
        for message in messages:
            message_path(message.path)
            add("messages/" + message.path, message.data)
    if output.tell() > MAX_CLEAR:
        raise ArchiveError("bundle_limit")
    return _run([age, "--encrypt", "--recipient", recipient], output.getvalue())


def decrypt(ciphertext, identity, *, age="/usr/bin/age"):
    if len(ciphertext) > MAX_CLEAR + 1024 * 1024:
        raise ArchiveError("restore_size_limit")
    # An anonymous pipe carries the key; neither argv nor disk contains it.
    read, write = os.pipe()
    try:
        if len(identity.encode()) > 4096:
            raise ArchiveError("identity_limit")
        os.write(write, identity.encode())
        os.close(write)
        write = -1
        clear = _run(
            [age, "--decrypt", "--identity", f"/dev/fd/{read}"],
            ciphertext,
            pass_fds=(read,),
        )
    finally:
        os.close(read)
        if write >= 0:
            os.close(write)
    if len(clear) > MAX_CLEAR:
        raise ArchiveError("restore_size_limit")
    return clear


def verify_clear(clear):
    """Validate the entire authenticated archive before writing any message."""
    if len(clear) > MAX_CLEAR:
        raise ArchiveError("restore_size_limit")
    try:
        with tarfile.open(fileobj=io.BytesIO(clear), mode="r|") as tar:
            contents = {}
            declared = actual = 0
            for index, item in enumerate(tar):
                if index >= 257:
                    raise ArchiveError("manifest_count")
                relative_path(item.name)
                if (
                    item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or item.sparse is not None
                    or any(
                        key.startswith("GNU.sparse") or key == "SCHILY.realsize"
                        for key in item.pax_headers
                    )
                ):
                    raise ArchiveError("unsafe_tar_member")
                declared += item.size
                if item.name in contents or item.size < 0 or declared > MAX_CLEAR:
                    raise ArchiveError("restore_size_limit")
                if item.name == "manifest.json" and item.size > 1024 * 1024:
                    raise ArchiveError("manifest_limit")
                data = tar.extractfile(item).read(item.size + 1)
                actual += len(data)
                if len(data) != item.size or actual > MAX_CLEAR:
                    raise ArchiveError("restore_size_limit")
                contents[item.name] = data
            if "manifest.json" not in contents:
                raise ArchiveError("manifest_missing")
            manifest = json.loads(contents["manifest.json"])
            if (
                manifest.get("format") != FORMAT
                or not isinstance(manifest.get("messages"), list)
                or len(manifest["messages"]) > 256
            ):
                raise ArchiveError("manifest_invalid")
            result = []
            expected = {"manifest.json"}
            for entry in manifest["messages"]:
                path = str(message_path(entry["path"]))
                name = "messages/" + path
                if name in expected:
                    raise ArchiveError("manifest_invalid")
                expected.add(name)
                data = contents[name]
                if (
                    len(data) != entry["size"]
                    or hashlib.sha256(data).hexdigest() != entry["sha256"]
                ):
                    raise ArchiveError("manifest_checksum")
                result.append((path, data))
            if contents.keys() != expected:
                raise ArchiveError("manifest_count")
            return manifest, result
    except (
        tarfile.TarError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
    ) as exc:
        raise ArchiveError("archive_invalid") from exc


def restore(ciphertext, identity, destination, *, age="/usr/bin/age"):
    """Create a NEW private quarantine. Never write into an existing directory."""
    manifest, messages = verify_clear(decrypt(ciphertext, identity, age=age))
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ArchiveError("restore_requires_new_directory")
    destination.mkdir(mode=0o700)
    # No tar extraction API: only validated regular message bytes are written.
    for path, data in messages:
        target = destination / path
        parent = destination
        for component in Path(path).parts[:-1]:
            parent = parent / component
            parent.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    return manifest
