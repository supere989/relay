"""Standard age v1 encryption, with plaintext held only in bounded memory."""

import io
import os
import subprocess
import tarfile
from pathlib import Path

from . import FORMAT, LEGACY_FORMAT
from . import recovery_tool as tool
from .model import ArchiveError
from .sources import message_path

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


def encrypt(messages, recipient, run_id, *, binding, mac_key, age="/usr/bin/age"):
    return _encrypt(
        messages, recipient, run_id, binding=binding, mac_key=mac_key, age=age
    )


def encrypt_legacy(messages, recipient, run_id, *, age="/usr/bin/age"):
    """Explicit v1 compatibility fixture/import path; new workers never use it."""
    return _encrypt(messages, recipient, run_id, binding=None, mac_key=None, age=age)


def _encrypt(messages, recipient, run_id, *, binding, mac_key, age):
    if not recipient.startswith("age1") or len(recipient) > 128:
        raise ArchiveError("invalid_recipient")
    manifest = {
        "format": FORMAT if binding is not None else LEGACY_FORMAT,
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
    if binding is not None:
        if not tool.OPAQUE.fullmatch(binding) or mac_key is None:
            raise ArchiveError("manifest_auth_context_missing")
        manifest.update(binding=binding, recipient=recipient)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:

        def add(name, data):
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), 0o600, 0
            tar.addfile(item, io.BytesIO(data))

        manifest_bytes = tool.canonical(manifest)
        if len(manifest_bytes) > 1024 * 1024:
            raise ArchiveError("manifest_limit")
        add("manifest.json", manifest_bytes)
        if binding is not None:
            add("manifest.hmac", tool.manifest_mac(manifest_bytes, mac_key))
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


def verify_clear(clear, *, binding=None, recipient=None, mac_key=None):
    """Validate the entire authenticated archive before writing any message."""
    try:
        return tool.validate_clear(
            clear, binding=binding, recipient=recipient, key=mac_key, legacy=True
        )
    except tool.RecoveryError as exc:
        reason = {
            "tar_count_limit": "manifest_count",
            "message_checksum_mismatch": "manifest_checksum",
        }.get(str(exc), str(exc))
        raise ArchiveError(reason) from exc


def restore(ciphertext, identity, destination, *, age="/usr/bin/age"):
    """Create a NEW private quarantine. Never write into an existing directory."""
    clear = decrypt(ciphertext, identity, age=age)
    try:
        header = tool.json_object(tool.tar_components(clear).get("manifest.json", b""))
        context = {}
        if header.get("format") == FORMAT:
            recipient = tool.public_recipient(identity)
            context = {
                "binding": header.get("binding"),
                "recipient": recipient,
                "mac_key": tool.mac_key(identity, header.get("binding"), recipient),
            }
    except tool.RecoveryError as exc:
        raise ArchiveError(str(exc)) from exc
    manifest, messages = verify_clear(clear, **context)
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
