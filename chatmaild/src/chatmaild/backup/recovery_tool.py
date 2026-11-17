#!/usr/bin/env python3
"""Independent POSIX/Linux archive recovery: Python stdlib and age only.

This exact module is exported as restore.py. It must never import relay,
database, wallet, broker or optional Python packages. Errors contain reason
codes only, never private identities or decrypted message data.
"""

import argparse
import hashlib
import hmac
import io
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import PurePosixPath

V1 = "chatmail-age-v1"
V2 = "chatmail-age-v2"
KIT_FORMAT = "chatmail-recovery-kit"
MAX_KIT = 4 * 1024 * 1024
MAX_CLEAR = 70 * 1024 * 1024
MAX_CIPHER = 71 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_MESSAGES = 256
MAX_KEYS = 64
MAX_ARCHIVES = 4096
MAX_KITS = 16
MAX_KIT_TOTAL = 16 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024 * 1024
HKDF_SALT = b"chatmail-archive/hkdf-sha256/v2"
HKDF_INFO = b"chatmail-archive/manifest-mac/v2\0"
MAC_PREFIX = b"chatmail-archive/manifest-hmac/v2\0"
COMPONENTS = frozenset(("recovery.json", "restore.py", "README.txt", "checksums.json"))
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
OPAQUE = re.compile(r"[a-f0-9]{32}\Z")


class RecoveryError(Exception):
    """A fixed nonsecret failure reason."""


def fail(reason):
    raise RecoveryError(reason)


def canonical(value):
    """Frozen v2 manifest encoding: sorted keys, ASCII escapes, no floats."""

    def check(item):
        if type(item) in (str, int, bool) or item is None:
            return
        if type(item) is list:
            for element in item:
                check(element)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for element in item.values():
                check(element)
            return
        fail("invalid_json_type")

    check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def json_object(data, maximum=MAX_MANIFEST):
    if not isinstance(data, bytes) or len(data) > maximum:
        fail("json_size_limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("duplicate_json_member")
            result[key] = value
        return result

    def invalid(_value):
        fail("invalid_json_number")

    try:
        result = json.loads(
            data, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid
        )
    except (ValueError, UnicodeError, RecursionError):
        fail("invalid_json")
    if type(result) is not dict:
        fail("invalid_json_object")
    canonical(result)
    return result


def hkdf(ikm, salt, info, length=32):
    """RFC 5869 extract/expand with SHA-256."""
    if not 0 < length <= 255 * 32:
        fail("invalid_hkdf_length")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output, previous = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output += previous
    return output[:length]


def normalize_identity(value):
    if type(value) is not str or len(value) > 4096:
        fail("invalid_identity")
    lines = [
        line.strip()
        for line in value.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(lines) != 1 or not re.fullmatch(
        r"AGE-SECRET-KEY-[A-Z0-9]{20,120}", lines[0]
    ):
        fail("invalid_identity")
    return lines[0]


def public_recipient(identity, *, keygen="/usr/bin/age-keygen"):
    identity = normalize_identity(identity)
    try:
        result = subprocess.run(
            [keygen, "-y"],
            input=(identity + "\n").encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("age_keygen_unavailable")
    if result.returncode or len(result.stdout) > 128:
        fail("invalid_identity")
    try:
        recipient = result.stdout.decode("ascii").strip()
    except UnicodeError:
        fail("invalid_identity")
    if not re.fullmatch(r"age1[0-9a-z]{20,100}", recipient):
        fail("invalid_recipient")
    return recipient


def mac_key(identity, binding, recipient):
    identity = normalize_identity(identity)
    if (
        type(binding) is not str
        or not OPAQUE.fullmatch(binding)
        or type(recipient) is not str
        or not re.fullmatch(r"age1[0-9a-z]{20,100}", recipient)
    ):
        fail("invalid_mac_context")
    return hkdf(
        identity.encode("ascii"),
        HKDF_SALT,
        HKDF_INFO + binding.encode("ascii") + b"\0" + recipient.encode("ascii"),
    )


def manifest_mac(manifest_bytes, key):
    if type(key) is not bytes or len(key) != 32 or len(manifest_bytes) > MAX_MANIFEST:
        fail("invalid_mac_input")
    return hmac.new(key, MAC_PREFIX + manifest_bytes, hashlib.sha256).digest()


def relative(value):
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > 4096
        or "\\" in value
        or "\0" in value
    ):
        fail("unsafe_path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or not path.parts
        or ".." in path.parts
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
    ):
        fail("unsafe_path")
    return path


def message_path(value):
    path = relative(value)
    controls = {
        "cur",
        "new",
        "tmp",
        "password",
        "metadata",
        ".chatmail-archive-incarnation",
    }
    if (
        not 2 <= len(path.parts) <= 18
        or path.parts[-2] not in ("cur", "new")
        or any(
            part in controls or part.startswith("dovecot") for part in path.parts[:-2]
        )
    ):
        fail("unsafe_message_path")
    return path


def read_fd(fd, maximum):
    chunks, remaining = [], maximum + 1
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > maximum:
        fail("input_size_limit")
    return data


def read_file(path, maximum, *, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            fail("invalid_input_file")
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            fail("kit_not_private")
        return read_fd(fd, maximum)
    finally:
        os.close(fd)


def zip_components(data):
    """Preflight the central directory before zipfile allocates its objects."""
    if not isinstance(data, bytes) or not 22 <= len(data) <= MAX_KIT:
        fail("kit_size_limit")
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        fail("invalid_kit_zip")
    fields = struct.unpack_from("<4s4H2LH", data, end)
    _sig, disk, directory_disk, count_disk, count, length, offset, comment = fields
    if (
        disk
        or directory_disk
        or count_disk != 4
        or count != 4
        or end + 22 + comment != len(data)
        or offset + length != end
    ):
        fail("invalid_kit_zip")
    position, total, names = offset, 0, set()
    for _ in range(4):
        if position + 46 > end or data[position : position + 4] != b"PK\x01\x02":
            fail("invalid_kit_zip")
        item = struct.unpack_from("<4s6H3L5H2L", data, position)
        flags, compression, compressed, size = item[3], item[4], item[8], item[9]
        name_length, extra_length, comment_length, start_disk = item[10:14]
        mode = item[15] >> 16
        position += 46
        if position + name_length + extra_length + comment_length > end:
            fail("invalid_kit_zip")
        try:
            name = data[position : position + name_length].decode("ascii")
        except UnicodeError:
            fail("invalid_kit_zip")
        if (
            name not in COMPONENTS
            or name in names
            or flags & ~0x800
            or compression != zipfile.ZIP_STORED
            or compressed != size
            or extra_length
            or comment_length
            or start_disk
            or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
        ):
            fail("unsafe_kit_member")
        names.add(name)
        total += size
        if total > MAX_KIT:
            fail("kit_size_limit")
        position += name_length
    if position != end or names != COMPONENTS:
        fail("invalid_kit_zip")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return {name: archive.read(name) for name in sorted(COMPONENTS)}
    except (zipfile.BadZipFile, OSError, ValueError):
        fail("invalid_kit_zip")


def decrypt(ciphertext, identity, *, age="/usr/bin/age"):
    if not isinstance(ciphertext, bytes) or not 0 < len(ciphertext) <= MAX_CIPHER:
        fail("ciphertext_size_limit")
    identity = normalize_identity(identity)
    read, write = os.pipe()
    try:
        os.write(write, (identity + "\n").encode("ascii"))
        os.close(write)
        write = -1
        try:
            result = subprocess.run(
                [age, "--decrypt", "--identity", f"/dev/fd/{read}"],
                input=ciphertext,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(read,),
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            fail("age_unavailable")
        if result.returncode:
            fail("age_authentication_failed")
        if len(result.stdout) > MAX_CLEAR:
            fail("clear_size_limit")
        return result.stdout
    finally:
        os.close(read)
        if write >= 0:
            os.close(write)


def tar_components(clear):
    if len(clear) > MAX_CLEAR:
        fail("clear_size_limit")
    result, declared, actual = {}, 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(clear), mode="r|") as archive:
            for index, item in enumerate(archive):
                if index >= MAX_MESSAGES + 2:
                    fail("tar_count_limit")
                relative(item.name)
                if (
                    item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    or item.sparse is not None
                    or any(
                        key.startswith("GNU.sparse") or key == "SCHILY.realsize"
                        for key in item.pax_headers
                    )
                ):
                    fail("unsafe_tar_member")
                declared += item.size
                if item.name in result or item.size < 0 or declared > MAX_CLEAR:
                    fail("tar_size_limit")
                if item.name == "manifest.json" and item.size > MAX_MANIFEST:
                    fail("manifest_size_limit")
                if item.name == "manifest.hmac" and item.size != 32:
                    fail("invalid_manifest_mac")
                data = archive.extractfile(item).read(item.size + 1)
                actual += len(data)
                if len(data) != item.size or actual > MAX_CLEAR:
                    fail("tar_size_limit")
                result[item.name] = data
    except (tarfile.TarError, OSError, ValueError, KeyError):
        fail("invalid_tar")
    return result


def validate_clear(
    clear, *, binding=None, recipient=None, key=None, legacy=False, run=None
):
    contents = tar_components(clear)
    raw = contents.get("manifest.json", b"")
    manifest = json_object(raw)
    version = manifest.get("format")
    base = {
        "format",
        "run",
        "consistency",
        "coverage",
        "unresolved_count",
        "held_unresolved_count",
        "messages",
    }
    if version == V2:
        if set(manifest) != base | {"binding", "recipient"} or raw != canonical(
            manifest
        ):
            fail("invalid_v2_manifest")
        if manifest["binding"] != binding or manifest["recipient"] != recipient:
            fail("archive_context_mismatch")
        tag = contents.get("manifest.hmac", b"")
        if len(tag) != 32 or not hmac.compare_digest(tag, manifest_mac(raw, key)):
            fail("manifest_authentication_failed")
        expected = {"manifest.json", "manifest.hmac"}
    elif version == V1 and legacy:
        if set(manifest) - base or not {
            "format",
            "run",
            "consistency",
            "messages",
        } <= set(manifest):
            fail("invalid_v1_manifest")
        expected = {"manifest.json"}
    else:
        fail("untrusted_archive_format")
    if (
        type(manifest.get("run")) is not str
        or not OPAQUE.fullmatch(manifest["run"])
        or run is not None
        and manifest["run"] != run
    ):
        fail("archive_run_mismatch")
    if manifest.get("consistency") != "capture-window-per-message" or manifest.get(
        "coverage", "capture-window"
    ) not in ("capture-window", "incomplete"):
        fail("invalid_coverage")
    for field in ("unresolved_count", "held_unresolved_count"):
        value = manifest.get(field, 0)
        if type(value) is not int or not 0 <= value <= 1000000:
            fail("invalid_coverage")
    entries = manifest.get("messages")
    if type(entries) is not list or len(entries) > MAX_MESSAGES:
        fail("invalid_message_count")
    messages = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"path", "size", "sha256", "id"}:
            fail("invalid_message_record")
        path = str(message_path(entry["path"]))
        name = "messages/" + path
        if (
            name in expected
            or type(entry["size"]) is not int
            or not 0 <= entry["size"] <= 32 * 1024 * 1024
            or type(entry["sha256"]) is not str
            or not HEX64.fullmatch(entry["sha256"])
            or type(entry["id"]) is not str
            or not 0 < len(entry["id"]) <= 128
        ):
            fail("invalid_message_record")
        expected.add(name)
        data = contents.get(name)
        if (
            data is None
            or len(data) != entry["size"]
            or hashlib.sha256(data).hexdigest() != entry["sha256"]
        ):
            fail("message_checksum_mismatch")
        messages.append((path, data))
    if set(contents) != expected:
        fail("archive_member_mismatch")
    return manifest, messages


def _mailbox_ancestor(fd):
    names = (
        ".chatmail-archive-incarnation",
        "password",
        "dovecot-uidlist",
        "dovecot.index",
        "dovecot.index.log",
        "dovecot.list.index",
        "maildirfolder",
    )
    for name in names:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        fail("live_mailbox_destination")
    layout = 0
    for name in ("cur", "new", "tmp"):
        try:
            if stat.S_ISDIR(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode):
                layout += 1
        except FileNotFoundError:
            pass
    if layout == 3:
        fail("live_mailbox_destination")


class Quarantine:
    """Exclusive private output, rooted in held descriptors, never extractall."""

    def __init__(self, destination):
        if type(destination) is not str or "\\" in destination or "\0" in destination:
            fail("unsafe_output_path")
        path = PurePosixPath(destination)
        if (
            not path.is_absolute()
            or str(path) != destination
            or ".." in path.parts
            or len(path.parts) < 2
        ):
            fail("unsafe_output_path")
        for root in ("/home/vmail", "/var/vmail", "/var/mail", "/var/spool/mail"):
            if path == PurePosixPath(root) or PurePosixPath(root) in path.parents:
                fail("live_mailbox_destination")
        self.fd = None
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        current = "/"
        try:
            for component in path.parts[1:-1]:
                _mailbox_ancestor(parent)
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                os.close(parent)
                parent = child
                current = current.rstrip("/") + "/" + component
                info = os.fstat(parent)
                sticky_tmp = (
                    current == "/tmp"
                    and info.st_uid == 0
                    and info.st_mode & stat.S_ISVTX
                )
                if (
                    info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022
                    and not sticky_tmp
                ):
                    fail("unsafe_output_ancestor")
            _mailbox_ancestor(parent)
            info = os.fstat(parent)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                fail("output_parent_not_private")
            relative(path.name)
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
            except FileExistsError:
                fail("output_exists")
            os.fsync(parent)
            self.fd = os.open(
                path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
            self.write(
                ".incomplete",
                b"Recovery incomplete: completion.json must be present and this marker absent.\n",
            )
        except BaseException:
            self.close()
            raise
        finally:
            os.close(parent)

    def write(self, name, data):
        parts = relative(name).parts
        parent = os.dup(self.fd)
        try:
            for component in parts[:-1]:
                try:
                    os.mkdir(component, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                else:
                    os.fsync(parent)
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent,
                )
                os.close(parent)
                parent = child
            fd = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if not written:
                        fail("output_write_failed")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)
        finally:
            os.close(parent)

    def finish(self, summary):
        self.write(".completion.tmp", canonical(summary) + b"\n")
        os.unlink(".incomplete", dir_fd=self.fd)
        os.rename(
            ".completion.tmp", "completion.json", src_dir_fd=self.fd, dst_dir_fd=self.fd
        )
        os.fsync(self.fd)

    def incomplete(self):
        if self.fd is not None:
            try:
                self.write(
                    ".incomplete", b"Recovery incomplete; do not import this output.\n"
                )
            except FileExistsError:
                pass

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def key_id(recipient):
    return hashlib.sha256(recipient.encode("ascii")).hexdigest()


def load_kit(data):
    parts = zip_components(data)
    checksums = json_object(parts["checksums.json"])
    if (
        set(checksums) != {"version", "files"}
        or type(checksums["version"]) is not int
        or checksums["version"] != 1
        or type(checksums["files"]) is not dict
        or set(checksums["files"]) != COMPONENTS - {"checksums.json"}
    ):
        fail("invalid_kit_checksums")
    for name, checksum in checksums["files"].items():
        if (
            type(checksum) is not str
            or not HEX64.fullmatch(checksum)
            or not hmac.compare_digest(
                hashlib.sha256(parts[name]).hexdigest(), checksum
            )
        ):
            fail("kit_checksum_mismatch")
    kit = json_object(parts["recovery.json"], MAX_KIT)
    fields = {
        "format",
        "version",
        "created_at",
        "binding",
        "coverage",
        "keys",
        "receipts",
    }
    if (
        set(kit) not in (fields, fields | {"receipt_coverage"})
        or kit["format"] != KIT_FORMAT
        or type(kit["version"]) is not int
        or kit["version"] != 1
        or type(kit["created_at"]) is not int
        or not 0 <= kit["created_at"] < 2**63
        or type(kit["binding"]) is not str
        or not OPAQUE.fullmatch(kit["binding"])
    ):
        fail("invalid_kit_header")
    coverage = kit["coverage"]
    if (
        type(coverage) is not dict
        or set(coverage) != {"kind", "unresolved", "held"}
        or coverage["kind"] != "capture-windows"
        or any(
            type(coverage[field]) is not int or not 0 <= coverage[field] <= 1000000
            for field in ("unresolved", "held")
        )
    ):
        fail("invalid_kit_coverage")
    if type(kit["keys"]) is not list or not 0 < len(kit["keys"]) <= MAX_KEYS:
        fail("invalid_kit_keys")
    keys = {}
    for record in kit["keys"]:
        if (
            type(record) is not dict
            or set(record) != {"id", "recipient", "identity"}
            or type(record["id"]) is not str
            or type(record["recipient"]) is not str
        ):
            fail("invalid_kit_key")
        identity = normalize_identity(record["identity"])
        recipient = public_recipient(identity)
        if (
            recipient != record["recipient"]
            or key_id(recipient) != record["id"]
            or record["id"] in keys
        ):
            fail("kit_key_mismatch")
        keys[record["id"]] = {
            "identity": identity,
            "recipient": recipient,
            "mac": mac_key(identity, kit["binding"], recipient),
        }
    if type(kit["receipts"]) is not list or len(kit["receipts"]) > MAX_ARCHIVES:
        fail("invalid_kit_receipts")
    receipts, runs = {}, set()
    for record in kit["receipts"]:
        if type(record) is not dict or set(record) != {
            "run",
            "file_id",
            "size",
            "sha256",
            "key",
            "state",
            "generation",
        }:
            fail("invalid_kit_receipt")
        if type(record["key"]) is not str:
            fail("invalid_kit_receipt")
        if (
            type(record["run"]) is not str
            or not OPAQUE.fullmatch(record["run"])
            or record["file_id"] is not None
            and (
                type(record["file_id"]) is not str
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", record["file_id"])
            )
            or type(record["size"]) is not int
            or not 0 < record["size"] <= MAX_CIPHER
            or type(record["sha256"]) is not str
            or not HEX64.fullmatch(record["sha256"])
            or record["key"] not in keys
            or record["state"]
            not in (
                "queued",
                "prepared",
                "uploading",
                "uploaded-unverified",
                "verified",
                "failed",
                "incomplete",
                "uncertain",
                "paused",
            )
            or type(record["generation"]) is not int
            or record["generation"] < 1
        ):
            fail("invalid_kit_receipt")
        if record["sha256"] in receipts or record["run"] in runs:
            fail("conflicting_kit_receipt")
        receipts[record["sha256"]] = record
        runs.add(record["run"])
    receipt_coverage = kit.get("receipt_coverage")
    if receipt_coverage is not None:
        if type(receipt_coverage) is not dict:
            fail("invalid_receipt_coverage")
        if receipt_coverage == {"kind": "none"}:
            if receipts:
                fail("invalid_receipt_coverage")
        else:
            expected = {
                "kind",
                "snapshot",
                "part",
                "parts",
                "total",
                "included",
                "cutoff",
                "complete",
            }
            if (
                set(receipt_coverage) != expected
                or receipt_coverage["kind"] != "snapshot"
                or type(receipt_coverage["snapshot"]) is not str
                or not OPAQUE.fullmatch(receipt_coverage["snapshot"])
                or any(
                    type(receipt_coverage[field]) is not int
                    or not 0 <= receipt_coverage[field] < 2**63
                    for field in ("part", "parts", "total", "included", "cutoff")
                )
                or not 1 <= receipt_coverage["part"] <= receipt_coverage["parts"]
                or receipt_coverage["parts"]
                != max(
                    1, (receipt_coverage["total"] + MAX_ARCHIVES - 1) // MAX_ARCHIVES
                )
                or receipt_coverage["included"] != len(receipts)
                or receipt_coverage["complete"] is not (receipt_coverage["parts"] == 1)
            ):
                fail("invalid_receipt_coverage")
    return kit, keys, receipts


def load_kits(parts):
    if isinstance(parts, bytes):
        return load_kit(parts)
    if (
        type(parts) not in (tuple, list)
        or not 0 < len(parts) <= MAX_KITS
        or sum(len(data) for data in parts) > MAX_KIT_TOTAL
    ):
        fail("kit_count_or_size_limit")
    selected, keys, receipts, runs = None, {}, {}, {}
    inventories = []
    for data in parts:
        kit, new_keys, new_receipts = load_kit(data)
        if selected is not None and kit["binding"] != selected["binding"]:
            fail("conflicting_kit_binding")
        selected = kit if selected is None else selected
        inventories.append(kit.get("receipt_coverage", {"kind": "unpaged"}))
        for identifier, key in new_keys.items():
            if identifier in keys and keys[identifier] != key:
                fail("conflicting_kit_key")
            keys[identifier] = key
        if len(keys) > MAX_KEYS:
            fail("invalid_kit_keys")
        for digest, receipt in new_receipts.items():
            previous = receipts.get(digest)
            if (
                previous is not None
                and (
                    any(
                        previous[field] != receipt[field]
                        for field in ("run", "size", "sha256", "key", "generation")
                    )
                    or previous["file_id"] is not None
                    and receipt["file_id"] is not None
                    and previous["file_id"] != receipt["file_id"]
                )
                or receipt["run"] in runs
                and runs[receipt["run"]] != digest
            ):
                fail("conflicting_kit_receipt")
            if previous is None:
                receipts[digest] = receipt
            elif previous["file_id"] is None and receipt["file_id"] is not None:
                receipts[digest] = dict(previous, file_id=receipt["file_id"])
            runs[receipt["run"]] = digest
    selected = dict(selected, receipt_parts=inventories)
    return selected, keys, receipts


def authenticate_archive(ciphertext, kit, keys, receipts):
    digest = hashlib.sha256(ciphertext).hexdigest()
    pinned = receipts.get(digest)
    if pinned is not None:
        if len(ciphertext) != pinned["size"]:
            fail("ciphertext_pin_mismatch")
        selected = [(pinned["key"], keys[pinned["key"]])]
    else:
        selected = sorted(keys.items())
    for _identifier, key in selected:
        try:
            clear = decrypt(ciphertext, key["identity"])
        except RecoveryError as exc:
            if str(exc) == "age_authentication_failed" and pinned is None:
                continue
            raise
        # Authentication failure is terminal after any successful age decrypt.
        # Never downgrade or try another trust route after a bad v2 tag/context.
        manifest, messages = validate_clear(
            clear,
            binding=kit["binding"],
            recipient=key["recipient"],
            key=key["mac"],
            legacy=pinned is not None,
            run=pinned["run"] if pinned else None,
        )
        return digest, manifest, messages
    fail("no_matching_recovery_key")


def restore_archives(kit_data, ciphertexts, destination):
    kit, keys, receipts = load_kits(kit_data)
    output = Quarantine(destination)
    complete = False
    runs, digests = {}, set()
    total = messages_count = duplicates = count = 0
    try:
        for ciphertext in ciphertexts:
            count += 1
            if count > MAX_ARCHIVES:
                fail("archive_count_limit")
            if (
                not isinstance(ciphertext, bytes)
                or not 0 < len(ciphertext) <= MAX_CIPHER
            ):
                fail("ciphertext_size_limit")
            digest = hashlib.sha256(ciphertext).hexdigest()
            if digest in digests:
                duplicates += 1
                continue
            digest, manifest, messages = authenticate_archive(
                ciphertext, kit, keys, receipts
            )
            run = manifest["run"]
            if run in runs and runs[run] != digest:
                fail("conflicting_archive_run")
            total += sum(len(data) for _path, data in messages)
            if total > MAX_OUTPUT:
                fail("output_size_limit")
            for path, data in messages:
                output.write(run + "/" + path, data)
            runs[run] = digest
            digests.add(digest)
            messages_count += len(messages)
        if not count:
            fail("no_archives")
        summary = {
            "format": "chatmail-recovery-completion",
            "version": 1,
            "binding": kit["binding"],
            "coverage": "capture-windows-not-latest-or-complete",
            "receipt_parts": kit.get(
                "receipt_parts", [kit.get("receipt_coverage", {"kind": "unpaged"})]
            ),
            "runs": [
                {"run": run, "sha256": digest} for run, digest in sorted(runs.items())
            ],
            "messages": messages_count,
            "bytes": total,
            "duplicate_inputs": duplicates,
        }
        output.finish(summary)
        complete = True
        return summary
    finally:
        if not complete:
            try:
                output.incomplete()
            except OSError:
                pass
        output.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Restore authenticated mailbox archives into a new private quarantine; requires Python 3, age and age-keygen."
    )
    kit = parser.add_mutually_exclusive_group(required=True)
    kit.add_argument(
        "--kit",
        action="append",
        help="Private recovery ZIP; repeat to combine historical parts",
    )
    kit.add_argument(
        "--kit-fd",
        type=int,
        action="append",
        help="Private regular file or pipe FD; repeat for parts",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="NEW absolute quarantine directory beneath an existing private parent",
    )
    parser.add_argument(
        "archives",
        nargs="+",
        help="Downloaded encrypted .age files; no network access is used",
    )
    args = parser.parse_args(argv)
    try:
        if len(args.archives) > MAX_ARCHIVES:
            fail("archive_count_limit")
        selectors = args.kit_fd if args.kit_fd is not None else args.kit
        if len(selectors) > MAX_KITS:
            fail("kit_count_or_size_limit")
        data = []
        total = 0
        for selector in selectors:
            if args.kit_fd is not None:
                info = os.fstat(selector)
                if (
                    selector in (1, 2)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                    or not (stat.S_ISREG(info.st_mode) or stat.S_ISFIFO(info.st_mode))
                ):
                    fail("kit_fd_not_private")
                item = read_fd(selector, MAX_KIT)
            else:
                item = read_file(selector, MAX_KIT, private=True)
            total += len(item)
            if total > MAX_KIT_TOTAL:
                fail("kit_count_or_size_limit")
            data.append(item)
        inputs = (read_file(path, MAX_CIPHER) for path in args.archives)
        result = restore_archives(data, inputs, args.output)
        print(
            json.dumps(
                {
                    "state": "complete",
                    "runs": len(result["runs"]),
                    "messages": result["messages"],
                    "duplicate_inputs": result["duplicate_inputs"],
                },
                sort_keys=True,
            )
        )
        return 0
    except RecoveryError as exc:
        print("Recovery failed: " + str(exc), file=sys.stderr)
    except KeyboardInterrupt:
        print("Recovery failed: interrupted", file=sys.stderr)
        return 130
    except Exception:
        print("Recovery failed: input_or_output_error", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
