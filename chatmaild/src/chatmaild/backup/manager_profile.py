"""Fail-closed whole-profile encryption boundary for the optional chat bot.

The RPC server cannot encrypt all persistent account/blob state itself. This
module accepts only the configured gocryptfs mount (or explicit synthetic
tmpfs fixtures). Unlocking is a separate, fixed broker operation, never a
plaintext-directory fallback.
"""

import ctypes
import fcntl
import hashlib
import json
import os
import re
import resource
import secrets
import stat
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .model import ArchiveError

VERSION = "2.69.0"
EPOCH = re.compile(r"[a-f0-9]{32}\Z")


def _unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def mount_record(path, text=None):
    mount_id = None
    if text is None:
        text = Path("/proc/self/mountinfo").read_text()
        fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = Path("/proc/self/fdinfo/" + str(fd)).read_text()
            match = re.search(r"(?m)^mnt_id:\s*([0-9]+)$", info)
            if match is None:
                raise ArchiveError("manager_profile_mount_missing")
            mount_id = match[1]
        finally:
            os.close(fd)
    matches = []
    target = str(Path(path).absolute())
    for line in text.splitlines():
        fields = line.split()
        if "-" not in fields:
            continue
        separator = fields.index("-")
        if separator < 6 or len(fields) < separator + 4:
            continue
        point = _unescape(fields[4])
        if mount_id is not None and fields[0] != mount_id:
            continue
        if target == point or target.startswith(point.rstrip("/") + "/"):
            matches.append(
                (
                    len(point),
                    point,
                    fields[separator + 1],
                    _unescape(fields[separator + 2]),
                )
            )
    if not matches:
        raise ArchiveError("manager_profile_mount_missing")
    return max(matches)[1:]


def private_directory(path):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ArchiveError("manager_profile_symlink")
    try:
        info = path.stat()
    except OSError:
        raise ArchiveError("manager_profile_unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ArchiveError("manager_profile_not_private")
    if path.resolve() != path:
        raise ArchiveError("manager_profile_symlink")
    return path


class Profile:
    def __init__(self, mount, backing=None, *, synthetic=False, state=None):
        self.mount = Path(mount).absolute()
        self.backing = Path(backing).absolute() if backing is not None else None
        self.synthetic = synthetic
        self.state = state

    def check(self, expected=None):
        if self.state is not None:
            self.state.check()
            if self.state.mount not in self.mount.parents:
                raise ArchiveError("manager_profile_path_denied")
        path = private_directory(self.mount)
        point, filesystem, source = mount_record(path)
        if self.synthetic:
            if filesystem != "tmpfs" or not str(path).startswith("/tmp/"):
                raise ArchiveError("manager_synthetic_profile_denied")
        elif self.state is None:
            if self.backing is None:
                raise ArchiveError("manager_profile_backing_missing")
            backing = private_directory(self.backing)
            if (
                point != str(path)
                or filesystem != "fuse.gocryptfs"
                or source != str(backing)
            ):
                raise ArchiveError("manager_profile_not_encrypted")
            config = backing / "gocryptfs.conf"
            info = config.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise ArchiveError("manager_profile_config_denied")
        root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(
                ".archive-manager-epoch", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root
            )
            try:
                info = os.fstat(fd)
                raw = os.read(fd, 65)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise ArchiveError("manager_profile_epoch_denied")
            finally:
                os.close(fd)
            try:
                epoch = raw.decode("ascii")
            except UnicodeError:
                raise ArchiveError("manager_profile_epoch_denied") from None
            if not EPOCH.fullmatch(epoch) or expected is not None and epoch != expected:
                raise ArchiveError("manager_profile_epoch_changed")
            fresh = os.stat(path, follow_symlinks=False)
            held = os.fstat(root)
            if (fresh.st_dev, fresh.st_ino) != (held.st_dev, held.st_ino):
                raise ArchiveError("manager_profile_namespace_changed")
            return epoch
        except (OSError, ValueError):
            raise ArchiveError("manager_profile_unavailable") from None
        finally:
            os.close(root)

    def initialize(self):
        # Explicit enrollment only. A worker never creates/repairs an epoch.
        private_directory(self.mount)
        point, filesystem, source = mount_record(self.mount)
        if self.state is not None:
            self.state.check()
            valid = self.state.mount in self.mount.parents
        elif self.synthetic:
            valid = filesystem == "tmpfs" and str(self.mount).startswith("/tmp/")
        else:
            backing = private_directory(self.backing)
            valid = (
                point == str(self.mount)
                and filesystem == "fuse.gocryptfs"
                and source == str(backing)
            )
        if not valid:
            raise ArchiveError("manager_profile_not_encrypted")
        root = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                fd = os.open(
                    ".archive-manager-epoch",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root,
                )
            except FileExistsError:
                fd = None
            if fd is not None:
                try:
                    os.write(fd, secrets.token_hex(16).encode("ascii"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
            try:
                os.mkdir(".rpc-tmp", 0o700, dir_fd=root)
            except FileExistsError:
                pass
            private_directory(self.mount / ".rpc-tmp")
            try:
                os.mkdir("accounts", 0o700, dir_fd=root)
            except FileExistsError:
                pass
            private_directory(self.mount / "accounts")
            os.fsync(root)
        finally:
            os.close(root)
        return self.check()

    def accounts_path(self, *, initialize=False):
        self.check()
        path = private_directory(self.mount / "accounts")
        index = path / "accounts.toml"
        if not initialize:
            try:
                info = index.lstat()
            except OSError:
                raise ArchiveError("manager_rpc_account_state_missing") from None
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise ArchiveError("manager_rpc_account_state_denied")
        elif not index.exists() and any(path.iterdir()):
            raise ArchiveError("manager_rpc_account_state_denied")
        return path

    @contextmanager
    def owner(self):
        """Exclusive SDK/profile opener, shared by serve and offline actions.

        The lock is acquired before RPC opens or interrupted issuance recovery.
        It contains no PID/credential data and lives in the encrypted profile.
        This also protects explicit initial enrollment before its epoch exists.
        """
        if self.state is not None:
            self.state.check()
        private_directory(self.mount)
        parent = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = None
        try:
            descriptor = os.open(
                ".rpc-owner.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise ArchiveError("manager_profile_owner_lock_denied")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ArchiveError("manager_profile_busy") from None
            current = os.stat(self.mount, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (
                os.fstat(parent).st_dev,
                os.fstat(parent).st_ino,
            ):
                raise ArchiveError("manager_profile_namespace_changed")
            if self.state is not None:
                self.state.check()
            yield descriptor
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)


def verify_server(path, checksum):
    return verify_binary(path, checksum, VERSION)


def verify_binary(path, checksum, version):
    if type(checksum) is not str or not re.fullmatch(r"[a-f0-9]{64}", checksum):
        raise ArchiveError("manager_rpc_checksum_required")
    path = Path(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o022
        or info.st_uid not in (0, os.geteuid())
    ):
        raise ArchiveError("manager_rpc_binary_denied")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != checksum:
        raise ArchiveError("manager_rpc_checksum_mismatch")
    result = subprocess.run(
        [str(path), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    output = result.stdout + result.stderr
    if (
        result.returncode
        or len(output) > 4096
        or not re.search(
            rb"(?<![0-9.])" + re.escape(version.encode("ascii")) + rb"(?![0-9.])",
            output,
        )
    ):
        raise ArchiveError("manager_rpc_version_mismatch")
    return str(path)


def no_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def mount_id(fd):
    value = Path("/proc/self/fdinfo/" + str(fd)).read_text()
    match = re.search(r"(?m)^mnt_id:\s*([0-9]+)$", value)
    if match is None:
        raise ArchiveError("manager_state_mount_missing")
    return int(match[1])


class StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("seconds", ctypes.c_int64),
        ("nanoseconds", ctypes.c_uint32),
        ("reserved", ctypes.c_int32),
    ]


class Statx(ctypes.Structure):
    """Linux UAPI statx layout, including its reserved expansion area."""

    _fields_ = [
        ("mask", ctypes.c_uint32),
        ("block_size", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64),
        ("links", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("reserved0", ctypes.c_uint16),
        ("inode", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64),
        ("attributes_mask", ctypes.c_uint64),
        ("access", StatxTimestamp),
        ("birth", StatxTimestamp),
        ("change", StatxTimestamp),
        ("modified", StatxTimestamp),
        ("rdev_major", ctypes.c_uint32),
        ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32),
        ("dev_minor", ctypes.c_uint32),
        ("mount_id", ctypes.c_uint64),
        ("dio_mem_align", ctypes.c_uint32),
        ("dio_offset_align", ctypes.c_uint32),
        ("subvolume", ctypes.c_uint64),
        ("atomic_min", ctypes.c_uint32),
        ("atomic_max", ctypes.c_uint32),
        ("atomic_segments", ctypes.c_uint32),
        ("dio_read_align", ctypes.c_uint32),
        ("atomic_max_opt", ctypes.c_uint32),
        ("reserved2", ctypes.c_uint32),
        ("reserved3", ctypes.c_uint64 * 8),
    ]


def unique_mount_id(fd):
    """Require the kernel's non-reused mount ID; ordinary mnt_id is diagnostic.

    No syscall-number, marker, nonce or ordinary-ID fallback is acceptable on
    a libc/kernel lacking STATX_MNT_ID_UNIQUE. AT_EMPTY_PATH binds the query
    to the held directory descriptor, not a replaceable pathname.
    """
    try:
        function = ctypes.CDLL(None, use_errno=True).statx
        function.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(Statx),
        )
        function.restype = ctypes.c_int
        result = Statx()
        if (
            ctypes.sizeof(result) != 256
            or function(fd, b"", 0x1000, 0x4000, ctypes.byref(result)) != 0
            or not result.mask & 0x4000
            or result.mount_id == 0
        ):
            raise ArchiveError("manager_unique_mount_id_unavailable")
        return result.mount_id
    except (AttributeError, OSError):
        raise ArchiveError("manager_unique_mount_id_unavailable") from None


def root_path(path, *, leaf_mode=None):
    """No symlink or untrusted ancestor can replace a root attestation."""
    path = Path(path).absolute()
    current = Path("/")
    for component in path.parts[1:]:
        current = current / component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ArchiveError("manager_state_root_path_denied")
    if leaf_mode is not None and stat.S_IMODE(info.st_mode) != leaf_mode:
        raise ArchiveError("manager_state_root_path_denied")
    return path


class StateGuard:
    """Kernel/DAC-protected shared state; markers alone never authorize it.

    The root helper attests its pre-mount mode-0000 underlay and private
    ciphertext root. Unprivileged services validate that root-owned statement
    against their actual kernel mount identity. Lazy detach cannot expose a
    writable plaintext replacement to these services. Root compromise or an
    administrator deliberately changing those protections is outside this
    authority boundary.
    """

    def __init__(self, policy, *, synthetic=False):
        if type(policy) is not dict or not {"mount", "epoch", "uid"} <= set(policy):
            raise ArchiveError("manager_state_policy_required")
        self.mount = Path(policy["mount"]).absolute()
        self.epoch = policy["epoch"]
        self.uid = policy["uid"]
        self.gid = policy.get("gid", os.getegid() if synthetic else None)
        self.attestation = (
            Path(policy["attestation"]).absolute() if "attestation" in policy else None
        )
        self.backing = policy.get("backing")
        self.synthetic = synthetic
        self._refusals = 0
        self._refusals_lock = threading.Lock()
        self._mount_identity = None
        self._identity_lock = threading.Lock()
        if (
            not EPOCH.fullmatch(self.epoch)
            or type(self.uid) is not int
            or self.uid != os.geteuid()
            or type(self.gid) is not int
            or self.gid < 0
            or not synthetic
            and (self.uid == 0 or self.attestation is None or self.backing is None)
        ):
            raise ArchiveError("manager_state_policy_denied")
        self.check()

    @property
    def refusals(self):
        with self._refusals_lock:
            return self._refusals

    def record_refusal(self, amount=1):
        with self._refusals_lock:
            self._refusals += amount

    def take_refusals(self):
        with self._refusals_lock:
            count, self._refusals = self._refusals, 0
            return count

    def _pin_mount_identity(self, boot_id, unique_id):
        with self._identity_lock:
            identity = (boot_id, unique_id)
            if self._mount_identity is None:
                self._mount_identity = identity
            elif self._mount_identity != identity:
                raise ArchiveError("manager_state_mount_changed")

    def check(self):
        fd = None
        try:
            private_directory(self.mount)
            fd = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            point, filesystem, source = mount_record(self.mount)
            if self.synthetic:
                if filesystem != "tmpfs" or not str(self.mount).startswith("/tmp/"):
                    raise ArchiveError("manager_state_not_encrypted")
            else:
                status = Path("/proc/self/status").read_text()
                if not re.search(r"(?m)^CapEff:\s*0+$", status) or not re.search(
                    r"(?m)^NoNewPrivs:\s*1$", status
                ):
                    raise ArchiveError("manager_state_privilege_denied")
                path = root_path(self.attestation)
                handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    info = os.fstat(handle)
                    raw = os.read(handle, 8193)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != 0
                        or info.st_mode & 0o022
                        or len(raw) > 8192
                    ):
                        raise ArchiveError("manager_state_attestation_denied")
                finally:
                    os.close(handle)
                value = json.loads(raw)
                boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                unique_id = unique_mount_id(fd)
                expected = {
                    "version": 2,
                    "boot_id": boot_id,
                    "namespace": os.stat("/proc/self/ns/mnt").st_ino,
                    "mount_id": mount_id(fd),
                    "mount_id_unique": unique_id,
                    "device": os.fstat(fd).st_dev,
                    "mount": str(self.mount),
                    "backing": self.backing,
                    "uid": self.uid,
                    "gid": self.gid,
                    "epoch": self.epoch,
                    "underlay_uid": 0,
                    "underlay_mode": 0,
                    "ciphertext_root": str(Path(self.backing).parent),
                    "ciphertext_uid": 0,
                    "ciphertext_mode": 448,
                    "backing_uid": self.uid,
                    "backing_gid": self.gid,
                    "backing_mode": 448,
                }
                if (
                    value != expected
                    or point != str(self.mount)
                    or filesystem != "fuse.gocryptfs"
                    or source != self.backing
                ):
                    raise ArchiveError("manager_state_attestation_denied")
                if os.fstat(fd).st_gid != self.gid:
                    raise ArchiveError("manager_state_attestation_denied")
            epoch_fd = os.open(
                ".archive-state-epoch", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd
            )
            try:
                info = os.fstat(epoch_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != self.uid
                    or info.st_mode & 0o077
                    or os.read(epoch_fd, 65).decode("ascii") != self.epoch
                ):
                    raise ArchiveError("manager_state_epoch_changed")
            finally:
                os.close(epoch_fd)
            fresh = os.stat(self.mount, follow_symlinks=False)
            held = os.fstat(fd)
            if (fresh.st_dev, fresh.st_ino) != (held.st_dev, held.st_ino):
                raise ArchiveError("manager_state_namespace_changed")
            if not self.synthetic:
                self._pin_mount_identity(boot_id, unique_id)
            return True
        except (OSError, ValueError, TypeError, KeyError):
            self.record_refusal()
            raise ArchiveError("manager_state_unavailable") from None
        except ArchiveError:
            self.record_refusal()
            raise
        finally:
            if fd is not None:
                os.close(fd)

    @contextmanager
    def parent(self, path, *, create=False):
        self.check()
        target = Path(path).absolute()
        try:
            relative = target.relative_to(self.mount)
        except ValueError:
            raise ArchiveError("manager_state_path_denied") from None
        if not relative.parts or any(part in (".", "..") for part in relative.parts):
            raise ArchiveError("manager_state_path_denied")
        current = os.open(self.mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in relative.parts[:-1]:
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current)
                        os.fsync(current)
                    except FileExistsError:
                        pass
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                os.close(current)
                current = child
                info = os.fstat(current)
                if info.st_uid != self.uid or info.st_mode & 0o077:
                    raise ArchiveError("manager_state_directory_denied")
            self.check()
            yield current, relative.name
        finally:
            os.close(current)


def mount_state(policy, broker, reference, *, initialize=False):
    """Scoped root mount helper. Never forced/lazy/automatic unmount.

    The ordinary application cannot traverse either underlay or ciphertext
    root. After detach kernel permissions continue to protect both without
    waiting for a polling watcher. This helper is the only privileged role;
    RPC and application workers never run here.
    """
    if (
        os.geteuid() != 0
        or type(policy.get("uid")) is not int
        or policy["uid"] <= 0
        or type(policy.get("gid")) is not int
        or policy["gid"] <= 0
    ):
        raise ArchiveError("manager_mount_helper_privilege_denied")
    no_core_dumps()
    mount = root_path(policy["mount"], leaf_mode=0)
    backing = Path(policy["backing"]).absolute()
    # The service owns this direct leaf so gocryptfs PreserveOwner returns
    # correct create attributes. Its enclosing root-only container prevents
    # the application from traversing ciphertext/config through ordinary paths.
    ciphertext_root = root_path(backing.parent, leaf_mode=0o700)
    info = backing.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != policy["uid"]
        or info.st_gid != policy["gid"]
        or stat.S_IMODE(info.st_mode) != 0o700
        or backing.resolve() != backing
    ):
        raise ArchiveError("manager_mount_backing_denied")
    if initialize:
        if any(backing.iterdir()):
            raise ArchiveError("manager_mount_backing_not_empty")
    else:
        info = (backing / "gocryptfs.conf").lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, policy["uid"])
            or info.st_mode & 0o077
        ):
            raise ArchiveError("manager_mount_backing_denied")
    attestation = Path(policy["attestation"]).absolute()
    root_path(attestation.parent)
    if attestation.exists() or attestation.is_symlink():
        raise ArchiveError("manager_mount_attestation_exists")
    epoch = policy["epoch"]
    if not EPOCH.fullmatch(epoch):
        raise ArchiveError("manager_state_policy_denied")
    root_path(policy["gocryptfs"])
    server = verify_binary(policy["gocryptfs"], policy["gocryptfs_sha256"], "2.6.1")
    underlying = os.open(mount, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    value = broker.get(reference)
    if (
        type(value) is not dict
        or set(value) != {"gocryptfs_passphrase"}
        or type(value["gocryptfs_passphrase"]) is not str
        or not 32 <= len(value["gocryptfs_passphrase"]) <= 1024
        or "\n" in value["gocryptfs_passphrase"]
    ):
        os.close(underlying)
        raise ArchiveError("manager_mount_key_unavailable")
    read, write = os.pipe()
    process = None
    try:
        os.write(write, value["gocryptfs_passphrase"].encode("utf-8") + b"\n")
        os.close(write)
        write = -1
        if initialize:
            result = subprocess.run(
                [server, "-init", "-passfile", "/dev/fd/" + str(read), str(backing)],
                pass_fds=(read,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
            if result.returncode:
                raise ArchiveError("manager_mount_initialize_failed")
            os.close(read)
            read, write = os.pipe()
            os.write(write, value["gocryptfs_passphrase"].encode("utf-8") + b"\n")
            os.close(write)
            write = -1
        process = subprocess.Popen(
            [
                server,
                "-fg",
                "-passfile",
                "/dev/fd/" + str(read),
                "-allow_other",
                "-ko",
                "default_permissions,nodev,nosuid",
                "-noexec",
                "-fsname",
                str(backing),
                str(backing),
                str(mount),
            ],
            pass_fds=(read,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        ready = False
        while time.monotonic() < deadline and process.poll() is None:
            root = os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                point, filesystem, source = mount_record(mount)
                info = os.fstat(root)
                if (
                    mount_id(root) != mount_id(underlying)
                    and point == str(mount)
                    and filesystem == "fuse.gocryptfs"
                    and source == str(backing)
                    and info.st_uid == policy["uid"]
                    and info.st_gid == policy["gid"]
                    and not info.st_mode & 0o077
                ):
                    flags = (
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        if initialize
                        else os.O_RDONLY | os.O_NOFOLLOW
                    )
                    fd = os.open(".archive-state-epoch", flags, 0o600, dir_fd=root)
                    try:
                        if initialize:
                            os.fchown(fd, policy["uid"], policy["gid"])
                            os.write(fd, epoch.encode("ascii"))
                            os.fsync(fd)
                            os.fsync(root)
                        elif os.read(fd, 65).decode("ascii") != epoch:
                            raise ArchiveError("manager_state_epoch_changed")
                    finally:
                        os.close(fd)
                    document = {
                        "version": 2,
                        "boot_id": Path("/proc/sys/kernel/random/boot_id")
                        .read_text()
                        .strip(),
                        "namespace": os.stat("/proc/self/ns/mnt").st_ino,
                        "mount_id": mount_id(root),
                        "mount_id_unique": unique_mount_id(root),
                        "device": info.st_dev,
                        "mount": str(mount),
                        "backing": str(backing),
                        "uid": policy["uid"],
                        "gid": policy["gid"],
                        "epoch": epoch,
                        "underlay_uid": 0,
                        "underlay_mode": 0,
                        "ciphertext_root": str(ciphertext_root),
                        "ciphertext_uid": 0,
                        "ciphertext_mode": 448,
                        "backing_uid": policy["uid"],
                        "backing_gid": policy["gid"],
                        "backing_mode": 448,
                    }
                    encoded = json.dumps(
                        document, sort_keys=True, separators=(",", ":")
                    ).encode("ascii")
                    fd = os.open(
                        attestation,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o644,
                    )
                    try:
                        os.fchmod(fd, 0o644)
                        os.write(fd, encoded)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    ready = True
                    break
            finally:
                os.close(root)
            time.sleep(0.05)
        if not ready:
            raise ArchiveError("manager_mount_start_failed")
        # Independent mount service remains alive even when RPC is restarted.
        result = process.wait()
        if result:
            raise ArchiveError("manager_mount_process_failed")
    finally:
        os.close(underlying)
        os.close(read)
        if write >= 0:
            os.close(write)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def main(argv=None):
    import argparse

    from .credentials import Broker

    parser = argparse.ArgumentParser(
        description="Explicit scoped encrypted archive-state mount helper; never force/lazy-unmount"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("command", choices=("new-key", "mount", "enroll-state"))
    args = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            root_path(args.config)
        raw = Path(args.config).read_bytes()
        if len(raw) > 65536:
            raise ArchiveError("config_limit")
        config = json.loads(raw)
        policy = config["state_storage"]
        broker = Broker(config["broker_argv"])
        if os.geteuid() == 0:
            root_path(config["broker_argv"][0])
        if args.command == "new-key":
            result = broker.call("manager-storage-key")
            print(json.dumps({"storage_key_ref": result["ref"]}))
        else:
            mount_state(
                policy,
                broker,
                policy["unlock_ref"],
                initialize=args.command == "enroll-state",
            )
        return 0
    except ArchiveError as exc:
        print(json.dumps({"error": exc.reason}))
    except Exception:
        print('{"error":"manager_state_helper_failed"}')
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
