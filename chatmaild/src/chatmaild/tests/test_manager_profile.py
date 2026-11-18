"""Unit guards; synthetic mount records are not a physical FUSE proof."""

import hashlib
import threading
from types import SimpleNamespace

import pytest

from chatmaild.backup import manager_profile as profile
from chatmaild.backup.model import ArchiveError


def test_mount_record_prefers_confined_mount_and_decodes_kernel_paths():
    text = "1 0 8:1 / / rw - ext4 /dev/disk rw\n2 1 0:1 / /private\\040state rw - fuse.gocryptfs /cipher\\040store rw\n"
    assert profile.mount_record("/private state/bot", text) == (
        "/private state",
        "fuse.gocryptfs",
        "/cipher store",
    )
    assert profile.mount_record("/ordinary", text)[1] == "ext4"


def test_synthetic_epoch_is_stable_and_changed_epoch_refuses(tmp_path, monkeypatch):
    root = tmp_path / "profile"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(
        profile, "mount_record", lambda _path: ("/tmp", "tmpfs", "tmpfs")
    )
    guard = profile.Profile(root, synthetic=True)
    epoch = guard.initialize()
    assert guard.initialize() == epoch and guard.check(epoch) == epoch
    with pytest.raises(ArchiveError, match="manager_profile_epoch_changed"):
        guard.check("f" * 32 if epoch != "f" * 32 else "e" * 32)
    (root / ".archive-manager-epoch").unlink()
    with pytest.raises(ArchiveError, match="manager_profile_unavailable"):
        guard.check(epoch)
    assert not (root / ".archive-manager-epoch").exists()


@pytest.mark.parametrize(
    "kind", ["ordinary", "wrong-source", "wrong-point", "shared", "symlink"]
)
def test_unprotected_profile_never_creates_epoch(tmp_path, monkeypatch, kind):
    root = tmp_path / "profile"
    backing = tmp_path / "backing"
    root.mkdir(mode=0o700)
    backing.mkdir(mode=0o700)
    point, filesystem, source = str(root), "fuse.gocryptfs", str(backing)
    if kind == "ordinary":
        filesystem = "ext4"
    elif kind == "wrong-source":
        source = "/other"
    elif kind == "wrong-point":
        point = str(tmp_path)
    elif kind == "shared":
        root.chmod(0o755)
    else:
        root.rmdir()
        root.symlink_to(backing, target_is_directory=True)
    monkeypatch.setattr(
        profile, "mount_record", lambda _path: (point, filesystem, source)
    )
    with pytest.raises(ArchiveError):
        profile.Profile(root, backing).initialize()
    assert not (backing / ".archive-manager-epoch").exists()
    assert not (root / ".archive-manager-epoch").exists()


@pytest.mark.parametrize("version_stream", ["stdout", "stderr"])
def test_rpc_server_digest_precedes_version_execution(
    tmp_path, monkeypatch, version_stream
):
    path = tmp_path / "server"
    path.write_bytes(b"synthetic binary")
    path.chmod(0o700)
    calls = []
    output = {"stdout": b"", "stderr": b""}
    output[version_stream] = b"deltachat-rpc-server 2.69.0\n"
    monkeypatch.setattr(
        profile.subprocess,
        "run",
        lambda argv, **_kwargs: (
            calls.append(argv) or SimpleNamespace(returncode=0, **output)
        ),
    )
    with pytest.raises(ArchiveError, match="manager_rpc_checksum_mismatch"):
        profile.verify_server(path, "0" * 64)
    assert not calls
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
    assert profile.verify_server(path, checksum) == str(path)
    assert calls == [[str(path), "--version"]]


@pytest.mark.parametrize("supported", [True, False])
def test_unique_mount_id_requires_kernel_result_mask(monkeypatch, supported):
    calls = []

    class Function:
        def __call__(self, descriptor, path, flags, mask, result):
            calls.append((descriptor, path, flags, mask))
            result._obj.mask = 0x4000 if supported else 0x1000
            result._obj.mount_id = 987654321
            return 0

    monkeypatch.setattr(
        profile.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: SimpleNamespace(statx=Function()),
    )
    assert profile.ctypes.sizeof(profile.Statx) == 256
    if supported:
        assert profile.unique_mount_id(17) == 987654321
    else:
        with pytest.raises(ArchiveError, match="manager_unique_mount_id_unavailable"):
            profile.unique_mount_id(17)
    assert calls == [(17, b"", 0x1000, 0x4000)]


def test_missing_libc_statx_has_no_ordinary_mount_id_fallback(monkeypatch):
    monkeypatch.setattr(
        profile.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace()
    )
    with pytest.raises(ArchiveError, match="manager_unique_mount_id_unavailable"):
        profile.unique_mount_id(17)


def test_guard_lifetime_pins_unique_mount_not_reusable_ordinary_id():
    guard = profile.StateGuard.__new__(profile.StateGuard)
    guard._mount_identity = None
    guard._identity_lock = threading.Lock()
    guard._pin_mount_identity("boot-a", 111)
    guard._pin_mount_identity("boot-a", 111)  # RPC restart on this mount is fine.
    with pytest.raises(ArchiveError, match="manager_state_mount_changed"):
        guard._pin_mount_identity("boot-a", 112)
    with pytest.raises(ArchiveError, match="manager_state_mount_changed"):
        guard._pin_mount_identity("boot-b", 111)
    assert guard._mount_identity == ("boot-a", 111)
