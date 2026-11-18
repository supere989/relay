"""Frozen standalone primitives: standard vectors and filesystem boundaries."""

import io
import os
import stat
import zipfile

import pytest

from chatmaild.backup import recovery_tool as tool
from chatmaild.tests.test_backup import age_key


def test_hkdf_rfc5869_sha256_case_one():
    actual = tool.hkdf(
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    assert (
        actual.hex()
        == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b"[]"])
def test_json_rejects_ambiguous_or_nonintegral_shapes(data):
    with pytest.raises(tool.RecoveryError):
        tool.json_object(data)


def test_canonical_json_and_mac_domains():
    assert tool.canonical({"b": 2, "a": "\u00e9"}) == b'{"a":"\\u00e9","b":2}'
    identity, recipient = age_key()
    normalized = tool.normalize_identity(identity)
    assert tool.public_recipient(normalized) == recipient
    one = tool.mac_key(normalized, "1" * 32, recipient)
    two = tool.mac_key(normalized, "2" * 32, recipient)
    different_contexts = one != two
    different_manifests = tool.manifest_mac(b'{"a":1}', one) != tool.manifest_mac(
        b'{"a":2}', one
    )
    assert different_contexts and different_manifests
    with pytest.raises(tool.RecoveryError):
        tool.normalize_identity(identity + identity)


def components(*, compression=zipfile.ZIP_STORED, link=False):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name in sorted(tool.COMPONENTS):
            item = zipfile.ZipInfo(name)
            item.compress_type = compression
            item.external_attr = (
                (stat.S_IFLNK if link else stat.S_IFREG) | 0o600
            ) << 16
            archive.writestr(item, b"synthetic")
    return output.getvalue()


def test_zip_preflight_rejects_compression_links_and_malformed_directory():
    assert set(tool.zip_components(components())) == tool.COMPONENTS
    for data in (
        components(compression=zipfile.ZIP_DEFLATED),
        components(link=True),
        components()[:-3],
    ):
        with pytest.raises(tool.RecoveryError):
            tool.zip_components(data)


def test_private_descriptor_output_and_completion_last(tmp_path):
    output = tmp_path / "quarantine"
    destination = tool.Quarantine(str(output))
    try:
        destination.write("1" * 32 + "/.Sent/cur/message:2,S", b"synthetic gzip bytes")
        assert (output / ".incomplete").exists()
        destination.finish({"format": "chatmail-recovery-completion", "version": 1})
    finally:
        destination.close()
    assert not (output / ".incomplete").exists()
    assert (output / "completion.json").is_file()
    assert output.stat().st_mode & 0o777 == 0o700
    with pytest.raises(tool.RecoveryError, match="output_exists"):
        tool.Quarantine(str(output))


def test_shared_symlink_mailbox_and_known_live_output_rejected(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    with pytest.raises(tool.RecoveryError, match="output_parent_not_private"):
        tool.Quarantine(str(shared / "new"))
    (tmp_path / "link").symlink_to(shared, target_is_directory=True)
    with pytest.raises((tool.RecoveryError, OSError)):
        tool.Quarantine(str(tmp_path / "link" / "new"))
    (tmp_path / "password").write_bytes(b"synthetic marker")
    with pytest.raises(tool.RecoveryError, match="live_mailbox_destination"):
        tool.Quarantine(str(tmp_path / "new"))
    with pytest.raises(tool.RecoveryError, match="live_mailbox_destination"):
        tool.Quarantine("/home/vmail/never-create-this")
    assert not (tmp_path / "new").exists()


def test_incomplete_output_is_private_on_write_error(tmp_path):
    output = tmp_path / "incomplete"
    destination = tool.Quarantine(str(output))
    try:
        with pytest.raises(tool.RecoveryError):
            destination.write("../escape", b"not written")
        destination.incomplete()
    finally:
        destination.close()
    assert (output / ".incomplete").exists() and not (
        output / "completion.json"
    ).exists()
    assert not (tmp_path.parent / "escape").exists()
    assert stat.S_ISDIR(os.stat(output).st_mode)


def test_created_directory_entries_are_synced_before_completion(tmp_path, monkeypatch):
    original = tool.os.fsync
    synced = []

    def sync(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            synced.append((info.st_dev, info.st_ino))
        original(fd)

    monkeypatch.setattr(tool.os, "fsync", sync)
    output = tmp_path / "new"
    destination = tool.Quarantine(str(output))
    try:
        destination.write("1" * 32 + "/.Sent/cur/message:2,S", b"private fixture")
        for parent in (
            tmp_path,
            output,
            output / ("1" * 32),
            output / ("1" * 32) / ".Sent",
            output / ("1" * 32) / ".Sent" / "cur",
        ):
            info = parent.stat()
            assert (info.st_dev, info.st_ino) in synced
        assert not (output / "completion.json").exists()
        destination.finish({"version": 1})
    finally:
        destination.close()


def test_optional_proxy_cannot_buffer_private_recovery_to_disk():
    from importlib.resources import files

    template = (
        files("chatmaild.backup")
        .joinpath("integration/nginx-archive.conf.example")
        .read_text()
    )
    assert "proxy_buffering off;" in template
    assert "proxy_max_temp_file_size 0;" in template
    assert "proxy_cache off;" in template
    assert "proxy_store off;" in template
