"""Packaging checks run on the actual asset ZIP, including installed wheels."""

import hashlib
import io
import json
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chatmaild.backup.manager_packaging import ASSETS, app_bytes, build_app
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_protocol import context


def test_reproducible_actual_xdc_contains_local_assets_and_valid_icon():
    bootstrap = context(Ed25519PrivateKey.generate())
    first = app_bytes(bootstrap)
    assert first == app_bytes(bootstrap)
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert set(archive.namelist()) == set(ASSETS) | {"bootstrap.js", "icon.png"}
        assert "webxdc.js" not in archive.namelist()
        assert archive.read("icon.png").startswith(b"\x89PNG\r\n\x1a\n")
        assert b'name = "Archive Manager"' in archive.read("manifest.toml")
        assert json.dumps(bootstrap["public_key"]).encode() in archive.read(
            "bootstrap.js"
        )
        for entry in archive.infolist():
            assert entry.date_time == (1980, 1, 1, 0, 0, 0)
            assert entry.external_attr >> 16 == 0o100644
            assert entry.compress_type == zipfile.ZIP_STORED
        assert archive.namelist() == sorted(archive.namelist())


def test_exclusive_output_and_context_change_do_not_reuse_an_instance(tmp_path):
    bootstrap = context(Ed25519PrivateKey.generate())
    output = tmp_path / "manager.xdc"
    digest = build_app(bootstrap, output)
    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    with pytest.raises(FileExistsError):
        build_app(bootstrap, output)
    with pytest.raises(ArchiveError):
        build_app(bootstrap, tmp_path / "wrong.zip")
    assert app_bytes({**bootstrap, "instance": "f" * 32}) != output.read_bytes()


def test_private_context_fields_cannot_enter_the_app():
    bootstrap = context(Ed25519PrivateKey.generate())
    for field in ("secret_key", "credential_ref", "password", "mailbox", "token"):
        with pytest.raises(ArchiveError):
            app_bytes({**bootstrap, field: "forbidden"})


def test_runtime_assets_never_fetch_or_embed_remote_code():
    with zipfile.ZipFile(
        io.BytesIO(app_bytes(context(Ed25519PrivateKey.generate())))
    ) as archive:
        html = archive.read("index.html").decode()
        assert "connect-src 'none'" in html and "frame-src 'none'" in html
        for name in ("app.js", "protocol.js"):
            source = archive.read(name).decode()
            for api in (
                "fetch(",
                "XMLHttpRequest",
                "WebSocket",
                "EventSource",
                "innerHTML",
                "joinRealtimeChannel",
                "selfAddr",
                "isAppSender",
                "isBroadcast",
            ):
                assert api not in source
