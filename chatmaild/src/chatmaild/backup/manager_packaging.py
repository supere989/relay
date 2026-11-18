"""Reproducible public-context Webxdc packaging; never registers or sends it."""

import argparse
import hashlib
import importlib.resources
import io
import json
import struct
import zipfile
import zlib
from pathlib import Path

from .manager_protocol import encode_json, validate_bootstrap
from .model import ArchiveError

ASSETS = (
    "index.html",
    "style.css",
    "protocol.js",
    "verify-worker.js",
    "app.js",
    "icon.svg",
    "manifest.toml",
    "vendor/nacl-fast.min.js",
    "vendor/LICENSE",
    "vendor/provenance.json",
)
VENDOR_VERSION = "1.0.3"
VENDOR_COMMIT = "5bf1ff5fa15e89ae249401b0d5aa54c5c5955041"
VENDOR_SHA256 = {
    "nacl-fast.min.js": "3ec535c004aeeb225785d8e93fb33bf99f52e399bd7dfc01969b5629baea5131",
    "LICENSE": "88d9b4eb60579c191ec391ca04c16130572d7eedc4a86daa58bf28c6e14c9bcd",
}


def icon_png():
    """A local 128px archive icon; no external renderer or downloaded image."""
    rows = bytearray()
    for y in range(128):
        rows.append(0)
        for x in range(128):
            color = (29, 64, 117)
            if 28 <= x < 100 and 35 <= y < 98 or 23 <= x < 105 and 27 <= y < 42:
                color = (240, 246, 255)
            if 53 <= x < 75 and 53 <= y < 61:
                color = (29, 64, 117)
            rows.extend(color)

    def chunk(kind, content):
        return (
            struct.pack("!I", len(content))
            + kind
            + content
            + struct.pack("!I", zlib.crc32(kind + content))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!2I5B", 128, 128, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(rows), 0))
        + chunk(b"IEND", b"")
    )


def app_bytes(bootstrap):
    """Return deterministic ZIP bytes for a validated *public* bootstrap."""
    validate_bootstrap(bootstrap)
    root = importlib.resources.files("chatmaild.backup").joinpath("archive_manager")
    assets = {name: root.joinpath(name).read_bytes() for name in ASSETS}
    provenance = json.loads(assets["vendor/provenance.json"])
    if (
        provenance.get("version") != VENDOR_VERSION
        or provenance.get("commit") != VENDOR_COMMIT
    ):
        raise ArchiveError("manager_vendor_integrity")
    for name in ("nacl-fast.min.js", "LICENSE"):
        if (
            hashlib.sha256(assets["vendor/" + name]).hexdigest() != VENDOR_SHA256[name]
            or provenance["files"][name]["sha256"] != VENDOR_SHA256[name]
        ):
            raise ArchiveError("manager_vendor_integrity")
    assets["bootstrap.js"] = (
        b'"use strict";window.ARCHIVE_MANAGER_BOOTSTRAP=Object.freeze('
        + encode_json(bootstrap, 4096)
        + b");\n"
    )
    assets["icon.png"] = icon_png()
    output = io.BytesIO()
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True
    ) as archive:
        for name, data in sorted(assets.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, data)
    return output.getvalue()


def build_app(bootstrap, output):
    """Write a new app exclusively; a public context is not owner authority."""
    data = app_bytes(bootstrap)
    output = Path(output)
    if output.suffix != ".xdc":
        raise ArchiveError("manager_app_extension")
    with output.open("xb") as target:
        target.write(data)
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--context",
        required=True,
        help="Public JSON bootstrap; no identity or credential data",
    )
    parser.add_argument("--output", required=True, help="New .xdc output file")
    args = parser.parse_args()
    bootstrap = json.loads(Path(args.context).read_bytes())
    digest = build_app(bootstrap, args.output)
    print(
        json.dumps(
            {"state": "built", "sha256": digest, "registered": False}, sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
