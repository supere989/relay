"""Synthetic, memory-key recovery fixture; no real accounts or credentials."""

import base64
import gzip
import hashlib
import json
import re
import secrets
import subprocess
import threading
from http.client import HTTPConnection
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

from chatmaild.backup import recovery_tool as tool
from chatmaild.backup.credentials import verified_identity
from chatmaild.backup.jobs import Worker
from chatmaild.backup.model import DRIVE_SCOPE, ArchiveError, Receipt, subject
from chatmaild.backup.store import Store
from chatmaild.backup.web import COOKIE, Portal, Server
from chatmaild.config import read_config, write_initial_config
from chatmaild.doveauth import encrypt_password


class PrivateBytes(bytes):
    def __repr__(self):
        return "<private synthetic recovery bytes>"


class MemoryKeys:
    def __init__(self):
        self.values = {}
        self.gets = []

    def create(self, reference):
        result = subprocess.run(
            ["/usr/bin/age-keygen"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        identity = tool.normalize_identity(result.stdout.decode("ascii"))
        recipient = tool.public_recipient(identity)
        self.values[reference] = {"identity": identity}
        return recipient

    def recovery_key(self, reference, recipient):
        self.gets.append(reference)
        if reference not in self.values:
            raise ArchiveError("recovery_key_missing")
        return verified_identity(self.values[reference], recipient)

    def manifest_key(self, reference, binding, recipient):
        return tool.mac_key(self.recovery_key(reference, recipient), binding, recipient)

    def put(self, _value):
        return "archive-credential-" + secrets.token_hex(16)


class Scenario:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        root = self.directory / "mailboxes"
        config = self.directory / "chatmail.ini"
        write_initial_config(
            config,
            "example.org",
            {
                "mailboxes_dir": str(root),
                "min_available_memory": "0",
                "min_free_disk_space": "0",
                "max_load_1m": "99999",
            },
        )
        self.config = read_config(config)
        self.address = "owner@example.org"
        self.password = "synthetic-mailbox-proof"
        self.user = self.config.get_user(self.address)
        self.user.set_password(encrypt_password(self.password))
        for name in ("cur", "new", "tmp"):
            (self.user.maildir / name).mkdir()
        (self.user.maildir / "cur" / "shared:2,S").write_bytes(b"version-one")
        (self.user.maildir / ".Sent" / "cur").mkdir(parents=True)
        self.gzip = gzip.compress(b"synthetic gzip must remain compressed", mtime=0)
        (self.user.maildir / ".Sent" / "cur" / "gzip:2,RS").write_bytes(self.gzip)
        self.store = Store(self.directory / "state" / "archive.sqlite")
        self.broker = MemoryKeys()
        self.recipients = {
            "archive-key-a": self.broker.create("archive-key-a"),
            "archive-key-b": self.broker.create("archive-key-b"),
        }
        self.credentials = SimpleNamespace(
            client_id="synthetic-client",
            broker=self.broker,
            access=lambda _binding: "synthetic-access",
            exchange=lambda *_args: {
                "id_token": "synthetic",
                "access_token": "synthetic",
                "scope": DRIVE_SCOPE,
                "refresh_token": "synthetic",
            },
            persist=lambda *_args: self.broker.put(None),
        )
        self.portal = Portal(
            self.store,
            self.config,
            self.credentials,
            "https://archive.example.org",
            verify=lambda *_args: subject("accounts.google.com", "one"),
            drive_factory=lambda *_args: SimpleNamespace(
                principal=lambda: "principal-one", folder=lambda: "folder-one"
            ),
        )
        self.raw, self.session = self.portal.session()
        login = parse_qs(urlsplit(self.portal.begin(self.session)).query)["state"][0]
        self.portal.callback(self.session, {"state": login, "code": "synthetic"})
        self.session = self.portal.session(self.raw)[1]
        b = self.portal.link(
            self.session, {"mailbox": self.address, "password": self.password}
        )
        self.store.consent(
            b.id,
            b.owner,
            b.generation,
            "principal-one",
            "archive-credential-a",
            "archive-key-a",
            self.recipients["archive-key-a"],
            "folder-one",
            expected_ref=None,
        )
        self.binding = self.store.get(b.id)
        self.remote = {}
        remote = self.remote

        class MemoryDrive:
            def __init__(self, _token, checkpoint):
                self.checkpoint = checkpoint

            def principal(self):
                self.checkpoint()
                return "principal-one"

            def allocate(self):
                return "file-" + secrets.token_hex(16)

            def upload(self, object_id, _folder, payload, _run):
                self.checkpoint()
                remote[object_id] = bytes(payload)
                self.on_commit()
                return Receipt(
                    object_id, len(payload), hashlib.sha256(payload).hexdigest()
                )

        self.worker = Worker(
            self.store,
            self.credentials,
            self.config.mailboxes_dir,
            self.directory / "spool",
            drive_factory=MemoryDrive,
        )
        self.archives = []
        self.expected = {}

    def capture(self):
        job = self.store.enqueue(self.binding.id)
        self.worker.run(job)
        row = self.store.job(job)
        if row["state"] != "verified" or not row["file_id"]:
            raise RuntimeError("synthetic_capture_failed")
        payload = self.remote[row["file_id"]]
        identity = self.broker.recovery_key(row["key_ref"], row["recipient"])
        _manifest, messages = tool.validate_clear(
            tool.decrypt(payload, identity),
            binding=self.binding.id,
            recipient=row["recipient"],
            key=tool.mac_key(identity, self.binding.id, row["recipient"]),
        )
        self.archives.append((job, payload))
        for path, data in messages:
            self.expected[job + "/" + path] = data
        return row

    def historical_key_transition_fixture(self):
        # Model preserved history from a pre-existing key change. This is NOT
        # an application rotation API: Store.consent's immutability remains.
        with self.store.transaction() as db:
            db.execute(
                "UPDATE bindings SET key_ref=?,recipient=? WHERE id=?",
                ("archive-key-b", self.recipients["archive-key-b"], self.binding.id),
            )
        self.binding = self.store.get(self.binding.id)
        (self.user.maildir / "cur" / "shared:2,S").write_bytes(b"version-two")

    def change_after_export(self):
        (self.user.maildir / "cur" / "shared:2,S").write_bytes(b"version-three")
        (self.user.maildir / ".Archive.2027" / "new").mkdir(parents=True)
        (self.user.maildir / ".Archive.2027" / "new" / "arrived-later").write_bytes(
            b"later folder"
        )

    def renew(self):
        url = self.portal.begin(
            self.portal.session(self.raw)[1], "drive", self.binding.id
        )
        state = parse_qs(urlsplit(url).query)["state"][0]
        self.portal.callback(
            self.portal.session(self.raw)[1],
            {"state": state, "code": "synthetic-renewal"},
        )
        self.binding = self.store.get(self.binding.id)
        (self.user.maildir / "cur" / "shared:2,S").write_bytes(b"version-four")

    def http_download(self, *, fields=None, raw=None, method="POST"):
        server = Server(("127.0.0.1", 0), self.portal)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        cookie = COOKIE + "=" + (self.raw if raw is None else raw)
        connection = HTTPConnection(*server.server_address, timeout=10)
        try:
            connection.request("GET", "/archive/", headers={"Cookie": cookie})
            page = connection.getresponse()
            html = page.read().decode("utf-8")
            token = re.search(r'name="csrf" value="([^"]+)"', html)[1]
            connection.close()
            body = {
                "binding": self.binding.id,
                "password": self.password,
                "csrf": token,
            }
            body.update(fields or {})
            connection = HTTPConnection(*server.server_address, timeout=30)
            connection.request(
                method,
                "/archive/recovery",
                body=urlencode(body),
                headers={
                    "Cookie": cookie,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            response = connection.getresponse()
            return (
                response.status,
                dict(response.getheaders()),
                PrivateBytes(response.read()),
            )
        finally:
            connection.close()
            server.shutdown()
            thread.join(3)
            server.server_close()

    def acceptance_packet(self):
        self.capture()
        self.historical_key_transition_fixture()
        self.capture()
        status, _headers, kit = self.http_download(fields={"mode": "keys"})
        if status != 200:
            raise RuntimeError("synthetic_export_failed")
        self.change_after_export()
        self.capture()
        self.renew()
        self.capture()
        return PrivateBytes(
            json.dumps(
                {
                    "kit": base64.b64encode(kit).decode("ascii"),
                    "archives": [
                        {
                            "name": run + ".age",
                            "data": base64.b64encode(payload).decode("ascii"),
                        }
                        for run, payload in self.archives
                    ],
                    "expected": {
                        path: hashlib.sha256(data).hexdigest()
                        for path, data in self.expected.items()
                    },
                }
            ).encode()
        )
