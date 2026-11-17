"""Explicit real SDK/local-mail acceptance, executed by the isolated test runner.

Requires /tmp tmpfs, Dovecot, aiosmtpd and the digest-pinned 2.69.0 server.
Profiles here are explicitly synthetic tmpfs, not a substitute for the separate
actual gocryptfs helper/underlay acceptance. No real accounts or Google calls.
Only public app/context assets may be exported for the browser test bridge.
"""

import argparse
import hashlib
import io
import json
import multiprocessing
import os
import re
import secrets
import signal
import subprocess
import tempfile
import threading
import time
import zipfile
from contextlib import ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from multiprocessing.connection import wait as wait_connections
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chatmaild.backup.manager import IssuanceWorker, Manager
from chatmaild.backup.manager_profile import Profile, StateGuard
from chatmaild.backup.manager_protocol import (
    b64encode,
    validate_command,
    verify_response,
)
from chatmaild.backup.manager_transport import (
    SDK,
    AttestationServer,
    SocketTransport,
    Transport,
    read_private_frame,
    reconcile,
    write_private_frame,
)
from chatmaild.backup.model import ArchiveError
from chatmaild.backup.store import Store
from chatmaild.backup.web import COOKIE, Server
from chatmaild.tests.manager_local_mail import LocalMail, LocalMailFailure
from chatmaild.tests.recovery_fixture import Scenario


def wait(predicate, reason, *, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError(reason)


PEER_RPC = frozenset(
    {
        "secure_join",
        "get_message_ids",
        "get_message",
        "get_webxdc_info",
        "get_webxdc_blob",
        "send_webxdc_status_update",
        "get_webxdc_status_updates",
        "get_full_chat_by_id",
        "create_group_chat",
        "add_contact_to_chat",
        "forward_messages",
    }
)
PEER_METHODS = frozenset({"configure", "begin", "self_key", "attest"})


def process_identity(pid):
    """Linux start ticks prevent a late cleanup from targeting a reused PID."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def peer_child(pipe, profile, server, checksum, initialize):
    """Raw peer RPC stays within this synthetic, supervised test child."""
    os.setsid()
    sdk = None
    try:
        sdk = SDK(profile, server, checksum, initialize=initialize)
        core = sdk.rpc.process
        write_private_frame(
            pipe,
            {
                "ok": True,
                "value": {"core": core.pid, "start": process_identity(core.pid)},
            },
        )
        while True:
            request = read_private_frame(pipe, 65536)
            if request is None:
                return
            method, args = request["method"], request["args"]
            try:
                if method.startswith("rpc.") and method[4:] in PEER_RPC:
                    value = getattr(sdk.rpc, method[4:])(*args)
                elif method in PEER_METHODS:
                    value = getattr(sdk, method)(*args)
                    if method == "attest":
                        value = value.__dict__
                else:
                    raise ArchiveError("manager_peer_method_denied")
                write_private_frame(pipe, {"ok": True, "value": value})
            except ArchiveError as exc:
                write_private_frame(pipe, {"ok": False, "value": exc.reason})
            except Exception:
                write_private_frame(
                    pipe, {"ok": False, "value": "manager_peer_call_failed"}
                )
    finally:
        if sdk is not None:
            try:
                sdk.close()
            finally:
                # Even a client cleanup exception must reap its owned core.
                core = sdk.rpc.process
                if core.poll() is None:
                    core.terminate()
                try:
                    core.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    core.kill()
                    core.wait(timeout=2)
        pipe.close()


class PeerRPC:
    def __init__(self, peer):
        self.peer = peer

    def __getattr__(self, method):
        if method not in PEER_RPC:
            raise AttributeError(method)
        return lambda *args: self.peer.call("rpc." + method, *args)


class Peer:
    """Bound every test-peer call and official SDK's unbounded thread joins."""

    def __init__(self, profile, server, checksum, *, initialize=False):
        self.process = None
        self.pipe = None
        self.core = None
        self.core_start = None
        self.close_mode = None
        self.rpc = PeerRPC(self)
        context = multiprocessing.get_context("spawn")
        parent, remote = context.Pipe()
        self.pipe = parent
        self.process = context.Process(
            target=peer_child, args=(remote, str(profile), server, checksum, initialize)
        )
        self.process.start()
        remote.close()
        try:
            ready = self.receive()
            self.core, self.core_start = ready["core"], ready["start"]
        except Exception:
            self.close()
            raise

    def receive(self):
        ready = wait_connections((self.pipe, self.process.sentinel), timeout=30)
        if self.pipe not in ready:
            raise ArchiveError(
                "manager_peer_call_timeout" if not ready else "manager_peer_child_exit"
            )
        try:
            value = read_private_frame(self.pipe, 2 * 1024 * 1024)
        except (OSError, EOFError):
            raise ArchiveError("manager_peer_child_exit") from None
        if not value["ok"]:
            raise ArchiveError(value["value"])
        return value["value"]

    def call(self, method, *args):
        try:
            write_private_frame(self.pipe, {"method": method, "args": args}, 65536)
            return self.receive()
        except ArchiveError as exc:
            if exc.reason in ("manager_peer_call_timeout", "manager_peer_child_exit"):
                self.close()
            raise
        except Exception:
            self.close()
            raise

    def __getattr__(self, method):
        if method not in PEER_METHODS:
            raise AttributeError(method)
        return lambda *args: self.call(method, *args)

    def close(self):
        if self.process is None:
            return
        try:
            if self.process.is_alive():
                try:
                    write_private_frame(self.pipe, None, 65536)
                except (OSError, EOFError):
                    pass
                self.process.join(5)
            self.close_mode = "graceful"
            # Rpc.close() has unbounded events/reader joins. Its official child
            # has a separate process group; terminate only that pinned group to
            # release EOF, then let the test child reap it and finish cleanup.
            if self.process.is_alive():
                self.close_mode = "owned_core_terminated"
                if (
                    self.core_start is not None
                    and process_identity(self.core) == self.core_start
                ):
                    try:
                        os.killpg(self.core, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                self.process.join(3)
            if self.process.is_alive():
                if (
                    self.core_start is not None
                    and process_identity(self.core) == self.core_start
                ):
                    try:
                        os.killpg(self.core, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.process.join(2)
            if self.process.is_alive():
                self.close_mode = "owned_worker_terminated"
                self.process.terminate()
                self.process.join(2)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(2)
            if self.process.is_alive():
                raise RuntimeError("peer_owned_cleanup_failed")
            if (
                self.core_start is not None
                and process_identity(self.core) == self.core_start
            ):
                raise RuntimeError("peer_core_not_reaped")
        finally:
            self.pipe.close()
            self.pipe = None
            self.process = None


class Acceptance:
    def __init__(self, server, checksum):
        self.phase = "profile_layout"
        self.mark(self.phase)
        self.directory = Path(
            tempfile.mkdtemp(prefix="manager-rpc-acceptance-", dir="/tmp")
        )
        self.directory.chmod(0o700)
        self.scenario = Scenario(self.directory / "owner")
        state = self.scenario.store.path.parent
        state_epoch = secrets.token_hex(16)
        (state / ".archive-state-epoch").write_text(state_epoch)
        (state / ".archive-state-epoch").chmod(0o600)
        self.guard = StateGuard(
            {"mount": str(state), "epoch": state_epoch, "uid": os.geteuid()},
            synthetic=True,
        )
        self.store = Store(self.scenario.store.path, guard=self.guard, create=False)
        self.scenario.store = self.store
        self.scenario.portal.store = self.store
        self.scenario.worker.store = self.store
        self.ownership = ExitStack()
        self.profiles = []
        for name in ("bot", "peer"):
            path = state / name
            path.mkdir(mode=0o700)
            profile = Profile(path, synthetic=True, state=self.guard)
            profile.initialize()
            self.profiles.append(profile)
        self.owner_fd = self.ownership.enter_context(self.profiles[0].owner())
        self.ownership.enter_context(self.profiles[1].owner())
        self.bot = Transport(
            self.profiles[0], server, checksum, timeout=30, initialize=True
        )
        self.mark("peer_sdk_start")
        self.peer = Peer(self.profiles[1].mount, server, checksum, initialize=True)
        key = Ed25519PrivateKey.generate()
        self.signer = SimpleNamespace(
            sign=key.sign,
            public=key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )
        self.manager = Manager(
            self.store,
            self.scenario.config,
            self.bot,
            self.signer,
            self.profiles[0],
            "https://archive.example.org",
        )
        self.mail = None
        self.web = None
        self.attestation = None
        self.threads = []
        self.peer_account = None
        self.bot_account = None
        self.instance = None
        self.peer_message = None
        self.peer_serial = 0
        self.responses = {}
        self.server, self.checksum = server, checksum
        self.checks = []
        self.bridge = None
        self.bridge_done = threading.Event()
        self.bridge_lock = threading.Lock()
        self.bridge_actions = []
        self.issuer = None
        self.mark("profiles_ready")

    def mark(self, phase):
        self.phase = phase
        print(json.dumps({"phase": phase}), flush=True)

    def start(self, *, restart_probe=False):
        self.mark("local_mail_start")
        self.mail = LocalMail()
        self.mail.start()
        password = secrets.token_urlsafe(24)
        self.mark("bot_configure")
        self.bot_account = self.bot.call(
            "configure",
            {"address": "bot@example.invalid", "password": password},
            self.mail.settings("bot"),
        )
        self.mark("peer_configure")
        self.peer_account = self.peer.configure(
            {"address": "peer@example.invalid", "password": password},
            self.mail.settings("peer"),
        )
        self.manager.db.enroll_account(
            self.profiles[0].check(),
            self.bot_account,
            self.bot.call("self_key", self.bot_account),
        )
        self.bot.call("begin", self.bot_account)
        self.peer.begin(self.peer_account)
        if restart_probe:
            return self
        self.manager.db.recover_issuance(self.profiles[0].check())
        self.issuer = IssuanceWorker(
            self.manager, self.bot_account, owner_fd=self.owner_fd
        )
        self.issuer.start()
        invitation = self.bot.call("invite", self.bot_account)
        self.mark("securejoin")
        peer_chat = self.peer.rpc.secure_join(self.peer_account, invitation)

        def securejoin():
            events = self.bot.call("events", self.bot_account)
            for event in events:
                if "contact" in event:
                    self.manager.db.securejoin(
                        self.profiles[0].check(),
                        self.bot_account,
                        event["contact"],
                        event["key_digest"],
                    )
                    self.join_event = event
                    return event["contact"]

        contact = wait(securejoin, "securejoin_completion_timeout")
        self.mark("automatic_app_issuance")

        def issued():
            with self.store.connect() as db:
                row = db.execute(
                    "SELECT instance FROM manager_issuance WHERE epoch=? AND account=? AND contact=? AND state='issued'",
                    (self.profiles[0].check(), self.bot_account, contact),
                ).fetchone()
            return row[0] if row else None

        self.instance = wait(issued, "automatic_app_issuance_timeout")

        def incoming_app():
            for message_id in self.peer.rpc.get_message_ids(
                self.peer_account, peer_chat, False, False
            ):
                message = self.peer.rpc.get_message(self.peer_account, message_id)
                if message.get("viewType") == "Webxdc":
                    if (
                        message.get("showPadlock") is not True
                        or message.get("isForwarded") is not False
                    ):
                        raise RuntimeError("peer_app_not_protected")
                    return message_id

        self.peer_message = wait(incoming_app, "issued_app_delivery_timeout")
        self.peer_chat = peer_chat
        self.mark("duplicate_securejoin_no_second_app")
        self.manager.db.securejoin(
            self.profiles[0].check(),
            self.bot_account,
            contact,
            self.join_event["key_digest"],
        )
        # The same durable event cannot create another pending claim, even if
        # the background worker polls after the duplicate completion arrives.
        with self.store.connect() as db:
            claims = db.execute(
                "SELECT state,instance FROM manager_issuance WHERE epoch=? AND account=? AND contact=?",
                (self.profiles[0].check(), self.bot_account, contact),
            ).fetchall()
            registrations = db.execute(
                "SELECT count(*) FROM manager_instances WHERE epoch=? AND account=? AND contact=?",
                (self.profiles[0].check(), self.bot_account, contact),
            ).fetchone()[0]
        if claims != [("issued", self.instance)] or registrations != 1:
            raise RuntimeError("duplicate_securejoin_created_second_issuance")
        time.sleep(1.1)  # More than two real worker polling intervals.
        apps = [
            message
            for message in self.peer.rpc.get_message_ids(
                self.peer_account, peer_chat, False, False
            )
            if self.peer.rpc.get_message(self.peer_account, message).get("viewType")
            == "Webxdc"
        ]
        if apps != [self.peer_message]:
            raise RuntimeError("duplicate_securejoin_delivered_second_app")
        self.checks.append(
            "securejoin_automatic_worker_issued_one_registered_app_despite_duplicate_completion"
        )
        self.mark("browser_pairing")
        # Actual core recognizes the ZIP and its binary icon and worker assets.
        info = self.peer.rpc.get_webxdc_info(self.peer_account, self.peer_message)
        if not info:
            raise RuntimeError("webxdc_info_missing")
        for name in ("index.html", "icon.png", "verify-worker.js"):
            if not self.peer.rpc.get_webxdc_blob(
                self.peer_account, self.peer_message, name
            ):
                raise RuntimeError("webxdc_asset_missing")
        runtime = self.directory / "runtime"
        runtime.mkdir(mode=0o700)
        self.attestation = AttestationServer(runtime / "attest.sock", self.manager)
        self._serve(self.attestation)
        browser_manager = Manager(
            self.store,
            self.scenario.config,
            SocketTransport(runtime / "attest.sock", self.guard),
            self.signer,
            self.profiles[0],
            self.manager.origin,
        )
        self.scenario.portal.manager = browser_manager
        self.web = Server(("127.0.0.1", 0), self.scenario.portal)
        self._serve(self.web)
        self.pair()
        return self

    def _serve(self, server):
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        thread.start()
        self.threads.append(thread)

    def command(self, action, *, binding=None, lease=None, args=None):
        return {
            "version": 1,
            "type": "archive-manager-command",
            "instance": self.instance,
            "id": secrets.token_hex(16),
            "action": action,
            "binding": binding["binding"] if binding else None,
            "link_revision": binding["link_revision"] if binding else 0,
            "generation": binding["generation"] if binding else 0,
            "lease": lease,
            "args": args or {},
        }

    def roundtrip(self, command):
        validate_command(command, instance=self.instance)
        before = self.mail.delivery.counts()
        cached = self.responses.get(command["id"])
        replays = self.store.metrics().get("events_manager_command_replayed", 0)
        self.peer.rpc.send_webxdc_status_update(
            self.peer_account,
            self.peer_message,
            json.dumps({"payload": command}, separators=(",", ":")),
            None,
        )

        def response():
            reconcile(self.manager)
            updates = json.loads(
                self.peer.rpc.get_webxdc_status_updates(
                    self.peer_account, self.peer_message, self.peer_serial
                )
            )
            for update in updates:
                self.peer_serial = max(self.peer_serial, update["serial"])
                payload = update.get("payload")
                if (
                    type(payload) is dict
                    and payload.get("type") == "archive-manager-response"
                ):
                    document = verify_response(
                        payload,
                        self.signer.public,
                        instance=self.instance,
                        profile_epoch=self.profiles[0].check(),
                        now=int(time.time()),
                        portal_origin=self.manager.origin,
                    )
                    if document["command_id"] == command["id"]:
                        self.responses[command["id"]] = (payload, document)
                        return payload, document
            if (
                cached
                and self.store.metrics().get("events_manager_command_replayed", 0)
                > replays
            ):
                return cached

        result = wait(response, "signed_response_timeout")
        # Both directions must traverse positively recognized encrypted MIME.
        # A replay may be deduplicated by the peer core, so only its inbound
        # encrypted command is required; result equality is checked separately.
        wait(
            lambda: self.mail.delivery.counts()["bot"] > before["bot"],
            "encrypted_command_missing",
        )
        if cached is None:
            wait(
                lambda: self.mail.delivery.counts()["peer"] > before["peer"],
                "encrypted_response_missing",
            )
        message = self.peer.rpc.get_message(self.peer_account, self.peer_message)
        if message.get("showPadlock") is not True:
            raise RuntimeError("decrypted_protected_app_missing")
        return result

    def http(self, method, path, fields=None, *, cookie=True):
        connection = HTTPConnection(*self.web.server_address, timeout=30)
        try:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            if cookie:
                headers["Cookie"] = (
                    COOKIE + "=" + (self.scenario.raw if cookie is True else cookie)
                )
            connection.request(
                method,
                path,
                body=urlencode(fields) if fields else None,
                headers=headers,
            )
            result = connection.getresponse()
            return result.status, dict(result.getheaders()), result.read()
        finally:
            connection.close()

    def pair(self):
        _envelope, doc = self.roundtrip(self.command("pair_start"))
        pairing = doc["pairing"]
        parsed = urlsplit(pairing["url"])
        query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        status, _headers, page = self.http("GET", parsed.path + "?" + parsed.query)
        if status != 200:
            raise RuntimeError("pair_browser_page_failed")
        csrf = re.search(rb'name="csrf" value="([^"]+)"', page)[1].decode()
        form = {
            **query,
            "comparison": pairing["comparison"],
            "binding": self.scenario.binding.id,
            "password": self.scenario.password,
            "csrf": csrf,
        }
        foreign_raw, foreign_session = self.scenario.portal.session()
        with self.store.connect() as db:
            # Synthetic verified foreign owner, without any Google network.
            db.execute(
                "UPDATE sessions SET owner=? WHERE id_hash=?",
                ("f" * 64, foreign_session["id_hash"]),
            )
        foreign_form = {**form, "csrf": self.scenario.portal.csrf(foreign_session)}
        negatives = [
            ("session", form, False),
            ("csrf", {**form, "csrf": "invalid"}, True),
            ("mailbox_proof", {**form, "password": "wrong-synthetic-proof"}, True),
            ("foreign_owner", foreign_form, foreign_raw),
            (
                "comparison",
                {
                    **form,
                    "comparison": "000000"
                    if pairing["comparison"] != "000000"
                    else "111111",
                },
                True,
            ),
            (
                "url_only",
                {key: value for key, value in form.items() if key != "comparison"},
                True,
            ),
        ]
        for reason, denied, cookie in negatives:
            status, _headers, _body = self.http(
                "POST", "/archive/manager-intent", denied, cookie=cookie
            )
            if status == 303 or status < 400:
                raise RuntimeError("pair_" + reason + "_unexpectedly_admitted")
            self.checks.append("pair_" + reason + "_refused")
        status, _headers, _body = self.http("POST", "/archive/manager-intent", form)
        if status != 303:
            raise RuntimeError("pair_browser_intent_failed")
        _envelope, doc = self.roundtrip(self.command("status"))
        pending = doc["pairing"]
        self.roundtrip(
            self.command(
                "pair_confirm",
                lease=pending["lease"],
                args={"challenge": pending["challenge"], "intent": pending["intent"]},
            )
        )
        form = {
            **query,
            "binding": self.scenario.binding.id,
            "password": self.scenario.password,
            "csrf": csrf,
            "confirm": "yes",
        }
        status, _headers, _body = self.http("POST", "/archive/manager-confirm", form)
        if status != 303:
            raise RuntimeError("pair_browser_confirmation_failed")
        _envelope, doc = self.roundtrip(self.command("status"))
        if doc["state"] != "linked" or len(doc["bindings"]) != 1:
            raise RuntimeError("pair_link_missing")
        self.checks.append("fresh_browser_proof_app_lease_browser_final_pair")

    def wrong_instance(self):
        self.mark("wrong_instance_encrypted_command")
        command = self.command("status")
        command["instance"] = secrets.token_hex(16)
        before = self.store.metrics().get("events_manager_command_invalid", 0)
        encrypted = self.mail.delivery.counts()["bot"]
        self.peer.rpc.send_webxdc_status_update(
            self.peer_account,
            self.peer_message,
            json.dumps({"payload": command}, separators=(",", ":")),
            None,
        )

        def refused():
            reconcile(self.manager)
            return (
                self.store.metrics().get("events_manager_command_invalid", 0) > before
            )

        wait(refused, "wrong_instance_not_refused")
        wait(
            lambda: self.mail.delivery.counts()["bot"] > encrypted,
            "wrong_instance_not_encrypted",
        )
        with self.store.connect() as db:
            if db.execute(
                "SELECT count(*) FROM manager_commands WHERE id=?", (command["id"],)
            ).fetchone()[0]:
                raise RuntimeError("wrong_instance_command_persisted")
        self.checks.append(
            "wrong_instance_encrypted_peer_update_refused_before_command_admission"
        )

    def forwarded_contexts(self):
        self.mark("actual_forwarded_and_group_context_refusal")
        original = self.peer.rpc.get_full_chat_by_id(self.peer_account, self.peer_chat)
        contact = original["contactIds"][0]
        group = self.peer.rpc.create_group_chat(
            self.peer_account, "Synthetic archive refusal", False
        )
        self.peer.rpc.add_contact_to_chat(self.peer_account, group, contact)
        for chat, reason in (
            (self.peer_chat, "manager_app_message_denied"),
            (group, "manager_chat_denied"),
        ):
            before = set(
                self.peer.rpc.get_message_ids(self.peer_account, chat, False, False)
            )
            self.peer.rpc.forward_messages(self.peer_account, [self.peer_message], chat)

            def forwarded():
                for message_id in self.peer.rpc.get_message_ids(
                    self.peer_account, chat, False, False
                ):
                    if message_id not in before:
                        message = self.peer.rpc.get_message(
                            self.peer_account, message_id
                        )
                        if (
                            message.get("viewType") == "Webxdc"
                            and message.get("isForwarded") is True
                        ):
                            return message_id

            message = wait(forwarded, "forwarded_app_missing")
            registered = {
                "epoch": self.profiles[1].check(),
                "account": self.peer_account,
                "chat": chat,
                "contact": contact,
                "message": message,
            }
            try:
                self.peer.attest(registered)
            except ArchiveError as exc:
                if exc.reason != reason:
                    raise RuntimeError("forwarded_context_wrong_refusal") from None
            else:
                raise RuntimeError("forwarded_context_admitted")
        self.checks.append(
            "actual_sdk_forwarded_single_and_group_apps_fail_context_authority"
        )

    def public_app(self, directory):
        from chatmaild.tests.manager_ui_fixture import sdk_fixture

        message = self.peer.rpc.get_message(self.peer_account, self.peer_message)
        app = Path(message["file"]).read_bytes()
        target = Path(directory)
        target.mkdir(mode=0o700)
        (target / "archive-manager.xdc").write_bytes(app)
        asset = target / "app"
        asset.mkdir(mode=0o700)
        with zipfile.ZipFile(io.BytesIO(app)) as archive:
            for item in archive.infolist():
                path = Path(item.filename)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or item.file_size > 1024 * 1024
                ):
                    raise RuntimeError("public_app_path_invalid")
                destination = asset / path
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                destination.write_bytes(archive.read(item))
        (asset / "webxdc.js").write_text(sdk_fixture())
        context = {
            "version": 1,
            "instance": self.instance,
            "profile_epoch": self.profiles[0].check(),
            "public_key": b64encode(self.signer.public),
            "portal_origin": self.manager.origin,
        }
        (target / "fixture.json").write_text(
            json.dumps(
                {"app_sha256": hashlib.sha256(app).hexdigest(), "context": context}
            )
        )
        return hashlib.sha256(app).hexdigest()

    def restart_profiles(self):
        self.mark("restart_bot_key_before_close")
        identity = self.bot.call("self_key", self.bot_account)
        self.mark("restart_issuance_stop_and_bot_close")
        if self.issuer is not None:
            self.issuer.close()
            self.issuer = None
        self.mark("restart_bot_close")
        self.bot.close()
        self.mark("restart_bot_reopen_key")
        if self.bot.call("self_key", self.bot_account) != identity:
            raise RuntimeError("restart_bot_identity_changed")
        self.mark("restart_bot_begin_io")
        self.bot.call("begin", self.bot_account)
        self.mark("restart_peer_key_before_close")
        peer_identity = self.peer.self_key(self.peer_account)
        self.mark("restart_peer_close_bounded")
        self.peer.close()
        self.checks.append("peer_shutdown_" + self.peer.close_mode)
        self.mark("restart_peer_reopen")
        self.peer = Peer(self.profiles[1].mount, self.server, self.checksum)
        self.mark("restart_peer_key_readback")
        if self.peer.self_key(self.peer_account) != peer_identity:
            raise RuntimeError("restart_peer_identity_changed")
        self.mark("restart_peer_begin_io")
        self.peer.begin(self.peer_account)
        # Reopen the actual facade as a service restart would; recorded command
        # results and authority come from persisted Store, never a fake adapter.
        self.manager = Manager(
            self.store,
            self.scenario.config,
            self.bot,
            self.signer,
            self.profiles[0],
            self.manager.origin,
        )
        self.manager.db.recover_issuance(self.profiles[0].check())
        self.issuer = IssuanceWorker(
            self.manager, self.bot_account, owner_fd=self.owner_fd
        )
        self.issuer.start()

    def restart_and_replay(self, command, envelope):
        self.mark("restart_replay")
        generation = self.store.get(self.scenario.binding.id).generation
        self.restart_profiles()
        self.mark("restart_replayed_encrypted_command")
        repeated, _doc = self.roundtrip(command)
        if (
            repeated != envelope
            or self.store.get(self.scenario.binding.id).generation != generation
        ):
            raise RuntimeError("restart_replay_reapplied")
        with self.store.connect() as db:
            if (
                db.execute(
                    "SELECT count(*) FROM manager_commands WHERE instance=? AND id=?",
                    (self.instance, command["id"]),
                ).fetchone()[0]
                != 1
            ):
                raise RuntimeError("restart_recorded_command_missing")
        self.checks.append(
            "both_sdk_identities_and_recorded_result_survive_restart_without_reapply"
        )

    def bridge_run(self, output, port, timeout):
        app_sha = self.public_app(output)
        acceptance = self

        class Bridge(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.connection.settimeout(60)
                if not acceptance.bridge_lock.acquire(blocking=False):
                    self.send_error(409)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "-1"))
                    if (
                        not 0 < size <= 8192
                        or self.headers.get("Content-Type") != "application/json"
                    ):
                        raise ValueError("bridge_body_limit")
                    value = json.loads(self.rfile.read(size))
                    if self.path == "/finish":
                        if value != {"complete": True} or acceptance.bridge_actions != [
                            "status",
                            "pause",
                        ]:
                            raise ValueError("bridge_incomplete")
                        result = {"complete": True}
                        acceptance.bridge_done.set()
                    elif self.path == "/command":
                        if type(value) is not dict or set(value) != {"command"}:
                            raise ValueError("bridge_body_invalid")
                        command = validate_command(
                            value["command"], instance=acceptance.instance
                        )
                        expected = (
                            "status"
                            if not acceptance.bridge_actions
                            else "pause"
                            if len(acceptance.bridge_actions) == 1
                            else None
                        )
                        if command["action"] != expected or expected is None:
                            raise ValueError("bridge_action_denied")
                        acceptance.mark("browser_" + expected + "_encrypted_roundtrip")
                        envelope, document = acceptance.roundtrip(command)
                        if expected == "pause":
                            if (
                                document["result"] != "confirmed"
                                or acceptance.store.get(
                                    acceptance.scenario.binding.id
                                ).enabled
                            ):
                                raise RuntimeError("bridge_pause_not_committed")
                            acceptance.restart_and_replay(command, envelope)
                        acceptance.bridge_actions.append(expected)
                        result = {
                            "response": envelope,
                            "binding_enabled": bool(
                                acceptance.store.get(
                                    acceptance.scenario.binding.id
                                ).enabled
                            ),
                        }
                    else:
                        raise ValueError("bridge_path_denied")
                    data = json.dumps(result, separators=(",", ":")).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(data)
                except Exception as exc:
                    acceptance.mark("bridge_refused_" + type(exc).__name__)
                    self.send_error(400)
                finally:
                    acceptance.bridge_lock.release()

        self.bridge = ThreadingHTTPServer(("127.0.0.1", port), Bridge)
        self.bridge.daemon_threads = True
        self._serve(self.bridge)
        ready = {
            "version": 1,
            "bridge_url": "http://127.0.0.1:" + str(self.bridge.server_port),
            "app_sha256": app_sha,
            "state": "ready",
            "profile_storage": "explicit-synthetic-tmpfs",
        }
        with (Path(output) / "ready.json").open("x") as stream:
            json.dump(ready, stream)
        self.mark("browser_bridge_ready")
        if not self.bridge_done.wait(timeout):
            raise TimeoutError("browser_bridge_timeout")
        self.checks.append("actual_packaged_ui_status_and_pause_through_encrypted_sdk")

    def close(self):
        for server in (self.bridge, self.web, self.attestation):
            if server is not None:
                server.shutdown()
                server.server_close()
        if self.issuer is not None:
            self.issuer.close()
            self.issuer = None
        self.bot.close()
        self.peer.close()
        if self.mail is not None:
            self.mail.close()
        for thread in self.threads:
            thread.join(2)
        self.ownership.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-server", required=True)
    parser.add_argument("--rpc-sha256", required=True)
    parser.add_argument("--public-output", type=Path)
    parser.add_argument("--bridge-port", type=int, default=18769)
    parser.add_argument("--bridge-timeout", type=int, default=240)
    parser.add_argument("--restart-probe", action="store_true")
    args = parser.parse_args(argv)

    def timed_out(*_args):
        raise TimeoutError("acceptance_timeout")

    signal.signal(signal.SIGTERM, timed_out)
    acceptance = None
    try:
        acceptance = Acceptance(args.rpc_server, args.rpc_sha256)
        if args.restart_probe:
            if args.public_output is not None:
                raise ValueError("restart_probe_cannot_issue_app")
            acceptance.start(restart_probe=True)
            acceptance.restart_profiles()
            print(
                json.dumps(
                    {
                        "state": "passed",
                        "probe": "configured_io_restart_only",
                        "profiles": 2,
                        "official_sdk": "2.69.0",
                        "checks": acceptance.checks,
                    }
                )
            )
            return 0
        acceptance.start()
        acceptance.wrong_instance()
        acceptance.forwarded_contexts()
        if args.public_output:
            if (
                not args.public_output.is_absolute()
                or args.public_output.exists()
                or not 1024 <= args.bridge_port <= 65535
                or not 30 <= args.bridge_timeout <= 600
            ):
                raise ValueError("bridge_arguments_invalid")
            acceptance.bridge_run(
                args.public_output, args.bridge_port, args.bridge_timeout
            )
            print(
                json.dumps(
                    {
                        "state": "passed",
                        "checks": acceptance.checks,
                        "real_rpc_bridge": True,
                        "pgp_mime": acceptance.mail.delivery.counts(),
                        "production_activation": False,
                    }
                )
            )
            return 0
        acceptance.mark("actual_pause")
        _envelope, status = acceptance.roundtrip(acceptance.command("status"))
        binding = status["bindings"][0]
        command = acceptance.command(
            "pause",
            binding=binding,
            lease=status["leases"][binding["binding"]]["pause"],
        )
        envelope, paused = acceptance.roundtrip(command)
        if (
            acceptance.store.get(acceptance.scenario.binding.id).enabled
            or paused["result"] != "confirmed"
        ):
            raise RuntimeError("actual_pause_missing")
        generation = acceptance.store.get(acceptance.scenario.binding.id).generation
        repeated, _document = acceptance.roundtrip(command)
        if (
            repeated != envelope
            or acceptance.store.get(acceptance.scenario.binding.id).generation
            != generation
        ):
            raise RuntimeError("command_replay_changed_state")
        acceptance.restart_and_replay(command, envelope)
        print(
            json.dumps(
                {
                    "official_sdk": "2.69.0",
                    "profiles": 2,
                    "securejoin": True,
                    "registered_webxdc": True,
                    "automatic_issuance": True,
                    "browser_pairing": True,
                    "actual_archive_paused": True,
                    "signed_response": True,
                    "replay_idempotent": True,
                    "profile_storage": "explicit-synthetic-tmpfs",
                    "checks": acceptance.checks,
                    "pgp_mime": acceptance.mail.delivery.counts(),
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": "manager_rpc_acceptance_failed",
                    "phase": acceptance.phase if acceptance else "initialize",
                    "exception": type(exc).__name__,
                    "reason": exc.reason if isinstance(exc, ArchiveError) else None,
                    "fixture_diagnostic": (
                        exc.diagnostic if isinstance(exc, LocalMailFailure) else None
                    ),
                }
            )
        )
        return 1
    finally:
        if acceptance is not None:
            acceptance.close()


if __name__ == "__main__":
    raise SystemExit(main())
