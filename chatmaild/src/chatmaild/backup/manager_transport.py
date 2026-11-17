"""Bounded official-SDK transport child; no archive work in SDK reader threads.

Every operation reloads core chat/contact/message metadata. Webxdc payload
authors are not authenticated, so only an issued app in a pinned protected
single chat is eligible; browser pairing supplies mailbox-owner authority.
"""

import base64
import hashlib
import importlib.metadata
import json
import logging
import multiprocessing
import os
import queue
import re
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import tempfile
import threading
import time
from multiprocessing.connection import wait as wait_connections
from pathlib import Path

from .manager_profile import VERSION, no_core_dumps, private_directory, verify_server
from .manager_store import DEFINITIVE_AUTHORITY_LOSS
from .model import ArchiveError

MAX_IPC = 9 * 1024 * 1024


def encode_private_frame(value, maximum=MAX_IPC):
    try:
        raw = json.dumps(
            value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
    except (ValueError, TypeError):
        raise ArchiveError("manager_transport_frame_invalid") from None
    if len(raw) > maximum:
        raise ArchiveError("manager_transport_response_oversized")
    return raw


def write_private_frame(pipe, value, maximum=MAX_IPC):
    pipe.send_bytes(encode_private_frame(value, maximum))


def read_private_frame(pipe, maximum=MAX_IPC):
    try:
        raw = pipe.recv_bytes(maxlength=maximum)
        return json.loads(raw)
    except (ValueError, UnicodeError, TypeError, OSError):
        raise ArchiveError("manager_transport_response_invalid") from None


def public_key_digest(vcard):
    if type(vcard) is not str or len(vcard) > 131072:
        raise ArchiveError("manager_peer_key_missing")
    # Core 2.69 emits CRLF and escapes the data-URL comma as a vCard
    # property value. Unfold before normalizing line endings so a folded
    # second property cannot bypass the exactly-one-key constraint.
    unfolded = re.sub(r"\r?\n[ \t]", "", vcard).replace("\r\n", "\n")
    matches = re.findall(r"(?im)^KEY(?:;[^:\r\n]*)?:([^\r\n]+)$", unfolded)
    if len(matches) != 1:
        raise ArchiveError("manager_peer_key_missing")
    value = matches[0]
    for prefix in (
        "data:application/pgp-keys;base64\\,",
        "data:application/pgp-keys;base64,",
    ):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ArchiveError("manager_peer_key_invalid") from None
    if not 32 <= len(key) <= 65536:
        raise ArchiveError("manager_peer_key_invalid")
    return hashlib.sha256(key).hexdigest()


def checked_context(registered, chat, contact, message, vcard, app, self_vcard):
    from .manager import Context

    if type(chat) is not dict or type(contact) is not dict or type(message) is not dict:
        raise ArchiveError("manager_rpc_context_invalid")
    if (
        chat.get("id") != registered["chat"]
        or chat.get("chatType") != "Single"
        or chat.get("isContactRequest") is not False
        or chat.get("isSelfTalk") is not False
        or chat.get("isDeviceChat") is not False
        or chat.get("isEncrypted") is not True
        or chat.get("canSend") is not True
        or chat.get("contactIds") != [registered["contact"]]
        or chat.get("mailingListAddress") is not None
    ):
        raise ArchiveError("manager_chat_denied")
    if (
        contact.get("id") != registered["contact"]
        or contact["id"] <= 9
        or contact.get("isBlocked") is not False
        or contact.get("isKeyContact") is not True
        or contact.get("e2eeAvail") is not True
    ):
        raise ArchiveError("manager_contact_denied")
    if (
        message.get("id") != registered["message"]
        or message.get("chatId") != registered["chat"]
        or message.get("fromId") != 1
        or message.get("viewType") != "Webxdc"
        or message.get("isForwarded") is not False
        or message.get("showPadlock") is not True
        or message.get("originalMsgId") is not None
        or message.get("savedMessageId") is not None
        or message.get("error") is not None
    ):
        raise ArchiveError("manager_app_message_denied")
    if not isinstance(app, bytes) or not 0 < len(app) <= 2 * 1024 * 1024:
        raise ArchiveError("manager_app_blob_denied")
    return Context(
        registered["epoch"],
        registered["account"],
        public_key_digest(self_vcard),
        registered["chat"],
        registered["contact"],
        public_key_digest(vcard),
        registered["message"],
        hashlib.sha256(app).hexdigest(),
    )


class SDK:
    """Only instantiated in the supervised child, never on a request thread."""

    def __init__(self, profile, server, checksum, *, initialize=False):
        if importlib.metadata.version("deltachat-rpc-client") != VERSION:
            raise ArchiveError("manager_sdk_version_mismatch")
        from deltachat_rpc_client import Rpc

        no_core_dumps()
        os.environ["RUST_LOG"] = "off"
        temporary = private_directory(Path(profile) / ".rpc-tmp")
        os.environ["TMPDIR"] = str(temporary)
        os.environ["TMP"] = str(temporary)
        os.environ["TEMP"] = str(temporary)
        tempfile.tempdir = str(temporary)
        logging.disable(logging.CRITICAL)
        accounts = private_directory(Path(profile) / "accounts")
        if not initialize and not (accounts / "accounts.toml").is_file():
            raise ArchiveError("manager_rpc_account_state_missing")
        self.rpc = Rpc(
            accounts_dir=str(accounts),
            rpc_server_path=verify_server(server, checksum),
            stderr=subprocess.PIPE,
            process_group=os.getpgrp(),
        )
        self.profile = Path(profile).resolve()
        self.stopped = threading.Event()
        self.started = threading.Event()
        self.watcher = threading.Thread(target=self._watch_owned_process, daemon=True)
        self.watcher.start()
        try:
            self.rpc.start()
        except Exception:
            # SDK2.69 reads its private stderr PIPE while cleaning startup
            # errors. Never replace it with None or expose exception bodies.
            raise ArchiveError("manager_transport_start_failed") from None
        self.started.set()

    def _watch_owned_process(self):
        draining = False
        while not self.stopped.wait(0.02):
            # Rpc.__getattr__ fabricates method objects for absent names;
            # before start() assigns its Popen, getattr is not a safe probe.
            process = self.rpc.__dict__.get("process")
            if process is None:
                continue
            if process.poll() is not None:
                process.wait()
                if self.stopped.is_set():
                    return
                # SDK futures/threads can otherwise remain blocked after EOF.
                # Retire this supervised worker; its parent fails every waiter
                # and reaps it instead of turning a missing reply into success.
                os._exit(70)
            if self.started.is_set() and not draining:
                threading.Thread(
                    target=self._discard_stderr, args=(process,), daemon=True
                ).start()
                draining = True

    def _discard_stderr(self, process):
        try:
            while not self.stopped.is_set() and os.read(process.stderr.fileno(), 4096):
                pass
        except (OSError, ValueError):
            pass

    def attest(self, registered):
        from .manager import Context

        account = registered["account"]
        chat = self.rpc.get_full_chat_by_id(account, registered["chat"])
        contact = self.rpc.get_contact(account, registered["contact"])
        message = self.rpc.get_message(account, registered["message"])
        vcard = self.rpc.make_vcard(account, [registered["contact"]])
        path = message.get("file")
        if type(path) is not str:
            raise ArchiveError("manager_app_blob_denied")
        if self.profile not in Path(path).resolve().parents:
            raise ArchiveError("manager_app_blob_denied")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ArchiveError("manager_app_blob_denied")
            app = os.read(fd, 2 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
        actual = checked_context(
            registered,
            chat,
            contact,
            message,
            vcard,
            app,
            self.rpc.make_vcard(account, [1]),
        )
        expected = Context(
            **{key: registered[key] for key in Context.__dataclass_fields__}
        )
        if actual != expected:
            raise ArchiveError("manager_peer_context_changed")
        return actual

    def updates(self, registered, serial):
        self.attest(registered)
        raw = self.rpc.get_webxdc_status_updates(
            registered["account"], registered["message"], serial
        )
        if type(raw) is not str or len(raw) > 16 * 1024 * 1024:
            raise ArchiveError("manager_history_quarantine_required")
        values = json.loads(raw)
        if type(values) is not list:
            raise ArchiveError("manager_update_batch_invalid")
        # Core exposes only last-known-serial, not a page-size parameter. Read
        # a bounded prefix and commit only processed serials; the next poll
        # requests the remaining suffix. Truly huge histories are explicitly
        # quarantined for reissue, never permanently retried at one cursor.
        prefix = values[:256]
        try:
            # Use exactly the sender's wrapper and ASCII expansion. A huge
            # first update cannot fit by choosing a shorter nonempty prefix;
            # quarantine durably instead of repeating a generic IPC failure.
            encode_private_frame({"ok": True, "value": prefix})
        except ArchiveError:
            raise ArchiveError("manager_history_quarantine_required") from None
        return prefix

    def send(self, registered, payload):
        self.attest(registered)
        if len(payload.encode("utf-8")) > 32768:
            raise ArchiveError("manager_response_limit")
        self.rpc.send_webxdc_status_update(
            registered["account"],
            registered["message"],
            json.dumps({"payload": json.loads(payload)}, separators=(",", ":")),
            None,
        )

    def close(self):
        self.stopped.set()

        def cleanup():
            try:
                self.rpc.close()
            except Exception:
                pass  # Raw SDK errors never cross the private supervisor.

        cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        cleanup_thread.start()
        process = self.rpc.__dict__.get("process")
        if process is not None:
            try:
                process.wait(timeout=0.4)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=0.4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=0.4)
        cleanup_thread.join(0.3)

    def events(self, account):
        result = []
        for _ in range(256):
            try:
                event = self.rpc.get_queue(account).get_nowait()
            except queue.Empty:
                break
            if (
                type(event) is dict
                and event.get("kind")
                in ("SecurejoinInviterProgress", "SecurejoinJoinerProgress")
                and event.get("progress") == 1000
            ):
                contact = event.get("contactId")
                if type(contact) is int and contact > 9:
                    peer = self.peer(account, contact)
                    result.append(
                        {"contact": contact, "key_digest": peer["key_digest"]}
                    )
            elif type(event) is dict and event.get("kind") == "EventChannelOverflow":
                result.append({"overflow": True})
        return result

    def peer(self, account, contact):
        contact_info = self.rpc.get_contact(account, contact)
        chat_id = self.rpc.get_chat_id_by_contact_id(account, contact)
        chat = self.rpc.get_full_chat_by_id(account, chat_id)
        if (
            contact <= 9
            or contact_info.get("isBlocked") is not False
            or contact_info.get("isKeyContact") is not True
            or contact_info.get("e2eeAvail") is not True
            or chat.get("chatType") != "Single"
            or chat.get("isEncrypted") is not True
            or chat.get("isContactRequest") is not False
            or chat.get("isSelfTalk") is not False
            or chat.get("isDeviceChat") is not False
            or chat.get("contactIds") != [contact]
        ):
            raise ArchiveError("manager_peer_denied")
        return {
            "account": account,
            "chat": chat_id,
            "contact": contact,
            "key_digest": public_key_digest(self.rpc.make_vcard(account, [contact])),
            "self_key_digest": self.self_key(account),
        }

    def self_key(self, account):
        return public_key_digest(self.rpc.make_vcard(account, [1]))

    def issue(self, account, contact, path, expected=None):
        peer = self.peer(account, contact)
        if (
            type(expected) is not dict
            or set(expected) != {"key_digest", "self_key_digest"}
            or any(peer[key] != expected[key] for key in expected)
        ):
            raise ArchiveError("manager_issue_context_changed")
        if self.profile not in Path(path).resolve().parents:
            raise ArchiveError("manager_app_path_denied")
        message = self.rpc.send_msg(
            account,
            peer["chat"],
            {"text": "Archive Manager", "viewtype": "Webxdc", "file": str(path)},
        )
        return {**peer, "message": message}

    def invite(self, account):
        return self.rpc.get_chat_securejoin_qr_code(account, None)

    def configure(self, credentials, settings):
        if (
            type(credentials) is not dict
            or set(credentials) != {"address", "password"}
            or not all(
                type(value) is str and 0 < len(value) <= 1024
                for value in credentials.values()
            )
        ):
            raise ArchiveError("manager_mailbox_credential_type")
        allowed = {
            "imapServer",
            "imapPort",
            "imapSecurity",
            "imapUser",
            "imapFolder",
            "smtpServer",
            "smtpPort",
            "smtpSecurity",
            "smtpUser",
            "certificateChecks",
        }
        if type(settings) is not dict or set(settings) - allowed:
            raise ArchiveError("manager_transport_settings_denied")
        account = self.rpc.add_account()
        self.rpc.add_or_update_transport(
            account,
            {
                **settings,
                "addr": credentials["address"],
                "password": credentials["password"],
            },
        )
        self.rpc.set_config(account, "bot", "1")
        return account

    def begin(self, account):
        self.rpc.start_io(account)


def child(pipe, profile, server, checksum, initialize):
    os.setsid()
    sdk = None

    def retire(_signum, _frame):
        # Parent escalation waits two seconds. Keep this dedicated child's
        # cleanup strictly shorter, including partial SDK startup. The worker
        # owns only its one RPC Popen; waitpid cannot reap another process's
        # children. A missing reply remains an unknown outcome to the parent.
        if sdk is not None:
            try:
                sdk.close()  # At most 1.5 seconds, including explicit reap.
            except Exception:
                pass
        deadline = time.monotonic() + 0.2
        while time.monotonic() < deadline:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                time.sleep(0.01)
        os._exit(71)

    signal.signal(signal.SIGTERM, retire)
    try:
        # Make partial startup visible to the signal cleanup, rather than
        # assigning the object only after a potentially stalled health check.
        sdk = SDK.__new__(SDK)
        sdk.__init__(profile, server, checksum, initialize=initialize)
        write_private_frame(pipe, {"ok": True, "value": None})
        while True:
            request = read_private_frame(pipe, 65536)
            if request is None:
                return
            if (
                type(request) is not dict
                or set(request) != {"method", "args"}
                or type(request["method"]) is not str
                or type(request["args"]) is not list
            ):
                raise ArchiveError("manager_transport_frame_invalid")
            method, args = request["method"], request["args"]
            try:
                if method not in (
                    "attest",
                    "updates",
                    "send",
                    "events",
                    "peer",
                    "issue",
                    "invite",
                    "configure",
                    "begin",
                    "self_key",
                ):
                    raise ArchiveError("manager_rpc_method_denied")
                value = getattr(sdk, method)(*args)
                if method == "attest":
                    value = value.__dict__
                write_private_frame(pipe, {"ok": True, "value": value})
            except ArchiveError as exc:
                write_private_frame(pipe, {"ok": False, "value": exc.reason})
            except Exception:
                write_private_frame(
                    pipe, {"ok": False, "value": "manager_transport_refused"}
                )
    except Exception:
        try:
            write_private_frame(
                pipe, {"ok": False, "value": "manager_transport_unavailable"}
            )
        except (OSError, EOFError):
            pass
    finally:
        if sdk is not None:
            sdk.close()
        pipe.close()


class Transport:
    def __init__(self, profile, server, checksum, *, timeout=15, initialize=False):
        self.profile, self.server, self.checksum = profile, server, checksum
        self.timeout = timeout
        self.lock = threading.Lock()
        self.close_lock = threading.Lock()
        self.process = None
        self.pipe = None
        self.initialize = initialize

    def start(self):
        self.profile.check()
        self.profile.accounts_path(initialize=self.initialize)
        # Restarts occur while attestation/issuance threads are live. Spawn a
        # clean interpreter instead of inheriting their locks through fork.
        context = multiprocessing.get_context("spawn")
        parent, remote = context.Pipe()
        process = context.Process(
            target=child,
            args=(
                remote,
                str(self.profile.mount),
                self.server,
                self.checksum,
                self.initialize,
            ),
            daemon=True,
        )
        process.start()
        remote.close()
        self.pipe, self.process = parent, process
        try:
            ready = self._receive()
        except ArchiveError:
            self.close()
            raise
        if not ready[0]:
            self.close()
            raise ArchiveError("manager_transport_start_failed")
        self.initialize = False

    def _receive(self):
        pipe, process = self.pipe, self.process
        if pipe is None or process is None:
            raise ArchiveError("manager_transport_unavailable")
        ready = wait_connections((pipe, process.sentinel), timeout=self.timeout)
        if not ready:
            raise ArchiveError("manager_transport_stall")
        if pipe not in ready:
            raise ArchiveError("manager_transport_child_exit")
        try:
            value = read_private_frame(pipe)
        except (OSError, EOFError):
            raise ArchiveError("manager_transport_child_exit") from None
        if (
            type(value) is not dict
            or set(value) != {"ok", "value"}
            or type(value["ok"]) is not bool
            or not value["ok"]
            and (
                type(value["value"]) is not str
                or not re.fullmatch(r"manager_[a-z_]{1,55}", value["value"])
            )
        ):
            raise ArchiveError("manager_transport_response_invalid")
        return value["ok"], value["value"]

    def call(self, method, *args):
        if not self.lock.acquire(timeout=self.timeout):
            raise ArchiveError("manager_transport_stall")
        try:
            self.profile.check()
            if self.process is None or not self.process.is_alive():
                self.close()
                self.start()
            try:
                write_private_frame(self.pipe, {"method": method, "args": args}, 65536)
                ok, value = self._receive()
                if not ok:
                    raise ArchiveError(value)
                return value
            except (OSError, EOFError):
                self.close()
                raise ArchiveError("manager_transport_unavailable") from None
            except ArchiveError as exc:
                if exc.reason in (
                    "manager_transport_stall",
                    "manager_transport_child_exit",
                    "manager_transport_response_invalid",
                    "manager_transport_response_oversized",
                    "manager_transport_frame_invalid",
                ):
                    self.close()
                raise
        finally:
            self.lock.release()

    def attest(self, registered):
        from .manager import Context

        value = self.call("attest", registered)
        if type(value) is not dict or set(value) != set(Context.__dataclass_fields__):
            self.close()
            raise ArchiveError("manager_transport_response_invalid")
        return Context(**value)

    def updates(self, registered, serial):
        return self.call("updates", registered, serial)

    def send(self, registered, payload):
        return self.call("send", registered, payload)

    def close(self):
        with self.close_lock:
            self._close()

    def _close(self):
        if self.process is not None:
            idle = self.lock.acquire(blocking=False)
            try:
                if idle and self.pipe is not None and self.process.is_alive():
                    try:
                        write_private_frame(self.pipe, None, 65536)
                    except (OSError, EOFError, ArchiveError):
                        pass
                    self.process.join(2)  # Official SDK.close can reap normally.
            finally:
                if idle:
                    self.lock.release()
            if self.process.is_alive():
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    if self.process.is_alive():
                        self.process.terminate()
                self.process.join(2)
            if self.process.is_alive():
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    if self.process.is_alive():
                        self.process.kill()
                self.process.join(1)
        if self.pipe is not None:
            self.pipe.close()
        self.pipe, self.process = None, None


def peer_uid(connection):
    return struct.unpack(
        "3i",
        connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        ),
    )[1]


def read_frame(connection, maximum=8192):
    result = b""
    while b"\n" not in result:
        value = connection.recv(min(1024, maximum + 1 - len(result)))
        if not value:
            raise ArchiveError("manager_attestation_unavailable")
        result += value
        if len(result) > maximum:
            raise ArchiveError("manager_attestation_limit")
    if not result.endswith(b"\n") or result.count(b"\n") != 1:
        raise ArchiveError("manager_attestation_frame_denied")
    try:
        value = json.loads(result)
    except (ValueError, UnicodeError):
        raise ArchiveError("manager_attestation_frame_denied") from None
    return value


class SocketTransport:
    """Browser-side client: only fresh registered-instance attestation."""

    def __init__(self, path, guard, *, timeout=20):
        self.path, self.guard, self.timeout = str(path), guard, timeout

    def attest(self, registered):
        from .manager import Context

        self.guard.check()
        path = Path(self.path)
        parent = path.parent.stat()
        info = path.lstat()
        if (
            path.is_symlink()
            or path.parent.resolve() != path.parent
            or parent.st_uid != self.guard.uid
            or parent.st_mode & 0o077
            or not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != self.guard.uid
            or info.st_mode & 0o077
        ):
            raise ArchiveError("manager_attestation_socket_denied")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect(self.path)
            if peer_uid(connection) != self.guard.uid:
                raise ArchiveError("manager_attestation_peer_denied")
            connection.sendall(
                json.dumps(
                    {"operation": "attest", "instance": registered["id"]},
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
            value = read_frame(connection)
            self.guard.check()
            if (
                type(value) is not dict
                or set(value) != {"ok", "context"}
                or value["ok"] is not True
                or type(value["context"]) is not dict
                or set(value["context"]) != set(Context.__dataclass_fields__)
            ):
                raise ArchiveError("manager_attestation_unavailable")
            return Context(**value["context"])
        except (OSError, ValueError, TypeError):
            raise ArchiveError("manager_attestation_unavailable") from None
        finally:
            connection.close()


class AttestationServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, path, manager):
        self.manager = manager
        self.slots = threading.BoundedSemaphore(4)
        self.stall_lock = threading.Lock()
        self.stalls = 0
        path = Path(path)
        parent = path.parent.stat()
        if (
            path.parent.resolve() != path.parent
            or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077
        ):
            raise ArchiveError("manager_attestation_socket_denied")
        manager.store.guard.check()
        if path.exists() or path.is_symlink():
            old = path.lstat()
            if not stat.S_ISSOCK(old.st_mode) or old.st_uid != os.geteuid():
                raise ArchiveError("manager_attestation_socket_denied")
            # Refuse a live daemon. Only a stale, same-UID socket may be replaced.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(1)
                probe.connect(str(path))
            except ConnectionRefusedError:
                path.unlink()
            else:
                raise ArchiveError("manager_daemon_already_running")
            finally:
                probe.close()
        super().__init__(str(path), AttestationHandler)
        path.chmod(0o600)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            with self.stall_lock:
                self.stalls += 1
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def flush_stalls(self):
        with self.stall_lock:
            count = self.stalls
            self.stalls = 0
        if count:
            try:
                self.manager.store.event("manager_attestation_stall", amount=count)
            except Exception:
                with self.stall_lock:
                    self.stalls += count

    def handle_error(self, request, client_address):
        try:
            self.manager.store.event("manager_attestation_unexpected")
        except Exception:
            pass


class AttestationHandler(socketserver.BaseRequestHandler):
    def handle(self):
        manager = self.server.manager
        try:
            self.request.settimeout(20)
            manager.store.guard.check()
            if peer_uid(self.request) != manager.store.guard.uid:
                raise ArchiveError("manager_attestation_peer_denied")
            value = read_frame(self.request)
            if (
                type(value) is not dict
                or set(value) != {"operation", "instance"}
                or value["operation"] != "attest"
                or type(value["instance"]) is not str
                or not re.fullmatch(r"[a-f0-9]{32}", value["instance"])
            ):
                raise ArchiveError("manager_attestation_request_denied")
            context = manager.attest(value["instance"])
            manager.store.guard.check()
            self.request.sendall(
                json.dumps(
                    {"ok": True, "context": context.__dict__}, separators=(",", ":")
                ).encode()
                + b"\n"
            )
        except (ArchiveError, OSError, ValueError):
            try:
                self.request.sendall(b'{"ok":false,"context":null}\n')
            except OSError:
                pass
            # No payload, exception body, keys or identifiers from the caller.
            try:
                manager.store.event("manager_attestation_refused")
            except ArchiveError:
                pass


def reconcile(manager, *, limit=16):
    """Poll persisted serials; events only accelerate this bounded reconciliation."""
    manager.db.expire()
    with manager.store.connect() as db:
        cursor = db.execute(
            "SELECT value FROM metadata WHERE key='manager_round_robin'"
        ).fetchone()
        cursor = cursor[0] if cursor else ""
        instances = db.execute(
            "SELECT id FROM manager_instances WHERE state='active' AND id>? ORDER BY id LIMIT ?",
            (cursor, min(limit, 16)),
        ).fetchall()
        if not instances:
            instances = db.execute(
                "SELECT id FROM manager_instances WHERE state='active' ORDER BY id LIMIT ?",
                (min(limit, 16),),
            ).fetchall()
        if instances:
            db.execute(
                "INSERT INTO metadata VALUES('manager_round_robin',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (instances[-1][0],),
            )
    for (instance,) in instances:
        try:
            manager.attest(instance)
            with manager.store.connect() as db:
                registered = manager.db.instance(instance, db)
            updates = manager.transport.updates(registered, registered["serial"])
            for update in updates:
                if (
                    type(update) is not dict
                    or type(update.get("serial")) is not int
                    or "payload" not in update
                ):
                    manager.store.event("manager_update_invalid", job=instance)
                    break
                result = manager.db.ingest(
                    instance, update["serial"], update["payload"]
                )
                if result == "gap":
                    break
            manager.tick()
            with manager.store.connect() as db:
                outbox = db.execute(
                    "SELECT seq,payload,attempts FROM manager_outbox WHERE instance=? AND state='pending' AND due<=? ORDER BY seq LIMIT 8",
                    (instance, time.time()),
                ).fetchall()
            for sequence, payload, attempt in outbox:
                try:
                    manager.attest(instance)
                    manager.transport.send(registered, payload)
                except ArchiveError as exc:
                    if exc.reason in DEFINITIVE_AUTHORITY_LOSS:
                        manager.db.revoke_instance(instance, exc.reason)
                        break
                    with manager.store.transaction() as db:
                        changed = db.execute(
                            "UPDATE manager_outbox SET attempts=attempts+1,state=CASE WHEN attempts>=4 THEN 'held' ELSE 'pending' END,due=? WHERE seq=? AND instance=? AND state='pending' AND EXISTS(SELECT 1 FROM manager_instances WHERE id=? AND state='active')",
                            (
                                time.time() + min(300, 2**attempt),
                                sequence,
                                instance,
                                instance,
                            ),
                        ).rowcount
                        manager.store._ledger(
                            db, "manager_send_ambiguous", job=instance
                        )
                        if not changed:
                            manager.store._ledger(
                                db, "manager_send_retry_fenced", job=instance
                            )
                    break
                else:
                    with manager.store.transaction() as db:
                        db.execute(
                            "UPDATE manager_outbox SET state='sent' WHERE seq=?",
                            (sequence,),
                        )
                        manager.store._ledger(db, "manager_response_sent", job=instance)
        except ArchiveError as exc:
            if exc.reason == "manager_history_quarantine_required":
                manager.db.revoke_instance(
                    instance, "manager_history_quarantined", state="quarantined"
                )
            elif exc.reason in DEFINITIVE_AUTHORITY_LOSS:
                manager.db.revoke_instance(instance, exc.reason)
            manager.store.event(exc.reason, job=instance)
