"""Optional archive entry point. No command activates a service or timer."""

import argparse
import json
import os
import secrets
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from chatmaild.config import read_config

from .bundle import restore
from .credentials import Broker, Credentials, activate_destination
from .drive import Drive
from .incarnation import Mailbox
from .jobs import Worker
from .model import DRIVE_SCOPE, ArchiveError, subject
from .policy import authority
from .policy import check as check_operator
from .store import Store
from .web import AUTH_URL, Portal, Server, verify_google


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise ArchiveError("config_limit")
    config = json.loads(raw)
    for field in ("database", "spool", "chatmail_ini"):
        if not Path(config[field]).is_absolute():
            raise ArchiveError("config_path_must_be_absolute")
    store = Store(config["database"])
    broker = Broker(config["broker_argv"])
    credentials = Credentials(
        broker, config["google_client_id"], config["google_client_secret_ref"]
    )
    return config, store, credentials


def operator_binding(config, store, identity, mailbox):
    operator = config.get("operator", {})
    if (
        not operator
        or os.getuid() != operator.get("uid")
        or identity != operator.get("identity")
        or mailbox not in operator.get("mailboxes", [])
    ):
        store.event("operator_authority_denied")
        raise ArchiveError("operator_authority_denied")
    owner, delegation = authority(config, mailbox)
    relay = read_config(config["chatmail_ini"])
    binding = None
    try:
        with Mailbox(relay.mailboxes_dir, mailbox) as source:
            incarnation = source.ensure_marker()
            source.check(incarnation)
            binding = store.bind(
                owner,
                mailbox,
                mode="operator",
                allowlist=operator["mailboxes"],
                incarnation=incarnation,
                operator_authority=delegation,
            )
            source.check(incarnation)
            return binding
    except ArchiveError:
        if binding is not None:
            store.invalidate_incarnation(binding.id)
        raise


def read_policy(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise ArchiveError("operator_policy_unavailable")
    return json.loads(raw)


def quarantine_destination(config, relay, destination):
    root = Path(
        config.get(
            "quarantine_root", str(Path(config["database"]).parent / "quarantine")
        )
    )
    target = Path(destination)
    if (
        not root.is_absolute()
        or not target.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or root.stat().st_mode & 0o077
    ):
        raise ArchiveError("quarantine_not_private")
    root, target, live = root.resolve(), target.resolve(), relay.mailboxes_dir.resolve()
    if (
        target.parent != root
        or target == live
        or live in target.parents
        or target.exists()
    ):
        raise ArchiveError("restore_destination_denied")
    return target


def operator_consent(
    config, store, credentials, identity, mailbox, *, policy_loader=None
):
    """Explicit local administrator flow, isolated from ordinary Google login.

    Register this loopback redirect in the operator OAuth client. No browser is
    launched and no authorization is inferred from an email address.
    """
    b = operator_binding(config, store, identity, mailbox)
    policy_loader = policy_loader or (lambda: config)
    store.enable(b.id, b.owner)
    b = store.get(b.id)
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    redirect = "http://127.0.0.1:8766/callback"
    received = {}

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if len(self.path) <= 8192 and urlsplit(self.path).path == "/callback":
                try:
                    values = parse_qs(urlsplit(self.path).query, max_num_fields=8)
                    if all(len(value) == 1 for value in values.values()):
                        received.update(
                            {key: value[0] for key, value in values.items()}
                        )
                except ValueError:
                    pass
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

    with HTTPServer(("127.0.0.1", 8766), Callback) as server:
        server.timeout = 60
        print(
            AUTH_URL
            + "?"
            + urlencode(
                {
                    "client_id": credentials.client_id,
                    "redirect_uri": redirect,
                    "response_type": "code",
                    "scope": "openid " + DRIVE_SCOPE,
                    "state": state,
                    "nonce": nonce,
                    "access_type": "offline",
                    "prompt": "consent",
                }
            )
        )
        print(
            "Open the authorization URL locally within 60 seconds; this explicit operator flow archives only its selected mailbox."
        )
        sys.stdout.flush()
        server.handle_request()
    if (
        not secrets.compare_digest(received.get("state", ""), state)
        or "error" in received
        or not received.get("code")
    ):
        store.event("operator_consent_incomplete", b.id)
        raise ArchiveError("operator_consent_incomplete")
    tokens = credentials.exchange(received["code"], redirect)
    if (
        verify_google(tokens.get("id_token", ""), credentials.client_id, nonce)
        != b.owner
    ):
        raise ArchiveError("google_account_mismatch")
    drive = Drive(tokens["access_token"])
    permission = drive.principal()
    if b.permission_id and b.permission_id != permission:
        raise ArchiveError("drive_principal_changed")

    def checkpoint():
        check_operator(policy_loader(), b)
        try:
            with Mailbox(
                read_config(config["chatmail_ini"]).mailboxes_dir, b.mailbox
            ) as source:
                source.check(b.incarnation)
        except ArchiveError:
            store.invalidate_incarnation(b.id)
            raise

    activate_destination(
        store,
        credentials,
        b,
        permission,
        tokens,
        drive,
        checkpoint,
        expected_ref=b.credential_ref,
    )
    store.enqueue(b.id)
    store.event("operator_consent_active", b.id)
    print(json.dumps({"binding": b.id, "state": "active"}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", required=True, help="Secret-free optional archive JSON config"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("web")
    commands.add_parser("worker")
    commands.add_parser("upload", help="Run one bounded batch of already queued jobs")
    prepare = commands.add_parser(
        "prepare", help="Enqueue one active binding; no upload"
    )
    prepare.add_argument("binding")
    retry = commands.add_parser(
        "retry", help="Explicitly resume the same stopped job and Drive file ID"
    )
    retry.add_argument("job")
    receipt = commands.add_parser(
        "receipt", help="Show pinned opaque recovery references for one historical job"
    )
    receipt.add_argument("job")
    retry_sources = commands.add_parser(
        "retry-sources", help="Explicitly retry held unresolved source entries"
    )
    retry_sources.add_argument("binding")
    verify = commands.add_parser(
        "verify", help="Re-download and verify an existing ciphertext receipt"
    )
    verify.add_argument("job")
    recovery = commands.add_parser(
        "restore-to-empty-staging",
        help="Decrypt local ciphertext into NEW private quarantine only",
    )
    recovery.add_argument("ciphertext")
    recovery.add_argument("key_ref")
    recovery.add_argument("destination")
    operator = commands.add_parser(
        "operator-consent", help="Separate explicit administrator Drive flow"
    )
    operator.add_argument("--identity", required=True)
    operator.add_argument("--mailbox", required=True)
    revoke = commands.add_parser(
        "operator-revoke",
        help="Explicitly disable selected operator archival authority",
    )
    revoke.add_argument("--identity", required=True)
    revoke.add_argument("--mailbox", required=True)
    args = parser.parse_args(argv)
    try:
        config, store, credentials = load(args.config)
        relay = read_config(config["chatmail_ini"])
        if args.command == "status":
            print(
                json.dumps(
                    {
                        "format": 1,
                        "metrics": store.metrics(),
                        "key_custody": "operator-wallet",
                        "distribution": "deterministic-backoff-no-random-choice",
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "web":
            portal = Portal(store, relay, credentials, config["public_url"])
            server = Server(("127.0.0.1", int(config.get("web_port", 10090))), portal)
            with server:
                server.serve_forever(poll_interval=0.25)
        elif args.command in ("worker", "upload"):
            worker = Worker(
                store,
                credentials,
                relay.mailboxes_dir,
                config["spool"],
                policy_loader=lambda: read_policy(args.config),
            )
            if args.command == "upload":
                for job in store.due():
                    worker.run(job)
            else:
                stop = threading.Event()
                for signum in (signal.SIGTERM, signal.SIGINT):
                    signal.signal(signum, lambda *_args: stop.set())
                worker.serve(stop)
        elif args.command == "prepare":
            print(json.dumps({"job": store.enqueue(args.binding)}))
        elif args.command == "retry":
            store.retry(args.job)
            print(json.dumps({"job": args.job, "state": "queued-for-retry"}))
        elif args.command == "receipt":
            job = store.job(args.job)
            print(
                json.dumps(
                    {
                        key: job[key]
                        for key in (
                            "id",
                            "binding_id",
                            "generation",
                            "state",
                            "file_id",
                            "size",
                            "sha256",
                            "key_ref",
                            "recipient",
                            "folder_id",
                            "permission_id",
                        )
                    }
                )
            )
        elif args.command == "retry-sources":
            b = store.get(args.binding)
            Worker(
                store,
                credentials,
                relay.mailboxes_dir,
                config["spool"],
                policy_loader=lambda: read_policy(args.config),
            ).checkpoint(b.id, b.generation)
            store.retry_sources(b.id)
        elif args.command == "verify":
            Worker(
                store,
                credentials,
                relay.mailboxes_dir,
                config["spool"],
                drive_factory=Drive,
                policy_loader=lambda: read_policy(args.config),
            ).verify(args.job)
            print(json.dumps({"job": args.job, "verified": True}))
        elif args.command == "restore-to-empty-staging":
            destination = quarantine_destination(config, relay, args.destination)
            path = Path(args.ciphertext)
            if path.stat().st_size > 71 * 1024 * 1024:
                raise ArchiveError("restore_size_limit")
            identity = credentials.broker.get(args.key_ref)["identity"]
            result = restore(path.read_bytes(), identity, destination)
            store.event("restore_quarantined", amount=len(result["messages"]))
            print(
                json.dumps(
                    {"messages": len(result["messages"]), "state": "quarantined"}
                )
            )
        elif args.command == "operator-consent":
            operator_consent(
                config,
                store,
                credentials,
                args.identity,
                args.mailbox,
                policy_loader=lambda: read_policy(args.config),
            )
        elif args.command == "operator-revoke":
            operator = config.get("operator", {})
            if os.getuid() != operator.get("uid") or args.identity != operator.get(
                "identity"
            ):
                raise ArchiveError("operator_authority_denied")
            owner = subject("https://accounts.google.com", operator.get("google_sub"))
            selected = [
                b
                for b in store.owned(owner)
                if b.mode == "operator" and b.mailbox == args.mailbox and not b.retired
            ]
            if not selected:
                raise ArchiveError("binding_denied")
            for b in selected:
                store.revoke_operator(b.id)
    except ArchiveError as exc:
        print(json.dumps({"error": exc.reason}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
