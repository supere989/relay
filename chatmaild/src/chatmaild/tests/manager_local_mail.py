"""Isolated loopback SMTP-to-Maildir + real Dovecot IMAP acceptance fixture.

Not a deployment helper. Uses only synthetic users and ephemeral /tmp state;
no password files, external delivery, system services or raw MIME logging.
The containing acceptance container must mount /tmp as tmpfs.
"""

import argparse
import json
import logging
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class LocalMailFailure(RuntimeError):
    """Only fixed fixture diagnostics; never carry daemon text or config."""

    def __init__(
        self, reason, exit_code=None, connect_errno=None, category=None, tokens=()
    ):
        super().__init__(reason)
        self.diagnostic = {
            "reason": reason,
            "child_exit": exit_code,
            "connect_errno": connect_errno,
            "startup_category": category,
            "fixed_tokens": list(tokens),
        }


class Delivery:
    def __init__(self, root, uid, gid):
        self.root, self.uid, self.gid = root, uid, gid
        self.lock = threading.Lock()
        self.encrypted = {"bot": 0, "peer": 0}

    def counts(self):
        with self.lock:
            return dict(self.encrypted)

    async def handle_DATA(self, _server, _session, envelope):
        if len(envelope.original_content) > 4 * 1024 * 1024:
            return "552 synthetic fixture size bound"
        destinations = []
        for address in envelope.rcpt_tos:
            name, separator, domain = address.lower().partition("@")
            if (
                separator != "@"
                or domain != "example.invalid"
                or name not in ("bot", "peer")
            ):
                return "550 synthetic recipients only"
            destinations.append(name)
        # Positive MIME structure, not an absence-of-plaintext heuristic. Never
        # retain a body/header sample or expose ciphertext in test artifacts.
        message = BytesParser(policy=policy.default).parsebytes(
            envelope.original_content
        )
        parts = list(message.iter_parts()) if message.is_multipart() else []
        encrypted = (
            message.get_content_type() == "multipart/encrypted"
            and message.get_param("protocol") == "application/pgp-encrypted"
            and len(parts) == 2
            and parts[0].get_content_type() == "application/pgp-encrypted"
            and parts[1].get_content_type() == "application/octet-stream"
            and bool(parts[1].get_payload(decode=True))
        )
        for name in destinations:
            path = (
                self.root
                / name
                / "new"
                / (str(time.time_ns()) + "." + secrets.token_hex(8))
            )
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                if os.geteuid() == 0:
                    os.fchown(fd, self.uid, self.gid)
                data = memoryview(envelope.original_content)
                while data:
                    data = data[os.write(fd, data) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            if encrypted:
                with self.lock:
                    self.encrypted[name] += 1
        return "250 synthetic delivery complete"


class LocalMail:
    def __init__(self):
        self.directory = Path(
            tempfile.mkdtemp(prefix="manager-local-mail-", dir="/tmp")
        )
        self.directory.chmod(0o755)
        self.imap, self.smtp = port(), port()
        self.uid = 10001 if os.geteuid() == 0 else os.geteuid()
        self.gid = 10001 if os.geteuid() == 0 else os.getegid()
        self.mail = self.directory / "mail"
        self.mail.mkdir(mode=0o755)
        for name in ("bot", "peer"):
            home = self.mail / name
            home.mkdir(mode=0o700)
            for component in (home, home / "cur", home / "new", home / "tmp"):
                if component != home:
                    component.mkdir(mode=0o700)
                if os.geteuid() == 0:
                    os.chown(component, self.uid, self.gid)
        self.process = None
        self.controller = None

    def start(self):
        from aiosmtpd.controller import Controller

        for name in ("mail.log", "aiosmtpd", "mail.debug"):
            logging.getLogger(name).disabled = True
        base = self.directory
        text = f"""protocols = imap
listen = 127.0.0.1
base_dir = {base}/run
state_dir = {base}/state
instance_name = archive-manager-synthetic
ssl = no
disable_plaintext_auth = no
auth_mechanisms = plain login
auth_username_format = %Ln
first_valid_uid = {self.uid}
last_valid_uid = {self.uid}
mail_location = maildir:{self.mail}/%n
mail_uid = {self.uid}
mail_gid = {self.gid}
log_path = /dev/stderr
info_log_path = /dev/null
debug_log_path = /dev/null
passdb {{
 driver = static
 args = nopassword=y
}}
userdb {{
 driver = static
 args = uid={self.uid} gid={self.gid} home={self.mail}/%n
}}
service imap-login {{
 inet_listener imap {{
  address = 127.0.0.1
  port = {self.imap}
 }}
 inet_listener imaps {{
  port = 0
 }}
}}
namespace inbox {{
 inbox = yes
}}
"""
        config = base / "dovecot.conf"
        config.write_text(text)
        config.chmod(0o600)
        self.process = subprocess.Popen(
            ["/usr/sbin/dovecot", "-F", "-c", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        os.set_blocking(self.process.stderr.fileno(), False)
        deadline = time.monotonic() + 10
        connect_errno = None
        while time.monotonic() < deadline:
            exit_code = self.process.poll()
            if exit_code is not None:
                # Classify bounded private startup bytes in RAM. No raw daemon
                # output, paths, configuration or messages leave this fixture.
                raw = self.process.stderr.read(8192) or b""
                category = "other"
                for marker, code in (
                    (b"Permission denied", "permission"),
                    (b"Address already in use", "port_in_use"),
                    (b"Error in configuration file", "config_parse"),
                    (b"Unknown setting", "config_parse"),
                    (b"No such file or directory", "missing_runtime_file"),
                    (b"Read-only file system", "readonly_runtime_path"),
                    (b"Invalid argument", "invalid_runtime_argument"),
                ):
                    if marker in raw:
                        category = code
                        break
                tokens = [
                    token.decode("ascii")
                    for token in (
                        b"default_login_user",
                        b"default_internal_user",
                        b"dovenull",
                        b"dovecot",
                        b"service(imap-login)",
                        b"service(auth)",
                        b"service(stats)",
                        b"service(anvil)",
                        b"service(log)",
                        b"ssl_dh",
                        b"ssl_cert",
                        b"ssl_key",
                        b"base_dir",
                        b"state_dir",
                        b"mail_location",
                        b"mail_uid",
                        b"mail_gid",
                        b"getpwnam",
                        b"getgrnam",
                        b"setuid",
                        b"setgid",
                        b"net_bind",
                        b"chown",
                        b"mkdir",
                        b"execv",
                        b"master.pid",
                        b"login",
                        b"chroot",
                        b"limits",
                    )
                    if token in raw
                ]
                raise LocalMailFailure(
                    "synthetic_imap_start_failed",
                    exit_code,
                    connect_errno,
                    category,
                    tokens,
                )
            try:
                with socket.create_connection(("127.0.0.1", self.imap), timeout=0.2):
                    break
            except OSError as exc:
                connect_errno = exc.errno
                time.sleep(0.05)
        else:
            raise LocalMailFailure(
                "synthetic_imap_start_timeout",
                None,
                connect_errno,
                "readiness_timeout",
            )
        self.delivery = Delivery(self.mail, self.uid, self.gid)
        self.controller = Controller(
            self.delivery,
            hostname="127.0.0.1",
            port=self.smtp,
            auth_require_tls=False,
            auth_callback=lambda *_args: True,
            decode_data=False,
        )
        self.controller.start()
        return self

    def settings(self, name):
        return {
            "imapServer": "127.0.0.1",
            "imapPort": self.imap,
            "imapSecurity": "plain",
            "imapUser": name,
            "smtpServer": "127.0.0.1",
            "smtpPort": self.smtp,
            "smtpSecurity": "plain",
            "smtpUser": name,
            "certificateChecks": "acceptInvalidCertificates",
        }

    def close(self):
        if self.controller is not None:
            self.controller.stop()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self.process is not None and self.process.stderr is not None:
            self.process.stderr.close()
        # /tmp is container tmpfs. Keep failed fixture state private until the
        # disposable container is removed; never retain it as host artifacts.

    def __enter__(self):
        return self.start()

    def __exit__(self, *_args):
        self.close()


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic LocalMail startup only; fixed diagnostics, no raw logs"
    )
    parser.add_argument("--startup-check", action="store_true", required=True)
    parser.parse_args()
    fixture = None
    try:
        fixture = LocalMail()
        fixture.start()
        print(json.dumps({"state": "passed", "imap_ready": True, "smtp_ready": True}))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "state": "failed",
                    "exception": type(exc).__name__,
                    "diagnostic": exc.diagnostic
                    if isinstance(exc, LocalMailFailure)
                    else None,
                }
            )
        )
        return 1
    finally:
        if fixture is not None:
            fixture.close()


if __name__ == "__main__":
    raise SystemExit(main())
