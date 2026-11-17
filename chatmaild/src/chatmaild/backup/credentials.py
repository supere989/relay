"""Fixed-argv private-pipe broker protocol and concrete procreator KWallet adapter.

The relay may configure a restricted remote transport implementing this JSON
contract. It must never fall back to files, ADC, or an operator Google account.
"""

import json
import os
import re
import secrets
import subprocess
import sys

import requests

from . import recovery_tool as tool
from .model import DRIVE_SCOPE, ArchiveError

TOKEN_URL = "https://oauth2.googleapis.com/token"
REF = re.compile(r"^[a-z0-9-]{1,160}$")


class Broker:
    def __init__(self, argv):
        if not argv or not all(isinstance(arg, str) for arg in argv):
            raise ValueError("fixed broker argv required")
        self.argv = tuple(argv)

    def call(self, operation, **payload):
        try:
            result = subprocess.run(
                self.argv,
                input=json.dumps({"operation": operation, **payload}).encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            if result.returncode or len(result.stdout) > 65536:
                raise ArchiveError("broker_unavailable")
            reply = json.loads(result.stdout)
            if not reply.get("ok"):
                raise ArchiveError("broker_unavailable")
            return reply["value"]
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            raise ArchiveError("broker_unavailable") from exc

    def put(self, value):
        ref = "archive-" + secrets.token_hex(24)
        self.call("put", ref=ref, value=value)
        return ref

    def get(self, ref):
        return self.call("get", ref=ref)

    def key(self):
        return self.call("key")

    def recovery_key(self, ref, recipient):
        value = self.call("recovery-key", ref=ref, recipient=recipient)
        return verified_identity(value, recipient)

    def manifest_key(self, ref, binding, recipient):
        value = self.call("manifest-key", ref=ref, binding=binding, recipient=recipient)
        if (
            type(value) is not dict
            or set(value) != {"key"}
            or type(value["key"]) is not str
            or not tool.HEX64.fullmatch(value["key"])
        ):
            raise ArchiveError("manifest_key_invalid")
        return bytes.fromhex(value["key"])


def verified_identity(value, recipient):
    if type(value) is not dict or set(value) != {"identity"}:
        raise ArchiveError("recovery_key_type")
    try:
        identity = tool.normalize_identity(value["identity"])
        actual = tool.public_recipient(identity)
    except tool.RecoveryError as exc:
        raise ArchiveError("recovery_key_invalid") from exc
    if actual != recipient:
        raise ArchiveError("recovery_recipient_mismatch")
    return identity


class Wallet:
    """Only used inside the broker process, next to an unlocked KWallet."""

    def __init__(
        self, kwsecret="/home/raymondj/.local/bin/kwsecret", folder="ChatmailArchive"
    ):
        self.kwsecret, self.folder = kwsecret, folder

    def call(self, operation, **payload):
        ref = payload.get("ref", "")
        if operation in ("put", "get", "recovery-key", "manifest-key") and (
            type(ref) is not str or not REF.fullmatch(ref)
        ):
            raise ArchiveError("invalid_credential_ref")
        if operation == "put":
            value = json.dumps(payload["value"], separators=(",", ":")).encode()
            self._run([self.kwsecret, "put", self.folder, ref, "--stdin"], value)
            self._run([self.kwsecret, "verify", self.folder, ref])
            return ref
        if operation == "get":
            # kwsecret exec feeds an environment to a tiny fixed child. stdout
            # is a private subprocess pipe to the caller, never a terminal.
            data = self._run(
                [
                    self.kwsecret,
                    "exec",
                    "-e",
                    f"CHATMAIL_ARCHIVE_SECRET={self.folder}/{ref}",
                    "--",
                    sys.executable,
                    "-m",
                    "chatmaild.backup.credentials",
                    "emit",
                ]
            )
            return json.loads(data)
        if operation in ("recovery-key", "manifest-key"):
            identity = verified_identity(
                self.call("get", ref=ref), payload.get("recipient")
            )
            if operation == "recovery-key":
                return {"identity": identity}
            try:
                return {
                    "key": tool.mac_key(
                        identity, payload.get("binding"), payload.get("recipient")
                    ).hex()
                }
            except tool.RecoveryError as exc:
                raise ArchiveError("manifest_key_invalid") from exc
        if operation == "key":
            identity = self._run(["/usr/bin/age-keygen"]).decode()
            recipient = next(
                (
                    line.split(": ", 1)[1]
                    for line in identity.splitlines()
                    if line.startswith("# public key: ")
                ),
                None,
            )
            if not recipient:
                raise ArchiveError("age_keygen_failed")
            ref = "archive-key-" + secrets.token_hex(24)
            self.call("put", ref=ref, value={"identity": identity})
            return {"ref": ref, "recipient": recipient}
        raise ArchiveError("broker_operation_denied")

    @staticmethod
    def _run(argv, data=None):
        try:
            result = subprocess.run(
                argv,
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ArchiveError("broker_unavailable") from exc
        if result.returncode:
            raise ArchiveError("broker_unavailable")
        return result.stdout


class Credentials:
    def __init__(self, broker, client_id, client_secret_ref, *, session=None):
        self.broker, self.client_id, self.client_secret_ref = (
            broker,
            client_id,
            client_secret_ref,
        )
        self.session = session or requests.Session()

    def exchange(self, code, redirect_uri):
        return self._token(
            {
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
        )

    def _token(self, fields):
        secret = self.broker.get(self.client_secret_ref)["client_secret"]
        try:
            response = self.session.post(
                TOKEN_URL,
                data={**fields, "client_id": self.client_id, "client_secret": secret},
                timeout=(5, 20),
            )
        except requests.RequestException as exc:
            raise ArchiveError("oauth_unavailable", retryable=True) from exc
        if response.status_code != 200:
            raise ArchiveError("reconnect")
        result = response.json()
        if not isinstance(result.get("access_token"), str):
            raise ArchiveError("oauth_invalid_response")
        return result

    def persist(self, binding, permission_id, tokens):
        if DRIVE_SCOPE not in tokens.get("scope", "").split() or not tokens.get(
            "refresh_token"
        ):
            raise ArchiveError("drive_consent_missing")
        return self.broker.put(
            {
                "owner": binding.owner,
                "binding": binding.id,
                "generation": binding.generation,
                "permission_id": permission_id,
                "refresh_token": tokens["refresh_token"],
                "scope": tokens["scope"],
            }
        )

    def access(self, binding):
        value = self.broker.get(binding.credential_ref)
        if (
            value.get("owner"),
            value.get("binding"),
            value.get("generation"),
            value.get("permission_id"),
        ) != (binding.owner, binding.id, binding.generation, binding.permission_id):
            raise ArchiveError("credential_binding_mismatch")
        if DRIVE_SCOPE not in value.get("scope", "").split():
            raise ArchiveError("drive_consent_missing")
        result = self._token(
            {"refresh_token": value["refresh_token"], "grant_type": "refresh_token"}
        )
        if "scope" in result and DRIVE_SCOPE not in result["scope"].split():
            raise ArchiveError("drive_consent_missing")
        return result["access_token"]


def activate_destination(
    store,
    credentials,
    binding,
    permission_id,
    tokens,
    drive,
    checkpoint,
    *,
    expected_ref,
):
    """First-wins activation with explicit custody for every created candidate."""
    artifacts = []

    def remember(kind, reference):
        store.candidate(binding, kind, reference)
        artifacts.append((kind, reference))

    try:
        reference = credentials.persist(binding, permission_id, tokens)
        remember("credential_ref", reference)
        if binding.key_ref:
            key = {"ref": binding.key_ref, "recipient": binding.recipient}
        else:
            key = credentials.broker.key()
            remember("key_ref", key["ref"])
        folder = binding.folder_id
        if folder is None:
            try:
                folder = drive.folder()
            except Exception as exc:
                store.event(
                    "drive_folder_creation_uncertain"
                    if not isinstance(exc, ArchiveError) or exc.uncertain
                    else "drive_folder_creation_failed",
                    binding.id,
                )
                raise
            remember("drive_folder", folder)
        checkpoint()
        activated = store.consent(
            binding.id,
            binding.owner,
            binding.generation,
            permission_id,
            reference,
            key["ref"],
            key["recipient"],
            folder,
            expected_ref=expected_ref,
        )
        if not activated:
            raise ArchiveError("stale_credential_outcome")
    except Exception:
        store.unused_candidates(binding, artifacts)
        raise


def main():
    if sys.argv[1:] == ["emit"]:
        sys.stdout.write(os.environ["CHATMAIL_ARCHIVE_SECRET"])
        return
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ArchiveError("broker_request_limit")
        request = json.loads(raw)
        operation = request.pop("operation")
        value = Wallet().call(operation, **request)
        sys.stdout.write(json.dumps({"ok": True, "value": value}))
    except Exception:
        # Never serialize exception messages, subprocess stderr, or request data.
        sys.stdout.write('{"ok":false}')
        sys.exit(1)


if __name__ == "__main__":
    main()
