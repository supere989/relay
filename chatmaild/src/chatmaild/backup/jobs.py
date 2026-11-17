"""Durable bounded archive jobs. Run only in a separate worker process."""

import hashlib
import json
import os
from pathlib import Path

from . import bundle
from .drive import Drive
from .incarnation import Mailbox
from .model import ArchiveError
from .policy import check as check_operator
from .sources import capture


class Worker:
    def __init__(
        self,
        store,
        credentials,
        mailboxes_root,
        spool,
        *,
        drive_factory=Drive,
        encrypt=bundle.encrypt,
        max_attempts=8,
        policy_loader=lambda: {},
    ):
        self.store, self.credentials = store, credentials
        self.mailboxes_root, self.spool = Path(mailboxes_root), Path(spool)
        self.spool.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.spool.is_symlink() or self.spool.stat().st_mode & 0o077:
            raise ArchiveError("spool_not_private")
        self.drive_factory, self.encrypt, self.max_attempts = (
            drive_factory,
            encrypt,
            max_attempts,
        )
        self.stop = None
        self.policy_loader = policy_loader

    def checkpoint(self, binding_id, generation, mailbox=None):
        if self.stop is not None and self.stop.is_set():
            raise ArchiveError("worker_shutdown", retryable=True)
        b = self.store.active(binding_id, generation)
        if b.mode == "operator":
            try:
                check_operator(self.policy_loader(), b)
            except Exception as exc:
                reason = (
                    exc.reason
                    if isinstance(exc, ArchiveError)
                    else "operator_policy_unavailable"
                )
                self.store.revoke_operator(b.id, reason)
                raise ArchiveError(reason) from exc
        if mailbox is not None:
            mailbox.check(b.incarnation)
        return b

    def reconcile(self):
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT value FROM metadata WHERE key='reconcile_after'"
            ).fetchone()
            after = row[0] if row else ""
            ids = [
                r[0]
                for r in db.execute(
                    "SELECT id FROM bindings WHERE enabled=1 AND consent='active' AND id>? ORDER BY id LIMIT 128",
                    (after,),
                )
            ]
            if not ids and after:
                ids = [
                    r[0]
                    for r in db.execute(
                        "SELECT id FROM bindings WHERE enabled=1 AND consent='active' ORDER BY id LIMIT 128"
                    )
                ]
            db.execute(
                "INSERT OR REPLACE INTO metadata(key,value) VALUES('reconcile_after',?)",
                (ids[-1] if ids else "",),
            )
        for binding_id in ids:
            try:
                self.checkpoint(binding_id, self.store.get(binding_id).generation)
                self.store.enqueue(binding_id)
            except ArchiveError as exc:
                self.store.event(exc.reason, binding_id)
        self.store.event("reconcile_bindings", amount=len(ids))

    def run(self, job_id):
        job = self.store.job(job_id)
        binding_id = job["binding_id"]
        try:
            with self.store.operation(binding_id, job_id, kind="worker"):
                snapshot = self.store.start_attempt(job_id)
                if snapshot is None:
                    return
                job, b = snapshot
                try:
                    self._run(job, b)
                except ArchiveError as exc:
                    self._failed(job, exc, credential_ref=job["attempt_credential_ref"])
                except Exception:
                    self._failed(
                        job,
                        ArchiveError(
                            "worker_unexpected", retryable=True, uncertain=True
                        ),
                        credential_ref=job["attempt_credential_ref"],
                    )
        except ArchiveError as exc:
            if exc.reason != "operation_busy":
                raise

    def attempt_checkpoint(self, job, b, mailbox=None):
        current = self.checkpoint(b.id, job["generation"], mailbox)
        if current.credential_ref != job["attempt_credential_ref"]:
            raise ArchiveError(
                "credential_changed", retryable=True, uncertain=bool(job["file_id"])
            )
        return current

    def _run(self, job, b):
        self.attempt_checkpoint(job, b)
        with Mailbox(self.mailboxes_root, b.mailbox) as mailbox:
            mailbox.check(b.incarnation)
            self._run_bound(job, b, mailbox)

    def _run_bound(self, job, b, mailbox):
        store, job_id = self.store, job["id"]
        store.event("worker_started", b.id, job_id)
        token = self.credentials.access(b)
        checkpoint = lambda: self.attempt_checkpoint(job, b, mailbox)
        drive = self.drive_factory(token, checkpoint=checkpoint)
        drive.on_commit = lambda: store.update_job(job_id, "uploaded-unverified")
        checkpoint()
        if drive.principal() != job["permission_id"]:
            raise ArchiveError("drive_principal_changed")
        if not job["spool"]:
            cursor, _revision, _scan = store.capture_start(
                job_id, credential_ref=job["attempt_credential_ref"]
            )
            messages = capture(
                self.mailboxes_root,
                b.mailbox,
                b.id,
                store.seen(b.id, lookup=True),
                checkpoint=checkpoint,
                after=cursor,
                mailbox_fd=mailbox.fd,
                retry_allowed=lambda entry: store.source_retry_allowed(b.id, entry),
            )
            store.record_unresolved(b.id, job_id, getattr(messages, "unresolved", ()))
            if getattr(messages, "held", 0):
                store.event("source_retry_held", b.id, job_id, messages.held)
            if not messages:
                store.update_job(
                    job_id,
                    "prepared",
                    size=0,
                    message_ids="[]",
                    capture_cursor=getattr(messages, "cursor", None),
                    capture_resolved=json.dumps(getattr(messages, "resolved", ())),
                )
                checkpoint()
                store.verified(job_id, credential_ref=job["attempt_credential_ref"])
                store.event("capture_no_changes", b.id, job_id)
                return
            store.event("capture_messages", b.id, job_id, len(messages))
            store.event(
                "capture_bytes", b.id, job_id, sum(len(m.data) for m in messages)
            )
            if self.encrypt is bundle.encrypt:
                key = self.credentials.broker.manifest_key(
                    job["key_ref"], b.id, job["recipient"]
                )
                checkpoint()
                ciphertext = self.encrypt(
                    messages, job["recipient"], job_id, binding=b.id, mac_key=key
                )
            else:
                ciphertext = self.encrypt(messages, job["recipient"], job_id)
            path = self.spool / (job_id + ".age")
            # Opaque fixed names, ciphertext only, no plaintext tar spool.
            temporary = self.spool / (job_id + ".partial")
            try:
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                dirfd = os.open(self.spool, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
            except FileExistsError as exc:
                raise ArchiveError("spool_recovery_required") from exc
            store.update_job(
                job_id,
                "prepared",
                spool=path.name,
                size=len(ciphertext),
                sha256=hashlib.sha256(ciphertext).hexdigest(),
                message_ids=json.dumps([m.id for m in messages]),
                capture_cursor=messages.cursor,
                capture_resolved=json.dumps(messages.resolved),
            )
            job = store.job(job_id)
        else:
            if job["spool"] != job_id + ".age":
                raise ArchiveError("spool_path_invalid")
            fd = os.open(self.spool / job["spool"], os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                ciphertext = stream.read(bundle.MAX_CLEAR + 1024 * 1024)
            if (
                len(ciphertext) != job["size"]
                or hashlib.sha256(ciphertext).hexdigest() != job["sha256"]
            ):
                raise ArchiveError("spool_checksum")
        if not job["file_id"]:
            store.update_job(job_id, "prepared", file_id=drive.allocate())
            job = store.job(job_id)
        checkpoint()
        store.update_job(job_id, "uploading")
        receipt = drive.upload(job["file_id"], job["folder_id"], ciphertext, job_id)
        store.update_job(job_id, "uploaded-unverified")
        if (receipt.file_id, receipt.size, receipt.sha256) != (
            job["file_id"],
            job["size"],
            job["sha256"],
        ):
            raise ArchiveError("receipt_mismatch")
        checkpoint()
        store.verified(job_id, credential_ref=job["attempt_credential_ref"])
        # Retain ciphertext spool for audit/recovery; explicit retention policy
        # is an operator decision. No local message or Drive file is pruned.

    def _failed(self, job, exc, *, credential_ref):
        return self.store.fail(
            job["id"],
            exc,
            credential_ref=credential_ref,
            max_attempts=self.max_attempts,
        )

    def verify(self, job_id):
        initial = self.store.job(job_id)
        with self.store.operation(initial["binding_id"], job_id, kind="verify"):
            job, b = self.store.start_attempt(job_id, verify=True)
            try:
                self.attempt_checkpoint(job, b)
                with Mailbox(self.mailboxes_root, b.mailbox) as mailbox:
                    checkpoint = lambda: self.attempt_checkpoint(job, b, mailbox)
                    checkpoint()
                    if (
                        not job["spool"]
                        or job["spool"] != job_id + ".age"
                        or not job["file_id"]
                    ):
                        raise ArchiveError("job_no_remote_receipt")
                    fd = os.open(self.spool / job["spool"], os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(fd, "rb") as stream:
                        ciphertext = stream.read(bundle.MAX_CLEAR + 1024 * 1024)
                    if (
                        len(ciphertext) != job["size"]
                        or hashlib.sha256(ciphertext).hexdigest() != job["sha256"]
                    ):
                        raise ArchiveError("spool_checksum")
                    drive = self.drive_factory(
                        self.credentials.access(b), checkpoint=checkpoint
                    )
                    checkpoint()
                    if drive.principal() != job["permission_id"]:
                        raise ArchiveError("drive_principal_changed")
                    drive.verify(job["file_id"], ciphertext)
                    checkpoint()
                    if (
                        not self.store.verified(
                            job_id, credential_ref=job["attempt_credential_ref"]
                        )
                        and self.store.job(job_id)["state"] != "verified"
                    ):
                        raise ArchiveError(
                            "credential_changed", retryable=True, uncertain=True
                        )
                    self.store.event("receipt_reverified", b.id, job_id)
            except ArchiveError as exc:
                self._failed(job, exc, credential_ref=job["attempt_credential_ref"])
                raise
            except Exception:
                exc = ArchiveError("verify_unexpected", retryable=True, uncertain=True)
                self._failed(job, exc, credential_ref=job["attempt_credential_ref"])
                raise exc from None

    def serve(self, stop, interval=60):
        """Caller supplies a threading.Event set by SIGTERM/SIGINT."""
        self.stop = stop
        while not stop.is_set():
            self.reconcile()
            for job_id in self.store.due():
                if stop.is_set():
                    break
                self.run(job_id)
            stop.wait(interval)
