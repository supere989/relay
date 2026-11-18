"""Versioned SQLite ledger. Transactions arbitrate ownership and worker races."""

import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from filelock import FileLock, Timeout

from .model import ArchiveError, Binding

SCHEMA = """
CREATE TABLE IF NOT EXISTS version (number INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO version VALUES (3);
CREATE TABLE IF NOT EXISTS bindings (
 id TEXT PRIMARY KEY, owner TEXT NOT NULL, mailbox TEXT NOT NULL,
 mode TEXT NOT NULL CHECK(mode IN ('personal','operator')),
 generation INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
 consent TEXT NOT NULL DEFAULT 'pending', permission_id TEXT,
 credential_ref TEXT, key_ref TEXT, recipient TEXT, folder_id TEXT,
 incarnation TEXT, retired INTEGER NOT NULL DEFAULT 0, operator_authority TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS personal_mailbox ON bindings(mailbox) WHERE mode='personal' AND retired=0;
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, binding_id TEXT NOT NULL REFERENCES bindings(id),
 generation INTEGER NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL DEFAULT 0,
 due REAL NOT NULL, file_id TEXT, spool TEXT, size INTEGER, sha256 TEXT,
 message_ids TEXT, last_reason TEXT, updated REAL NOT NULL, capture_cursor INTEGER,
 key_ref TEXT, recipient TEXT, folder_id TEXT, permission_id TEXT, incarnation TEXT,
 capture_resolved TEXT, attempt_credential_ref TEXT, capture_revision INTEGER,
 capture_scan INTEGER);
CREATE INDEX IF NOT EXISTS jobs_due ON jobs(state,due);
CREATE TABLE IF NOT EXISTS messages (
 binding_id TEXT NOT NULL, message_id TEXT NOT NULL, job_id TEXT NOT NULL,
 PRIMARY KEY(binding_id,message_id));
CREATE TABLE IF NOT EXISTS ledger (
 seq INTEGER PRIMARY KEY, at REAL NOT NULL, binding_id TEXT, job_id TEXT,
 reason TEXT NOT NULL, amount INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions (
 id_hash TEXT PRIMARY KEY, owner TEXT, csrf_hash TEXT NOT NULL, expires REAL NOT NULL,
 state_hash TEXT, nonce TEXT, purpose TEXT, binding_id TEXT, binding_generation INTEGER,
 oauth_expires REAL, binding_credential_ref TEXT);
CREATE TABLE IF NOT EXISTS unresolved (
 binding_id TEXT NOT NULL, entry_id TEXT NOT NULL, reason TEXT NOT NULL,
 attempts INTEGER NOT NULL, last_seen REAL NOT NULL, scan_revision INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(binding_id,entry_id));
CREATE TABLE IF NOT EXISTS artifacts (
 kind TEXT NOT NULL, reference TEXT NOT NULL, binding_id TEXT NOT NULL,
 generation INTEGER NOT NULL, state TEXT NOT NULL, updated REAL NOT NULL,
 PRIMARY KEY(kind,reference));
CREATE TABLE IF NOT EXISTS recovery_receipts (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
 binding_id TEXT NOT NULL REFERENCES bindings(id), key_ref TEXT NOT NULL,
 recipient TEXT NOT NULL, file_id TEXT, size INTEGER NOT NULL,
 sha256 TEXT NOT NULL, generation INTEGER NOT NULL, observed_state TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS recovery_receipts_binding ON recovery_receipts(binding_id,seq);
CREATE INDEX IF NOT EXISTS jobs_binding ON jobs(binding_id);
CREATE TABLE IF NOT EXISTS recovery_snapshots (
 id TEXT PRIMARY KEY, binding_id TEXT NOT NULL REFERENCES bindings(id), owner TEXT NOT NULL,
 generation INTEGER NOT NULL, incarnation TEXT NOT NULL, high_water INTEGER NOT NULL,
 total INTEGER NOT NULL, refs_json TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL);
"""


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path, *, guard=None, create=True):
        self.path = Path(path)
        self.guard = guard
        self._initializing = create
        if guard is None and self.path.is_file():
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                check = sqlite3.connect(
                    "file:/proc/self/fd/" + str(fd) + "?mode=ro&immutable=1", uri=True
                )
                try:
                    if check.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='manager_instances'"
                    ).fetchone():
                        raise ArchiveError("manager_state_policy_required")
                    if (
                        check.execute(
                            "SELECT 1 FROM sqlite_master WHERE name='metadata'"
                        ).fetchone()
                        and check.execute(
                            "SELECT 1 FROM metadata WHERE key='protected_storage_epoch'"
                        ).fetchone()
                    ):
                        raise ArchiveError("manager_state_policy_required")
                finally:
                    check.close()
            finally:
                os.close(fd)
        if guard is not None:
            guard.check()
            with guard.parent(self.path, create=create):
                if not create and not self.path.is_file():
                    raise ArchiveError("manager_state_database_missing")
        else:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.resolve().parent.stat().st_uid != os.geteuid() or (
            self.path.exists() and self.path.stat().st_uid != os.geteuid()
        ):
            raise ArchiveError("state_owner_mismatch")
        if self.path.resolve().parent.stat().st_mode & 0o077:
            raise ArchiveError("state_directory_not_private")
        with self.transaction() as db:
            existing = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='version'"
            ).fetchone()
            if existing:
                version = db.execute("SELECT number FROM version").fetchall()
                if version == [(2,)]:
                    db.execute(
                        "ALTER TABLE jobs ADD COLUMN attempt_credential_ref TEXT"
                    )
                    db.execute("ALTER TABLE jobs ADD COLUMN capture_revision INTEGER")
                    db.execute("ALTER TABLE jobs ADD COLUMN capture_scan INTEGER")
                    db.execute(
                        "ALTER TABLE unresolved ADD COLUMN scan_revision INTEGER NOT NULL DEFAULT 0"
                    )
                    db.execute(
                        "ALTER TABLE sessions ADD COLUMN binding_credential_ref TEXT"
                    )
                    count = db.execute(
                        "SELECT count(*) FROM sessions WHERE purpose='drive' AND state_hash IS NOT NULL"
                    ).fetchone()[0]
                    db.execute(
                        "UPDATE sessions SET state_hash=NULL,nonce=NULL,purpose=NULL,binding_id=NULL,binding_generation=NULL,oauth_expires=NULL WHERE purpose='drive'"
                    )
                    if count:
                        self._ledger(
                            db, "oauth_baseline_migration_invalidated", amount=count
                        )
                    db.execute("UPDATE version SET number=3")
                elif version != [(3,)]:
                    raise ArchiveError("unsupported_store_version")
                else:
                    # Preserve pre-release v3 state created before the narrowly
                    # added scan fence; unknown historical baselines stay NULL.
                    columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
                    for column in ("capture_revision", "capture_scan"):
                        if column not in columns:
                            db.execute(
                                "ALTER TABLE jobs ADD COLUMN " + column + " INTEGER"
                            )
                    if "scan_revision" not in {
                        row[1] for row in db.execute("PRAGMA table_info(unresolved)")
                    }:
                        db.execute(
                            "ALTER TABLE unresolved ADD COLUMN scan_revision INTEGER NOT NULL DEFAULT 0"
                        )
        with self.connect() as db:
            db.executescript(SCHEMA)
            if db.execute("SELECT number FROM version").fetchall() != [(3,)]:
                raise ArchiveError("unsupported_store_version")
            if guard is not None:
                previous = db.execute(
                    "SELECT value FROM metadata WHERE key='protected_storage_epoch'"
                ).fetchone()
                if previous and previous[0] != guard.epoch:
                    raise ArchiveError("manager_state_epoch_changed")
                db.execute(
                    "INSERT OR IGNORE INTO metadata VALUES('protected_storage_epoch',?)",
                    (guard.epoch,),
                )
        self.operations = self.path.resolve().parent / ".operations"
        if guard is not None:
            with guard.parent(self.path) as (fd, name):
                target = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    os.fchmod(target, 0o600)
                finally:
                    os.close(target)
            with guard.parent(self.operations / "lock", create=True):
                pass
        else:
            os.chmod(self.path, 0o600)
            self.operations.mkdir(mode=0o700, exist_ok=True)
        if (
            self.operations.is_symlink()
            or self.operations.stat().st_mode & 0o077
            or self.operations.stat().st_uid != os.geteuid()
        ):
            raise ArchiveError("operation_directory_not_private")
        self._initializing = False

    @contextmanager
    def connect(self):
        if self.guard is not None:
            with self.guard.parent(self.path) as (fd, name):
                mode = "rwc" if self._initializing else "rw"
                handle = None
                try:
                    flags = os.O_RDWR | os.O_NOFOLLOW
                    if self._initializing:
                        flags |= os.O_CREAT
                    handle = os.open(name, flags, 0o600, dir_fd=fd)
                    info = os.fstat(handle)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != self.guard.uid
                        or info.st_mode & 0o077
                    ):
                        raise ArchiveError("manager_state_database_denied")
                    with self._connect(
                        "file:/proc/self/fd/" + str(handle) + "?mode=" + mode, uri=True
                    ) as db:
                        yield db
                except OSError:
                    raise ArchiveError("manager_state_database_denied") from None
                finally:
                    if handle is not None:
                        os.close(handle)
        else:
            with self._connect(self.path) as db:
                yield db

    @contextmanager
    def _connect(self, path, *, uri=False):
        if self.guard is not None:
            self.guard.check()
        db = sqlite3.connect(path, timeout=2, uri=uri)
        flushed_refusals = 0
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA temp_store=MEMORY")
            db.execute("PRAGMA busy_timeout=2000")
            yield db
            if self.guard is not None:
                self.guard.check()
                flushed_refusals = self.guard.take_refusals()
                if flushed_refusals:
                    self._ledger(db, "manager_storage_refused", amount=flushed_refusals)
            db.commit()
        except BaseException:
            if self.guard is not None and flushed_refusals:
                # Preserve increments after take(), and restore this batch
                # even if rollback itself fails. RAM is not crash-durable.
                self.guard.record_refusal(flushed_refusals)
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            yield db

    def event(self, reason, binding=None, job=None, amount=1):
        # Callers use constant reason codes, never exception text or OAuth bodies.
        with self.connect() as db:
            db.execute(
                "INSERT INTO ledger(at,binding_id,job_id,reason,amount) VALUES(?,?,?,?,?)",
                (time.time(), binding, job, reason, amount),
            )
        logging.info(
            "archive event=%s binding=%s job=%s count=%d", reason, binding, job, amount
        )

    @staticmethod
    def _ledger(db, reason, binding=None, job=None, amount=1):
        db.execute(
            "INSERT INTO ledger(at,binding_id,job_id,reason,amount) VALUES(?,?,?,?,?)",
            (time.time(), binding, job, reason, amount),
        )

    def operation_path(self, binding_id):
        if self.guard is not None:
            self.guard.check()
        if (
            self.operations.stat().st_uid != os.geteuid()
            or self.path.stat().st_uid != os.geteuid()
        ):
            raise ArchiveError("state_owner_mismatch")
        if not re.fullmatch(r"[a-f0-9]{32}", binding_id):
            raise ArchiveError("binding_denied")
        path = self.operations / (binding_id + ".lock")
        if path.is_symlink() or (
            path.exists()
            and (path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077)
        ):
            raise ArchiveError("operation_lock_owner_mismatch")
        return path

    def recovery_catalog(self, db, binding_id):
        """Append immutable nonsecret receipt pins; never infer archive format."""
        conflict = db.execute(
            """SELECT 1 FROM recovery_receipts r JOIN jobs j ON j.id=r.job_id
          WHERE r.binding_id=? AND (j.binding_id IS NOT r.binding_id OR j.key_ref IS NOT r.key_ref
          OR j.recipient IS NOT r.recipient OR (r.file_id IS NOT NULL AND j.file_id IS NOT r.file_id) OR j.size IS NOT r.size
          OR j.sha256 IS NOT r.sha256 OR j.generation IS NOT r.generation) LIMIT 1""",
            (binding_id,),
        ).fetchone()
        if conflict:
            raise ArchiveError("recovery_catalog_conflict")
        db.execute(
            """INSERT INTO recovery_receipts(job_id,binding_id,key_ref,recipient,file_id,size,sha256,generation,observed_state)
          SELECT id,binding_id,key_ref,recipient,file_id,size,sha256,generation,state FROM jobs j
          WHERE binding_id=? AND (file_id IS NOT NULL OR spool IS NOT NULL) AND key_ref IS NOT NULL AND recipient IS NOT NULL
          AND size IS NOT NULL AND sha256 IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM recovery_receipts r WHERE r.job_id=j.id) ORDER BY id""",
            (binding_id,),
        )
        return db.execute(
            "SELECT coalesce(max(seq),0),count(*) FROM recovery_receipts WHERE binding_id=?",
            (binding_id,),
        ).fetchone()

    @contextmanager
    def operation(self, binding_id, job_id=None, *, kind="worker"):
        if self.guard is not None:
            self.guard.check()
            path = self.operation_path(binding_id)
            with self.guard.parent(path) as (fd, name):
                with self._operation(
                    "/proc/self/fd/" + str(fd) + "/" + name,
                    binding_id,
                    job_id,
                    kind=kind,
                ):
                    yield
        else:
            with self._operation(
                str(self.operation_path(binding_id)), binding_id, job_id, kind=kind
            ):
                yield

    @contextmanager
    def _operation(self, path, binding_id, job_id=None, *, kind="worker"):
        lock = FileLock(path, mode=0o600)
        try:
            lock.acquire(timeout=0)
        except Timeout as exc:
            self.event("binding_operation_busy", binding_id, job_id)
            if kind == "worker":
                self.event("worker_lock_stall", binding_id, job_id)
            raise ArchiveError("operation_busy", retryable=True) from exc
        try:
            yield
        finally:
            lock.release()

    def bind(
        self,
        owner,
        mailbox,
        *,
        mode="personal",
        allowlist=(),
        incarnation=None,
        operator_authority=None,
    ):
        if mode not in ("personal", "operator") or (
            mode == "operator" and mailbox not in allowlist
        ):
            self.event("operator_scope_denied")
            raise ArchiveError("operator_scope_denied")
        with self.transaction() as db:
            row = db.execute(
                "SELECT id,owner,mode,incarnation,operator_authority FROM bindings WHERE mailbox=? AND mode=? AND retired=0"
                + (" AND owner=?" if mode == "operator" else ""),
                (mailbox, mode, owner) if mode == "operator" else (mailbox, mode),
            ).fetchone()
            if row:
                if (row[3] != incarnation and incarnation is not None) or (
                    mode == "operator" and row[4] != operator_authority
                ):
                    # A fresh proof may claim a recreated namespace. Historical
                    # ownership, wallet references and receipts never change.
                    changed = db.execute(
                        "UPDATE bindings SET retired=1,enabled=0,generation=generation+1,consent='reproof_required' WHERE id=? AND retired=0",
                        (row[0],),
                    )
                    if changed.rowcount != 1:
                        raise ArchiveError("binding_transition_conflict")
                    self._ledger(db, "source_binding_retired", row[0])
                    db.execute(
                        "UPDATE jobs SET state='paused',last_reason='mailbox_incarnation_changed' WHERE binding_id=? AND state!='verified'",
                        (row[0],),
                    )
                    row = None
                elif row[1:3] != (owner, mode):
                    raise ArchiveError("mailbox_already_bound")
                else:
                    return self.get(row[0], db=db)
            binding_id = secrets.token_hex(16)
            db.execute(
                "INSERT INTO bindings(id,owner,mailbox,mode,incarnation,operator_authority) VALUES(?,?,?,?,?,?)",
                (binding_id, owner, mailbox, mode, incarnation, operator_authority),
            )
        self.event("binding_created", binding_id)
        return self.get(binding_id)

    def get(self, binding_id, *, owner=None, db=None):
        if db is None:
            with self.connect() as db:
                return self.get(binding_id, owner=owner, db=db)
        row = db.execute("SELECT * FROM bindings WHERE id=?", (binding_id,)).fetchone()
        if not row or (owner is not None and row[1] != owner):
            raise ArchiveError("binding_denied")
        return Binding(*row)

    def owned(self, owner):
        with self.connect() as db:
            return [
                self.get(row[0], db=db)
                for row in db.execute("SELECT id FROM bindings WHERE owner=?", (owner,))
            ]

    def consent(
        self,
        binding_id,
        owner,
        generation,
        permission_id,
        credential_ref,
        key_ref,
        recipient,
        folder_id,
        *,
        expected_ref,
    ):
        with self.transaction() as db:
            b = self.get(binding_id, owner=owner, db=db)
            if b.retired or not b.enabled or b.generation != generation:
                raise ArchiveError("stale_generation")
            if b.permission_id and b.permission_id != permission_id:
                raise ArchiveError("drive_principal_changed")
            if b.key_ref and (b.key_ref, b.recipient, b.folder_id) != (
                key_ref,
                recipient,
                folder_id,
            ):
                raise ArchiveError("destination_initialization_conflict")
            if b.credential_ref != expected_ref:
                self._ledger(db, "stale_credential_outcome", b.id)
                return False
            if (
                credential_ref == expected_ref
                or db.execute(
                    "SELECT 1 FROM bindings WHERE credential_ref=?", (credential_ref,)
                ).fetchone()
                or db.execute(
                    "SELECT 1 FROM artifacts WHERE kind='credential_ref' AND reference=? AND (state!='candidate' OR binding_id!=? OR generation!=?)",
                    (credential_ref, b.id, generation),
                ).fetchone()
            ):
                raise ArchiveError("credential_ref_reused")
            changed = db.execute(
                "UPDATE bindings SET consent='active',permission_id=?,credential_ref=?,key_ref=?,recipient=?,folder_id=? WHERE id=? AND generation=? AND credential_ref IS ? AND enabled=1 AND retired=0",
                (
                    permission_id,
                    credential_ref,
                    key_ref,
                    recipient,
                    folder_id,
                    binding_id,
                    generation,
                    expected_ref,
                ),
            )
            if changed.rowcount != 1:
                raise ArchiveError("binding_transition_conflict")
            db.execute(
                "INSERT INTO artifacts VALUES('credential_ref',?,?,?,'used',?) ON CONFLICT(kind,reference) DO UPDATE SET state='used',updated=excluded.updated",
                (credential_ref, b.id, generation, time.time()),
            )
            for kind, reference in (
                ("credential_ref", credential_ref),
                ("key_ref", key_ref),
                ("drive_folder", folder_id),
            ):
                db.execute(
                    "UPDATE artifacts SET state='used',updated=? WHERE kind=? AND reference=?",
                    (time.time(), kind, reference),
                )
            # Reconnection explicitly resumes the same durable objects. Never
            # replace an uncertain committed file with a newly allocated ID.
            db.execute(
                "UPDATE jobs SET state=CASE WHEN spool IS NULL THEN 'queued' ELSE 'prepared' END,attempt=0,due=?,updated=? WHERE binding_id=? AND generation=? AND state IN ('failed','paused') AND (file_id IS NOT NULL OR state='paused')",
                (time.time(), time.time(), binding_id, generation),
            )
        self.event("consent_active", binding_id)
        return True

    def candidate(self, binding, kind, reference):
        if kind not in ("credential_ref", "key_ref", "drive_folder"):
            raise ValueError("invalid artifact kind")
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,'candidate',?)",
                (kind, reference, binding.id, binding.generation, time.time()),
            )

    def unused_candidates(self, binding, artifacts):
        changed = []
        with self.transaction() as db:
            for kind, reference in artifacts:
                row = db.execute(
                    "UPDATE artifacts SET state='unused',updated=? WHERE kind=? AND reference=? AND binding_id=? AND generation=? AND state='candidate'",
                    (time.time(), kind, reference, binding.id, binding.generation),
                )
                if row.rowcount:
                    changed.append(kind)
        for kind in changed:
            self.event("unused_" + kind, binding.id)

    def pause(self, binding_id, reason="reconnect", *, generation, expected_ref):
        with self.transaction() as db:
            b = self.get(binding_id, db=db)
            if b.retired or not b.enabled or b.generation != generation:
                self._ledger(db, "stale_generation_outcome", b.id)
                return False
            if b.credential_ref != expected_ref:
                self._ledger(db, "stale_credential_outcome", b.id)
                return False
            changed = db.execute(
                "UPDATE bindings SET consent=? WHERE id=? AND generation=? AND credential_ref IS ? AND enabled=1 AND retired=0",
                (reason, binding_id, generation, expected_ref),
            )
            if changed.rowcount != 1:
                raise ArchiveError("binding_transition_conflict")
        self.event(reason, binding_id)
        return True

    def optout(self, binding_id, owner):
        with self.transaction() as db:
            self.optout_in(db, binding_id, owner)
        self.event("optout", binding_id)

    def optout_in(self, db, binding_id, owner):
        """Same transition inside an already-authorized atomic facade result."""
        self.get(binding_id, owner=owner, db=db)
        db.execute(
            "UPDATE bindings SET enabled=0,generation=generation+1,consent='disabled',credential_ref=NULL WHERE id=?",
            (binding_id,),
        )
        db.execute(
            "UPDATE jobs SET state='paused',last_reason='binding_inactive' WHERE binding_id=? AND state!='verified'",
            (binding_id,),
        )

    def enable(self, binding_id, owner):
        with self.transaction() as db:
            self.enable_in(db, binding_id, owner)

    def enable_in(self, db, binding_id, owner):
        if self.get(binding_id, owner=owner, db=db).retired:
            raise ArchiveError("mailbox_reproof_required")
        db.execute(
            "UPDATE bindings SET enabled=1,consent='pending' WHERE id=? AND enabled=0",
            (binding_id,),
        )

    def active(self, binding_id, generation):
        b = self.get(binding_id)
        if (
            b.retired
            or not b.enabled
            or b.generation != generation
            or b.consent != "active"
        ):
            raise ArchiveError("binding_inactive")
        return b

    def enqueue(self, binding_id, max_pending=128):
        with self.transaction() as db:
            b = self.get(binding_id, db=db)
            if b.retired or not b.enabled or b.consent != "active":
                return None
            existing = db.execute(
                "SELECT id FROM jobs WHERE binding_id=? AND generation=? AND (state IN ('queued','prepared','uploading','uploaded-unverified','uncertain','incomplete') OR (state IN ('failed','paused') AND file_id IS NOT NULL)) ORDER BY updated LIMIT 1",
                (binding_id, b.generation),
            ).fetchone()
            if existing:
                return existing[0]
            if (
                db.execute(
                    "SELECT count(*) FROM jobs WHERE state NOT IN ('verified','failed','paused')"
                ).fetchone()[0]
                >= max_pending
            ):
                raise ArchiveError("queue_saturated", retryable=True)
            job = secrets.token_hex(16)
            now = time.time()
            db.execute(
                "INSERT INTO jobs(id,binding_id,generation,state,due,updated,key_ref,recipient,folder_id,permission_id,incarnation) VALUES(?,?,?,'queued',?,?,?,?,?,?,?)",
                (
                    job,
                    binding_id,
                    b.generation,
                    now,
                    now,
                    b.key_ref,
                    b.recipient,
                    b.folder_id,
                    b.permission_id,
                    b.incarnation,
                ),
            )
        self.event("job_queued", binding_id, job)
        return job

    def retry(self, job_id):
        job = self.job(job_id)
        with self.operation(job["binding_id"], job_id, kind="retry"):
            self._retry_claimed(job_id)

    def _retry_claimed(self, job_id):
        with self.transaction() as db:
            binding = self.retry_in(db, job_id)
        self.event("job_manual_retry", binding, job_id)

    def retry_in(self, db, job_id):
        row = db.execute(
            "SELECT binding_id,generation,spool,state FROM jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        if not row:
            raise ArchiveError("job_missing")
        b = self.get(row[0], db=db)
        if (
            b.retired
            or not b.enabled
            or b.consent != "active"
            or b.generation != row[1]
        ):
            raise ArchiveError("binding_inactive")
        if row[3] == "verified":
            raise ArchiveError("job_already_verified")
        changed = db.execute(
            "UPDATE jobs SET state=?,attempt=0,due=?,updated=? WHERE id=? AND state!='verified'",
            ("prepared" if row[2] else "queued", time.time(), time.time(), job_id),
        )
        if changed.rowcount != 1:
            raise ArchiveError("job_transition_conflict")
        return b.id

    def job(self, job_id, *, db=None):
        if db is None:
            with self.connect() as db:
                return self.job(job_id, db=db)
        cursor = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
        row = cursor.fetchone()
        if row is None:
            raise ArchiveError("job_missing")
        return dict(zip((column[0] for column in cursor.description), row))

    def start_attempt(self, job_id, *, verify=False):
        with self.transaction() as db:
            job = self.job(job_id, db=db)
            if not verify and job["state"] in ("verified", "failed", "paused"):
                return None
            b = self.get(job["binding_id"], db=db)
            if job["state"] != "verified":
                changed = db.execute(
                    "UPDATE jobs SET attempt_credential_ref=? WHERE id=? AND state!='verified'",
                    (b.credential_ref, job_id),
                )
                if changed.rowcount != 1:
                    raise ArchiveError("job_transition_conflict")
            job["attempt_credential_ref"] = b.credential_ref
            return job, b

    def update_job(self, job_id, state, **fields):
        allowed = {
            "attempt",
            "due",
            "file_id",
            "spool",
            "size",
            "sha256",
            "message_ids",
            "last_reason",
            "capture_cursor",
            "capture_resolved",
        }
        if fields.keys() - allowed:
            raise ValueError("unknown job field")
        fields.update(state=state, updated=time.time())
        with self.transaction() as db:
            current = self.job(job_id, db=db)
            if current["state"] == "verified":
                self._ledger(
                    db, "verified_transition_ignored", current["binding_id"], job_id
                )
                return False
            if state == "verified":
                raise ArchiveError("verification_requires_receipt")
            b = self.get(current["binding_id"], db=db)
            if (
                b.retired
                or not b.enabled
                or b.consent != "active"
                or b.generation != current["generation"]
            ):
                raise ArchiveError("binding_inactive")
            for key in (
                "file_id",
                "spool",
                "size",
                "sha256",
                "message_ids",
                "capture_cursor",
                "capture_resolved",
            ):
                if (
                    key in fields
                    and current[key] is not None
                    and (key == "file_id" or current["spool"] is not None)
                    and fields[key] != current[key]
                ):
                    raise ArchiveError("immutable_job_field")
            changed = db.execute(
                "UPDATE jobs SET "
                + ",".join(k + "=?" for k in fields)
                + " WHERE id=? AND state!='verified'",
                (*fields.values(), job_id),
            )
            if changed.rowcount != 1:
                raise ArchiveError("job_transition_conflict")
            return True

    def fail(self, job_id, exc, *, credential_ref, max_attempts):
        """Resolve outcomes against CURRENT state in one short transaction."""
        with self.transaction() as db:
            job = self.job(job_id, db=db)
            b = self.get(job["binding_id"], db=db)
            if job["state"] == "verified":
                self._ledger(db, "verified_outcome_ignored", b.id, job_id)
                self._ledger(db, exc.reason, b.id, job_id)
                return "verified"
            active = (
                not b.retired
                and b.enabled
                and b.generation == job["generation"]
                and b.consent == "active"
            )
            attempt = job["attempt"] + 1
            if b.retired or not b.enabled or b.generation != job["generation"]:
                state = "paused"
                self._ledger(db, "stale_generation_outcome", b.id, job_id)
            elif exc.reason == "mailbox_incarnation_changed":
                db.execute(
                    "UPDATE bindings SET retired=1,enabled=0,generation=generation+1,consent='reproof_required' WHERE id=? AND retired=0",
                    (b.id,),
                )
                db.execute(
                    "UPDATE jobs SET state='paused',last_reason=? WHERE binding_id=? AND state!='verified'",
                    (exc.reason, b.id),
                )
                state = "paused"
            elif job["attempt_credential_ref"] != credential_ref:
                self._ledger(db, "stale_attempt_outcome", b.id, job_id)
                self._ledger(db, "stale_credential_outcome", b.id, job_id)
                self._ledger(db, exc.reason, b.id, job_id)
                return job["state"]
            elif b.credential_ref != credential_ref:
                state = (
                    (
                        "uncertain"
                        if job["file_id"]
                        else "prepared"
                        if job["spool"]
                        else "queued"
                    )
                    if active
                    else "paused"
                )
                attempt = job["attempt"]
                self._ledger(db, "stale_credential_outcome", b.id, job_id)
            elif not active:
                state = "paused"
            elif exc.reason in (
                "reconnect",
                "drive_consent_missing",
                "credential_binding_mismatch",
                "drive_principal_changed",
                "broker_unavailable",
            ):
                changed = db.execute(
                    "UPDATE bindings SET consent=? WHERE id=? AND generation=? AND credential_ref IS ? AND enabled=1 AND retired=0",
                    (
                        "broker_pending"
                        if exc.reason == "broker_unavailable"
                        else "reconnect",
                        b.id,
                        job["generation"],
                        credential_ref,
                    ),
                )
                if changed.rowcount != 1:
                    raise ArchiveError("binding_transition_conflict")
                state = "paused"
            elif exc.reason in (
                "binding_inactive",
                "stale_generation",
                "operator_revoked",
            ) or exc.reason.startswith("operator_policy_"):
                state = "paused"
            elif exc.uncertain or job["state"] == "uploaded-unverified":
                state = "uncertain" if attempt < max_attempts else "failed"
            elif exc.reason.startswith("source_"):
                state = (
                    "incomplete"
                    if exc.retryable and attempt < max_attempts
                    else "failed"
                )
            else:
                state = (
                    "prepared" if exc.retryable and attempt < max_attempts else "failed"
                )
            changed = db.execute(
                "UPDATE jobs SET state=?,attempt=?,due=?,updated=?,last_reason=? WHERE id=? AND state!='verified'",
                (
                    state,
                    attempt,
                    time.time() + min(300, 2 ** min(attempt, 9)),
                    time.time(),
                    exc.reason,
                    job_id,
                ),
            )
            if changed.rowcount != 1:
                raise ArchiveError("job_transition_conflict")
            self._ledger(db, exc.reason, b.id, job_id)
            self._ledger(
                db,
                "job_retry"
                if state in ("queued", "prepared", "uncertain", "incomplete")
                else "job_stopped",
                b.id,
                job_id,
            )
            return state

    def seen(self, binding_id, *, lookup=False):
        if lookup:
            store = self

            class Lookup:
                def __contains__(self, message_id):
                    with store.connect() as db:
                        return (
                            db.execute(
                                "SELECT 1 FROM messages WHERE binding_id=? AND message_id=?",
                                (binding_id, message_id),
                            ).fetchone()
                            is not None
                        )

            return Lookup()
        with self.connect() as db:
            return {
                row[0]
                for row in db.execute(
                    "SELECT message_id FROM messages WHERE binding_id=?", (binding_id,)
                )
            }

    def capture_cursor(self, binding_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("capture_cursor:" + binding_id,),
            ).fetchone()
            return int(row[0]) if row else 0

    @staticmethod
    def _metadata_int(db, key):
        row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return int(row[0]) if row else 0

    def capture_start(self, job_id, *, credential_ref):
        with self.transaction() as db:
            job = self.job(job_id, db=db)
            b = self.get(job["binding_id"], db=db)
            if job["state"] == "verified" or job["spool"] is not None:
                raise ArchiveError("capture_already_prepared")
            if (
                b.retired
                or not b.enabled
                or b.consent != "active"
                or b.generation != job["generation"]
            ):
                raise ArchiveError("binding_inactive")
            if b.credential_ref != credential_ref:
                raise ArchiveError("credential_changed", retryable=True)
            cursor = self._metadata_int(db, "capture_cursor:" + b.id)
            revision = self._metadata_int(db, "capture_revision:" + b.id)
            scan = self._metadata_int(db, "capture_scan:" + b.id) + 1
            db.execute(
                "INSERT OR REPLACE INTO metadata VALUES(?,?)",
                ("capture_scan:" + b.id, str(scan)),
            )
            changed = db.execute(
                "UPDATE jobs SET capture_revision=?,capture_scan=? WHERE id=? AND state!='verified' AND spool IS NULL",
                (revision, scan, job_id),
            )
            if changed.rowcount != 1:
                raise ArchiveError("job_transition_conflict")
            return cursor, revision, scan

    def verified(self, job_id, *, credential_ref):
        with self.transaction() as db:
            job = self.job(job_id, db=db)
            if job["state"] == "verified":
                self._ledger(db, "verified_repeat_ignored", job["binding_id"], job_id)
                return False
            b = self.get(job["binding_id"], db=db)
            if (
                b.retired
                or not b.enabled
                or b.generation != job["generation"]
                or b.consent != "active"
            ):
                raise ArchiveError("stale_generation")
            if job["attempt_credential_ref"] != credential_ref:
                self._ledger(db, "stale_attempt_outcome", b.id, job_id)
                self._ledger(db, "stale_credential_outcome", b.id, job_id)
                return False
            if b.credential_ref != credential_ref:
                state = (
                    "uncertain"
                    if job["file_id"]
                    else "prepared"
                    if job["spool"]
                    else "queued"
                )
                changed = db.execute(
                    "UPDATE jobs SET state=?,due=?,updated=? WHERE id=? AND state!='verified'",
                    (state, time.time(), time.time(), job_id),
                )
                if changed.rowcount != 1:
                    raise ArchiveError("job_transition_conflict")
                self._ledger(db, "stale_credential_outcome", b.id, job_id)
                return False
            for mid in json.loads(job["message_ids"]):
                db.execute(
                    "INSERT OR IGNORE INTO messages VALUES(?,?,?)", (b.id, mid, job_id)
                )
            revision = self._metadata_int(db, "capture_revision:" + b.id)
            advance = (
                job["capture_revision"] is not None
                and job["capture_revision"] == revision
                and job["capture_cursor"] is not None
            )
            if advance:
                db.execute(
                    "INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)",
                    ("capture_cursor:" + b.id, str(job["capture_cursor"])),
                )
                db.execute(
                    "INSERT OR REPLACE INTO metadata VALUES(?,?)",
                    ("capture_revision:" + b.id, str(revision + 1)),
                )
                if job["capture_scan"] is not None:
                    for entry in json.loads(job["capture_resolved"] or "[]"):
                        db.execute(
                            "DELETE FROM unresolved WHERE binding_id=? AND entry_id=? AND scan_revision<=?",
                            (b.id, entry, job["capture_scan"]),
                        )
            else:
                self._ledger(db, "stale_cursor_outcome", b.id, job_id)
            changed = db.execute(
                "UPDATE jobs SET state='verified',updated=? WHERE id=? AND state!='verified'",
                (time.time(), job_id),
            )
            if changed.rowcount != 1:
                raise ArchiveError("job_transition_conflict")
            self._ledger(db, "job_verified", b.id, job_id)
        logging.info("archive event=job_verified binding=%s job=%s", b.id, job_id)
        return True

    def invalidate_incarnation(self, binding_id):
        with self.transaction() as db:
            changed = db.execute(
                "UPDATE bindings SET enabled=0,retired=1,generation=generation+1,consent='reproof_required' WHERE id=? AND retired=0",
                (binding_id,),
            ).rowcount
            if changed:
                db.execute(
                    "UPDATE jobs SET state='paused',last_reason='mailbox_incarnation_changed' WHERE binding_id=? AND state!='verified'",
                    (binding_id,),
                )
        if changed:
            self.event("mailbox_incarnation_changed", binding_id)
        return bool(changed)

    def revoke_operator(self, binding_id, reason="operator_revoked"):
        with self.transaction() as db:
            b = self.get(binding_id, db=db)
            if b.mode != "operator":
                raise ArchiveError("operator_scope_denied")
            changed = db.execute(
                "UPDATE bindings SET enabled=0,generation=generation+1,consent=? WHERE id=? AND enabled=1",
                (reason, binding_id),
            ).rowcount
            if changed:
                db.execute(
                    "UPDATE jobs SET state='paused',last_reason=? WHERE binding_id=? AND state!='verified'",
                    (reason, binding_id),
                )
        if changed:
            self.event(reason, binding_id)
        return bool(changed)

    def record_unresolved(self, binding_id, job_id, issues):
        with self.transaction() as db:
            job = self.job(job_id, db=db)
            b = self.get(binding_id, db=db)
            if b.retired or not b.enabled or b.generation != job["generation"]:
                self._ledger(db, "stale_generation_source_outcome", b.id, job_id)
                for _entry, reason in issues:
                    self._ledger(db, reason, b.id, job_id)
                return
            for entry, reason in issues:
                changed = db.execute(
                    "INSERT INTO unresolved VALUES(?,?,?,1,?,?) ON CONFLICT(binding_id,entry_id) DO UPDATE SET reason=excluded.reason,attempts=min(8,unresolved.attempts+1),last_seen=excluded.last_seen,scan_revision=excluded.scan_revision WHERE unresolved.scan_revision<=excluded.scan_revision",
                    (binding_id, entry, reason, time.time(), job["capture_scan"] or 0),
                )
                if not changed.rowcount:
                    self._ledger(db, "stale_source_outcome", b.id, job_id)
        for _entry, reason in issues:
            self.event(reason, binding_id, job_id)

    def source_retry_allowed(self, binding_id, entry):
        with self.connect() as db:
            row = db.execute(
                "SELECT attempts FROM unresolved WHERE binding_id=? AND entry_id=?",
                (binding_id, entry),
            ).fetchone()
            return not row or row[0] < 8

    def retry_sources(self, binding_id):
        with self.connect() as db:
            db.execute(
                "UPDATE unresolved SET attempts=0 WHERE binding_id=?", (binding_id,)
            )
        self.event("source_manual_retry", binding_id)

    def unresolved(self, binding_id):
        with self.connect() as db:
            return db.execute(
                "SELECT entry_id,reason,attempts FROM unresolved WHERE binding_id=?",
                (binding_id,),
            ).fetchall()

    def due(self, limit=16):
        with self.connect() as db:
            return [
                row[0]
                for row in db.execute(
                    "SELECT id FROM jobs WHERE state IN ('queued','prepared','uploading','uploaded-unverified','uncertain','incomplete') AND due<=? ORDER BY due LIMIT ?",
                    (time.time(), limit),
                )
            ]

    def metrics(self):
        with self.connect() as db:
            return self.metrics_in(db)

    @staticmethod
    def metrics_readonly(path):
        """Legacy bare-path snapshot: no create, migration, locks or journals.

        Active journal/WAL state requires guarded configuration instead.
        This immutable snapshot API cannot provide live-writer consistency.
        """
        path = Path(path).absolute()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            for suffix in ("-wal", "-journal"):
                side = Path(str(path) + suffix)
                if side.exists() and side.stat().st_size:
                    raise ArchiveError("archive_metrics_config_required")
            db = sqlite3.connect(
                "file:/proc/self/fd/" + str(fd) + "?mode=ro&immutable=1", uri=True
            )
            try:
                if (
                    db.execute(
                        "SELECT 1 FROM sqlite_master WHERE name='manager_instances'"
                    ).fetchone()
                    or db.execute(
                        "SELECT 1 FROM metadata WHERE key='protected_storage_epoch'"
                    ).fetchone()
                ):
                    raise ArchiveError("archive_metrics_config_required")
                result = Store.metrics_in(db)
            finally:
                db.close()
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ArchiveError("archive_metrics_snapshot_changed")
            return result
        finally:
            os.close(fd)

    @staticmethod
    def metrics_in(db):
        result = {
            "jobs_" + state: count
            for state, count in db.execute(
                "SELECT state,count(*) FROM jobs GROUP BY state"
            )
        }
        result.update(
            {
                "events_" + reason: count
                for reason, count in db.execute(
                    "SELECT reason,sum(amount) FROM ledger GROUP BY reason"
                )
            }
        )
        result["verified_bytes"] = db.execute(
            "SELECT coalesce(sum(size),0) FROM jobs WHERE state='verified'"
        ).fetchone()[0]
        result["verified_messages"] = db.execute(
            "SELECT count(*) FROM messages"
        ).fetchone()[0]
        result["last_verified"] = db.execute(
            "SELECT coalesce(max(updated),0) FROM jobs WHERE state='verified'"
        ).fetchone()[0]
        result["unresolved_entries"] = db.execute(
            "SELECT count(*) FROM unresolved"
        ).fetchone()[0]
        result["incomplete_bindings"] = db.execute(
            "SELECT count(DISTINCT binding_id) FROM unresolved"
        ).fetchone()[0]
        for state, count in db.execute(
            "SELECT state,count(*) FROM artifacts GROUP BY state"
        ):
            result["artifacts_" + state] = count
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='manager_issuance'"
        ).fetchone():
            for state, count, oldest in db.execute(
                "SELECT state,count(*),min(updated) FROM manager_issuance GROUP BY state"
            ):
                result["manager_issuance_" + state] = count
                result["manager_issuance_" + state + "_oldest_seconds"] = max(
                    0, int(time.time() - oldest)
                )
        return result
