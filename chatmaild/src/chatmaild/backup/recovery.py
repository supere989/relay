"""Guarded owner recovery export; secret material exists only in request memory."""

import hashlib
import hmac
import importlib.resources
import io
import json
import logging
import re
import secrets
import stat
import time
import zipfile
from dataclasses import dataclass

from . import recovery_tool as tool
from .model import ArchiveError
from .store import digest

README = """CHATMAIL INDEPENDENT RECOVERY KIT

This ZIP contains private decryption material. Keep it private (chmod 600) and
make a safe independent copy. The operator wallet still retains these keys;
export enables recovery without that operator, wallet, broker or relay later.
Trust this complete kit only from the authenticated owner download. Component
checksums detect inconsistency; they do not authenticate a replaced whole kit.

POSIX/Linux prerequisites: Python 3, age AND age-keygen in /usr/bin. Extract only
restore.py for execution; it reads the kit ZIP itself and never extractall.
Prepare a private parent (0700) outside any live mailbox, then run:
  python3 -I restore.py --kit recovery.zip --output /PRIVATE/PARENT/NEW *.age
--kit-fd FD instead accepts an already-open private regular file or pipe.
Repeat --kit PART.zip (or --kit-fd FD) to combine up to 16 parts/16 MiB total.
Each part must belong to the same binding; conflicting keys/receipts fail.
No network, relay code, database, wallet, or broker is used by that tool.

The current same-binding/same-key kit restores later authenticated v2 uploads,
including ordinary consent renewal; a new receipt export is NOT required for
each upload. Actual cryptographic key rotation or a new binding/incarnation
requires new recovery material. Older v1 archives need an exact exported
ciphertext digest/size/run receipt. Missing historical v1 receipts require a new
kit. Known unverified/uncertain receipts do not assert a remote file exists.
The portal always offers a keys-only kit with receipt_coverage:none for v2.
Historical receipts are bounded parts of a fixed snapshot expiring in 10 minutes.
Every part includes all snapshot keys. Retain every part needed for legacy v1;
missing receipt parts cannot authenticate their unlisted v1 ciphertexts. Later
uploads do not change a snapshot. Download a fresh snapshot for later legacy
receipts. Receipt file IDs can be null for encrypted spools not yet allocated.

Each distinct run is restored into its own run-ID Maildir tree. Conflicting
versions of a message path remain separate; no latest version is guessed. Exact
duplicate ciphertext inputs are counted and ignored. Different authenticated
ciphertexts claiming one run ID fail. A valid authenticated replay does not
prove freshness, newest state, or completeness. Capture windows are not a
point-in-time/full client identity, settings, contacts or IMAP-index backup.
cur/new, folder paths, flags and original gzip-compressed bytes are preserved.

Limits per invocation: 4 MiB per kit/part, 16 parts/16 MiB total, 64 keys,
4096 receipts per part and 4096 input archives, 71 MiB per
ciphertext, 70 MiB decrypted tar, 1 MiB manifest, 256 messages/32 MiB per message,
1 GiB aggregate output. Restore larger sets in batches into separate NEW private
quarantines; retain each completion manifest and the encrypted originals.

Output must be a fresh absolute path. Its immediate parent must already exist,
be owned by you, and have no group/other permissions. Ancestors are opened with
directory descriptors/no-follow and must be root/you-owned and not group/other
writable, except root-owned sticky /tmp. Common live mailbox roots and ancestor
mailbox/control markers are rejected. This cannot identify every custom live
root or defeat malicious same-user filesystem manipulation. Never import into
Dovecot automatically. Completion.json is written last; .incomplete or missing
completion.json means failure/incomplete output, which must not be imported.
The portal records response completion/abort, not that your browser saved it.
""".encode("utf-8")


@dataclass(repr=False)
class Download:
    body: bytes
    binding: str
    export_id: str

    def __repr__(self):
        return "<private recovery download>"


class Recovery:
    def __init__(self, store, config, broker):
        self.store, self.config, self.broker = store, config, broker

    def _authority(self, db, session, expected=None, csrf=None):
        row = db.execute(
            "SELECT owner,csrf_hash,expires FROM sessions WHERE id_hash=?",
            (session.get("id_hash"),),
        ).fetchone()
        if (
            row is None
            or not row[0]
            or row[0] != session.get("owner")
            or row[2] <= time.time()
        ):
            raise ArchiveError("recovery_session_denied")
        if csrf is not None and not hmac.compare_digest(row[1], digest(csrf)):
            raise ArchiveError("recovery_csrf_denied")
        binding_id = (
            expected.id if expected is not None else session["recovery_binding"]
        )
        b = self.store.get(binding_id, owner=row[0], db=db)
        if b.mode != "personal" or b.retired:
            raise ArchiveError("recovery_binding_denied")
        if expected is not None and (
            b.generation != expected.generation or b.incarnation != expected.incarnation
        ):
            raise ArchiveError("recovery_authority_changed")
        return b

    def _history(self, db, b, *, mode="history", snapshot=None, part=1):
        if not b.key_ref or not b.recipient:
            raise ArchiveError("recovery_history_missing")
        if db.execute(
            "SELECT 1 FROM jobs WHERE binding_id=? AND (key_ref IS NULL OR recipient IS NULL) LIMIT 1",
            (b.id,),
        ).fetchone():
            raise ArchiveError("recovery_history_missing")
        pairs = [(b.key_ref, b.recipient)]
        pairs.extend(
            db.execute(
                "SELECT DISTINCT key_ref,recipient FROM jobs WHERE binding_id=? LIMIT ?",
                (b.id, tool.MAX_KEYS + 1),
            )
        )
        refs = {}
        for reference, recipient in pairs:
            if (
                type(reference) is not str
                or not reference
                or len(reference) > 160
                or type(recipient) is not str
                or not recipient.startswith("age1")
                or len(recipient) > 128
            ):
                raise ArchiveError("recovery_history_missing")
            if reference in refs and refs[reference] != recipient:
                raise ArchiveError("recovery_history_conflict")
            refs[reference] = recipient
        if len(refs) > tool.MAX_KEYS:
            raise ArchiveError("recovery_history_limit")
        coverage = {"kind": "none"}
        rows = []
        if mode == "history":
            if db.execute(
                "SELECT 1 FROM jobs WHERE binding_id=? AND (file_id IS NOT NULL OR spool IS NOT NULL) AND (size IS NULL OR sha256 IS NULL) LIMIT 1",
                (b.id,),
            ).fetchone():
                raise ArchiveError("recovery_history_missing")
            high_water, total = self.store.recovery_catalog(db, b.id)
            if snapshot is None:
                snapshot = secrets.token_hex(16)
                created = time.time()
                db.execute(
                    "INSERT INTO recovery_snapshots VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        snapshot,
                        b.id,
                        b.owner,
                        b.generation,
                        b.incarnation,
                        high_water,
                        total,
                        json.dumps(sorted(refs.items())),
                        created,
                        created + 600,
                    ),
                )
                self.store._ledger(db, "recovery_snapshot_created", b.id, snapshot)
            row = db.execute(
                "SELECT binding_id,owner,generation,incarnation,high_water,total,refs_json,expires FROM recovery_snapshots WHERE id=?",
                (snapshot,),
            ).fetchone()
            if (
                row is None
                or row[:4] != (b.id, b.owner, b.generation, b.incarnation)
                or row[7] <= time.time()
            ):
                raise ArchiveError("recovery_snapshot_denied")
            high_water, total = row[4:6]
            refs = dict(json.loads(row[6]))
            parts = max(1, (total + tool.MAX_ARCHIVES - 1) // tool.MAX_ARCHIVES)
            if not 1 <= part <= parts:
                raise ArchiveError("recovery_part_denied")
            rows = db.execute(
                "SELECT job_id,file_id,size,sha256,key_ref,observed_state,generation FROM recovery_receipts WHERE binding_id=? AND seq<=? ORDER BY seq LIMIT ? OFFSET ?",
                (b.id, high_water, tool.MAX_ARCHIVES, (part - 1) * tool.MAX_ARCHIVES),
            ).fetchall()
            coverage = {
                "kind": "snapshot",
                "snapshot": snapshot,
                "part": part,
                "parts": parts,
                "total": total,
                "included": len(rows),
                "cutoff": high_water,
                "complete": parts == 1,
            }
        receipts, digests = [], set()
        states = {
            "queued",
            "prepared",
            "uploading",
            "uploaded-unverified",
            "verified",
            "failed",
            "incomplete",
            "uncertain",
            "paused",
        }
        for run, file_id, size, checksum, key_ref, state, generation in rows:
            if (
                type(run) is not str
                or not tool.OPAQUE.fullmatch(run)
                or file_id is not None
                and (
                    type(file_id) is not str
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", file_id)
                )
                or type(size) is not int
                or not 0 < size <= tool.MAX_CIPHER
                or type(checksum) is not str
                or not tool.HEX64.fullmatch(checksum)
                or key_ref not in refs
                or state not in states
                or type(generation) is not int
                or generation < 1
            ):
                raise ArchiveError("recovery_history_missing")
            if checksum in digests:
                raise ArchiveError("recovery_history_conflict")
            digests.add(checksum)
            receipts.append(
                {
                    "run": run,
                    "file_id": file_id,
                    "size": size,
                    "sha256": checksum,
                    "key": tool.key_id(refs[key_ref]),
                    "state": state,
                    "generation": generation,
                }
            )
        unresolved = db.execute(
            "SELECT count(*),coalesce(sum(attempts>=8),0) FROM unresolved WHERE binding_id=?",
            (b.id,),
        ).fetchone()
        return {
            "refs": tuple(sorted(refs.items())),
            "receipts": receipts,
            "coverage": {
                "kind": "capture-windows",
                "unresolved": unresolved[0],
                "held": unresolved[1],
            },
            "receipt_coverage": coverage,
        }

    def authorize(self, session, expected, history, export_id, key_count):
        """Authorization linearization; no broker/filesystem/network I/O here."""
        with self.store.transaction() as db:
            b = self._authority(db, session, expected)
            selection = history["receipt_coverage"]
            current = self._history(
                db,
                b,
                mode="keys" if selection["kind"] == "none" else "history",
                snapshot=selection.get("snapshot"),
                part=selection.get("part", 1),
            )
            if current != history:
                raise ArchiveError("recovery_history_changed")
            self.store._ledger(db, "recovery_authorized", b.id, export_id)
            self.store._ledger(db, "recovery_keys", b.id, export_id, key_count)
            self.store._ledger(
                db, "recovery_receipts", b.id, export_id, len(history["receipts"])
            )

    def _zip(self, binding, history, keys):
        metadata = {
            "format": tool.KIT_FORMAT,
            "version": 1,
            "created_at": int(time.time()),
            "binding": binding.id,
            "coverage": history["coverage"],
            "keys": keys,
            "receipts": history["receipts"],
            "receipt_coverage": history["receipt_coverage"],
        }
        script = (
            importlib.resources.files("chatmaild.backup")
            .joinpath("recovery_tool.py")
            .read_bytes()
        )
        parts = {
            "recovery.json": tool.canonical(metadata),
            "restore.py": script,
            "README.txt": README,
        }
        parts["checksums.json"] = tool.canonical(
            {
                "version": 1,
                "files": {
                    name: hashlib.sha256(data).hexdigest()
                    for name, data in sorted(parts.items())
                },
            }
        )
        if sum(len(data) for data in parts.values()) + 4096 > tool.MAX_KIT:
            raise ArchiveError("recovery_kit_limit")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in sorted(parts.items()):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (
                    stat.S_IFREG | (0o700 if name == "restore.py" else 0o600)
                ) << 16
                archive.writestr(info, data)
        if output.tell() > tool.MAX_KIT:
            raise ArchiveError("recovery_kit_limit")
        return output.getvalue()

    def export(self, session, form):
        # Import locally to keep web -> recovery -> proof dependency acyclic.
        from .web import proven_mailbox

        export_id = secrets.token_hex(16)
        started = time.monotonic()
        authorized = False
        binding_id = form.get("binding")
        safe_id = (
            binding_id
            if type(binding_id) is str and tool.OPAQUE.fullmatch(binding_id)
            else None
        )
        self.store.event("recovery_request", safe_id, export_id)
        try:
            if (
                not {"binding", "password", "csrf"} <= set(form)
                or set(form)
                - {"binding", "password", "csrf", "mode", "snapshot", "part"}
                or safe_id is None
                or type(form["csrf"]) is not str
            ):
                raise ArchiveError("recovery_request_denied")
            mode = form.get("mode", "history")
            snapshot = form.get("snapshot") or None
            part = form.get("part", "1")
            if (
                mode not in ("history", "keys")
                or snapshot is not None
                and (type(snapshot) is not str or not tool.OPAQUE.fullmatch(snapshot))
                or type(part) is not str
                or not re.fullmatch(r"[1-9][0-9]{0,8}", part)
                or mode == "keys"
                and (snapshot is not None or part != "1")
            ):
                raise ArchiveError("recovery_request_denied")
            context = dict(session, recovery_binding=safe_id)
            with self.store.connect() as db:
                initial = self._authority(db, context, csrf=form["csrf"])
            with proven_mailbox(
                self.config, initial.mailbox, form["password"], final_check=False
            ) as mailbox:
                mailbox.check(initial.incarnation)
                with self.store.operation(initial.id, kind="recovery"):
                    with self.store.transaction() as db:
                        b = self._authority(db, context, initial, csrf=form["csrf"])
                        history = self._history(
                            db, b, mode=mode, snapshot=snapshot, part=int(part)
                        )
                    keys, public = [], {}
                    for reference, recipient in history["refs"]:
                        if time.monotonic() - started > 20:
                            raise ArchiveError("recovery_time_limit")
                        identity = self.broker.recovery_key(reference, recipient)
                        identifier = tool.key_id(recipient)
                        if identifier in public and public[identifier] != identity:
                            raise ArchiveError("recovery_history_conflict")
                        if identifier not in public:
                            public[identifier] = identity
                            keys.append(
                                {
                                    "id": identifier,
                                    "recipient": recipient,
                                    "identity": identity,
                                }
                            )
                    if time.monotonic() - started > 20:
                        raise ArchiveError("recovery_time_limit")
                    body = self._zip(
                        b, history, sorted(keys, key=lambda row: row["id"])
                    )
                    mailbox.check(initial.incarnation)
                    self.authorize(context, initial, history, export_id, len(keys))
                    authorized = True
                    return Download(body, b.id, export_id)
        except ArchiveError as exc:
            self.store.event(
                "recovery_response_aborted" if authorized else "recovery_denied",
                safe_id,
                export_id,
            )
            self.store.event(exc.reason, safe_id, export_id)
            if exc.reason == "operation_busy":
                self.store.event("recovery_stall", safe_id, export_id)
            raise
        except Exception:
            self.store.event(
                "recovery_response_aborted" if authorized else "recovery_denied",
                safe_id,
                export_id,
            )
            self.store.event("recovery_unexpected", safe_id, export_id)
            raise ArchiveError("recovery_unexpected") from None
        finally:
            try:
                self.store.event(
                    "recovery_duration_ms",
                    safe_id,
                    export_id,
                    int((time.monotonic() - started) * 1000),
                )
            except Exception:
                logging.warning(
                    "archive event=recovery_duration_ledger_failed binding=%s export=%s",
                    safe_id,
                    export_id,
                )
