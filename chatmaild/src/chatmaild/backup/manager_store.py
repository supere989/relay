"""Durable manager handoff, authority revisions and idempotent outbox.

All tables share the archive Store transaction/ledger. The optional service
requires that database to live inside its protected profile mount.
"""

import hashlib
import json
import secrets
import time

from .model import ArchiveError

DEFINITIVE_AUTHORITY_LOSS = frozenset(
    (
        "manager_instance_denied",
        "manager_profile_epoch_changed",
        "manager_profile_epoch_denied",
        "manager_chat_denied",
        "manager_contact_denied",
        "manager_app_message_denied",
        "manager_app_blob_denied",
        "manager_peer_key_missing",
        "manager_peer_key_invalid",
        "manager_peer_context_changed",
    )
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS manager_accounts (
 epoch TEXT NOT NULL, account INTEGER NOT NULL, self_key_digest TEXT NOT NULL,
 PRIMARY KEY(epoch,account));
CREATE TABLE IF NOT EXISTS manager_peers (
 epoch TEXT NOT NULL, account INTEGER NOT NULL, contact INTEGER NOT NULL,
 key_digest TEXT NOT NULL, securejoin_at REAL NOT NULL,
 PRIMARY KEY(epoch,account,contact));
CREATE TABLE IF NOT EXISTS manager_issuance (
 id TEXT PRIMARY KEY, epoch TEXT NOT NULL, account INTEGER NOT NULL,
 contact INTEGER NOT NULL, key_digest TEXT NOT NULL, state TEXT NOT NULL,
 instance TEXT, claim_token TEXT, self_key_digest TEXT,
 created REAL NOT NULL, updated REAL NOT NULL, reason TEXT,
 UNIQUE(epoch,account,contact,key_digest));
CREATE TABLE IF NOT EXISTS manager_issuance_history (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, issuance TEXT NOT NULL,
 instance TEXT NOT NULL, claim_token TEXT NOT NULL, state TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL, reason TEXT,
 replacement_instance TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manager_instances (
 id TEXT PRIMARY KEY, epoch TEXT NOT NULL, account INTEGER NOT NULL,
 self_key_digest TEXT,
 chat INTEGER NOT NULL, contact INTEGER NOT NULL, key_digest TEXT NOT NULL,
 message INTEGER NOT NULL, app_digest TEXT NOT NULL, state TEXT NOT NULL,
 revision INTEGER NOT NULL DEFAULT 1, serial INTEGER NOT NULL DEFAULT 0,
 UNIQUE(epoch,account,message));
CREATE TABLE IF NOT EXISTS manager_pairs (
 id TEXT PRIMARY KEY, instance TEXT NOT NULL REFERENCES manager_instances(id),
 context_digest TEXT NOT NULL, comparison_hash TEXT NOT NULL, comparison TEXT NOT NULL, expires REAL NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'requested',
 session_hash TEXT, owner TEXT, binding_id TEXT, generation INTEGER,
 incarnation TEXT, intent TEXT, app_confirmed INTEGER NOT NULL DEFAULT 0,
 browser_confirmed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS manager_revisions (
 binding_id TEXT PRIMARY KEY REFERENCES bindings(id), revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS manager_links (
 handle TEXT PRIMARY KEY, instance TEXT NOT NULL REFERENCES manager_instances(id),
 owner TEXT NOT NULL, binding_id TEXT NOT NULL REFERENCES bindings(id),
 generation INTEGER NOT NULL, incarnation TEXT NOT NULL, revision INTEGER NOT NULL,
 active INTEGER NOT NULL DEFAULT 1, UNIQUE(instance,binding_id));
CREATE TABLE IF NOT EXISTS manager_leases (
 digest TEXT PRIMARY KEY, instance TEXT NOT NULL, action TEXT NOT NULL,
 handle TEXT, revision INTEGER NOT NULL, generation INTEGER NOT NULL,
 challenge TEXT, intent TEXT, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS manager_commands (
 instance TEXT NOT NULL REFERENCES manager_instances(id), id TEXT NOT NULL,
 digest TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL, updated REAL NOT NULL,
 result TEXT, PRIMARY KEY(instance,id));
CREATE INDEX IF NOT EXISTS manager_commands_due ON manager_commands(state,due);
CREATE TABLE IF NOT EXISTS manager_outbox (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, instance TEXT NOT NULL, command_id TEXT NOT NULL,
 payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 due REAL NOT NULL, UNIQUE(instance,command_id));
"""


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def row(db, query, params=()):
    cursor = db.execute(query, params)
    value = cursor.fetchone()
    return (
        dict(zip((column[0] for column in cursor.description), value, strict=True))
        if value
        else None
    )


class ManagerStore:
    def __init__(self, store):
        if getattr(store, "guard", None) is None:
            raise ArchiveError("manager_state_policy_required")
        store.guard.check()
        self.store = store
        with store.connect() as db:
            db.executescript(SCHEMA)
            if "self_key_digest" not in {
                item[1] for item in db.execute("PRAGMA table_info(manager_instances)")
            }:
                db.execute(
                    "ALTER TABLE manager_instances ADD COLUMN self_key_digest TEXT"
                )
            unknown = db.execute(
                "SELECT count(*) FROM manager_instances WHERE self_key_digest IS NULL AND state='active'"
            ).fetchone()[0]
            if unknown:
                db.execute(
                    "UPDATE manager_instances SET state='revoked',revision=revision+1 WHERE self_key_digest IS NULL"
                )
                db.execute(
                    "UPDATE manager_links SET active=0,revision=revision+1 WHERE instance IN (SELECT id FROM manager_instances WHERE self_key_digest IS NULL)"
                )
                self.store._ledger(
                    db, "manager_profile_pin_migration_invalidated", amount=unknown
                )

    def enroll_account(self, epoch, account, self_key_digest):
        with self.store.transaction() as db:
            previous = db.execute(
                "SELECT self_key_digest FROM manager_accounts WHERE epoch=? AND account=?",
                (epoch, account),
            ).fetchone()
            if previous and previous[0] != self_key_digest:
                raise ArchiveError("manager_bot_identity_changed")
            db.execute(
                "INSERT OR IGNORE INTO manager_accounts VALUES(?,?,?)",
                (epoch, account, self_key_digest),
            )
            self.store._ledger(db, "manager_bot_identity_enrolled")

    def instance(self, instance, db):
        value = row(db, "SELECT * FROM manager_instances WHERE id=?", (instance,))
        if value is None or value["state"] != "active":
            raise ArchiveError("manager_instance_denied")
        return value

    def register(
        self,
        epoch,
        account,
        chat,
        contact,
        key_digest,
        message,
        app_digest,
        *,
        instance=None,
        claim=None,
    ):
        instance = instance or secrets.token_hex(16)
        with self.store.transaction() as db:
            account_pin = db.execute(
                "SELECT self_key_digest FROM manager_accounts WHERE epoch=? AND account=?",
                (epoch, account),
            ).fetchone()
            if account_pin is None:
                raise ArchiveError("manager_bot_identity_required")
            peer = db.execute(
                "SELECT key_digest FROM manager_peers WHERE epoch=? AND account=? AND contact=?",
                (epoch, account, contact),
            ).fetchone()
            if peer is None or peer[0] != key_digest:
                raise ArchiveError("manager_securejoin_required")
            if claim is not None:
                pending = row(
                    db, "SELECT * FROM manager_issuance WHERE id=?", (claim["id"],)
                )
                if (
                    pending is None
                    or pending["state"] != "issuing"
                    or (
                        pending["claim_token"],
                        pending["instance"],
                        pending["epoch"],
                        pending["account"],
                        pending["contact"],
                        pending["key_digest"],
                        pending["self_key_digest"],
                    )
                    != (
                        claim["claim_token"],
                        instance,
                        epoch,
                        account,
                        contact,
                        key_digest,
                        account_pin[0],
                    )
                ):
                    raise ArchiveError("manager_issue_claim_changed")
            db.execute(
                "INSERT INTO manager_instances(id,epoch,account,self_key_digest,chat,contact,key_digest,message,app_digest,state) VALUES(?,?,?,?,?,?,?,?,?,'active')",
                (
                    instance,
                    epoch,
                    account,
                    account_pin[0],
                    chat,
                    contact,
                    key_digest,
                    message,
                    app_digest,
                ),
            )
            if claim is not None:
                if (
                    db.execute(
                        "UPDATE manager_issuance SET state='issued',updated=?,reason=NULL WHERE id=? AND state='issuing' AND claim_token=? AND instance=?",
                        (time.time(), claim["id"], claim["claim_token"], instance),
                    ).rowcount
                    != 1
                ):
                    raise ArchiveError("manager_issue_claim_changed")
                self.store._ledger(db, "manager_issue_registered", job=instance)
            self.store._ledger(db, "manager_instance_registered", job=instance)
        return instance

    def securejoin(self, epoch, account, contact, key_digest, *, max_pending=64):
        with self.store.transaction() as db:
            if (
                db.execute(
                    "SELECT 1 FROM manager_accounts WHERE epoch=? AND account=?",
                    (epoch, account),
                ).fetchone()
                is None
            ):
                raise ArchiveError("manager_bot_identity_required")
            cancelled = db.execute(
                "UPDATE manager_issuance SET state='cancelled',updated=?,reason='manager_peer_identity_changed' WHERE epoch=? AND account=? AND contact=? AND key_digest!=? AND state='pending'",
                (time.time(), epoch, account, contact, key_digest),
            ).rowcount
            if cancelled:
                self.store._ledger(db, "manager_issue_cancelled", amount=cancelled)
            db.execute(
                "INSERT INTO manager_peers VALUES(?,?,?,?,?) ON CONFLICT(epoch,account,contact) DO UPDATE SET key_digest=excluded.key_digest,securejoin_at=excluded.securejoin_at",
                (epoch, account, contact, key_digest, time.time()),
            )
            existing = db.execute(
                "SELECT id FROM manager_issuance WHERE epoch=? AND account=? AND contact=? AND key_digest=?",
                (epoch, account, contact, key_digest),
            ).fetchone()
            if existing is not None:
                self.store._ledger(db, "manager_issue_duplicate_join")
            else:
                saturated = (
                    db.execute(
                        "SELECT count(*) FROM manager_issuance WHERE epoch=? AND account=? AND state IN ('pending','issuing')",
                        (epoch, account),
                    ).fetchone()[0]
                    >= max_pending
                )
                state = "held" if saturated else "pending"
                now = time.time()
                db.execute(
                    "INSERT INTO manager_issuance(id,epoch,account,contact,key_digest,state,created,updated,reason) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        secrets.token_hex(16),
                        epoch,
                        account,
                        contact,
                        key_digest,
                        state,
                        now,
                        now,
                        "manager_issue_saturated" if saturated else None,
                    ),
                )
                self.store._ledger(
                    db,
                    "manager_issue_saturated" if saturated else "manager_issue_pending",
                )
            self.store._ledger(db, "manager_securejoin_completed")

    def recover_issuance(self, epoch):
        """Called only after acquiring the exclusive profile owner lock."""
        with self.store.transaction() as db:
            abandoned = db.execute(
                "SELECT instance FROM manager_issuance WHERE epoch=? AND state='issuing'",
                (epoch,),
            ).fetchall()
            db.execute(
                "UPDATE manager_issuance SET state='uncertain',updated=?,reason='manager_issue_interrupted' WHERE epoch=? AND state='issuing'",
                (time.time(), epoch),
            )
            for (instance,) in abandoned:
                self.store._ledger(db, "manager_issue_interrupted", job=instance)
        return len(abandoned)

    def claim_issuance(self, epoch, account, *, contact=None, replacement=None):
        """Reserve the instance and CAS token before packaging or SDK work."""
        with self.store.transaction() as db:
            if replacement is not None:
                candidate = row(
                    db,
                    "SELECT * FROM manager_issuance WHERE id=? AND epoch=? AND account=? AND contact=?",
                    (replacement, epoch, account, contact),
                )
                if candidate is None or candidate["state"] not in (
                    "uncertain",
                    "failed",
                    "held",
                ):
                    raise ArchiveError("manager_issue_replacement_denied")
            else:
                query = "SELECT * FROM manager_issuance WHERE epoch=? AND account=? AND state='pending'"
                values = [epoch, account]
                if contact is not None:
                    query += " AND contact=?"
                    values.append(contact)
                candidate = row(db, query + " ORDER BY created,id LIMIT 1", values)
                if candidate is None:
                    return None
            peer = db.execute(
                "SELECT key_digest FROM manager_peers WHERE epoch=? AND account=? AND contact=?",
                (epoch, account, candidate["contact"]),
            ).fetchone()
            account_pin = db.execute(
                "SELECT self_key_digest FROM manager_accounts WHERE epoch=? AND account=?",
                (epoch, account),
            ).fetchone()
            if (
                peer is None
                or peer[0] != candidate["key_digest"]
                or account_pin is None
            ):
                db.execute(
                    "UPDATE manager_issuance SET state='cancelled',updated=?,reason='manager_issue_authority_lost' WHERE id=?",
                    (time.time(), candidate["id"]),
                )
                self.store._ledger(
                    db, "manager_issue_authority_lost", job=candidate["instance"]
                )
                return None
            instance = secrets.token_hex(16)
            token = secrets.token_hex(32)
            if replacement is not None and candidate["instance"] is not None:
                db.execute(
                    "INSERT INTO manager_issuance_history(issuance,instance,claim_token,state,created,updated,reason,replacement_instance) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        candidate["id"],
                        candidate["instance"],
                        candidate["claim_token"],
                        candidate["state"],
                        candidate["created"],
                        candidate["updated"],
                        candidate["reason"],
                        instance,
                    ),
                )
                self.store._ledger(
                    db,
                    "manager_issue_replacement",
                    binding=candidate["instance"],
                    job=instance,
                )
            changed = db.execute(
                "UPDATE manager_issuance SET state='issuing',instance=?,claim_token=?,self_key_digest=?,updated=?,reason=NULL WHERE id=? AND state=?",
                (
                    instance,
                    token,
                    account_pin[0],
                    time.time(),
                    candidate["id"],
                    candidate["state"],
                ),
            )
            if changed.rowcount != 1:
                raise ArchiveError("manager_issue_claim_changed")
            self.store._ledger(db, "manager_issue_claimed", job=instance)
            return row(
                db, "SELECT * FROM manager_issuance WHERE id=?", (candidate["id"],)
            )

    def fail_issuance(self, claim, reason, *, uncertain):
        with self.store.transaction() as db:
            changed = db.execute(
                "UPDATE manager_issuance SET state=?,updated=?,reason=? WHERE id=? AND state='issuing' AND claim_token=? AND instance=?",
                (
                    "uncertain" if uncertain else "failed",
                    time.time(),
                    reason,
                    claim["id"],
                    claim["claim_token"],
                    claim["instance"],
                ),
            )
            self.store._ledger(
                db,
                reason if changed.rowcount else "manager_issue_stale_outcome",
                job=claim["instance"],
            )
            return changed.rowcount == 1

    def revoke_instance(self, instance, reason, *, state="revoked"):
        with self.store.transaction() as db:
            if state not in ("revoked", "quarantined"):
                raise ArchiveError("manager_instance_transition_denied")
            db.execute(
                "UPDATE manager_instances SET state=?,revision=revision+1 WHERE id=? AND state='active'",
                (state, instance),
            )
            db.execute(
                "UPDATE manager_links SET active=0,revision=revision+1 WHERE instance=? AND active=1",
                (instance,),
            )
            db.execute(
                "UPDATE manager_pairs SET state='revoked' WHERE instance=? AND state!='linked'",
                (instance,),
            )
            held = db.execute(
                "UPDATE manager_outbox SET state='held' WHERE instance=? AND state IN ('pending','unsigned','signing-held')",
                (instance,),
            ).rowcount
            if held:
                self.store._ledger(
                    db, "manager_outbox_authority_held", job=instance, amount=held
                )
            self.store._ledger(db, reason, job=instance)

    def ingest(self, instance, serial, payload, *, max_pending=128):
        """Command/refusal and serial advance commit together; replay is harmless."""
        from .manager_protocol import validate_command

        now = time.time()
        with self.store.transaction() as db:
            current = self.instance(instance, db)
            if type(serial) is not int or serial < 1:
                raise ArchiveError("manager_serial_denied")
            if serial <= current["serial"]:
                self.store._ledger(db, "manager_serial_replay", job=instance)
                return "replay"
            if serial != current["serial"] + 1:
                self.store._ledger(db, "manager_serial_gap", job=instance)
                return "gap"
            reason = None
            command = None
            try:
                if (
                    type(payload) is dict
                    and payload.get("type") == "archive-manager-response"
                ):
                    reason = "manager_response_ignored"
                else:
                    command = validate_command(payload, instance=instance)
            except (ValueError, TypeError, ArchiveError):
                reason = "manager_command_invalid"
            if command is not None:
                encoded = canonical(command)
                checksum = digest(encoded)
                previous = row(
                    db,
                    "SELECT digest,result FROM manager_commands WHERE instance=? AND id=?",
                    (instance, command["id"]),
                )
                if previous:
                    reason = (
                        "manager_command_replayed"
                        if previous["digest"] == checksum
                        else "manager_command_id_conflict"
                    )
                    if previous["digest"] == checksum:
                        db.execute(
                            "UPDATE manager_outbox SET state=CASE WHEN state IN ('unsigned','signing-held') THEN state ELSE 'pending' END,due=? WHERE instance=? AND command_id=?",
                            (now, instance, command["id"]),
                        )
                elif (
                    db.execute(
                        "SELECT (SELECT count(*) FROM manager_commands c JOIN manager_instances i ON i.id=c.instance WHERE i.state='active' AND c.state IN ('queued','running'))+(SELECT count(*) FROM manager_outbox o JOIN manager_instances i ON i.id=o.instance WHERE i.state='active' AND o.state IN ('unsigned','signing-held'))"
                    ).fetchone()[0]
                    >= max_pending
                ):
                    reason = "manager_queue_saturated"
                elif (
                    db.execute(
                        "SELECT count(*) FROM manager_commands WHERE instance=? AND updated>?",
                        (instance, now - 60),
                    ).fetchone()[0]
                    >= 30
                ):
                    reason = "manager_command_rate_limited"
                else:
                    db.execute(
                        "INSERT INTO manager_commands(instance,id,digest,payload,state,due,updated) VALUES(?,?,?,?,'queued',?,?)",
                        (instance, command["id"], checksum, encoded, now, now),
                    )
                    reason = "manager_command_queued"
            db.execute(
                "UPDATE manager_instances SET serial=? WHERE id=? AND serial=?",
                (serial, instance, current["serial"]),
            )
            self.store._ledger(db, reason, job=instance)
            return reason

    def expire(self):
        with self.store.transaction() as db:
            count = db.execute(
                "SELECT count(*) FROM manager_pairs WHERE expires<=? AND state IN ('requested','browser','app')",
                (time.time(),),
            ).fetchone()[0]
            if count:
                db.execute(
                    "UPDATE manager_pairs SET state='expired',comparison='' WHERE expires<=? AND state IN ('requested','browser','app')",
                    (time.time(),),
                )
                self.store._ledger(db, "manager_pair_expired", amount=count)
            db.execute("DELETE FROM manager_leases WHERE expires<=?", (time.time(),))

    def lease(self, db, instance, action, *, link=None, challenge=None, intent=None):
        value = secrets.token_urlsafe(24)
        db.execute(
            "INSERT INTO manager_leases VALUES(?,?,?,?,?,?,?,?,?,0)",
            (
                digest(value),
                instance,
                action,
                link["handle"] if link else None,
                link["revision"] if link else 0,
                link["generation"] if link else 0,
                challenge,
                intent,
                time.time() + 120,
            ),
        )
        return value

    def check_lease(self, db, command, *, link=None, challenge=None, intent=None):
        token = command.get("lease")
        if type(token) is not str:
            raise ArchiveError("manager_lease_denied")
        value = row(db, "SELECT * FROM manager_leases WHERE digest=?", (digest(token),))
        if (
            value is None
            or value["used"]
            or value["expires"] <= time.time()
            or (
                value["instance"],
                value["action"],
                value["handle"],
                value["revision"],
                value["generation"],
                value["challenge"],
                value["intent"],
            )
            != (
                command["instance"],
                command["action"],
                link["handle"] if link else None,
                link["revision"] if link else 0,
                link["generation"] if link else 0,
                challenge,
                intent,
            )
        ):
            raise ArchiveError("manager_lease_denied")
        if (
            db.execute(
                "UPDATE manager_leases SET used=1 WHERE digest=? AND used=0",
                (digest(token),),
            ).rowcount
            != 1
        ):
            raise ArchiveError("manager_lease_denied")

    def complete(self, db, command, response):
        encoded = canonical(response)
        changed = db.execute(
            "UPDATE manager_commands SET state='done',result=?,updated=? WHERE instance=? AND id=? AND state IN ('queued','running')",
            (encoded, time.time(), command["instance"], command["id"]),
        )
        if changed.rowcount != 1:
            raise ArchiveError("manager_command_transition_conflict")
        db.execute(
            "INSERT INTO manager_outbox(instance,command_id,payload,due,state) VALUES(?,?,?,?,'unsigned')",
            (command["instance"], command["id"], encoded, time.time()),
        )
        self.store._ledger(db, "manager_command_completed", job=command["id"])
