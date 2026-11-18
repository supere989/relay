"""Archive Manager owner facade, independent of transport and interactive UI.

RPC, mailbox and wallet calls happen outside SQL transactions. Commands have
durable IDs; authority/revision/lease checks and the final mutation, signed
result and outbox insertion commit together. Transport status updates confer
no browser identity and never carry Google credentials or recovery material.
"""

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import threading
import time
from contextlib import ExitStack
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from chatmaild.config import read_config

from .incarnation import Mailbox
from .manager_protocol import b64decode, b64encode, encode_json, sign_response
from .manager_store import (
    DEFINITIVE_AUTHORITY_LOSS,
    ManagerStore,
    canonical,
    digest,
    row,
)
from .model import ArchiveError

PAIR_DOMAIN = b"chatmail-archive-manager-pair/v1\0"
READ_ACTIONS = {"status", "refresh", "pair_start"}
REMOTE_RECEIPT = "state='verified' AND file_id IS NOT NULL AND length(file_id) BETWEEN 1 AND 200 AND file_id NOT GLOB '*[^A-Za-z0-9_-]*' AND size>0 AND sha256 IS NOT NULL AND length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*'"


def fit_document(document):
    """Bound optional detail deterministically, preserving every control."""
    from .manager_protocol import MAX_RESPONSE

    omitted = 0
    while len(encode_json(document, 1024 * 1024)) > MAX_RESPONSE:
        eligible = [item for item in document["bindings"] if item["jobs"]]
        if not eligible:
            raise ArchiveError("manager_response_capacity")
        selected = max(eligible, key=lambda item: (len(item["jobs"]), item["binding"]))
        selected["jobs"].pop()
        selected["jobs_omitted"] += 1
        omitted += 1
    return omitted


@dataclass(frozen=True)
class Context:
    epoch: str
    account: int
    self_key_digest: str
    chat: int
    contact: int
    key_digest: str
    message: int
    app_digest: str

    def checksum(self):
        return digest(canonical(self.__dict__))


class BrokerSigner:
    def __init__(self, broker, reference):
        self.broker, self.reference = broker, reference
        self._public = None

    @property
    def public(self):
        # Optional bot-key availability must not gate ordinary owner sign-in.
        # Validate only at an actual pairing/issuance use, outside SQL.
        if self._public is not None:
            return self._public
        value = self.broker.call("manager-public", ref=self.reference)
        try:
            public = base64.b64decode(value["public_key"], validate=True)
        except (KeyError, TypeError, ValueError):
            raise ArchiveError("manager_signer_unavailable") from None
        if len(public) != 32:
            raise ArchiveError("manager_signer_unavailable")
        self._public = public
        return public

    def sign(self, message):
        value = self.broker.call(
            "manager-sign",
            ref=self.reference,
            message=base64.b64encode(message).decode("ascii"),
        )
        try:
            signature = base64.b64decode(value["signature"], validate=True)
        except (KeyError, TypeError, ValueError):
            raise ArchiveError("manager_signer_unavailable") from None
        if len(signature) != 64:
            raise ArchiveError("manager_signer_unavailable")
        return signature


class Manager:
    def __init__(self, store, config, transport, signer, profile, origin):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ArchiveError("manager_origin_denied")
        self.store, self.config, self.transport, self.signer, self.profile = (
            store,
            config,
            transport,
            signer,
            profile,
        )
        self.origin = origin.rstrip("/")
        self.db = ManagerStore(store)

    def attest(self, instance):
        with self.store.connect() as db:
            registered = self.db.instance(instance, db)
        try:
            self.profile.check(registered["epoch"])
            current = self.transport.attest(registered)
        except ArchiveError as exc:
            if exc.reason in DEFINITIVE_AUTHORITY_LOSS:
                self.db.revoke_instance(instance, "manager_peer_context_changed")
            raise
        expected = Context(*(registered[key] for key in Context.__dataclass_fields__))
        if current != expected:
            self.db.revoke_instance(instance, "manager_peer_context_changed")
            raise ArchiveError("manager_peer_context_changed")
        return current

    def _link(self, db, command):
        link = row(
            db,
            "SELECT * FROM manager_links WHERE handle=? AND instance=? AND active=1",
            (command["binding"], command["instance"]),
        )
        if link is None:
            raise ArchiveError("manager_link_denied")
        binding = self.store.get(link["binding_id"], owner=link["owner"], db=db)
        revision = db.execute(
            "SELECT revision FROM manager_revisions WHERE binding_id=?", (binding.id,)
        ).fetchone()
        if (
            binding.mode != "personal"
            or binding.retired
            or binding.incarnation != link["incarnation"]
            or binding.generation != link["generation"]
            or revision is None
            or revision[0] != link["revision"]
            or (command["link_revision"], command["generation"])
            != (link["revision"], binding.generation)
        ):
            raise ArchiveError("manager_link_stale")
        return link, binding

    def _status(self, db, instance):
        links = db.execute(
            "SELECT handle,revision,generation,binding_id,owner,incarnation FROM manager_links WHERE instance=? AND active=1 ORDER BY handle LIMIT 17",
            (instance,),
        ).fetchall()
        if len(links) > 16:
            raise ArchiveError("manager_link_limit")
        result = []
        for handle, revision, generation, binding_id, owner, incarnation in links:
            b = self.store.get(binding_id, owner=owner, db=db)
            shared = db.execute(
                "SELECT revision FROM manager_revisions WHERE binding_id=?", (b.id,)
            ).fetchone()
            if (
                b.mode != "personal"
                or b.retired
                or b.generation != generation
                or b.incarnation != incarnation
                or shared is None
                or shared[0] != revision
            ):
                raise ArchiveError("manager_link_stale")
            condition = (
                "binding_id=? AND ((generation=? AND state!='verified') OR ("
                + REMOTE_RECEIPT
                + "))"
            )
            jobs = db.execute(
                "SELECT id,state,last_reason FROM jobs WHERE "
                + condition
                + " ORDER BY updated DESC LIMIT 8",
                (b.id, generation),
            ).fetchall()
            work_count = db.execute(
                "SELECT count(*) FROM jobs WHERE " + condition, (b.id, generation)
            ).fetchone()[0]
            queued = (
                db.execute(
                    "SELECT count(*) FROM jobs WHERE binding_id=? AND generation=? AND state IN ('queued','prepared','uploading','uploaded-unverified','uncertain','incomplete')",
                    (b.id, generation),
                ).fetchone()[0]
                if b.enabled and b.consent == "active"
                else 0
            )
            unresolved, held = db.execute(
                "SELECT count(*),coalesce(sum(attempts>=8),0) FROM unresolved WHERE binding_id=?",
                (b.id,),
            ).fetchone()
            verified, remote_count = db.execute(
                "SELECT max(updated),count(*) FROM jobs WHERE binding_id=? AND "
                + REMOTE_RECEIPT,
                (b.id,),
            ).fetchone()
            consent = (
                b.consent
                if b.consent
                in (
                    "pending",
                    "active",
                    "declined",
                    "revoked",
                    "paused",
                    "opted-out",
                    "expired",
                )
                else {
                    "disabled": "opted-out",
                    "reproof_required": "revoked",
                    "reconnect": "expired",
                }.get(b.consent, "paused")
            )
            result.append(
                {
                    "binding": handle,
                    "label": b.mailbox,
                    "state": consent,
                    "enabled": bool(b.enabled),
                    "generation": generation,
                    "link_revision": revision,
                    "unresolved": unresolved,
                    "held_unresolved": held,
                    "eligible_unresolved": unresolved - held
                    if b.enabled and b.consent == "active"
                    else 0,
                    "last_verified": int(verified) if verified else None,
                    "jobs": [
                        {"job": job, "state": state, "reason": reason}
                        for job, state, reason in jobs
                    ],
                    "jobs_omitted": max(0, work_count - len(jobs)),
                    "queued_jobs": queued,
                    "verified_files": remote_count,
                    "coverage": "incomplete"
                    if unresolved
                    else "capture-windows"
                    if remote_count
                    else "unknown",
                }
            )
        return result

    def _document(
        self,
        instance,
        command,
        revision,
        *,
        bindings=None,
        pairing=None,
        result="snapshot",
        code=None,
        handoff=None,
    ):
        now = int(time.time())
        return {
            "version": 1,
            "instance": instance["id"],
            "profile_epoch": instance["epoch"],
            "command_id": command["id"],
            "revision": revision,
            "issued_at": now,
            "expires_at": now + 120,
            "state": "refused"
            if code
            else "pairing"
            if pairing
            else "linked"
            if bindings
            else "unlinked",
            "result": result,
            "code": code,
            "action": command["action"],
            "bindings": bindings or [],
            "leases": {},
            "pairing": pairing,
            "handoff": handoff,
        }

    def _context_in(self, db, instance, context, revision=None):
        current = self.db.instance(instance, db)
        if (
            Context(*(current[key] for key in Context.__dataclass_fields__)) != context
            or revision is not None
            and current["revision"] != revision
        ):
            raise ArchiveError("manager_context_stale")
        return current

    def _pairing(self, db, instance):
        pair = row(
            db,
            "SELECT * FROM manager_pairs WHERE instance=? AND state IN ('requested','browser','app') ORDER BY expires DESC,rowid DESC LIMIT 1",
            (instance,),
        )
        if pair is None:
            return None
        if pair["expires"] <= time.time():
            return None
        return pair

    def _pair_document(self, pair, context, *, lease=None):
        signature = pair.get("signature")
        url = (
            self.origin
            + "/archive/manager-pair?"
            + urlencode({"challenge": pair["id"], "token": signature})
            if signature
            else self.origin + "/archive/"
        )
        return {
            "phase": "open_browser"
            if pair["state"] == "requested"
            else "confirm_app"
            if pair["state"] == "browser"
            else "browser_confirm",
            "url": url,
            "comparison": pair["comparison"],
            "challenge": pair["id"],
            "intent": pair.get("intent"),
            "peer_label": "Protected peer key " + context.key_digest[:16],
            "lease": lease,
        }

    def _pair_signature(self, pair, context):
        return self.signer.sign(
            PAIR_DOMAIN
            + encode_json(
                {
                    "challenge": pair["id"],
                    "instance": pair["instance"],
                    "context": context.checksum(),
                    "expires": int(pair["expires"]),
                },
                4096,
            )
        )

    def pair_url_check(self, pair, token, context):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        try:
            public = self.signer.public
            message = PAIR_DOMAIN + encode_json(
                {
                    "challenge": pair["id"],
                    "instance": pair["instance"],
                    "context": context.checksum(),
                    "expires": int(pair["expires"]),
                },
                4096,
            )
            Ed25519PublicKey.from_public_bytes(public).verify(
                b64decode(token, 64, exact=64), message
            )
        except Exception:
            raise ArchiveError("manager_pair_url_denied") from None

    def _session(self, db, session, csrf):
        current = row(
            db,
            "SELECT owner,csrf_hash,expires FROM sessions WHERE id_hash=?",
            (session.get("id_hash"),),
        )
        if (
            current is None
            or not current["owner"]
            or current["owner"] != session.get("owner")
            or current["expires"] <= time.time()
            or not hmac.compare_digest(current["csrf_hash"], digest(csrf))
        ):
            raise ArchiveError("manager_browser_session_denied")
        return current["owner"]

    def browser_intent(self, session, form):
        from .web import proven_mailbox

        if set(form) != {
            "challenge",
            "token",
            "comparison",
            "binding",
            "password",
            "csrf",
        }:
            raise ArchiveError("manager_pair_form_denied")
        with self.store.connect() as db:
            owner = self._session(db, session, form["csrf"])
            pair = row(
                db, "SELECT * FROM manager_pairs WHERE id=?", (form["challenge"],)
            )
            if (
                pair is None
                or pair["state"] != "requested"
                or pair["expires"] <= time.time()
                or pair["attempts"] >= 5
            ):
                raise ArchiveError("manager_pair_denied")
            binding = self.store.get(form["binding"], owner=owner, db=db)
            if binding.mode != "personal" or binding.retired:
                raise ArchiveError("manager_pair_binding_denied")
        context = self.attest(pair["instance"])
        self.pair_url_check(pair, form["token"], context)
        if not hmac.compare_digest(digest(form["comparison"]), pair["comparison_hash"]):
            with self.store.transaction() as db:
                db.execute(
                    "UPDATE manager_pairs SET attempts=attempts+1 WHERE id=?",
                    (pair["id"],),
                )
                self.store._ledger(db, "manager_pair_comparison_denied", job=pair["id"])
            raise ArchiveError("manager_pair_comparison_denied")
        with proven_mailbox(
            self.config, binding.mailbox, form["password"], final_check=False
        ) as source:
            source.check(binding.incarnation)
            current_context = self.attest(pair["instance"])
            if current_context != context:
                raise ArchiveError("manager_context_stale")
            source.check(binding.incarnation)
            with self.store.transaction() as db:
                self._session(db, session, form["csrf"])
                self._context_in(db, pair["instance"], context)
                current = self.store.get(binding.id, owner=owner, db=db)
                if current != binding or current.retired:
                    raise ArchiveError("manager_pair_binding_changed")
                changed = db.execute(
                    "UPDATE manager_pairs SET state='browser',session_hash=?,owner=?,binding_id=?,generation=?,incarnation=?,intent=?,browser_confirmed=0 WHERE id=? AND state='requested' AND expires>? AND attempts<5",
                    (
                        session["id_hash"],
                        owner,
                        binding.id,
                        binding.generation,
                        binding.incarnation,
                        secrets.token_hex(16),
                        pair["id"],
                        time.time(),
                    ),
                )
                if changed.rowcount != 1:
                    raise ArchiveError("manager_pair_transition_conflict")
                self.store._ledger(
                    db, "manager_pair_browser_intent", binding.id, pair["id"]
                )

    def browser_finish(self, session, form):
        from .web import proven_mailbox

        if (
            set(form)
            != {"challenge", "token", "binding", "password", "csrf", "confirm"}
            or form["confirm"] != "yes"
        ):
            raise ArchiveError("manager_pair_form_denied")
        with self.store.connect() as db:
            owner = self._session(db, session, form["csrf"])
            pair = row(
                db, "SELECT * FROM manager_pairs WHERE id=?", (form["challenge"],)
            )
            if (
                pair is None
                or pair["state"] != "app"
                or not pair["app_confirmed"]
                or pair["session_hash"] != session["id_hash"]
                or pair["owner"] != owner
                or pair["binding_id"] != form["binding"]
                or pair["expires"] <= time.time()
            ):
                raise ArchiveError("manager_pair_confirmation_denied")
            binding = self.store.get(pair["binding_id"], owner=owner, db=db)
        context = self.attest(pair["instance"])
        self.pair_url_check(pair, form["token"], context)
        with proven_mailbox(
            self.config, binding.mailbox, form["password"], final_check=False
        ) as source:
            source.check(pair["incarnation"])
            if self.attest(pair["instance"]) != context:
                raise ArchiveError("manager_context_stale")
            source.check(pair["incarnation"])
            with self.store.transaction() as db:
                self._session(db, session, form["csrf"])
                self._context_in(db, pair["instance"], context)
                current = self.store.get(binding.id, owner=owner, db=db)
                if (
                    current.mode != "personal"
                    or current.retired
                    or (current.generation, current.incarnation)
                    != (pair["generation"], pair["incarnation"])
                ):
                    raise ArchiveError("manager_pair_binding_changed")
                refreshed = row(
                    db, "SELECT * FROM manager_pairs WHERE id=?", (pair["id"],)
                )
                if refreshed != pair or refreshed["expires"] <= time.time():
                    raise ArchiveError("manager_pair_transition_conflict")
                if (
                    db.execute(
                        "SELECT count(*) FROM manager_links WHERE instance=? AND active=1",
                        (pair["instance"],),
                    ).fetchone()[0]
                    >= 16
                ):
                    raise ArchiveError("manager_link_limit")
                db.execute(
                    "INSERT OR IGNORE INTO manager_revisions VALUES(?,1)", (binding.id,)
                )
                revision = db.execute(
                    "SELECT revision FROM manager_revisions WHERE binding_id=?",
                    (binding.id,),
                ).fetchone()[0]
                db.execute(
                    "INSERT INTO manager_links VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(instance,binding_id) DO UPDATE SET owner=excluded.owner,generation=excluded.generation,incarnation=excluded.incarnation,revision=excluded.revision,active=1",
                    (
                        secrets.token_hex(16),
                        pair["instance"],
                        owner,
                        binding.id,
                        binding.generation,
                        binding.incarnation,
                        revision,
                    ),
                )
                changed = db.execute(
                    "UPDATE manager_pairs SET state='linked',browser_confirmed=1 WHERE id=? AND state='app' AND expires>?",
                    (pair["id"], time.time()),
                )
                if changed.rowcount != 1:
                    raise ArchiveError("manager_pair_transition_conflict")
                db.execute(
                    "UPDATE manager_instances SET revision=revision+1 WHERE id=?",
                    (pair["instance"],),
                )
                self.store._ledger(db, "manager_pair_completed", binding.id, pair["id"])

    def browser_page(self, session, fields, csrf):
        if set(fields) != {"challenge", "token"} or not re.fullmatch(
            r"[a-f0-9]{32}", fields["challenge"]
        ):
            raise ArchiveError("manager_pair_url_denied")
        if not session.get("owner"):
            address = html.escape(
                self.origin + "/archive/manager-pair?" + urlencode(fields), quote=True
            )
            return (
                '<!doctype html><html><head><meta charset="utf-8"><title>Pair Archive Manager</title></head><body><h1>Pair Archive Manager</h1><p>Sign in to the owner portal, then return to this tab. The comparison code is shown only in your intended protected chat app.</p><a href="/archive/" target="_blank" rel="noopener noreferrer">Open owner sign-in</a><p><a href="'
                + address
                + '">Continue after sign-in</a></p></body></html>'
            ).encode("utf-8")
        with self.store.connect() as db:
            pair = row(
                db, "SELECT * FROM manager_pairs WHERE id=?", (fields["challenge"],)
            )
            if (
                pair is None
                or pair["expires"] <= time.time()
                or pair["state"] not in ("requested", "browser", "app", "linked")
            ):
                raise ArchiveError("manager_pair_denied")
            if pair["state"] != "requested" and (
                pair["session_hash"] != session["id_hash"]
                or pair["owner"] != session["owner"]
            ):
                raise ArchiveError("manager_pair_browser_mismatch")
            bindings = self.store.owned(session["owner"])
        context = self.attest(pair["instance"])
        self.pair_url_check(pair, fields["token"], context)
        hidden = "".join(
            '<input type="hidden" name="'
            + name
            + '" value="'
            + html.escape(value, quote=True)
            + '">'
            for name, value in {**fields, "csrf": csrf}.items()
        )
        body = (
            "<h1>Pair this mailbox with Archive Manager</h1><p>Protected peer public-key digest: <code>"
            + context.key_digest
            + "</code></p><p>Operation: allow this exact bot-issued app to view archive status, pause/resume future archiving, retry existing jobs, and open owner-only consent/recovery handoffs. It cannot receive mailbox passwords, Google tokens or recovery keys.</p>"
        )
        if pair["state"] == "requested":
            options = "".join(
                '<option value="' + b.id + '">' + html.escape(b.mailbox) + "</option>"
                for b in bindings
                if b.mode == "personal" and not b.retired
            )
            body += (
                '<p>Enter the separate six-digit comparison shown in your intended app. A forwarded URL alone must not be enough. Deliberately forwarding both channels can defeat this human comparison.</p><form method="post" action="/archive/manager-intent">'
                + hidden
                + '<label>Personal mailbox <select name="binding" required>'
                + options
                + '</select></label><label>App comparison code <input name="comparison" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required></label><label>Fresh mailbox password <input type="password" name="password" maxlength="1024" autocomplete="current-password" required></label><button>Prepare this pairing intent</button></form>'
            )
        elif pair["state"] == "browser":
            body += (
                '<p>Confirm the matching pairing intent in the intended app, then reload this page for the final browser confirmation.</p><a href="'
                + html.escape(
                    self.origin + "/archive/manager-pair?" + urlencode(fields),
                    quote=True,
                )
                + '">Check app confirmation</a>'
            )
        elif pair["state"] == "app":
            with self.store.connect() as db:
                b = self.store.get(pair["binding_id"], owner=session["owner"], db=db)
            body += (
                "<p>The app confirmed this intent for "
                + html.escape(b.mailbox)
                + '. Final confirmation binds only this protected peer and app instance.</p><form method="post" action="/archive/manager-confirm">'
                + hidden
                + '<input type="hidden" name="binding" value="'
                + b.id
                + '"><input type="hidden" name="confirm" value="yes"><label>Fresh mailbox password <input type="password" name="password" maxlength="1024" autocomplete="current-password" required></label><button>Confirm and pair this mailbox</button></form>'
            )
        else:
            body += "<p>Pairing confirmed. Return to the app and refresh signed status. You can unlink there; future source-generation or mailbox ownership changes require fresh pairing.</p>"
        return (
            '<!doctype html><html><head><meta charset="utf-8"><title>Pair Archive Manager</title></head><body>'
            + body
            + "</body></html>"
        ).encode("utf-8")

    def _lease_plan(self, document):
        pending = []
        expires = min(document["expires_at"], time.time() + 120)
        for binding in document["bindings"]:
            document["leases"][binding["binding"]] = {}
            for action in (
                "pause",
                "resume",
                "retry",
                "reconnect",
                "recovery",
                "unlink",
            ):
                token = secrets.token_urlsafe(24)
                document["leases"][binding["binding"]][action] = token
                pending.append(
                    (
                        digest(token),
                        document["instance"],
                        action,
                        binding["binding"],
                        binding["link_revision"],
                        binding["generation"],
                        None,
                        None,
                        expires,
                    )
                )
        pairing = document["pairing"]
        if pairing and pairing["phase"] == "confirm_app":
            token = secrets.token_urlsafe(24)
            pairing["lease"] = token
            pending.append(
                (
                    digest(token),
                    document["instance"],
                    "pair_confirm",
                    None,
                    0,
                    0,
                    pairing["challenge"],
                    pairing["intent"],
                    expires,
                )
            )
        return pending

    def _pair_authority(self, db, command, context):
        pair = row(
            db,
            "SELECT * FROM manager_pairs WHERE id=? AND instance=?",
            (command["args"]["challenge"], command["instance"]),
        )
        if (
            pair is None
            or pair["state"] != "browser"
            or pair["expires"] <= time.time()
            or pair["context_digest"] != context.checksum()
            or pair["intent"] != command["args"]["intent"]
        ):
            raise ArchiveError("manager_pair_confirmation_denied")
        session = row(
            db,
            "SELECT owner,expires FROM sessions WHERE id_hash=?",
            (pair["session_hash"],),
        )
        b = self.store.get(pair["binding_id"], owner=pair["owner"], db=db)
        if (
            session is None
            or session["owner"] != pair["owner"]
            or session["expires"] <= time.time()
            or b.mode != "personal"
            or b.retired
            or (b.generation, b.incarnation)
            != (pair["generation"], pair["incarnation"])
        ):
            raise ArchiveError("manager_pair_binding_changed")
        return pair, b

    def process(self, instance, command_id):
        try:
            with self.store.operation(instance, command_id, kind="manager_instance"):
                return self._process_claimed(instance, command_id)
        except ArchiveError as exc:
            if exc.reason == "operation_busy":
                self.store.event("manager_operation_stall", job=command_id)
                return None
            raise

    def _process_claimed(self, instance, command_id):
        started = time.monotonic()
        try:
            context = self.attest(instance)
            self._reconcile_links(instance)
            with self.store.connect() as db:
                record = row(
                    db,
                    "SELECT * FROM manager_commands WHERE instance=? AND id=?",
                    (instance, command_id),
                )
                if record is None or record["state"] == "done":
                    return self.publish(instance, command_id) if record else None
                if record["attempts"] >= 5:
                    return None
                command = json.loads(record["payload"])
                registered = self._context_in(db, instance, context)
                before = self._status(db, instance)
                link, binding = (
                    self._link(db, command)
                    if command["binding"] is not None
                    else (None, None)
                )
                pair, browser_binding = (
                    self._pair_authority(db, command, context)
                    if command["action"] == "pair_confirm"
                    else (None, None)
                )
                pending_pair = self._pairing(db, instance)
            with ExitStack() as stack:
                if binding is not None:
                    stack.enter_context(
                        self.store.operation(binding.id, command_id, kind="manager")
                    )
                sources = []
                bindings_to_check = (
                    [binding or browser_binding] if binding or browser_binding else []
                )
                if command["action"] in ("status", "refresh", "pair_start"):
                    with self.store.connect() as db:
                        bindings_to_check = [
                            self.store.get(binding_id, owner=owner, db=db)
                            for binding_id, owner in db.execute(
                                "SELECT binding_id,owner FROM manager_links WHERE instance=? AND active=1",
                                (instance,),
                            ).fetchall()
                        ]
                for b in bindings_to_check:
                    source = stack.enter_context(
                        Mailbox(self.config.mailboxes_dir, b.mailbox)
                    )
                    try:
                        source.check(b.incarnation)
                    except ArchiveError as exc:
                        if exc.reason == "mailbox_incarnation_changed":
                            self.store.invalidate_incarnation(b.id)
                            self._reconcile_links(instance)
                        raise
                    sources.append((source, b.incarnation))
                created_pair = None
                pairing = None
                if command["action"] == "pair_start":
                    comparison = f"{secrets.randbelow(1000000):06d}"
                    created_pair = {
                        "id": secrets.token_hex(16),
                        "instance": instance,
                        "context_digest": context.checksum(),
                        "comparison": comparison,
                        "comparison_hash": digest(comparison),
                        "expires": int(time.time()) + 600,
                        "state": "requested",
                    }
                    created_pair["signature"] = b64encode(
                        self._pair_signature(created_pair, context)
                    )
                    pairing = self._pair_document(created_pair, context)
                elif pending_pair:
                    pending_pair["signature"] = b64encode(
                        self._pair_signature(pending_pair, context)
                    )
                    if command["action"] == "pair_confirm":
                        pending_pair["state"] = "app"
                    pairing = self._pair_document(pending_pair, context)
                handoff = None
                if link and command["action"] not in READ_ACTIONS:
                    if command["action"] in ("reconnect", "recovery", "resume"):
                        handoff = {
                            "action": "recovery"
                            if command["action"] == "recovery"
                            else "reconnect",
                            "url": self.origin + "/archive/",
                        }
                if self.attest(instance) != context:
                    raise ArchiveError("manager_context_stale")
                for source, incarnation in sources:
                    source.check(incarnation)
                with self.store.transaction() as db:
                    self._context_in(db, instance, context, registered["revision"])
                    if self._status(db, instance) != before:
                        raise ArchiveError("manager_snapshot_stale")
                    if created_pair:
                        if (
                            db.execute(
                                "SELECT count(*) FROM manager_pairs WHERE instance=? AND expires>? AND state!='linked'",
                                (instance, time.time()),
                            ).fetchone()[0]
                            >= 4
                        ):
                            raise ArchiveError("manager_pair_rate_limited")
                        db.execute(
                            "INSERT INTO manager_pairs(id,instance,context_digest,comparison_hash,comparison,expires) VALUES(?,?,?,?,?,?)",
                            tuple(
                                created_pair[key]
                                for key in (
                                    "id",
                                    "instance",
                                    "context_digest",
                                    "comparison_hash",
                                    "comparison",
                                    "expires",
                                )
                            ),
                        )
                        self.store._ledger(
                            db, "manager_pair_requested", job=created_pair["id"]
                        )
                    elif command["action"] == "pair_confirm":
                        current_pair, _b = self._pair_authority(db, command, context)
                        if current_pair != pair:
                            raise ArchiveError("manager_pair_transition_conflict")
                        self.db.check_lease(
                            db, command, challenge=pair["id"], intent=pair["intent"]
                        )
                        db.execute(
                            "UPDATE manager_pairs SET state='app',app_confirmed=1 WHERE id=? AND state='browser'",
                            (pair["id"],),
                        )
                        self.store._ledger(
                            db, "manager_pair_app_confirmed", job=pair["id"]
                        )
                    elif link and command["action"] not in READ_ACTIONS:
                        current_link, current_binding = self._link(db, command)
                        if current_link != link or current_binding != binding:
                            raise ArchiveError("manager_link_stale")
                        self.db.check_lease(db, command, link=link)
                        if command["action"] == "pause":
                            if binding.enabled:
                                self.store.optout_in(db, binding.id, link["owner"])
                            self.store._ledger(db, "optout", binding.id)
                        elif command["action"] == "resume":
                            self.store.enable_in(db, binding.id, link["owner"])
                        elif command["action"] == "retry":
                            job = self.store.job(command["args"]["job"], db=db)
                            if (
                                job["binding_id"] != binding.id
                                or job["generation"] != binding.generation
                                or job["attempt"] >= 8
                            ):
                                raise ArchiveError("manager_retry_denied")
                            self.store.retry_in(db, job["id"])
                            self.store._ledger(
                                db, "job_manual_retry", binding.id, job["id"]
                            )
                        db.execute(
                            "UPDATE manager_revisions SET revision=revision+1 WHERE binding_id=? AND revision=?",
                            (binding.id, link["revision"]),
                        )
                        generation = self.store.get(binding.id, db=db).generation
                        db.execute(
                            "UPDATE manager_links SET revision=revision+1,generation=? WHERE binding_id=? AND active=1",
                            (generation, binding.id),
                        )
                        if command["action"] == "unlink":
                            db.execute(
                                "UPDATE manager_links SET active=0 WHERE handle=?",
                                (link["handle"],),
                            )
                        self.store._ledger(
                            db, "manager_" + command["action"], binding.id, command_id
                        )
                    elif command["action"] not in READ_ACTIONS:
                        raise ArchiveError("manager_link_denied")
                    current_pair = created_pair or self._pairing(db, instance)
                    if current_pair:
                        known = (
                            created_pair
                            if created_pair and created_pair["id"] == current_pair["id"]
                            else pending_pair
                        )
                        if known is None or known["id"] != current_pair["id"]:
                            raise ArchiveError("manager_snapshot_stale")
                        current_pair["signature"] = known["signature"]
                    pairing = (
                        self._pair_document(current_pair, context)
                        if current_pair
                        else None
                    )
                    document = self._document(
                        registered,
                        command,
                        registered["revision"] + 1,
                        bindings=self._status(db, instance),
                        pairing=pairing,
                        result="snapshot"
                        if command["action"] in READ_ACTIONS
                        else "confirmed",
                        handoff=handoff,
                    )
                    leases = self._lease_plan(document)
                    self._bound_document(db, document)
                    db.executemany(
                        "INSERT INTO manager_leases VALUES(?,?,?,?,?,?,?,?,?,0)", leases
                    )
                    db.execute(
                        "UPDATE manager_instances SET revision=revision+1 WHERE id=? AND revision=?",
                        (instance, registered["revision"]),
                    )
                    self.db.complete(db, command, document)
            return self.publish(instance, command_id)
        except ArchiveError as exc:
            self.store.event(exc.reason, job=command_id)
            return self._refuse(instance, command_id, exc.reason)
        finally:
            self.store.event(
                "manager_command_duration_ms",
                job=command_id,
                amount=int((time.monotonic() - started) * 1000),
            )

    def _refuse(self, instance, command_id, reason):
        with self.store.connect() as db:
            record = row(
                db,
                "SELECT * FROM manager_commands WHERE instance=? AND id=?",
                (instance, command_id),
            )
            registered = row(
                db, "SELECT * FROM manager_instances WHERE id=?", (instance,)
            )
        if record is None or record["state"] == "done" or registered is None:
            return None
        command = json.loads(record["payload"])
        safe = (
            reason
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason)
            else "manager_command_refused"
        )
        document = self._document(
            registered,
            command,
            registered["revision"] + 1,
            result="rejected",
            code=safe,
        )
        with self.store.transaction() as db:
            current = row(
                db, "SELECT revision FROM manager_instances WHERE id=?", (instance,)
            )
            if current["revision"] != registered["revision"]:
                raise ArchiveError("manager_context_stale")
            db.execute(
                "UPDATE manager_instances SET revision=revision+1 WHERE id=?",
                (instance,),
            )
            self.db.complete(db, command, document)
            self.store._ledger(db, "manager_command_refused", job=command_id)
        return self.publish(instance, command_id)

    def publish(self, instance, command_id):
        """Sign the immutable committed snapshot outside every SQL transaction."""
        with self.store.connect() as db:
            pending = row(
                db,
                "SELECT * FROM manager_outbox WHERE instance=? AND command_id=?",
                (instance, command_id),
            )
        if pending is None:
            return None
        if pending["state"] in ("pending", "sent"):
            return json.loads(pending["payload"])
        try:
            self.attest(instance)
            signed = sign_response(json.loads(pending["payload"]), self.signer)
        except ArchiveError:
            with self.store.transaction() as db:
                delay = 300 if pending["attempts"] >= 4 else 2 ** pending["attempts"]
                db.execute(
                    "UPDATE manager_outbox SET attempts=min(5,attempts+1),state=CASE WHEN attempts>=4 THEN 'signing-held' ELSE 'unsigned' END,due=? WHERE seq=? AND payload=? AND state IN ('unsigned','signing-held')",
                    (time.time() + delay, pending["seq"], pending["payload"]),
                )
                self.store._ledger(db, "manager_signer_stall", job=command_id)
            return None
        with self.store.transaction() as db:
            db.execute(
                "UPDATE manager_outbox SET payload=?,state='pending',due=? WHERE seq=? AND payload=? AND state IN ('unsigned','signing-held')",
                (canonical(signed), time.time(), pending["seq"], pending["payload"]),
            )
            current = row(
                db,
                "SELECT payload,state FROM manager_outbox WHERE seq=?",
                (pending["seq"],),
            )
            if current["state"] not in ("pending", "sent"):
                raise ArchiveError("manager_signature_publish_conflict")
            return json.loads(current["payload"])

    def _bound_document(self, db, document):
        omitted = fit_document(document)
        if omitted:
            self.store._ledger(
                db,
                "manager_job_details_omitted",
                job=document["command_id"],
                amount=omitted,
            )

    def tick(self, limit=16):
        with self.store.connect() as db:
            commands = db.execute(
                "SELECT c.instance,c.id FROM manager_commands c JOIN manager_instances i ON i.id=c.instance WHERE i.state='active' AND c.state='queued' AND c.due<=? AND c.attempts<5 ORDER BY c.due LIMIT ?",
                (time.time(), min(limit, 16)),
            ).fetchall()
        for instance, command in commands:
            self.process(instance, command)
        with self.store.connect() as db:
            unsigned = db.execute(
                "SELECT o.instance,o.command_id FROM manager_outbox o JOIN manager_instances i ON i.id=o.instance WHERE i.state='active' AND o.state IN ('unsigned','signing-held') AND o.due<=? ORDER BY o.due LIMIT ?",
                (time.time(), min(limit, 16)),
            ).fetchall()
        for instance, command in unsigned:
            self.publish(instance, command)
        return len(commands)

    def _reconcile_links(self, instance):
        with self.store.transaction() as db:
            invalid = db.execute(
                "SELECT l.handle,l.binding_id FROM manager_links l JOIN bindings b ON b.id=l.binding_id LEFT JOIN manager_revisions r ON r.binding_id=b.id WHERE l.instance=? AND l.active=1 AND (b.owner!=l.owner OR b.mode!='personal' OR b.retired=1 OR b.generation!=l.generation OR b.incarnation IS NOT l.incarnation OR r.revision IS NOT l.revision)",
                (instance,),
            ).fetchall()
            for handle, binding in invalid:
                db.execute(
                    "UPDATE manager_links SET active=0,revision=revision+1 WHERE handle=?",
                    (handle,),
                )
                self.store._ledger(db, "manager_link_authority_lost", binding, instance)
            if invalid:
                db.execute(
                    "UPDATE manager_instances SET revision=revision+1 WHERE id=?",
                    (instance,),
                )

    def issue_app(self, account, contact, *, replacement=None):
        claim = self.db.claim_issuance(
            self.profile.check(), account, contact=contact, replacement=replacement
        )
        if claim is None:
            raise ArchiveError("manager_issue_not_pending")
        return self.issue_claim(claim)

    def issue_claim(self, claim, *, cancelled=lambda: False):
        from .manager_packaging import app_bytes

        epoch, account, contact, instance = (
            claim["epoch"],
            claim["account"],
            claim["contact"],
            claim["instance"],
        )
        uncertain = False
        try:
            if cancelled():
                raise ArchiveError("manager_issue_cancelled")
            self.profile.check(epoch)
            peer = self.transport.call("peer", account, contact)
            with self.store.connect() as db:
                current = row(
                    db, "SELECT * FROM manager_issuance WHERE id=?", (claim["id"],)
                )
                self_pin = db.execute(
                    "SELECT self_key_digest FROM manager_accounts WHERE epoch=? AND account=?",
                    (epoch, account),
                ).fetchone()
                enrolled = db.execute(
                    "SELECT key_digest FROM manager_peers WHERE epoch=? AND account=? AND contact=?",
                    (epoch, account, contact),
                ).fetchone()
            if (
                current is None
                or current["state"] != "issuing"
                or current["claim_token"] != claim["claim_token"]
                or current["instance"] != instance
            ):
                raise ArchiveError("manager_issue_claim_changed")
            if (
                self_pin is None
                or self_pin[0] != peer["self_key_digest"]
                or peer["self_key_digest"] != claim["self_key_digest"]
            ):
                raise ArchiveError("manager_bot_identity_changed")
            if (
                enrolled is None
                or enrolled[0] != claim["key_digest"]
                or peer["key_digest"] != claim["key_digest"]
            ):
                raise ArchiveError("manager_securejoin_required")
            app = app_bytes(
                {
                    "version": 1,
                    "instance": instance,
                    "profile_epoch": epoch,
                    "public_key": b64encode(self.signer.public),
                    "portal_origin": self.origin,
                }
            )
            destination = self.profile.mount / ("archive-manager-" + instance + ".xdc")
            with self.store.guard.parent(destination) as (parent, name):
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                try:
                    view = memoryview(app)
                    while view:
                        count = os.write(fd, view)
                        if not count:
                            raise ArchiveError("manager_app_write_failed")
                        view = view[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
            self.store.event("manager_issue_prepared", job=instance)
            if cancelled():
                raise ArchiveError("manager_issue_cancelled")
            uncertain = True  # A lost SDK reply can follow actual acceptance.
            issued = self.transport.call(
                "issue",
                account,
                contact,
                str(destination),
                {
                    "key_digest": claim["key_digest"],
                    "self_key_digest": claim["self_key_digest"],
                },
            )
            if (
                issued["key_digest"] != claim["key_digest"]
                or issued["self_key_digest"] != claim["self_key_digest"]
                or type(issued["message"]) is not int
            ):
                raise ArchiveError("manager_issue_context_changed")
            if cancelled():
                raise ArchiveError("manager_issue_cancelled")
            registered = {
                "id": instance,
                "epoch": epoch,
                "account": account,
                "self_key_digest": claim["self_key_digest"],
                "chat": issued["chat"],
                "contact": contact,
                "key_digest": claim["key_digest"],
                "message": issued["message"],
                "app_digest": hashlib.sha256(app).hexdigest(),
            }
            context = self.transport.attest(registered)
            if context != Context(
                *(registered[key] for key in Context.__dataclass_fields__)
            ):
                raise ArchiveError("manager_issue_context_changed")
            return self.db.register(
                epoch,
                account,
                issued["chat"],
                contact,
                claim["key_digest"],
                issued["message"],
                registered["app_digest"],
                instance=instance,
                claim=claim,
            )
        except Exception:
            # Sending may already have happened. Never automatically issue a
            # second app or grant authority to an unregistered orphan.
            reason = (
                "manager_issue_uncertain"
                if uncertain
                else "manager_issue_preparation_failed"
            )
            self.db.fail_issuance(claim, reason, uncertain=uncertain)
            raise ArchiveError(reason) from None


class IssuanceWorker:
    """One bounded job worker; no packaging/sending on the event handoff loop."""

    def __init__(self, manager, account, *, owner_fd=None):
        self.manager, self.account = manager, account
        self.epoch = manager.profile.check()
        self.stop = threading.Event()
        self.owner_fd = os.dup(owner_fd) if owner_fd is not None else None
        self.thread = threading.Thread(
            target=self.run, name="archive-manager-issuance", daemon=True
        )

    def tick(self):
        claim = self.manager.db.claim_issuance(self.epoch, self.account)
        if claim is None:
            return False
        self.manager.issue_claim(claim, cancelled=self.stop.is_set)
        return True

    def run(self):
        try:
            while not self.stop.is_set():
                try:
                    self.tick()
                except Exception:
                    try:
                        self.manager.store.event("manager_issue_worker_refused")
                    except Exception:
                        pass  # Store's bounded inaccessible-storage counter owns this seam.
                self.stop.wait(0.5)
        finally:
            if self.owner_fd is not None:
                os.close(self.owner_fd)
                self.owner_fd = None

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.manager.transport.close()
        self.thread.join(35)
        if self.thread.is_alive():
            self.manager.store.event("manager_issue_shutdown_stall")


def load_manager(config, store, credentials, *, web=False, enroll=False):
    from .manager_profile import Profile
    from .manager_transport import SocketTransport, Transport

    settings = config.get("manager")
    if type(settings) is not dict or getattr(store, "guard", None) is None:
        raise ArchiveError("manager_state_policy_required")
    try:
        profile = Profile(settings["profile"], state=store.guard)
        profile.check()
        signer = BrokerSigner(credentials.broker, settings["signing_ref"])
        transport = (
            SocketTransport(settings["attestation_socket"], store.guard)
            if web
            else Transport(
                profile,
                settings["rpc_server"],
                settings["rpc_sha256"],
                initialize=enroll,
            )
        )
        return Manager(
            store,
            read_config(config["chatmail_ini"]),
            transport,
            signer,
            profile,
            config["public_url"],
        )
    except (KeyError, TypeError, ValueError):
        raise ArchiveError("manager_config_invalid") from None


def main(argv=None):
    import argparse
    import os
    import signal
    import sys
    import threading
    from pathlib import Path

    from .cli import load
    from .credentials import Broker
    from .manager_profile import Profile, StateGuard, no_core_dumps
    from .manager_store import ManagerStore
    from .manager_transport import AttestationServer, reconcile
    from .store import Store

    parser = argparse.ArgumentParser(
        description="Optional owner Archive Manager; no service activation or implicit enrollment"
    )
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "command",
        choices=(
            "serve",
            "enroll-profile",
            "enroll-mailbox",
            "invite",
            "issue",
            "status",
        ),
    )
    parser.add_argument("--contact", type=int)
    parser.add_argument("--replace-issuance")
    args = parser.parse_args(argv)
    transport = None
    issuer = None
    ownership = ExitStack()
    try:
        no_core_dumps()
        if args.command == "enroll-profile":
            raw = Path(args.config).read_bytes()
            if len(raw) > 65536:
                raise ArchiveError("config_limit")
            config = json.loads(raw)
            settings = config["manager"]
            guard = StateGuard(config["state_storage"])
            with guard.parent(Path(settings["profile"]) / "epoch", create=True):
                pass
            profile = Profile(settings["profile"], state=guard)
            ownership.enter_context(profile.owner())
            epoch = profile.initialize()
            store = Store(config["database"], guard=guard, create=True)
            ManagerStore(store)
            broker = Broker(config["broker_argv"])
            key = (
                broker.call("manager-public", ref=settings["signing_ref"])
                if settings.get("signing_ref")
                else broker.call("manager-key")
            )
            print(
                json.dumps(
                    {
                        "profile_epoch": epoch,
                        "signing_ref": key["ref"],
                        "public_key": key["public_key"],
                    }
                )
            )
            return 0
        config, store, credentials = load(args.config)
        manager = load_manager(
            config, store, credentials, enroll=args.command == "enroll-mailbox"
        )
        transport = manager.transport
        settings = config["manager"]
        if args.command == "status":
            with store.connect() as db:
                issuance = [
                    dict(
                        zip(
                            ("id", "account", "contact", "state", "instance", "reason"),
                            item,
                            strict=True,
                        )
                    )
                    for item in db.execute(
                        "SELECT id,account,contact,state,instance,reason FROM manager_issuance ORDER BY updated DESC,id LIMIT 64"
                    )
                ]
                total = db.execute("SELECT count(*) FROM manager_issuance").fetchone()[
                    0
                ]
            print(
                json.dumps(
                    {
                        "format": 1,
                        "metrics": store.metrics(),
                        "state_epoch": store.guard.epoch,
                        "profile_epoch": manager.profile.check(),
                        "distribution": "deterministic",
                        "issuance": issuance,
                        "issuance_omitted": total - len(issuance),
                    },
                    sort_keys=True,
                )
            )
            return 0
        try:
            owner_fd = ownership.enter_context(manager.profile.owner())
        except ArchiveError as error:
            store.event(error.reason)
            raise
        manager.db.recover_issuance(manager.profile.check())
        if args.command == "enroll-mailbox":
            account = transport.call(
                "configure",
                credentials.broker.get(settings["mailbox_ref"]),
                settings.get("transport_settings", {}),
            )
            manager.db.enroll_account(
                manager.profile.check(), account, transport.call("self_key", account)
            )
            store.event("manager_mailbox_enrolled")
            print(json.dumps({"account_id": account}))
            return 0
        account = settings["account_id"]
        if type(account) is not int or account < 1:
            raise ArchiveError("manager_account_required")
        current_key = transport.call("self_key", account)
        with store.connect() as db:
            expected = db.execute(
                "SELECT self_key_digest FROM manager_accounts WHERE epoch=? AND account=?",
                (manager.profile.check(), account),
            ).fetchone()
        if expected is None or current_key != expected[0]:
            raise ArchiveError("manager_bot_identity_changed")
        transport.call("begin", account)
        if args.command == "invite":
            invitation = transport.call("invite", account)
            path = manager.profile.mount / (
                "securejoin-invitation-" + secrets.token_hex(16) + ".txt"
            )
            with store.guard.parent(path) as (parent, name):
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent,
                )
                try:
                    os.write(fd, invitation.encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
            print(json.dumps({"private_invitation_path": str(path)}))
        elif args.command == "issue":
            if args.contact is None or args.contact <= 9:
                raise ArchiveError("manager_contact_required")
            if args.replace_issuance is not None and not re.fullmatch(
                r"[a-f0-9]{32}", args.replace_issuance
            ):
                raise ArchiveError("manager_issue_replacement_denied")
            print(
                json.dumps(
                    {
                        "instance": manager.issue_app(
                            account, args.contact, replacement=args.replace_issuance
                        ),
                        "state": "issued",
                    }
                )
            )
        else:
            stop = threading.Event()
            for signum in (signal.SIGTERM, signal.SIGINT):
                signal.signal(signum, lambda *_args: stop.set())
            server = AttestationServer(settings["attestation_socket"], manager)
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
            )
            thread.start()
            issuer = IssuanceWorker(manager, account, owner_fd=owner_fd)
            issuer.start()
            try:
                while not stop.is_set():
                    for event in transport.call("events", account):
                        if event.get("overflow"):
                            store.event("manager_event_overflow")
                        else:
                            manager.db.securejoin(
                                manager.profile.check(),
                                account,
                                event["contact"],
                                event["key_digest"],
                            )
                    reconcile(manager)
                    server.flush_stalls()
                    stop.wait(0.5)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
        return 0
    except ArchiveError as exc:
        print(json.dumps({"error": exc.reason}), file=sys.stderr)
    except Exception:
        print('{"error":"manager_operation_failed"}', file=sys.stderr)
    finally:
        if issuer is not None:
            issuer.close()
        if transport is not None:
            transport.close()
        ownership.close()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
