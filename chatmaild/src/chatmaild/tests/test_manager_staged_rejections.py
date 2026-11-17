"""Regression contracts for the exact staged capacity/authority review."""

import secrets
import time

import pytest

from chatmaild.backup import manager as manager_module
from chatmaild.backup.manager_store import DEFINITIVE_AUTHORITY_LOSS, digest
from chatmaild.backup.manager_transport import reconcile
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_backend import execute, pair
from chatmaild.tests.test_manager_backend import setup as backend_setup
from chatmaild.tests.test_manager_child_context import context as child_setup
from chatmaild.tests.test_manager_child_context import snapshot
from chatmaild.tests.test_manager_review import pending_browser


def command(instance):
    return {
        "version": 1,
        "type": "archive-manager-command",
        "instance": instance,
        "id": secrets.token_hex(16),
        "action": "status",
        "binding": None,
        "link_revision": 0,
        "generation": 0,
        "lease": None,
        "args": {},
    }


@pytest.mark.parametrize("state", ["revoked", "quarantined"])
@pytest.mark.parametrize("work", ["queued", "running", "unsigned", "signing-held"])
def test_inactive_history_cannot_consume_active_admission_capacity(
    tmp_path, state, work
):
    context = backend_setup.__wrapped__(tmp_path)
    manager = context.manager
    epoch = manager.profile.check()
    other = manager.db.register(epoch, 1, 21, 10, "a" * 64, 101, "b" * 64)
    originals = []
    for serial in (1, 2):
        value = command(context.instance)
        assert (
            manager.db.ingest(context.instance, serial, value, max_pending=2)
            == "manager_command_queued"
        )
        originals.append(value)
    if work in ("unsigned", "signing-held"):

        def unavailable(_message):
            raise ArchiveError("manager_signer_unavailable")

        manager.signer.sign = unavailable
        for value in originals:
            assert manager.process(context.instance, value["id"]) is None
        with manager.store.transaction() as db:
            db.execute(
                "UPDATE manager_outbox SET state=? WHERE instance=?",
                (work, context.instance),
            )
    elif work == "running":
        with manager.store.transaction() as db:
            db.execute(
                "UPDATE manager_commands SET state='running' WHERE instance=?",
                (context.instance,),
            )
    assert (
        manager.db.ingest(other, 1, command(other), max_pending=2)
        == "manager_queue_saturated"
    )
    with manager.store.connect() as db:
        history = db.execute(
            "SELECT * FROM manager_commands WHERE instance=? ORDER BY id",
            (context.instance,),
        ).fetchall()
    manager.db.revoke_instance(context.instance, "manager_test_revoked", state=state)
    if work in ("unsigned", "signing-held"):
        # Admission must also ignore inactive unsigned history left by older
        # state, independent of today's revoke-to-held transition.
        with manager.store.transaction() as db:
            db.execute(
                "UPDATE manager_outbox SET state=? WHERE instance=?",
                (work, context.instance),
            )
    assert (
        manager.db.ingest(other, 2, command(other), max_pending=2)
        == "manager_command_queued"
    )
    assert (
        manager.db.ingest(other, 3, command(other), max_pending=2)
        == "manager_command_queued"
    )
    assert (
        manager.db.ingest(other, 4, command(other), max_pending=2)
        == "manager_queue_saturated"
    )
    with manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT * FROM manager_commands WHERE instance=? ORDER BY id",
                (context.instance,),
            ).fetchall()
            == history
        )
        assert (
            db.execute(
                "SELECT serial FROM manager_instances WHERE id=?", (context.instance,)
            ).fetchone()[0]
            == 2
        )
        assert (
            db.execute(
                "SELECT serial FROM manager_instances WHERE id=?", (other,)
            ).fetchone()[0]
            == 4
        )
        assert (
            db.execute(
                "SELECT count(*) FROM manager_commands c JOIN manager_instances i ON i.id=c.instance WHERE i.state='active' AND c.state IN ('queued','running')"
            ).fetchone()[0]
            == 2
        )


AUTHORITY_REASONS = (
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


@pytest.mark.parametrize("reason", AUTHORITY_REASONS)
@pytest.mark.parametrize("phase", ["parent_send_check", "child_updates", "child_send"])
def test_definitive_authority_loss_holds_without_payload_retry(tmp_path, reason, phase):
    context = child_setup.__wrapped__(tmp_path)
    assert reason in DEFINITIVE_AUTHORITY_LOSS
    before, commands, outbox, _active = snapshot(context)
    if phase == "parent_send_check":
        original = context.bridge.attest

        def deny_second(registered):
            actual = original(registered)
            if context.bridge.parent_checks == 2:
                raise ArchiveError(reason)
            return actual

        context.bridge.attest = deny_second
    else:

        def denied(*_args):
            assert context.bridge.parent_checks > 0
            raise ArchiveError(reason)

        if phase == "child_updates":
            context.bridge.updates = denied
        else:
            context.bridge.send = denied
    reconcile(context.manager)
    after, unchanged, held, active = snapshot(context)
    assert after == ("revoked", before[1]) and unchanged == commands and active == 0
    assert context.core.reads == (0 if phase == "child_updates" else 1)
    assert context.core.sends == 0
    assert all(item[1] == "held" for item in held)
    assert [(item[0], item[2:]) for item in held] == [
        (item[0], item[2:]) for item in outbox
    ]
    with context.manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason IN ('manager_send_ambiguous','manager_response_sent')"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize(
    "metadata,reason",
    [
        ("chat", "manager_chat_denied"),
        ("contact", "manager_contact_denied"),
        ("message", "manager_app_message_denied"),
    ],
)
@pytest.mark.parametrize("operation", ["updates", "send"])
def test_actual_delayed_child_metadata_denial_prevents_payload_operation(
    tmp_path, metadata, reason, operation
):
    context = child_setup.__wrapped__(tmp_path)
    original = getattr(
        context.core,
        {
            "chat": "get_full_chat_by_id",
            "contact": "get_contact",
            "message": "get_message",
        }[metadata],
    )

    def mutate():
        assert context.bridge.parent_checks > 0

        def changed(*args):
            value = original(*args)
            value[
                {
                    "chat": "isEncrypted",
                    "contact": "isBlocked",
                    "message": "isForwarded",
                }[metadata]
            ] = metadata != "chat"
            return value

        setattr(
            context.core,
            {
                "chat": "get_full_chat_by_id",
                "contact": "get_contact",
                "message": "get_message",
            }[metadata],
            changed,
        )

    context.bridge.operation = operation
    context.bridge.mutate = mutate
    before = snapshot(context)
    reconcile(context.manager)
    after = snapshot(context)
    assert (
        after[0] == ("revoked", before[0][1])
        and after[1] == before[1]
        and after[3] == 0
    )
    assert context.core.sends == 0 and context.core.reads == (
        0 if operation == "updates" else 1
    )
    assert [(item[0], item[2:]) for item in after[2]] == [
        (item[0], item[2:]) for item in before[2]
    ]
    assert all(item[1] == "held" for item in after[2])
    with context.manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason=?", (reason,)
            ).fetchone()[0]
            > 0
        )
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason IN ('manager_send_ambiguous','manager_response_sent')"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("revoked", [False, True])
def test_unknown_send_outcome_keeps_ambiguity_but_cannot_resurrect_held_row(
    tmp_path, revoked
):
    context = child_setup.__wrapped__(tmp_path)
    original = context.bridge.send

    def lost_reply(registered, payload):
        original(registered, payload)
        if revoked:
            context.manager.db.revoke_instance(
                context.instance, "manager_test_concurrent_revoke"
            )
        raise ArchiveError("manager_transport_stall")

    context.bridge.send = lost_reply
    before = snapshot(context)
    reconcile(context.manager)
    after = snapshot(context)
    assert (
        context.core.sends == 1
        and after[0][1] == before[0][1]
        and after[1] == before[1]
    )
    if revoked:
        assert after[0][0] == "revoked" and after[3] == 0
        assert all(item[1] == "held" for item in after[2])
        assert [(item[0], item[2:]) for item in after[2]] == [
            (item[0], item[2:]) for item in before[2]
        ]
    else:
        assert after[0][0] == "active" and after[3] == 1
        assert sum(item[2] for item in after[2]) == 1
        assert all(item[1] == "pending" for item in after[2])
    with context.manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason='manager_send_ambiguous'"
            ).fetchone()[0]
            == 1
        )
        assert db.execute(
            "SELECT count(*) FROM ledger WHERE reason='manager_send_retry_fenced'"
        ).fetchone()[0] == int(revoked)
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason='manager_response_sent'"
            ).fetchone()[0]
            == 0
        )


def test_parent_lookup_after_concurrent_revocation_is_definitive_not_ambiguous(
    tmp_path,
):
    context = child_setup.__wrapped__(tmp_path)
    original = context.manager.attest
    calls = []

    def raced(instance):
        calls.append(instance)
        if len(calls) == 2:
            context.manager.db.revoke_instance(
                instance, "manager_test_concurrent_revoke"
            )
        return original(instance)

    context.manager.attest = raced
    before = snapshot(context)
    reconcile(context.manager)
    after = snapshot(context)
    assert (
        after[0] == ("revoked", before[0][1])
        and after[1] == before[1]
        and after[3] == 0
    )
    assert context.core.sends == 0 and all(item[1] == "held" for item in after[2])
    assert [(item[0], item[2:]) for item in after[2]] == [
        (item[0], item[2:]) for item in before[2]
    ]
    with context.manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason='manager_send_ambiguous'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("phase", ["linked", "pair_confirm"])
def test_every_exposed_lease_expires_with_its_document_despite_creation_delay(
    tmp_path, monkeypatch, phase
):
    context = backend_setup.__wrapped__(tmp_path)
    if phase == "linked":
        pair(context)
    else:
        _pairing, form = pending_browser(context)
        context.manager.browser_intent(context.scenario.session, form)
    clock = [time.time()]
    monkeypatch.setattr(manager_module.time, "time", lambda: clock[0])
    original = context.manager._document

    def delayed(*args, **kwargs):
        document = original(*args, **kwargs)
        clock[0] += 60
        return document

    monkeypatch.setattr(context.manager, "_document", delayed)
    _command, _envelope, document = execute(context, "status")
    tokens = [
        token for actions in document["leases"].values() for token in actions.values()
    ]
    if document["pairing"] and document["pairing"]["lease"]:
        tokens.append(document["pairing"]["lease"])
    assert len(tokens) == (6 if phase == "linked" else 1)
    with context.manager.store.connect() as db:
        expiries = [
            db.execute(
                "SELECT expires FROM manager_leases WHERE digest=?", (digest(token),)
            ).fetchone()[0]
            for token in tokens
        ]
    assert all(
        expiry <= document["expires_at"] and expiry <= clock[0] + 120
        for expiry in expiries
    )
