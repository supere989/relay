"""The child enforces registered pins again before each payload operation.

RPC metadata calls are separate observations, not an atomic core snapshot.
These barriers change public identity/app data after the successful parent
check and before the child's fresh check; payload reads/sends must not run.
"""

import base64
import hashlib
import secrets

import pytest

from chatmaild.backup.manager_transport import SDK, public_key_digest, reconcile
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_backend import pair
from chatmaild.tests.test_manager_backend import setup as manager_setup


@pytest.fixture
def context(tmp_path):
    context = manager_setup.__wrapped__(tmp_path)
    pair(context)
    manager = context.manager
    app = manager.profile.mount / "public-app-fixture.xdc"
    app.write_bytes(b"public synthetic app bytes")
    app.chmod(0o600)

    class Core:
        peer_key = bytes(range(64))
        self_key = bytes(reversed(range(64)))
        reads = 0
        sends = 0

        def get_full_chat_by_id(self, _account, _chat):
            return {
                "id": 20,
                "chatType": "Single",
                "isContactRequest": False,
                "isSelfTalk": False,
                "isDeviceChat": False,
                "isEncrypted": True,
                "canSend": True,
                "contactIds": [10],
                "mailingListAddress": None,
            }

        def get_contact(self, _account, _contact):
            return {
                "id": 10,
                "isBlocked": False,
                "isKeyContact": True,
                "e2eeAvail": True,
            }

        def get_message(self, _account, _message):
            return {
                "id": 100,
                "chatId": 20,
                "fromId": 1,
                "viewType": "Webxdc",
                "isForwarded": False,
                "showPadlock": True,
                "originalMsgId": None,
                "savedMessageId": None,
                "error": None,
                "file": str(app),
            }

        def make_vcard(self, _account, contacts):
            key = self.self_key if contacts == [1] else self.peer_key
            return (
                "BEGIN:VCARD\r\nKEY:data:application/pgp-keys;base64\\,"
                + base64.b64encode(key).decode("ascii")
                + "\r\nEND:VCARD\r\n"
            )

        def get_webxdc_status_updates(self, *_args):
            self.reads += 1
            return "[]"

        def send_webxdc_status_update(self, *_args):
            self.sends += 1

    core = Core()
    self_pin = public_key_digest(core.make_vcard(1, [1]))
    peer_pin = public_key_digest(core.make_vcard(1, [10]))
    with manager.store.transaction() as db:
        db.execute(
            "UPDATE manager_instances SET self_key_digest=?,key_digest=?,app_digest=? WHERE id=?",
            (
                self_pin,
                peer_pin,
                hashlib.sha256(app.read_bytes()).hexdigest(),
                context.instance,
            ),
        )
        db.execute("UPDATE manager_accounts SET self_key_digest=?", (self_pin,))
        db.execute("UPDATE manager_peers SET key_digest=?", (peer_pin,))
    sdk = SDK.__new__(SDK)
    sdk.profile = manager.profile.mount
    sdk.rpc = core

    class Bridge:
        changed = False
        operation = None
        change = None
        parent_checks = 0

        def attest(self, registered):
            actual = sdk.attest(registered)
            self.parent_checks += 1
            return actual

        def mutate(self):
            assert self.parent_checks > 0
            self.changed = True
            if self.change == "peer":
                core.peer_key = b"p" * 64
            elif self.change == "self":
                core.self_key = b"s" * 64
            else:
                app.write_bytes(b"different public app bytes")

        def updates(self, registered, serial):
            if self.operation == "updates":
                self.mutate()
            return sdk.updates(registered, serial)

        def send(self, registered, payload):
            if self.operation == "send":
                self.mutate()
            return sdk.send(registered, payload)

    context.core, context.bridge, context.sdk = core, Bridge(), sdk
    manager.transport = context.bridge
    return context


def snapshot(context):
    with context.manager.store.connect() as db:
        instance = db.execute(
            "SELECT state,serial FROM manager_instances WHERE id=?", (context.instance,)
        ).fetchone()
        commands = db.execute(
            "SELECT id,state,attempts,due,result FROM manager_commands WHERE instance=? ORDER BY id",
            (context.instance,),
        ).fetchall()
        outbox = db.execute(
            "SELECT command_id,state,attempts,due FROM manager_outbox WHERE instance=? ORDER BY command_id",
            (context.instance,),
        ).fetchall()
        active = db.execute(
            "SELECT count(*) FROM manager_links WHERE instance=? AND active=1",
            (context.instance,),
        ).fetchone()[0]
    return instance, commands, outbox, active


@pytest.mark.parametrize("operation", ["updates", "send"])
@pytest.mark.parametrize("change", ["peer", "self", "app"])
def test_child_mismatch_after_parent_check_revokes_without_payload_operation_or_retry(
    context, operation, change
):
    context.bridge.operation = operation
    context.bridge.change = change
    before, commands, outbox, active = snapshot(context)
    assert active == 1 and outbox
    reconcile(context.manager)
    after, unchanged, held, active = snapshot(context)
    assert context.bridge.changed and context.bridge.parent_checks >= 1
    assert context.core.reads == (0 if operation == "updates" else 1)
    assert context.core.sends == 0
    assert after == ("revoked", before[1]) and active == 0 and unchanged == commands
    assert [(item[0], item[2], item[3]) for item in held] == [
        (item[0], item[2], item[3]) for item in outbox
    ]
    assert all(item[1] == "held" for item in held)
    context.manager.tick()
    assert snapshot(context) == (after, commands, held, 0)
    with context.manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason IN ('manager_send_ambiguous','manager_response_sent')"
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute(
                "SELECT count(*) FROM ledger WHERE reason='manager_outbox_authority_held'"
            ).fetchone()[0]
            == 1
        )


def test_unchanged_child_context_reads_and_sends_normally(context):
    before, commands, outbox, _active = snapshot(context)
    reconcile(context.manager)
    after, unchanged, sent, active = snapshot(context)
    assert after == before and unchanged == commands and active == 1
    assert context.core.reads == 1 and context.core.sends == len(outbox)
    assert all(item[1] == "sent" for item in sent)


def test_parent_attest_revokes_when_child_reports_context_mismatch(context):
    with context.manager.store.connect() as db:
        registered = context.manager.db.instance(context.instance, db)
    context.manager.attest(context.instance)
    context.core.peer_key = b"changed-public-peer-key" * 3
    with pytest.raises(ArchiveError, match="manager_peer_context_changed"):
        context.manager.attest(context.instance)
    assert context.core.reads == 0 and context.core.sends == 0
    assert snapshot(context)[0][0] == "revoked" and snapshot(context)[3] == 0
    # The child itself refuses both payload methods even if called directly.
    with pytest.raises(ArchiveError, match="manager_peer_context_changed"):
        context.sdk.updates(registered, registered["serial"])
    with pytest.raises(ArchiveError, match="manager_peer_context_changed"):
        context.sdk.send(registered, "{}")
    assert context.core.reads == 0 and context.core.sends == 0


def test_queued_command_remains_inert_after_context_revocation(context):
    command = {
        "version": 1,
        "type": "archive-manager-command",
        "instance": context.instance,
        "id": secrets.token_hex(16),
        "action": "status",
        "binding": None,
        "link_revision": 0,
        "generation": 0,
        "lease": None,
        "args": {},
    }
    context.serial += 1
    assert (
        context.manager.db.ingest(context.instance, context.serial, command)
        == "manager_command_queued"
    )
    context.bridge.operation = "updates"
    context.bridge.change = "peer"
    before = snapshot(context)
    reconcile(context.manager)
    context.manager.tick()
    after = snapshot(context)
    assert after[1] == before[1] and after[0][1] == before[0][1]
    with context.manager.store.connect() as db:
        assert (
            db.execute(
                "SELECT state FROM manager_commands WHERE id=?", (command["id"],)
            ).fetchone()[0]
            == "queued"
        )
