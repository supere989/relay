"""Regressions for restart progress, commit truth and authority checkpoints."""

import json
import secrets
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from chatmaild.backup.manager_protocol import verify_response
from chatmaild.backup.manager_store import ManagerStore
from chatmaild.backup.manager_transport import SDK, AttestationServer, reconcile
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_backend import execute, pair
from chatmaild.tests.test_manager_backend import setup as manager_setup


@pytest.fixture
def context(tmp_path):
    return manager_setup.__wrapped__(tmp_path)


def pending_browser(context):
    _c, _e, document = execute(context, "pair_start")
    pairing = document["pairing"]
    query = {
        key: values[0]
        for key, values in parse_qs(urlsplit(pairing["url"]).query).items()
    }
    scenario = context.scenario
    form = {
        **query,
        "comparison": pairing["comparison"],
        "binding": scenario.binding.id,
        "password": scenario.password,
        "csrf": scenario.portal.csrf(scenario.session),
    }
    return pairing, form


def ready_finish(context):
    _pairing, form = pending_browser(context)
    context.manager.browser_intent(context.scenario.session, form)
    _c, _e, status = execute(context, "status")
    pending = status["pairing"]
    execute(
        context,
        "pair_confirm",
        lease=pending["lease"],
        args={"challenge": pending["challenge"], "intent": pending["intent"]},
    )
    return {key: value for key, value in form.items() if key != "comparison"} | {
        "confirm": "yes"
    }


def test_supported_serial_prefix_drains_400_updates_over_one_mib_after_restart(context):
    updates = []
    for serial in range(1, 401):
        payload = {
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
        updates.append(
            {"serial": serial, "description": "x" * 3000, "payload": payload}
        )
    assert len(json.dumps(updates)) > 1024 * 1024
    sdk = SDK.__new__(SDK)
    sdk.attest = lambda _registered: None
    sdk.rpc = SimpleNamespace(
        get_webxdc_status_updates=lambda _account, _message, last: json.dumps(
            [update for update in updates if update["serial"] > last]
        )
    )
    with context.scenario.store.connect() as db:
        registered = context.manager.db.instance(context.instance, db)
    first = sdk.updates(registered, 0)
    assert len(first) == 256
    for update in first:
        context.manager.db.ingest(context.instance, update["serial"], update["payload"])
    restarted = ManagerStore(context.scenario.store)
    with context.scenario.store.connect() as db:
        checkpoint = restarted.instance(context.instance, db)["serial"]
    assert checkpoint == 256
    second = sdk.updates(registered, checkpoint)
    assert len(second) == 144
    for update in second:
        restarted.ingest(context.instance, update["serial"], update["payload"])
    with context.scenario.store.connect() as db:
        assert restarted.instance(context.instance, db)["serial"] == 400
        accounted = db.execute(
            "SELECT sum(amount) FROM ledger WHERE reason IN ('manager_command_queued','manager_command_rate_limited','manager_queue_saturated')"
        ).fetchone()[0]
    assert accounted == 400


def test_truly_oversized_history_has_durable_quarantine_and_reissue_boundary(context):
    sdk = SDK.__new__(SDK)
    sdk.attest = lambda _registered: None
    sdk.rpc = SimpleNamespace(
        get_webxdc_status_updates=lambda *_args: " " * (16 * 1024 * 1024 + 1)
    )
    with context.scenario.store.connect() as db:
        registered = context.manager.db.instance(context.instance, db)
    with pytest.raises(ArchiveError, match="manager_history_quarantine_required"):
        sdk.updates(registered, 0)

    def oversized(*_args):
        raise ArchiveError("manager_history_quarantine_required")

    context.transport.updates = oversized
    reconcile(context.manager)
    with context.scenario.store.connect() as db:
        state, serial = db.execute(
            "SELECT state,serial FROM manager_instances WHERE id=?", (context.instance,)
        ).fetchone()
    assert state == "quarantined" and serial == 0
    assert context.scenario.store.metrics()["events_manager_history_quarantined"] == 1


def test_pending_work_and_source_retries_respect_generation_and_consent(context):
    store = context.scenario.store
    binding = context.scenario.binding
    old = store.enqueue(binding.id)
    store.optout(binding.id, binding.owner)
    store.enable(binding.id, binding.owner)
    current = store.get(binding.id)
    store.consent(
        current.id,
        current.owner,
        current.generation,
        current.permission_id,
        "new-synthetic-credential",
        current.key_ref,
        current.recipient,
        current.folder_id,
        expected_ref=None,
    )
    context.scenario.binding = store.get(binding.id)
    pair(context)
    current_job = store.enqueue(binding.id)
    with store.connect() as db:
        db.execute("UPDATE jobs SET state='queued' WHERE id=?", (old,))
        db.executemany(
            "INSERT INTO unresolved VALUES(?,?,?, ?,?,0)",
            [
                (binding.id, "eligible", "source_changed", 1, time.time()),
                (binding.id, "held", "source_oversized", 8, time.time()),
            ],
        )
    _c, _e, status = execute(context, "status")
    live = status["bindings"][0]
    assert (
        live["queued_jobs"] == 1
        and live["held_unresolved"] == 1
        and live["eligible_unresolved"] == 1
    )
    assert old not in [job["job"] for job in live["jobs"]]
    assert current_job in [job["job"] for job in live["jobs"]]
    b = store.get(binding.id)
    store.pause(b.id, "pending", generation=b.generation, expected_ref=b.credential_ref)
    _c, _e, status = execute(context, "status")
    blocked = status["bindings"][0]
    assert blocked["queued_jobs"] == 0 and blocked["eligible_unresolved"] == 0
    assert blocked["held_unresolved"] == 1 and blocked["unresolved"] == 2


def test_actual_retained_spool_retry_ack_matches_fresh_post_commit_status(context):
    pair(context)
    worker = context.scenario.worker

    class FailedDrive:
        def __init__(self, _token, checkpoint):
            self.checkpoint = checkpoint

        def principal(self):
            return "principal-one"

        def allocate(self):
            return "synthetic-retained-file"

        def upload(self, *_args):
            raise ArchiveError("drive_transient", retryable=True)

    worker.drive_factory = FailedDrive
    worker.max_attempts = 1
    store = context.scenario.store
    job = store.enqueue(context.scenario.binding.id)
    worker.run(job)
    failed = store.job(job)
    assert failed["state"] == "failed" and failed["spool"] and failed["size"] > 0
    _c, _e, status = execute(context, "status")
    binding = status["bindings"][0]
    _c, _e, ack = execute(
        context,
        "retry",
        binding=binding,
        lease=status["leases"][binding["binding"]]["retry"],
        args={"job": job},
    )
    _c, _e, fresh = execute(context, "status")
    assert ack["result"] == "confirmed"
    assert ack["bindings"] == fresh["bindings"]
    assert ack["bindings"][0]["queued_jobs"] == 1
    assert (
        next(item for item in ack["bindings"][0]["jobs"] if item["job"] == job)["state"]
        == "prepared"
    )
    retained = store.job(job)
    assert (retained["spool"], retained["file_id"], retained["sha256"]) == (
        failed["spool"],
        failed["file_id"],
        failed["sha256"],
    )


def test_signature_broker_runs_after_commit_without_an_open_write_transaction(context):
    status = pair(context)
    binding = status["bindings"][0]
    original = context.signer.sign
    observed = []

    def signing(message):
        with context.scenario.store.transaction() as db:
            b = context.scenario.store.get(context.scenario.binding.id, db=db)
            pending = db.execute(
                "SELECT count(*) FROM manager_outbox WHERE state='unsigned'"
            ).fetchone()[0]
            observed.append(not b.enabled and pending == 1)
        return original(message)

    context.signer.sign = signing
    _c, _e, ack = execute(
        context,
        "pause",
        binding=binding,
        lease=status["leases"][binding["binding"]]["pause"],
    )
    assert observed == [True] and ack["result"] == "confirmed"


def test_signer_outage_retains_committed_document_and_retry_never_reapplies_action(
    context,
):
    status = pair(context)
    binding = status["bindings"][0]
    original = context.signer.sign

    def unavailable(_message):
        raise ArchiveError("manager_signer_unavailable")

    context.signer.sign = unavailable
    command = {
        "version": 1,
        "type": "archive-manager-command",
        "instance": context.instance,
        "id": secrets.token_hex(16),
        "action": "pause",
        "binding": binding["binding"],
        "link_revision": binding["link_revision"],
        "generation": binding["generation"],
        "lease": status["leases"][binding["binding"]]["pause"],
        "args": {},
    }
    context.serial += 1
    context.manager.db.ingest(context.instance, context.serial, command)
    assert context.manager.process(context.instance, command["id"]) is None
    b = context.scenario.store.get(context.scenario.binding.id)
    assert not b.enabled
    with context.scenario.store.connect() as db:
        terminal = db.execute(
            "SELECT state,result FROM manager_commands WHERE instance=? AND id=?",
            (context.instance, command["id"]),
        ).fetchone()
        state = db.execute(
            "SELECT state FROM manager_outbox WHERE instance=? AND command_id=?",
            (context.instance, command["id"]),
        ).fetchone()[0]
    assert terminal[0] == "done" and state == "unsigned"
    context.signer.sign = original
    envelope = context.manager.publish(context.instance, command["id"])
    document = verify_response(
        envelope,
        context.signer.public,
        instance=context.instance,
        profile_epoch=context.manager.profile.check(),
        now=int(time.time()),
        portal_origin=context.manager.origin,
    )
    assert document == json.loads(terminal[1])
    assert context.scenario.store.get(b.id) == b


def test_final_browser_confirmation_cannot_cross_expiry_during_attestation(
    context, monkeypatch
):
    form = ready_finish(context)
    original = context.manager.attest
    current = time.time()
    calls = []

    def delayed(instance):
        value = original(instance)
        calls.append(True)
        if len(calls) == 2:
            monkeypatch.setattr(time, "time", lambda: current + 601)
        return value

    context.manager.attest = delayed
    with pytest.raises(ArchiveError):
        context.manager.browser_finish(context.scenario.session, form)
    with context.scenario.store.connect() as db:
        assert db.execute("SELECT count(*) FROM manager_links").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT state FROM manager_pairs WHERE id=?", (form["challenge"],)
            ).fetchone()[0]
            == "app"
        )


@pytest.mark.parametrize("phase", ["intent", "finish"])
def test_namespace_loss_during_final_attestation_cannot_commit_pairing(context, phase):
    form = ready_finish(context) if phase == "finish" else pending_browser(context)[1]
    original = context.manager.attest
    calls = []

    def replaced(instance):
        value = original(instance)
        calls.append(True)
        if len(calls) == 2:
            context.scenario.user.maildir.rename(
                context.scenario.directory / "retired-mailbox"
            )
        return value

    context.manager.attest = replaced
    method = (
        context.manager.browser_finish
        if phase == "finish"
        else context.manager.browser_intent
    )
    with pytest.raises(ArchiveError):
        method(context.scenario.session, form)
    with context.scenario.store.connect() as db:
        assert db.execute("SELECT count(*) FROM manager_links").fetchone()[0] == 0
        assert db.execute(
            "SELECT state FROM manager_pairs WHERE id=?", (form["challenge"],)
        ).fetchone()[0] == ("app" if phase == "finish" else "requested")


def test_saturated_accept_path_never_waits_for_a_blocked_ledger_writer(
    context, tmp_path
):
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    server = AttestationServer(runtime / "attest.sock", context.manager)
    for _ in range(4):
        assert server.slots.acquire(blocking=False)
    original = context.scenario.store.event
    entered, release = threading.Event(), threading.Event()

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    context.scenario.store.event = blocked
    request = SimpleNamespace(shutdown=lambda *_args: None, close=lambda: None)
    thread = None
    try:
        start = time.monotonic()
        server.process_request(request, None)
        assert time.monotonic() - start < 0.5 and not entered.is_set()
        thread = threading.Thread(target=server.flush_stalls)
        thread.start()
        assert entered.wait(2)
        start = time.monotonic()
        server.process_request(request, None)
        assert time.monotonic() - start < 0.5
        release.set()
        thread.join(3)
        assert not thread.is_alive()
        context.scenario.store.event = original
        server.flush_stalls()
        assert context.scenario.store.metrics()["events_manager_attestation_stall"] == 2
    finally:
        release.set()
        if thread:
            thread.join(3)
        for _ in range(4):
            server.slots.release()
        server.server_close()
