"""Facade/state tests on explicit tmpfs fixtures, not real transport proof."""

import json
import os
import secrets
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chatmaild.backup.manager import Context, Manager
from chatmaild.backup.manager_profile import Profile, StateGuard
from chatmaild.backup.manager_protocol import verify_response
from chatmaild.backup.model import ArchiveError
from chatmaild.backup.store import Store
from chatmaild.tests.recovery_fixture import Scenario


@pytest.fixture
def setup(tmp_path):
    scenario = Scenario(tmp_path / "server")
    state = scenario.store.path.parent
    epoch = secrets.token_hex(16)
    (state / ".archive-state-epoch").write_text(epoch)
    (state / ".archive-state-epoch").chmod(0o600)
    guard = StateGuard(
        {"mount": str(state), "epoch": epoch, "uid": os.geteuid()}, synthetic=True
    )
    scenario.store = Store(scenario.store.path, guard=guard, create=False)
    scenario.portal.store = scenario.store
    scenario.worker.store = scenario.store
    profile_path = state / "bot"
    profile_path.mkdir(mode=0o700)
    profile = Profile(profile_path, synthetic=True, state=guard)
    bot_epoch = profile.initialize()
    signer = Ed25519PrivateKey.generate()
    signer = SimpleNamespace(
        sign=signer.sign,
        public=signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
    )
    transport = SimpleNamespace(changed=False)

    def attest(registered):
        fields = {key: registered[key] for key in Context.__dataclass_fields__}
        if transport.changed:
            fields["key_digest"] = "f" * 64
        return Context(**fields)

    transport.attest = attest
    manager = Manager(
        scenario.store,
        scenario.config,
        transport,
        signer,
        profile,
        "https://archive.example.org",
    )
    manager.db.enroll_account(bot_epoch, 1, "c" * 64)
    manager.db.securejoin(bot_epoch, 1, 10, "a" * 64)
    instance = manager.db.register(bot_epoch, 1, 20, 10, "a" * 64, 100, "b" * 64)
    return SimpleNamespace(
        scenario=scenario,
        manager=manager,
        transport=transport,
        signer=signer,
        instance=instance,
        serial=0,
    )


def execute(setup, action, *, binding=None, lease=None, args=None, command_id=None):
    command = {
        "version": 1,
        "type": "archive-manager-command",
        "instance": setup.instance,
        "id": command_id or secrets.token_hex(16),
        "action": action,
        "binding": binding["binding"] if binding else None,
        "link_revision": binding["link_revision"] if binding else 0,
        "generation": binding["generation"] if binding else 0,
        "lease": lease,
        "args": args or {},
    }
    setup.serial += 1
    setup.manager.db.ingest(setup.instance, setup.serial, command)
    envelope = setup.manager.process(setup.instance, command["id"])
    document = verify_response(
        envelope,
        setup.signer.public,
        instance=setup.instance,
        profile_epoch=setup.manager.profile.check(),
        now=int(time.time()),
        portal_origin=setup.manager.origin,
    )
    return command, envelope, document


def pair(setup):
    _command, _envelope, document = execute(setup, "pair_start")
    pairing = document["pairing"]
    query = {
        key: values[0]
        for key, values in parse_qs(urlsplit(pairing["url"]).query).items()
    }
    scenario = setup.scenario
    csrf = scenario.portal.csrf(scenario.session)
    setup.manager.browser_intent(
        scenario.session,
        {
            **query,
            "comparison": pairing["comparison"],
            "binding": scenario.binding.id,
            "password": scenario.password,
            "csrf": csrf,
        },
    )
    _command, _envelope, status = execute(setup, "status")
    pending = status["pairing"]
    assert pending["phase"] == "confirm_app"
    execute(
        setup,
        "pair_confirm",
        lease=pending["lease"],
        args={"challenge": pending["challenge"], "intent": pending["intent"]},
    )
    setup.manager.browser_finish(
        scenario.session,
        {
            **query,
            "binding": scenario.binding.id,
            "password": scenario.password,
            "csrf": csrf,
            "confirm": "yes",
        },
    )
    status = execute(setup, "status")[2]
    assert status["state"] == "linked", status["code"]
    return status


def test_real_store_pair_and_pause_atomic_signed_ack(setup):
    status = pair(setup)
    binding = status["bindings"][0]
    _command, envelope, paused = execute(
        setup,
        "pause",
        binding=binding,
        lease=status["leases"][binding["binding"]]["pause"],
    )
    assert not setup.scenario.store.get(setup.scenario.binding.id).enabled
    assert paused["bindings"][0]["generation"] == binding["generation"] + 1
    assert paused["bindings"][0]["link_revision"] == binding["link_revision"] + 1
    with setup.scenario.store.connect() as db:
        stored = db.execute(
            "SELECT result FROM manager_commands WHERE instance=? AND id=?",
            (setup.instance, paused["command_id"]),
        ).fetchone()[0]
        outbox = db.execute(
            "SELECT payload FROM manager_outbox WHERE instance=? AND command_id=?",
            (setup.instance, paused["command_id"]),
        ).fetchone()[0]
    assert json.loads(stored) == paused
    assert json.loads(outbox) == envelope


def test_offline_old_lease_cannot_reverse_new_pause(setup):
    status = pair(setup)
    binding = status["bindings"][0]
    execute(
        setup,
        "pause",
        binding=binding,
        lease=status["leases"][binding["binding"]]["pause"],
    )
    _command, _envelope, rejected = execute(
        setup,
        "resume",
        binding=binding,
        lease=status["leases"][binding["binding"]]["resume"],
    )
    assert (
        rejected["state"] == "refused"
        and not setup.scenario.store.get(setup.scenario.binding.id).enabled
    )


def test_same_id_same_payload_replays_recorded_response_without_mutation(setup):
    status = pair(setup)
    binding = status["bindings"][0]
    command, envelope, _document = execute(
        setup,
        "pause",
        binding=binding,
        lease=status["leases"][binding["binding"]]["pause"],
    )
    generation = setup.scenario.store.get(setup.scenario.binding.id).generation
    setup.serial += 1
    assert (
        setup.manager.db.ingest(setup.instance, setup.serial, command)
        == "manager_command_replayed"
    )
    assert setup.manager.process(setup.instance, command["id"]) == envelope
    assert setup.scenario.store.get(setup.scenario.binding.id).generation == generation
    command["action"] = "resume"
    setup.serial += 1
    assert (
        setup.manager.db.ingest(setup.instance, setup.serial, command)
        == "manager_command_id_conflict"
    )


def test_peer_change_revokes_links_and_rejects_commands(setup):
    pair(setup)
    setup.transport.changed = True
    with pytest.raises(ArchiveError, match="manager_peer_context_changed"):
        setup.manager.attest(setup.instance)
    with setup.scenario.store.connect() as db:
        assert (
            db.execute("SELECT count(*) FROM manager_links WHERE active=1").fetchone()[
                0
            ]
            == 0
        )


def test_same_epoch_account_and_peer_cannot_hide_changed_bot_self_key(setup):
    pair(setup)

    def replaced(registered):
        fields = {key: registered[key] for key in Context.__dataclass_fields__}
        fields["self_key_digest"] = "d" * 64
        return Context(**fields)

    setup.transport.attest = replaced
    with pytest.raises(ArchiveError, match="manager_peer_context_changed"):
        setup.manager.attest(setup.instance)
    with setup.scenario.store.connect() as db:
        assert (
            db.execute(
                "SELECT state FROM manager_instances WHERE id=?", (setup.instance,)
            ).fetchone()[0]
            == "revoked"
        )
        assert (
            db.execute("SELECT count(*) FROM manager_links WHERE active=1").fetchone()[
                0
            ]
            == 0
        )


@pytest.mark.parametrize("change", ["code", "owner", "expired", "logout", "generation"])
def test_pair_intent_cannot_cross_browser_owner_context(setup, change):
    _command, _envelope, document = execute(setup, "pair_start")
    pairing = document["pairing"]
    fields = {
        key: values[0]
        for key, values in parse_qs(urlsplit(pairing["url"]).query).items()
    }
    scenario = setup.scenario
    csrf = scenario.portal.csrf(scenario.session)
    if change == "code":
        pairing["comparison"] = (
            "000000" if pairing["comparison"] != "000000" else "111111"
        )
    elif change == "owner":
        with scenario.store.connect() as db:
            db.execute(
                "UPDATE sessions SET owner=? WHERE id_hash=?",
                ("f" * 64, scenario.session["id_hash"]),
            )
    elif change == "expired":
        with scenario.store.connect() as db:
            db.execute("UPDATE manager_pairs SET expires=0")
    elif change == "logout":
        with scenario.store.connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE id_hash=?", (scenario.session["id_hash"],)
            )
    else:
        setup.manager.browser_intent(
            scenario.session,
            {
                **fields,
                "comparison": pairing["comparison"],
                "binding": scenario.binding.id,
                "password": scenario.password,
                "csrf": csrf,
            },
        )
        scenario.store.optout(scenario.binding.id, scenario.binding.owner)
        _c, _e, status = execute(setup, "status")
        pending = status["pairing"]
        _c, _e, rejected = execute(
            setup,
            "pair_confirm",
            lease=pending["lease"],
            args={"challenge": pending["challenge"], "intent": pending["intent"]},
        )
        assert rejected["state"] == "refused"
        return
    with pytest.raises(ArchiveError):
        setup.manager.browser_intent(
            scenario.session,
            {
                **fields,
                "comparison": pairing["comparison"],
                "binding": scenario.binding.id,
                "password": scenario.password,
                "csrf": csrf,
            },
        )


def test_refusal_and_serial_checkpoint_commit_together(setup):
    assert (
        setup.manager.db.ingest(setup.instance, 1, {"type": "archive-manager-response"})
        == "manager_response_ignored"
    )
    assert setup.manager.db.ingest(setup.instance, 3, {}) == "gap"
    with setup.scenario.store.connect() as db:
        assert setup.manager.db.instance(setup.instance, db)["serial"] == 1
    assert setup.manager.db.ingest(setup.instance, 2, {}) == "manager_command_invalid"
    with setup.scenario.store.connect() as db:
        assert setup.manager.db.instance(setup.instance, db)["serial"] == 2


@pytest.mark.parametrize("action", ["pause", "resume"])
def test_desired_state_repeated_action_preserves_archive_generation_and_credentials(
    setup, action
):
    status = pair(setup)
    if action == "pause":
        binding = status["bindings"][0]
        _c, _e, status = execute(
            setup,
            "pause",
            binding=binding,
            lease=status["leases"][binding["binding"]]["pause"],
        )
    before = setup.scenario.store.get(setup.scenario.binding.id)
    binding = status["bindings"][0]
    _c, _e, document = execute(
        setup,
        action,
        binding=binding,
        lease=status["leases"][binding["binding"]][action],
    )
    assert document["result"] == "confirmed"
    assert setup.scenario.store.get(before.id) == before
    assert document["bindings"][0]["generation"] == before.generation


def test_actual_worker_idle_scan_never_advances_remote_verification_status(
    setup, monkeypatch
):
    pair(setup)
    captured = setup.scenario.capture()
    _c, _e, first = execute(setup, "status")
    initial = first["bindings"][0]
    assert initial["verified_files"] == 1
    assert initial["last_verified"] == int(captured["updated"])
    future = time.time() + 300
    monkeypatch.setattr(time, "time", lambda: future)
    unchanged = setup.scenario.store.enqueue(setup.scenario.binding.id)
    setup.scenario.worker.run(unchanged)
    row = setup.scenario.store.job(unchanged)
    assert row["state"] == "verified" and row["size"] == 0 and row["file_id"] is None
    _c, _e, second = execute(setup, "status")
    current = second["bindings"][0]
    assert current["verified_files"] == initial["verified_files"]
    assert current["last_verified"] == initial["last_verified"]
    assert unchanged not in [job["job"] for job in current["jobs"]]
