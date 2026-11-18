"""Owned-process failures cannot strand futures or fabricate successful replies."""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from chatmaild.backup import manager_transport as transport
from chatmaild.backup.manager_profile import Profile
from chatmaild.backup.model import ArchiveError
from chatmaild.tests.test_manager_backend import execute, pair
from chatmaild.tests.test_manager_backend import setup as manager_setup


def ready(pipe, profile):
    os.setsid()
    Path(profile, "accounts", "accounts.toml").write_text(
        "# synthetic supervisor fixture\n"
    )
    transport.write_private_frame(pipe, {"ok": True, "value": None})


def exit_before_start(pipe, profile, _server, _checksum, _initialize):
    os.setsid()
    os._exit(31)


def exit_pending(pipe, profile, _server, _checksum, _initialize):
    ready(pipe, profile)
    transport.read_private_frame(pipe, 65536)
    os._exit(32)


def stalled(pipe, profile, _server, _checksum, _initialize):
    ready(pipe, profile)
    transport.read_private_frame(pipe, 65536)
    while True:
        time.sleep(1)


def malformed(pipe, profile, _server, _checksum, _initialize):
    ready(pipe, profile)
    transport.read_private_frame(pipe, 65536)
    transport.write_private_frame(pipe, {"ok": "not-a-bool", "value": None})
    while True:
        time.sleep(1)


def oversized(pipe, profile, _server, _checksum, _initialize):
    ready(pipe, profile)
    transport.read_private_frame(pipe, 65536)
    pipe.send_bytes(b"x" * (transport.MAX_IPC + 1))
    while True:
        time.sleep(1)


def watched_sdk_child_exit(pipe, profile, _server, _checksum, _initialize):
    ready(pipe, profile)
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            "import sys;sys.stdin.buffer.read(1);raise SystemExit(17)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    sdk = transport.SDK.__new__(transport.SDK)
    sdk.rpc = SimpleNamespace(process=process)
    sdk.stopped = threading.Event()
    sdk.started = threading.Event()
    sdk.started.set()
    threading.Thread(target=sdk._watch_owned_process, daemon=True).start()
    transport.read_private_frame(pipe, 65536)
    process.stdin.write(b"x")
    process.stdin.flush()
    # Simulate an SDK Future that never wakes despite the actual child exit.
    while True:
        time.sleep(1)


@pytest.fixture
def profile(tmp_path):
    path = tmp_path / "profile"
    path.mkdir(mode=0o700)
    result = Profile(path, synthetic=True)
    result.initialize()
    return result


def test_exit_before_start_is_prompt_and_reaped(profile, monkeypatch):
    monkeypatch.setattr(transport, "child", exit_before_start)
    adapter = transport.Transport(
        profile, "/unused", "0" * 64, timeout=3, initialize=True
    )
    started = time.monotonic()
    with pytest.raises(ArchiveError, match="manager_transport_child_exit"):
        adapter.start()
    assert time.monotonic() - started < 1.5
    assert adapter.process is None and adapter.pipe is None


@pytest.mark.parametrize(
    "worker,reason",
    [
        (exit_pending, "manager_transport_child_exit"),
        (watched_sdk_child_exit, "manager_transport_child_exit"),
        (stalled, "manager_transport_stall"),
        (malformed, "manager_transport_response_invalid"),
        (oversized, "manager_transport_response_invalid"),
    ],
)
def test_pending_request_failure_is_not_acknowledged_and_worker_is_reaped(
    profile, monkeypatch, worker, reason
):
    monkeypatch.setattr(transport, "child", worker)
    adapter = transport.Transport(
        profile, "/unused", "0" * 64, timeout=0.5, initialize=True
    )
    adapter.start()
    process = adapter.process
    started = time.monotonic()
    with pytest.raises(ArchiveError, match=reason):
        adapter.call("self_key", 1)
    assert time.monotonic() - started < 2
    assert process.exitcode is not None
    assert adapter.process is None and adapter.pipe is None


def test_normal_restart_refuses_missing_account_index_without_recreation(
    profile, monkeypatch
):
    monkeypatch.setattr(transport, "child", exit_before_start)
    adapter = transport.Transport(profile, "/unused", "0" * 64)
    with pytest.raises(ArchiveError, match="manager_rpc_account_state_missing"):
        adapter.start()
    assert not (profile.mount / "accounts" / "accounts.toml").exists()
    assert adapter.process is None


def test_concurrent_waiters_fail_bounded_after_dead_worker(profile, monkeypatch):
    monkeypatch.setattr(transport, "child", exit_pending)
    adapter = transport.Transport(
        profile, "/unused", "0" * 64, timeout=0.5, initialize=True
    )
    adapter.start()
    failures = []

    def request():
        try:
            adapter.call("self_key", 1)
        except ArchiveError as exc:
            failures.append(exc.reason)

    threads = [threading.Thread(target=request) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(3)
        assert not thread.is_alive()
    adapter.close()
    assert len(failures) == 4
    assert all(
        reason in ("manager_transport_child_exit", "manager_transport_stall")
        for reason in failures
    )


def test_restart_replays_terminal_result_without_reapplying_mutation(tmp_path):
    context = manager_setup.__wrapped__(tmp_path)
    status = pair(context)
    binding = status["bindings"][0]
    command, envelope, _ack = execute(
        context,
        "pause",
        binding=binding,
        lease=status["leases"][binding["binding"]]["pause"],
    )
    before = context.scenario.store.get(context.scenario.binding.id)
    from chatmaild.backup.manager import Manager

    restarted = Manager(
        context.scenario.store,
        context.scenario.config,
        context.transport,
        context.signer,
        context.manager.profile,
        context.manager.origin,
    )
    assert restarted.process(context.instance, command["id"]) == envelope
    assert context.scenario.store.get(before.id) == before


def test_delayed_status_cannot_publish_active_snapshot_after_portal_optout(tmp_path):
    context = manager_setup.__wrapped__(tmp_path)
    pair(context)
    original = context.manager.attest
    calls = []

    def delayed(instance):
        result = original(instance)
        calls.append(True)
        if len(calls) == 2:
            context.scenario.store.optout(
                context.scenario.binding.id, context.scenario.binding.owner
            )
        return result

    context.manager.attest = delayed
    _command, _envelope, document = execute(context, "status")
    assert (
        document["state"] == "refused"
        and document["bindings"] == []
        and document["leases"] == {}
    )
    assert not context.scenario.store.get(context.scenario.binding.id).enabled
