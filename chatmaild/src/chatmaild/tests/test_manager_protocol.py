"""Pure signing/schema tests. All identities and state are synthetic."""

import json
import secrets
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chatmaild.backup import manager_protocol as protocol
from chatmaild.backup.model import ArchiveError


def public_key(signer):
    return protocol.b64encode(
        signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )


def context(signer):
    return {
        "version": 1,
        "instance": "1" * 32,
        "profile_epoch": "2" * 32,
        "public_key": public_key(signer),
        "portal_origin": "https://archive.example.test",
    }


def document(**changes):
    value = {
        "version": 1,
        "instance": "1" * 32,
        "profile_epoch": "2" * 32,
        "command_id": "3" * 32,
        "revision": 2,
        "issued_at": 1000,
        "expires_at": 1300,
        "state": "linked",
        "result": "snapshot",
        "code": None,
        "action": "status",
        "bindings": [
            {
                "binding": "4" * 32,
                "label": "owner@example.test",
                "state": "active",
                "enabled": True,
                "generation": 1,
                "link_revision": 2,
                "unresolved": 0,
                "held_unresolved": 0,
                "eligible_unresolved": 0,
                "last_verified": 999,
                "jobs": [],
                "jobs_omitted": 0,
                "queued_jobs": 0,
                "verified_files": 2,
                "coverage": "capture-windows",
            }
        ],
        "leases": {"4" * 32: {"pause": "p" * 43}},
        "pairing": None,
        "handoff": None,
    }
    value.update(changes)
    return value


def maximum_document(label="x" * 160):
    """Real generated lease lengths and real archive reasons at every limit."""
    value = document(bindings=[], leases={})
    reasons = (
        "source_changed",
        "source_not_regular",
        "source_message_limit",
        "source_unavailable",
        "source_folder_limit",
        "source_folder_unavailable",
        "unsafe_message_path",
        "source_batch_limit",
    )
    for index in range(protocol.MAX_BINDINGS):
        binding = deepcopy(document()["bindings"][0])
        handle = f"{index + 1:032x}"
        binding.update(
            binding=handle,
            label=label,
            unresolved=8,
            held_unresolved=4,
            eligible_unresolved=4,
            coverage="incomplete",
            jobs=[
                {
                    "job": f"{index * 8 + number + 100:032x}",
                    "state": "failed",
                    "reason": reason,
                }
                for number, reason in enumerate(reasons)
            ],
        )
        value["bindings"].append(binding)
        value["leases"][handle] = {
            action: secrets.token_urlsafe(24)
            for action in (
                "pause",
                "resume",
                "retry",
                "reconnect",
                "recovery",
                "unlink",
            )
        }
    return value


def command(action="pause", **changes):
    value = {
        "version": 1,
        "type": protocol.COMMAND_TYPE,
        "instance": "1" * 32,
        "id": "3" * 32,
        "action": action,
        "binding": "4" * 32,
        "link_revision": 2,
        "generation": 1,
        "lease": "p" * 43,
        "args": {},
    }
    value.update(changes)
    return value


def verify(envelope, signer, **changes):
    kwargs = {
        "instance": "1" * 32,
        "profile_epoch": "2" * 32,
        "now": 1100,
        "min_revision": 0,
        "portal_origin": "https://archive.example.test",
    }
    kwargs.update(changes)
    return protocol.verify_response(envelope, public_key(signer), **kwargs)


def test_exact_signed_response_and_duplicate_verification_are_deterministic():
    signer = Ed25519PrivateKey.generate()
    envelope = protocol.sign_response(document(), signer)
    assert verify(envelope, signer) == document()
    assert envelope == protocol.sign_response(document(), signer)
    assert verify(envelope, signer) == verify(envelope, signer)
    assert protocol.validate_bootstrap(context(signer)) == context(signer)


@pytest.mark.parametrize(
    "change",
    [
        "signature",
        "payload",
        "key",
        "instance",
        "epoch",
        "expired",
        "future",
        "revision",
    ],
)
def test_signature_context_clock_and_revision_fail_closed(change):
    signer = Ed25519PrivateKey.generate()
    envelope = protocol.sign_response(document(), signer)
    kwargs = {}
    if change == "signature":
        envelope["signature"] = protocol.b64encode(b"\x00" * 64)
    elif change == "payload":
        altered = document(result="confirmed")
        envelope["payload"] = protocol.b64encode(
            protocol.encode_json(altered, protocol.MAX_RESPONSE)
        )
    elif change == "key":
        signer = Ed25519PrivateKey.generate()
    elif change == "instance":
        kwargs["instance"] = "5" * 32
    elif change == "epoch":
        kwargs["profile_epoch"] = "5" * 32
    elif change == "expired":
        kwargs["now"] = 1300
    elif change == "future":
        kwargs["now"] = 900
    else:
        kwargs["min_revision"] = 3
    with pytest.raises(ArchiveError):
        verify(envelope, signer, **kwargs)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"version":1,"version":1}',
        b'{"__proto__":{}}',
        b'{"constructor":{}}',
        b'{"v":1.0}',
        b'{"v":NaN}',
        b"\xff",
        b"[" * 10000,
    ],
)
def test_safe_json_rejects_duplicate_unsafe_numeric_utf8_and_deep_inputs(raw):
    with pytest.raises(ArchiveError):
        protocol.decode_json(raw, protocol.MAX_COMMAND)


def test_signed_duplicate_json_cannot_hide_a_different_state():
    signer = Ed25519PrivateKey.generate()
    raw = protocol.encode_json(document(), protocol.MAX_RESPONSE)
    raw = raw[:-1] + b',"result":"confirmed"}'
    envelope = {
        "version": 1,
        "type": protocol.RESPONSE_TYPE,
        "payload": protocol.b64encode(raw),
        "signature": protocol.b64encode(signer.sign(protocol.DOMAIN + raw)),
    }
    with pytest.raises(ArchiveError):
        verify(envelope, signer)


@pytest.mark.parametrize("action", ["status", "refresh", "pair_start"])
def test_only_read_or_initial_pair_requests_allow_explicit_null_lease(action):
    value = command(action, binding=None, link_revision=0, generation=0, lease=None)
    assert protocol.validate_command(value) == value


@pytest.mark.parametrize(
    "action",
    ["pause", "resume", "retry", "reconnect", "recovery", "unlink", "pair_confirm"],
)
def test_mutation_and_pair_confirmation_require_a_lease(action):
    args = (
        {"job": "6" * 32}
        if action == "retry"
        else {"challenge": "6" * 32, "intent": "7" * 32}
        if action == "pair_confirm"
        else {}
    )
    value = command(action, lease=None, args=args)
    if action == "pair_confirm":
        value.update(binding=None, link_revision=0, generation=0)
    with pytest.raises(ArchiveError):
        protocol.validate_command(value)
    value["lease"] = "p" * 43
    assert protocol.validate_command(value) == value


@pytest.mark.parametrize(
    "changes",
    [
        {"sender": "owner"},
        {"role": "bot"},
        {"selfAddr": "owner@example.test"},
        {"args": {"password": "forbidden"}},
        {"action": []},
        {"generation": True},
        {"link_revision": 2**54},
        {"instance": "wrong"},
    ],
)
def test_command_rejects_authority_claims_unexpected_data_and_wrong_types(changes):
    with pytest.raises(ArchiveError):
        protocol.validate_command(command(**changes))


def test_response_transport_and_document_are_exact_bounded_schemas():
    signer = Ed25519PrivateKey.generate()
    for value in (
        document(leases={"9" * 32: {"pause": "p" * 43}}),
        document(expires_at=1700),
        document(state=[]),
    ):
        with pytest.raises(ArchiveError):
            protocol.sign_response(value, signer)
    value = deepcopy(document())
    value["bindings"][0]["jobs"] = [
        {"job": "6" * 32, "state": "failed", "reason": "source_changed"}
    ] * 9
    with pytest.raises(ArchiveError):
        protocol.sign_response(value, signer)
    envelope = protocol.sign_response(document(), signer)
    envelope["sender"] = "bot"
    with pytest.raises(ArchiveError):
        verify(envelope, signer)


@pytest.mark.parametrize(
    "url",
    [
        "http://archive.example.test/archive",
        "https://evil.example/archive",
        "https://user@archive.example.test/archive",
        "https://archive.example.test/archive#secret",
    ],
)
def test_handoffs_cannot_escape_the_pinned_https_origin(url):
    value = document(handoff={"action": "recovery", "url": url})
    with pytest.raises(ArchiveError):
        protocol.validate_document(value, portal_origin="https://archive.example.test")


def test_exact_bytes_are_verified_without_python_javascript_canonicalization():
    signer = Ed25519PrivateKey.generate()
    raw = json.dumps(document(), indent=2).encode()
    envelope = {
        "version": 1,
        "type": protocol.RESPONSE_TYPE,
        "payload": protocol.b64encode(raw),
        "signature": protocol.b64encode(signer.sign(protocol.DOMAIN + raw)),
    }
    assert verify(envelope, signer) == document()


def test_raw_response_ceiling_leaves_whole_update_framing_headroom():
    signer = Ed25519PrivateKey.generate()
    canonical = protocol.encode_json(document(), protocol.MAX_RESPONSE)
    raw = canonical + b" " * (protocol.MAX_RESPONSE - len(canonical))
    envelope = {
        "version": 1,
        "type": protocol.RESPONSE_TYPE,
        "payload": protocol.b64encode(raw),
        "signature": protocol.b64encode(signer.sign(protocol.DOMAIN + raw)),
    }
    wire = protocol.encode_json(
        {
            "payload": envelope,
            "info": "x" * 50,
            "summary": "x" * 20,
            "href": "index.html",
        },
        protocol.MAX_WIRE,
    )
    assert len(raw) == 22000
    assert len(wire) < protocol.MAX_WIRE - 2000
    assert verify(envelope, signer) == document()
    oversized = raw + b" "
    envelope["payload"] = protocol.b64encode(oversized)
    envelope["signature"] = protocol.b64encode(signer.sign(protocol.DOMAIN + oversized))
    with pytest.raises(ArchiveError):
        verify(envelope, signer)


@pytest.mark.parametrize("label", ["x" * 160, "\U0001f5c3" * 40])
def test_actual_maximum_state_fits_without_losing_any_mailbox_or_control(label):
    from chatmaild.backup.manager import fit_document

    signer = Ed25519PrivateKey.generate()
    original = maximum_document(label)
    for index, binding in enumerate(original["bindings"]):
        binding["jobs_omitted"] = index
    assert len(protocol.encode_json(original, 1024 * 1024)) > protocol.MAX_RESPONSE
    first, second = deepcopy(original), deepcopy(original)
    dropped = fit_document(first)
    assert dropped > 0
    assert fit_document(second) == dropped
    assert first == second
    assert len(first["bindings"]) == 16
    assert first["leases"] == original["leases"]
    assert all(
        len(token) == 32
        for leases in first["leases"].values()
        for token in leases.values()
    )
    for source, fitted in zip(original["bindings"], first["bindings"], strict=True):
        assert {
            key: value
            for key, value in source.items()
            if key not in ("jobs", "jobs_omitted")
        } == {
            key: value
            for key, value in fitted.items()
            if key not in ("jobs", "jobs_omitted")
        }
        assert fitted["jobs"] == source["jobs"][: len(fitted["jobs"])]
        assert fitted["jobs_omitted"] == source["jobs_omitted"] + len(
            source["jobs"]
        ) - len(fitted["jobs"])
    assert (
        sum(len(binding["jobs"]) for binding in first["bindings"]) + dropped == 16 * 8
    )
    envelope = protocol.sign_response(first, signer)
    assert (
        len(protocol.encode_json({"payload": envelope}, protocol.MAX_WIRE))
        < protocol.MAX_WIRE
    )
    assert verify(envelope, signer) == first


@pytest.mark.parametrize(
    "change",
    [
        "missing_held",
        "held_over_total",
        "eligible_over_total",
        "disabled_eligible",
        "inactive_eligible",
        "negative_omitted",
        "false_verified_coverage",
    ],
)
def test_retry_coverage_and_omission_metadata_are_strict(change):
    value = document()
    binding = value["bindings"][0]
    if change == "missing_held":
        binding.pop("held_unresolved")
    elif change == "held_over_total":
        binding["held_unresolved"] = 1
    elif change == "eligible_over_total":
        binding["eligible_unresolved"] = 1
    elif change in ("disabled_eligible", "inactive_eligible"):
        binding.update(unresolved=1, eligible_unresolved=1, coverage="incomplete")
        if change == "disabled_eligible":
            binding["enabled"] = False
        else:
            binding["state"] = "revoked"
    elif change == "negative_omitted":
        binding["jobs_omitted"] = -1
    else:
        binding.update(verified_files=0, last_verified=None)
    with pytest.raises(ArchiveError):
        protocol.sign_response(value, Ed25519PrivateKey.generate())
