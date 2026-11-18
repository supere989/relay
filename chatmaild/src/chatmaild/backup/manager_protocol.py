"""Bounded Archive Manager wire contracts; parsing never grants authority.

The backend must independently authorize the protected chat, key contact,
profile epoch, registered outgoing app, linked owner and action lease. Webxdc
payloads do not authenticate their sender. Signed documents cover exact UTF-8
bytes, not a second language's idea of canonical JSON.
"""

import base64
import binascii
import json
import re
from urllib.parse import urlsplit

from .model import ArchiveError

VERSION = 1
COMMAND_TYPE = "archive-manager-command"
RESPONSE_TYPE = "archive-manager-response"
DOMAIN = b"chatmail-archive-manager-response/v1\0"
MAX_COMMAND = 4096
MAX_RESPONSE = 22000
MAX_WIRE = 32768
MAX_BINDINGS = 16
MAX_JOBS = 8
MAX_TTL = 600
MAX_SAFE_INT = 9007199254740991
ACTIONS = frozenset(
    (
        "status",
        "refresh",
        "pause",
        "resume",
        "retry",
        "reconnect",
        "recovery",
        "unlink",
        "pair_start",
        "pair_confirm",
    )
)
READ_ACTIONS = frozenset(("status", "refresh", "pair_start"))
OPAQUE = re.compile(r"[0-9a-f]{32}\Z")
CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,192}\Z")
CONSENTS = frozenset(
    ("pending", "active", "declined", "revoked", "paused", "opted-out", "expired")
)
JOB_STATES = frozenset(
    (
        "queued",
        "prepared",
        "uploading",
        "uploaded-unverified",
        "verified",
        "incomplete",
        "failed",
        "uncertain",
        "paused",
    )
)


def reject(reason="manager_protocol_invalid"):
    raise ArchiveError(reason)


def _keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        reject()


def _choice(value, choices):
    return type(value) is str and value in choices


def _integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INT:
        reject()


def _opaque(value, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not OPAQUE.fullmatch(value):
        reject()


def _text(value, maximum=160):
    if (
        type(value) is not str
        or not value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        reject()
    try:
        if len(value.encode("utf-8")) > maximum:
            reject()
    except UnicodeError:
        reject()


def _code(value):
    if value is not None and (type(value) is not str or not CODE.fullmatch(value)):
        reject()


def _token(value, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not str or not TOKEN.fullmatch(value):
        reject()


def portal_url(value, origin=None, *, origin_only=False):
    _text(value, 2048)
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        reject()
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "\\" in value
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        reject("manager_portal_url_invalid")
    authority = "https://" + parsed.netloc
    if origin_only and (
        parsed.path not in ("", "/") or parsed.query or value != authority
    ):
        reject("manager_portal_url_invalid")
    if origin is not None and authority != origin:
        reject("manager_portal_origin_mismatch")
    return value


def b64encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value, maximum, exact=None):
    if (
        type(value) is not str
        or not value
        or len(value) > (maximum * 4 + 2) // 3
        or not re.fullmatch(r"[A-Za-z0-9_-]+", value)
    ):
        reject()
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error):
        reject()
    if (
        len(decoded) > maximum
        or exact is not None
        and len(decoded) != exact
        or b64encode(decoded) != value
    ):
        reject()
    return decoded


def decode_json(raw, maximum):
    if type(raw) is str:
        try:
            raw = raw.encode("utf-8")
        except UnicodeError:
            reject()
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        reject("manager_protocol_size")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result or key in ("__proto__", "constructor", "prototype"):
                reject()
            result[key] = value
        return result

    def invalid(_value):
        reject()

    try:
        result = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=invalid,
            parse_float=invalid,
        )
    except (ValueError, UnicodeError, RecursionError):
        reject()
    return result


def encode_json(value, maximum):
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        reject()
    # Also reject JSON floats, unsafe keys and accidental non-JSON inputs.
    decode_json(raw, maximum)
    return raw


def validate_bootstrap(value):
    _keys(
        value, ("version", "instance", "profile_epoch", "public_key", "portal_origin")
    )
    if type(value["version"]) is not int or value["version"] != VERSION:
        reject()
    _opaque(value["instance"])
    _opaque(value["profile_epoch"])
    b64decode(value["public_key"], 32, 32)
    portal_url(value["portal_origin"], origin_only=True)
    return value


def validate_command(raw, *, instance=None):
    value = (
        decode_json(raw, MAX_COMMAND)
        if isinstance(raw, (str, bytes))
        else decode_json(encode_json(raw, MAX_COMMAND), MAX_COMMAND)
    )
    _keys(
        value,
        (
            "version",
            "type",
            "instance",
            "id",
            "action",
            "binding",
            "link_revision",
            "generation",
            "lease",
            "args",
        ),
    )
    if (
        type(value["version"]) is not int
        or value["version"] != VERSION
        or value["type"] != COMMAND_TYPE
        or not _choice(value["action"], ACTIONS)
    ):
        reject()
    _opaque(value["instance"])
    _opaque(value["id"])
    _opaque(value["binding"], True)
    _integer(value["link_revision"])
    _integer(value["generation"])
    if instance is not None and value["instance"] != instance:
        reject("manager_instance_mismatch")
    action = value["action"]
    _token(value["lease"], action in READ_ACTIONS)
    if action == "pair_confirm":
        _keys(value["args"], ("challenge", "intent"))
        _opaque(value["args"]["challenge"])
        _opaque(value["args"]["intent"])
    elif action == "retry":
        _keys(value["args"], ("job",))
        _opaque(value["args"]["job"])
    else:
        _keys(value["args"], ())
    if action in ("pair_start", "pair_confirm"):
        if (
            value["binding"] is not None
            or value["generation"] != 0
            or value["link_revision"] != 0
        ):
            reject()
    elif action not in READ_ACTIONS and value["binding"] is None:
        reject()
    return value


def validate_document(value, *, portal_origin=None):
    _keys(
        value,
        (
            "version",
            "instance",
            "profile_epoch",
            "command_id",
            "revision",
            "issued_at",
            "expires_at",
            "state",
            "result",
            "code",
            "action",
            "bindings",
            "leases",
            "pairing",
            "handoff",
        ),
    )
    if (
        type(value["version"]) is not int
        or value["version"] != VERSION
        or not _choice(value["state"], ("unlinked", "pairing", "linked", "refused"))
        or not _choice(value["result"], ("snapshot", "queued", "confirmed", "rejected"))
    ):
        reject()
    for name in ("instance", "profile_epoch"):
        _opaque(value[name])
    _opaque(value["command_id"], True)
    for name in ("revision", "issued_at", "expires_at"):
        _integer(value[name])
    if not 0 < value["expires_at"] - value["issued_at"] <= MAX_TTL:
        reject()
    _code(value["code"])
    if value["action"] is not None and not _choice(value["action"], ACTIONS):
        reject()
    if (
        type(value["bindings"]) is not list
        or len(value["bindings"]) > MAX_BINDINGS
        or type(value["leases"]) is not dict
    ):
        reject()
    handles = set()
    for binding in value["bindings"]:
        _keys(
            binding,
            (
                "binding",
                "label",
                "state",
                "enabled",
                "generation",
                "link_revision",
                "unresolved",
                "held_unresolved",
                "eligible_unresolved",
                "last_verified",
                "jobs",
                "jobs_omitted",
                "queued_jobs",
                "verified_files",
                "coverage",
            ),
        )
        _opaque(binding["binding"])
        if binding["binding"] in handles:
            reject()
        handles.add(binding["binding"])
        _text(binding["label"])
        if (
            not _choice(binding["state"], CONSENTS)
            or type(binding["enabled"]) is not bool
            or not _choice(
                binding["coverage"], ("capture-windows", "incomplete", "unknown")
            )
        ):
            reject()
        for name in (
            "generation",
            "link_revision",
            "unresolved",
            "held_unresolved",
            "eligible_unresolved",
            "jobs_omitted",
            "queued_jobs",
            "verified_files",
        ):
            _integer(binding[name], 1 if name == "generation" else 0)
        if (
            binding["held_unresolved"] + binding["eligible_unresolved"]
            > binding["unresolved"]
        ):
            reject()
        if binding["eligible_unresolved"] and (
            not binding["enabled"] or binding["state"] != "active"
        ):
            reject()
        if binding["last_verified"] is not None:
            _integer(binding["last_verified"])
        if binding["coverage"] == "capture-windows" and (
            not binding["verified_files"]
            or binding["last_verified"] is None
            or binding["unresolved"]
        ):
            reject()
        if type(binding["jobs"]) is not list or len(binding["jobs"]) > MAX_JOBS:
            reject()
        jobs = set()
        for job in binding["jobs"]:
            _keys(job, ("job", "state", "reason"))
            _opaque(job["job"])
            if job["job"] in jobs or not _choice(job["state"], JOB_STATES):
                reject()
            jobs.add(job["job"])
            _code(job["reason"])
    for handle, leases in value["leases"].items():
        if (
            handle not in handles
            or type(leases) is not dict
            or set(leases) - (ACTIONS - READ_ACTIONS - {"pair_confirm"})
        ):
            reject()
        for lease in leases.values():
            _token(lease)
    pairing = value["pairing"]
    if pairing is not None:
        _keys(
            pairing,
            (
                "phase",
                "url",
                "comparison",
                "challenge",
                "intent",
                "peer_label",
                "lease",
            ),
        )
        if (
            not _choice(
                pairing["phase"], ("open_browser", "confirm_app", "browser_confirm")
            )
            or type(pairing["comparison"]) is not str
            or not re.fullmatch(r"[0-9]{6}", pairing["comparison"])
        ):
            reject()
        portal_url(pairing["url"], portal_origin)
        _opaque(pairing["challenge"])
        _opaque(pairing["intent"], pairing["phase"] != "confirm_app")
        _token(pairing["lease"], pairing["phase"] != "confirm_app")
        _text(pairing["peer_label"])
    handoff = value["handoff"]
    if handoff is not None:
        _keys(handoff, ("action", "url"))
        if not _choice(handoff["action"], ("reconnect", "recovery")):
            reject()
        portal_url(handoff["url"], portal_origin)
    encode_json(value, MAX_RESPONSE)
    return value


def sign_response(document, signer):
    validate_document(document)
    raw = encode_json(document, MAX_RESPONSE)
    signature = (
        signer.sign(DOMAIN + raw) if hasattr(signer, "sign") else signer(DOMAIN + raw)
    )
    if type(signature) is not bytes or len(signature) != 64:
        reject("manager_signature_invalid")
    envelope = {
        "version": VERSION,
        "type": RESPONSE_TYPE,
        "payload": b64encode(raw),
        "signature": b64encode(signature),
    }
    # The transport limit applies to the full status update, not raw JSON or
    # base64 payload alone. Leave headroom for SDK framing above this wrapper.
    encode_json({"payload": envelope}, MAX_WIRE)
    return envelope


def verify_response(
    envelope,
    public_key,
    *,
    instance,
    profile_epoch,
    now,
    min_revision=0,
    portal_origin=None,
):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    encode_json({"payload": envelope}, MAX_WIRE)

    _keys(envelope, ("version", "type", "payload", "signature"))
    if (
        type(envelope["version"]) is not int
        or envelope["version"] != VERSION
        or envelope["type"] != RESPONSE_TYPE
    ):
        reject()
    raw = b64decode(envelope["payload"], MAX_RESPONSE)
    signature = b64decode(envelope["signature"], 64, 64)
    key = b64decode(public_key, 32, 32) if isinstance(public_key, str) else public_key
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, DOMAIN + raw)
    except (InvalidSignature, ValueError, TypeError):
        reject("manager_signature_invalid")
    document = validate_document(
        decode_json(raw, MAX_RESPONSE), portal_origin=portal_origin
    )
    if document["instance"] != instance or document["profile_epoch"] != profile_epoch:
        reject("manager_instance_mismatch")
    if document["expires_at"] <= now or document["issued_at"] > now + 30:
        reject("manager_response_expired")
    if document["revision"] < min_revision:
        reject("manager_response_stale")
    return document
