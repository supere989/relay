"""Prepare a synthetic, public-only packaged UI fixture for browser execution.

The signer exists only in this process. No private key, password, OAuth token,
recovery identity or real recipient is written to a test artifact.
"""

import argparse
import json
import time
import zipfile
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chatmaild.backup.manager_packaging import build_app
from chatmaild.backup.manager_protocol import (
    DOMAIN,
    MAX_RESPONSE,
    RESPONSE_TYPE,
    b64encode,
    encode_json,
    sign_response,
)
from chatmaild.tests.test_manager_protocol import context, document, maximum_document


def sdk_fixture(history=None):
    # This is a test messenger shim served as webxdc.js, never an app asset.
    # A real messenger supplies its own SDK. Deterministic request IDs are
    # restricted to synthetic fixture mode, never the real RPC bridge mode.
    return """\"use strict\";
(function(){
  const query=new URLSearchParams(location.search), sent=[];
  let listener=null, counter=0x33;
  window.__archiveSdk={sent, deliver:function(payload){if(!listener)throw new Error('listener unavailable');listener({payload,serial:sent.length+10,max_serial:sent.length+10});}};
  window.webxdc={sendUpdateInterval:Number(query.get('interval')||20),sendUpdateMaxSize:Number(query.get('maxsize')||128000),
    sendUpdate:function(update){sent.push({payload:update.payload,at:Date.now()});},
    setUpdateListener:function(callback){
      if(listener)throw new Error('listener registered twice');listener=callback;
      if(query.get('fixture')==='1')window.nacl.setPRNG(function(output,n){for(let i=0;i<n;i++)output[i]=counter;counter=(counter+0x11)&255;});
      if(query.get('history')==='1'&&HISTORY)callback({payload:HISTORY,serial:1,max_serial:1});
      return Promise.resolve();
    }};
})();
""".replace("HISTORY", json.dumps(history, separators=(",", ":")))


def prepare(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    signer = Ed25519PrivateKey.generate()
    bootstrap = context(signer)
    app = output / "archive-manager.xdc"
    digest = build_app(bootstrap, app)
    assets = output / "app"
    assets.mkdir()
    with zipfile.ZipFile(app) as archive:
        for name in archive.namelist():
            destination = assets / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(name))
    stamp = int(time.time())

    def state(revision, **changes):
        return document(
            revision=revision, issued_at=stamp, expires_at=stamp + 600, **changes
        )

    initial = state(2)
    first = initial["bindings"][0]
    first["label"] = "Synthetic test mailbox"
    first.update(
        unresolved=2,
        held_unresolved=1,
        eligible_unresolved=1,
        jobs_omitted=3,
        coverage="incomplete",
    )
    first["last_verified"] = stamp - 60
    first["jobs"] = [{"job": "6" * 32, "state": "failed", "reason": "source_changed"}]
    initial["leases"]["4" * 32] = dict.fromkeys(
        ("pause", "resume", "retry", "reconnect", "recovery", "unlink"), "p" * 43
    )
    second = deepcopy(first)
    second.update(binding="5" * 32, label="Another synthetic mailbox")
    initial["bindings"].append(second)
    initial["leases"]["5" * 32] = dict(initial["leases"]["4" * 32])
    queued = deepcopy(initial)
    queued.update(revision=3, command_id="4" * 32, result="queued", action="pause")
    queued["bindings"][0]["queued_jobs"] = 1
    confirmed = deepcopy(initial)
    confirmed.update(
        revision=4, command_id="4" * 32, result="confirmed", action="pause"
    )
    confirmed["bindings"][0].update(
        enabled=False,
        state="opted-out",
        generation=2,
        link_revision=3,
        eligible_unresolved=0,
    )
    history = deepcopy(confirmed)
    history.update(revision=1, command_id="4" * 32)
    expired = deepcopy(initial)
    expired.update(revision=90, issued_at=stamp - 120, expires_at=stamp - 1)
    pairing = state(
        10,
        state="pairing",
        bindings=[],
        leases={},
        pairing={
            "phase": "open_browser",
            "url": bootstrap["portal_origin"]
            + "/archive/manager-pair?challenge="
            + "7" * 32,
            "comparison": "628194",
            "challenge": "7" * 32,
            "intent": None,
            "peer_label": "Verified synthetic archive service",
            "lease": None,
        },
    )
    intent = deepcopy(pairing)
    intent["revision"] = 11
    intent["command_id"] = "4" * 32
    intent["pairing"].update(phase="confirm_app", intent="8" * 32, lease="c" * 43)
    lost_pair_url = deepcopy(pairing)
    lost_pair_url.update(command_id="5" * 32, action="refresh")
    lost_pair_intent = deepcopy(intent)
    lost_pair_intent.update(command_id="6" * 32, action="refresh")
    fixtures = {
        name: sign_response(value, signer)
        for name, value in (
            ("snapshot", initial),
            ("queued", queued),
            ("confirmed", confirmed),
            ("history", history),
            ("expired", expired),
            ("pairing", pairing),
            ("intent", intent),
            ("lost_pair_url", lost_pair_url),
            ("lost_pair_intent", lost_pair_intent),
        )
    }
    forged = deepcopy(fixtures["confirmed"])
    altered = deepcopy(confirmed)
    altered["bindings"][0].update(state="active", enabled=True, verified_files=999)
    forged["payload"] = b64encode(encode_json(altered, MAX_RESPONSE))
    fixtures["forged"] = forged
    fixtures["wrong_instance"] = sign_response(
        {**initial, "revision": 100, "instance": "f" * 32}, signer
    )
    replay = deepcopy(initial)
    replay.update(revision=8, command_id="9" * 32)
    fixtures["unmatched_replay"] = sign_response(replay, signer)
    off = deepcopy(confirmed)
    off.update(revision=2, command_id="3" * 32, result="snapshot", action="status")
    fixtures["off_snapshot"] = sign_response(off, signer)
    unknown = deepcopy(initial)
    unknown["bindings"][0].update(
        verified_files=0,
        last_verified=None,
        coverage="unknown",
        unresolved=0,
        held_unresolved=0,
        eligible_unresolved=0,
        jobs=[],
        jobs_omitted=0,
    )
    fixtures["unknown_snapshot"] = sign_response(unknown, signer)
    too_large = encode_json(initial, MAX_RESPONSE)
    too_large += b" " * (MAX_RESPONSE + 1 - len(too_large))
    fixtures["raw_over_budget"] = {
        "version": 1,
        "type": RESPONSE_TYPE,
        "payload": b64encode(too_large),
        "signature": b64encode(signer.sign(DOMAIN + too_large)),
    }
    from chatmaild.backup.manager import fit_document

    maximum = maximum_document("\U0001f5c3" * 40)
    maximum.update(issued_at=stamp, expires_at=stamp + 600)
    dropped = fit_document(maximum)
    fixtures["maximum_snapshot"] = sign_response(maximum, signer)
    fixtures["maximum_jobs_omitted"] = dropped
    # Fixed signed server time plus a controlled browser clock make lost-ack
    # tests independent of test-container startup/crypto timing. Only the
    # fixture=1 messenger shim uses the deterministic request-ID sequence.
    lost_start = deepcopy(initial)
    lost_start.update(issued_at=stamp - 100, expires_at=stamp + 20)
    lost_fresh = deepcopy(initial)
    lost_fresh.update(
        revision=4,
        command_id="5" * 32,
        action="refresh",
        issued_at=stamp + 25,
        expires_at=stamp + 300,
    )
    still_applicable = deepcopy(lost_fresh)
    still_applicable.update(issued_at=stamp + 10)
    advanced = deepcopy(still_applicable)
    advanced["bindings"][0].update(generation=2, link_revision=3)
    absent = deepcopy(still_applicable)
    absent["bindings"] = absent["bindings"][1:]
    absent["leases"].pop("4" * 32)
    boundary = deepcopy(still_applicable)
    boundary["issued_at"] = lost_start["expires_at"] + 1
    late = deepcopy(confirmed)
    late.update(revision=5, issued_at=stamp + 26, expires_at=stamp + 300)
    unmatched = deepcopy(lost_fresh)
    unmatched.update(revision=3, command_id="9" * 32)
    historical = deepcopy(lost_fresh)
    historical.update(revision=1, command_id="4" * 32)
    queued_lost = deepcopy(lost_start)
    queued_lost.update(revision=3, command_id="4" * 32, result="queued", action="pause")
    queued_lost["bindings"][0]["queued_jobs"] = 1
    generation = deepcopy(still_applicable)
    generation["bindings"][0]["generation"] = 2
    revision = deepcopy(still_applicable)
    revision["bindings"][0]["link_revision"] = 3
    followup = deepcopy(lost_fresh)
    followup.update(revision=6, command_id="6" * 32)
    for name, value in (
        ("lost_start", lost_start),
        ("lost_fresh", lost_fresh),
        ("lost_applicable", still_applicable),
        ("lost_advanced", advanced),
        ("lost_absent", absent),
        ("lost_boundary", boundary),
        ("lost_late", late),
        ("lost_unmatched", unmatched),
        ("lost_history", historical),
        ("lost_queued", queued_lost),
        ("lost_generation", generation),
        ("lost_revision", revision),
        ("lost_followup", followup),
    ):
        fixtures[name] = sign_response(value, signer)
    fixtures["fixture_stamp"] = stamp
    fixtures["context"] = bootstrap
    fixtures["app_sha256"] = digest
    (output / "fixtures.json").write_text(json.dumps(fixtures, sort_keys=True))
    (assets / "webxdc.js").write_text(sdk_fixture(fixtures["history"]))
    return {"state": "prepared", "app_sha256": digest, "private_keys_written": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", required=True, help="New task-only artifact directory"
    )
    args = parser.parse_args()
    print(json.dumps(prepare(args.output), sort_keys=True))
