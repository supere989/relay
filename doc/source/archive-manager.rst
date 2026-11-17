Archive Manager in Delta Chat
=============================

Archive Manager is an optional service conversation for ordinary Delta Chat
clients with Webxdc support. It does not modify a client fork or native Settings.
The service issues a private-chat app showing explicitly linked personal
mailboxes, Drive consent, recent verified results, pending work and incomplete
coverage. It delegates to the existing archive worker; it does not upload from
the app or import server archives into a Delta Chat profile.

No bot account, invitation, service, Google destination or real recipient is
activated by this source change. The normal archive browser portal remains
available independently. See :doc:`drive-archive` for consent, capture, private
recovery and the existing separate operator archive mode.
The separate :doc:`archive-manager-operations` guide owns encrypted-state
enrollment, attestation, configuration and runtime activation commands; the
public packager described here does not replace those operator steps.

Owner onboarding and controls
-----------------------------

Start in the separately configured archive service's accepted, protected private
conversation and complete its SecureJoin verification. Use the app actually
issued there by the bot. A forwarded file or a matching display name does not
register another conversation or give it mailbox authority. The backend checks
the protected Single chat, pinned key contact/public key, profile epoch and exact
bot-originated outgoing app instance for every request. App ``role``, sender
claims, ``selfAddr``, ``isAppSender`` and ``isBroadcast`` are never authority.

Choose **Connect mailbox**. The signed app snapshot supplies an HTTPS portal
link and a separate comparison code. Open the link deliberately and check the
full portal address. In the browser, sign in as the verified Google owner,
provide fresh proof of an existing mailbox password, explicitly select a
personal binding and check the displayed peer/key identity. Compare the code
with the private app. Then confirm the signed browser intent in the app and
finish with the browser's final confirmation. Operator bindings are excluded.
Refresh the app after making the browser selection so that its intent is a
signed response to this session's current request.

A forwarded portal link alone cannot finish pairing. Keep the comparison
channel private; deliberately forwarding both the private app/channel and its
browser context can still enable phishing. Pairing does not replace the user's
responsibility to check the actual service identity and portal address.

Each mailbox link is explicit. Select a linked mailbox to refresh its signed
status, turn future archiving off, resume, obtain a Drive reconnect handoff or
retry bounded recent work. Off, pause and unlink do not delete existing Drive
files. Unlink removes this conversation's authority to that mailbox. Google
consent, fresh mailbox passwords and private recovery downloads stay in the
secure browser portal; never send them in chat or put them into app updates.

The app distinguishes these outcomes:

* **Sending / waiting for the bot:** the messaging API was called; neither
  server persistence nor a committed archive change has been acknowledged.
* **Queued:** a matching signed server response accepted the request into its
  persisted work. This is not a verified Drive file.
* **Confirmed:** a matching signed response reports the facade's committed
  change. A later background upload can still be pending or incomplete.
* **Verified:** the archive service's separate worker downloaded and verified
  that file. It does not establish complete mailbox coverage.

Before the first verified remote receipt, zero unresolved entries still means
**no verified archive yet**, not verified coverage. Message retries waiting for
another eligible attempt are shown separately from retries held for manual
action. Off or inactive-consent bindings do not advertise those entries as
eligible automatic work. The recent-work list may omit older or optional
details to fit the message budget; its explicit omitted count does not hide
mailbox selections, controls, totals or unresolved coverage.

Previously signed chat history is displayed as stale. It cannot confirm a new
request or imply that the service is online. Only a fresh verified response
correlated with this session's pending or accepted command enables current
controls. An unsolicited valid signed snapshot also stays stale until refresh.
Expired, older, conflicting or forged responses do
not replace authoritative state. Reopen or refresh to reconcile; a client being
offline can delay messages independently of the worker's own queued work.

If an acknowledgement is lost, the app keeps that request's outcome **unknown**
and does not send the change again. A fresh, correlated read-only status can
release controls only when the earlier request can no longer apply: the same
mailbox's generation or link revision advanced, the link disappeared, or the
service's signed time passed the earlier signed control expiry with a rounding
margin. Advancing only the client clock or global status revision is not enough.
If the old control remains applicable, further changes stay blocked. A queued
acknowledgement also stays pending until a terminal reply or this reconciliation.
Releasing controls never claims that the earlier change succeeded; its unknown
outcome remains visible, and a late reply cannot confirm a new request.

Client and external-link boundary
---------------------------------

The app follows the `Webxdc 1.4 specification
<https://webxdc.org/docs/spec/CHANGELOG.html>`_, checked November 17, 2026. Its
updates use the stable messaging API, not ephemeral realtime channels. It
honors `sendUpdate limits <https://webxdc.org/docs/spec/sendUpdate.html>`_;
absent advertised limits, those are a 10-second interval and 128,000 serialized
bytes. Archive Manager uses tighter schema and queue bounds of its own.

All app scripts, styling, icon and signature verifier are local. There are no
CDNs, remote fonts, backend fetches, Google frames or embedded browser login.
The `messenger specification <https://webxdc.org/docs/spec/messenger.html>`_
requires Internet access to be denied and, when external links are supported,
the full URL and explicit user confirmation before opening one. Archive Manager
provides a deliberate HTTPS link and a visible address/copy fallback. The
messenger owns that external-site confirmation; a standalone test browser does
not prove a particular client's native confirmation UI.

Signature verification runs only in the packaged local Web Worker using the
pinned TweetNaCl verifier. No WebCrypto Ed25519 support is assumed, and there is
no blocking main-thread cryptography fallback. Workers are not an explicit
minimum in the Webxdc messenger specification. A client that cannot start the
local worker gets no authoritative archive state or mutation controls, only a
clear compatibility message and the fixed trusted portal address. This feature
therefore does not claim universal client compatibility. Mobile layout,
keyboard focus, labels and screen-reader status are part of its acceptance
tests, alongside actual worker execution.

Protocol and privacy
--------------------

The versioned command schema carries an opaque instance, random command ID,
selected opaque mailbox handle, expected link revision and binding generation.
Refresh/status and initial pairing requests can have an explicit null lease,
after the same protected-chat and registered-instance checks; they grant no
owner mutation authority. Every mutation has a fresh purpose-bound server
lease, including challenge-bound app pairing confirmation and unlink.

The service signs a bounded exact UTF-8 response document with Ed25519 over the
frozen ``chatmail-archive-manager-response/v1`` domain prefix and those bytes.
The wire envelope transports the document and signature as canonical base64url.
The app verifies before parsing or displaying authoritative state; Python and
JavaScript do not attempt to recreate each other's JSON serialization. Strict
schemas reject duplicate/unsafe JSON members, invalid sizes/types, wrong
key/instance/epoch, clock expiry and revision rollback. Exact duplicates are
deterministic. The app contains only its public verification key, random
instance/epoch context and trusted portal origin, with no shared secret.

The raw UTF-8 document budget is 22,000 bytes. The full base64url envelope,
signature and outer Webxdc payload must fit 32,768 bytes, leaving framing
headroom. Up to 16 linked mailboxes retain their selection, revision, generation
and control fields. If their optional recent-job details would exceed the
budget, the service deterministically shortens those lists, increments each
mailbox's omitted count and records the outcome in the existing ledger. It
does not discard archive history or silently omit a mailbox.

The verifier is unmodified TweetNaCl.js 1.0.3, official tag/commit
``5bf1ff5fa15e89ae249401b0d5aa54c5c5955041``, under the Unlicense. Its npm
SHA-512 integrity and exact GitHub tag member bytes were cross-checked before
vendoring. Source and member hashes are retained in
``archive_manager/vendor/provenance.json`` and independently pinned by the
packager. Never replace that file or verifier as an unreviewed dependency bump.

The bot's signing key stays in the wallet and signer memory. Its whole persistent
RPC account/blob profile and archive control state use the separately managed
genuine gocryptfs boundary, with root-owned inaccessible underlay, storage
attestation and guarded database/operation locks. Permissions alone are not
encryption. Mount or peer-context loss refuses operations; there is no plaintext
profile fallback. Unlocking and activation require the separately reviewed
launcher/configuration, not the Webxdc packager.

Build and issuance
------------------

The public-only packaging interface is
``chatmaild.backup.manager_packaging.app_bytes(bootstrap)`` or
``build_app(bootstrap, NEW_XDC_PATH)``. A bootstrap has exactly ``version``,
``instance``, ``profile_epoch``, ``public_key`` and ``portal_origin``. To build
an unregistered app from a public bootstrap JSON file::

    python3 -m chatmaild.backup.manager_packaging --context public-bootstrap.json --output archive-manager.xdc

This command creates only a new artifact; it does not configure a bot, send
mail, pair an owner or register an app instance. Runtime issuance preallocates
the instance inside guarded encrypted state, packages it, sends it using the
official pinned RPC client/server 2.69.0, then registers the actual outgoing
message ID and immutable app hash. It must not treat an independently built or
forwarded artifact as registered.

The `container format <https://webxdc.org/docs/spec/format.html>`_ is a ZIP
containing ``index.html``, ``manifest.toml`` and the local assets. The packager
uses fixed timestamps, modes, member ordering and stored compression for
reproducible bytes with the same public context and assets. It creates a
128-pixel ``icon.png`` for messenger thumbnails; the SVG is internal UI only.
``webxdc.js`` is supplied by the client and is deliberately not packaged.
Installed-wheel asset checks and actual RPC ``getWebxdcInfo``/blob checks must
cover the issued container, including its local verification worker.

Validation and analysis map
---------------------------

.. mermaid::

    flowchart LR
      encryptedState[Guarded gocryptfs state and inaccessible underlay] --> mountFence[Root attestation and kernel unique mount identity]
      mountFence --> sharedGuard[Shared SQLite and operation guards]
      sharedGuard --> sdk[Official RPC 2.69 child]
      sdk --> peer[Protected Single chat and SecureJoin key pin]
      peer --> pending[Atomic peer pin and durable pending issuance]
      pending --> claim[Reserved instance and exclusive claim]
      claim --> issuer[One background issuance worker]
      issuer --> sdk
      issuer --> register[Fresh context and atomic registration]
      register --> issued[Registered bot app hash and public context]
      issuer -. ambiguous outcome .-> uncertain[Uncertain issuance without automatic resend]
      uncertain --> replacement[Explicit offline replacement and retained history]
      replacement --> claim
      issued --> ui[Packaged Webxdc controls]
      ui --> sdkQueue[SDK messaging queue]
      sdkQueue --> peer
      issued --> browser[Separate portal fresh owner proof and comparison]
      browser --> appIntent[Signed app intent and purpose lease]
      appIntent --> browserFinal[Browser final confirmation]
      browserFinal --> ownerLink[Explicit personal mailbox link]
      peer --> ownerLink
      ownerLink --> lease[Revision generation and purpose lease]
      lease --> facade[Atomic archive facade and terminal result]
      facade --> worker[Existing background archive worker]
      facade --> statusBudget[Whole wire budget and explicit recent detail omissions]
      statusBudget --> outbox[Exact signed response outbox]
      outbox --> verify[Local NaCl verification worker]
      verify --> ui

Observe and Audit reuse Store's existing ledger and ``chatmail-fsreport``
surface. Command queued/completed/refused/replayed/ID-conflict outcomes, pairing
steps and expiry, peer-context changes, queue saturation/serial gaps, transport
ambiguity/stalls, storage/attestation refusal and command duration have opaque
reason codes and counters. No keys, private payloads, Google tokens, mailbox
passwords, recovery kits or owner labels belong in those artifacts. Frontend
connection details count delayed/rejected verification events without contents.
Optional recent-detail omissions have their own explicit counts and ledger
outcome; held retries are not counted as eligible or queued work.
Automatic issuance exposes pending/issuing/issued/uncertain counts and oldest
pending age through the same metrics. Duplicate completion events, saturation,
claim conflicts, interrupted issuance and explicit replacements are audited.
An issued app is registered and accepted by the local core; peer delivery is a
separate fact. Missing completion events require repeating SecureJoin, never
inferring authority from an arbitrary encrypted contact.
Distribute is not applicable: routing and bounded scheduling are deterministic;
cryptographic randomness creates IDs and nonces, not behavioral choices.

Renderer/simulator checks alone do not establish the service workflow. Acceptance
requires at least one control from the actual packaged UI through real 2.69
encrypted profile messaging over isolated local SMTP/IMAP, the actual archive
facade and a signed bot response. A synthetic mobile PNG is a preview, not that
proof. Real Google consent, production deployment, native client external-link
confirmation and any client versions not exercised remain explicit limits.
