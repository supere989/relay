Archive Manager operations
==========================

Archive Manager is optional. It uses the official Python
``deltachat-rpc-client==2.69.0`` with a separately installed, digest-checked
``deltachat-rpc-server`` of exactly the same version. It does not replace or
fork the relay's native mail services. The personal owner portal, explicit
Drive consent, existing operator Drive authority, and existing GCS archive
remain separate. See :doc:`archive-manager` for the app's user flow.

This change supplies source and acceptance fixtures. It does not install,
enroll, migrate or start a production bot. Passing unit tests alone does not
qualify a mount layout or a real mail transport. The application-level FUSE and
real-mail acceptance commands below are activation requirements.

Storage and privileges
----------------------

The core does not provide complete at-rest protection for its databases,
configuration, identity and blobs. All bot state and the shared archive SQLite
database, journals, operation locks, pairing challenges, leases and outbox must
reside in the genuine encrypted state mount. A normal private directory is
insufficient. There is no plaintext directory, credential-file, or fallback
ledger path.

A separately managed root mount helper owns mount lifetime. RPC stop/restart
must never unmount the shared state. The underlying mountpoint is root-owned,
mode 0000, beneath root-owned non-writable ancestors. Application services run
as the same dedicated, non-root archive UID, with zero capabilities and
``NoNewPrivileges``. Kernel permissions deny new database, WAL, journal, lock
and profile writes into the underlay after detach, even before a watcher can
notice. Held handles either continue addressing encrypted storage or fail.

The root helper publishes only nonsecret attestation metadata: boot ID,
namespace, the kernel's unique mount ID/device/source, service UID/GID and enrolled state
epoch. Applications validate that root-owned attestation and the current FUSE
view before opening state. Root configuration and broker executables must be
root-controlled. Do not run application workers as root or grant them mount or
permission-bypass capabilities. Do not enable force, lazy or automatic unmount
in production lifecycle units. Tests deliberately use detach to challenge the
kernel boundary.

The ciphertext container is root-owned mode 0700. Its direct backing-directory
child is owned by the dedicated service UID/GID, mode 0700. The service cannot
traverse the enclosing container. The root helper mounts gocryptfs 2.6.1 in
forward mode with ``-allow_other -ko default_permissions,nodev,nosuid -noexec``.
Default ownership preservation supplies correct create attributes for the
unprivileged service; ``-force_owner`` and ``-sharedstorage`` are not used.
The latter changes inode/hard-link behavior and is not a substitute for this
reviewed layout. Ownership guards remain strict.

Version-2 attestations require Linux ``statx(STATX_MNT_ID_UNIQUE)`` on the held
directory descriptor. Missing libc/kernel support fails closed. Ordinary
``mnt_id`` values can be reused after remount and are diagnostic only. Each
guard pins its first accepted boot/unique-mount identity: a remount requires a
fresh root attestation and restarting all consumers. Restarting only RPC on
the same mount remains supported. Data and state epochs remain stable through
a legitimate remount; they do not replace mount-session freshness.

``Store`` retains parent/file descriptors for guarded SQLite opens and lock
lifetimes, rejects symlinks, and uses memory for SQLite temporary storage.
SQLite can canonicalize descriptor paths, so directory-descriptor spelling
alone is not the detach boundary. The sealed underlay and unprivileged process
contract remain essential. The attested mount namespace must be shared by the
dependent units; an unrelated private mount namespace intentionally fails
validation.

Bot profile layout
------------------

The profile's explicit enrollment creates a separate bot-profile epoch and
private ``accounts`` and ``.rpc-tmp`` children. The state epoch and bot-profile
epoch have different purposes. Only ``accounts`` is passed as the SDK accounts
directory: the core requires a clean directory when creating its
``accounts.toml`` index. Passing the profile root containing epoch and temporary
metadata is invalid.

Normal restart requires the enrolled accounts index; it never repairs a
missing child or silently provisions a replacement identity. Startup and every
command compare the actual bot self public key, decoded from the supported
core vCard API, as well as profile epoch and account ID. Replacing a profile
while retaining its local IDs or copying an epoch cannot retain authority.

Core and SDK temporary files use the profile's private encrypted ``.rpc-tmp``
directory. RPC binaries and installed Python code stay outside the no-exec
encrypted state mount. Core dumps and raw RPC/MIME logs are disabled. Version
probes inspect bounded private stdout/stderr after verifying the configured
binary digest; those streams are never printed. The SDK retains its private
stderr pipe for compatible startup cleanup; runtime stderr is discarded.

The supervised transport worker uses a clean ``spawn`` interpreter, including
restarts while attestation and issuance threads are active. It detects its owned RPC process exiting and
fails outstanding calls. Startup and request deadlines are backstops. A lost
reply is not a successful archive mutation acknowledgement. The backend stores
each command ID and digest, its committed result, and its outbox atomically;
publication signs the immutable committed snapshot outside the transaction.
Retries send the same logical result and never repeat a completed mutation.
Idle shutdown first uses the existing private shutdown frame so the SDK can
close and reap its child; a short deadline falls back to terminating only the
owned process group. Busy and failed requests fail without a mutation replay.

Explicit enrollment and startup
-------------------------------

All commands require a nonsecret reviewed JSON configuration via ``--config``.
The configuration adds ``state_storage`` and ``manager`` sections to the
existing archive configuration. Paths and references are public metadata;
passwords, unlock passphrases and private signing keys are not configuration
fields. ``state_storage`` identifies the mount/backing, state epoch, dedicated
UID/GID, root attestation, pinned gocryptfs executable/digest and wallet unlock
reference. ``manager`` identifies the encrypted profile, account ID, pinned RPC
executable/digest, signing and mailbox wallet references, private attestation
socket and explicit transport settings.

The scoped helper interface is::

    chatmail-archive-state --config CONFIG new-key
    chatmail-archive-state --config CONFIG enroll-state
    chatmail-archive-state --config CONFIG mount

The packaged ``integration/archive-manager.json.example`` provides the exact
nonsecret configuration shape, with deliberately invalid enrollment epochs
and references. Never place credential values in this file. The backing leaf
must be the direct child of its root-private container; ``backing.parent`` is
the container identity attested by the helper. Create the sealed mountpoint,
container and service-owned leaf during a separate reviewed installation,
before using enrollment commands. Neither a normal startup nor an unavailable
wallet repairs missing storage.

``new-key`` stores and verifies a new unlock secret through the configured
wallet broker and reports only its opaque reference. Initial enrollment is
explicit and refuses a nonempty backing directory. Its gocryptfs ``-init``
stdout/stderr are discarded because initialization can otherwise print
recovery/master-key material. Ordinary ``mount`` requires the enrolled state;
it never creates replacement state. The helper runs in the foreground under
its independent optional service.

Once storage has passed acceptance, the application interface is::

    chatmail-archive-manager --config CONFIG enroll-profile
    chatmail-archive-manager --config CONFIG enroll-mailbox
    chatmail-archive-manager --config CONFIG invite
    chatmail-archive-manager --config CONFIG serve
    chatmail-archive-manager --config CONFIG issue --contact CONTACT_ID
    chatmail-archive-manager --config CONFIG status

Profile enrollment creates state only inside the verified mount and reports
the public signing key/reference and bot epoch. Mailbox enrollment obtains the
dedicated bot mailbox's credentials through the fixed broker and private
channel, configures only that core account using the supported transport API,
and pins its actual self key. It reports the numeric account ID, never the
credential reply. Update only the corresponding public configuration fields.

Transport settings use the current ``EnteredLoginParam`` names, such as
``imapServer``, ``imapPort``, ``imapSecurity``, ``imapUser``, ``smtpServer``,
``smtpPort``, ``smtpSecurity``, ``smtpUser`` and ``certificateChecks``.
Credentials are inserted privately from the wallet. The local-mail fixture
uses explicit loopback plaintext sockets; that is not a production TLS
configuration.

The private invitation is written only within the encrypted profile. Generate
it during explicit setup before starting ``serve``; display/share that intended
invitation through a reviewed owner-enrollment channel. When an owner completes
actual SecureJoin, the running daemon atomically pins that peer key and queues
one automatic app issuance for that profile/account/contact/key. The separate
bounded issuance worker packages and sends through the same owned, serialized
SDK transport. Normal QR onboarding does not require stopping the daemon or
discovering a contact ID to invoke ``issue``.

An address, display name, imported vCard or generic encrypted contact alone is
not SecureJoin enrollment. Duplicate completion events retain the existing
issuance outcome and never send another app. A changed peer key cancels old
pending work; a newly issued instance has no inherited owner links. Event
overflow is audited. If the verified completion was lost, repeat the actual
SecureJoin handshake rather than inferring enrollment from a contact list.
Each issued app has
its own instance, actual outgoing message ID/hash and embedded public response
verification key. A public packaging command by itself does not register or
authorize an app.

Every SDK-opening CLI action acquires the same exclusive, nonblocking encrypted
profile-owner lock before opening RPC. A running daemon makes offline
enrollment/issuance fail with ``manager_profile_busy``. Its startup recovers
abandoned ``issuing`` claims to ``uncertain`` only after obtaining that lock.
Issuance reserves its random instance and claim token before packaging or SDK
work. Instance registration and the matching claim's terminal ``issued`` state
commit together after fresh actual context checks. ``Issued`` means local core
acceptance and registration; it does not claim peer delivery.

A lost send reply or interrupted registration can leave an unregistered app
in the chat. Such an orphan has no owner authority. The daemon records
``uncertain`` and never automatically resends it. ``status`` is read-only with
respect to RPC and shows up to 64 recent issuance IDs, contacts, states and
fixed reasons, with an explicit omitted count. After inspecting an uncertain,
failed or held record, an operator may stop the daemon and explicitly replace
that exact issuance::

    chatmail-archive-manager --config CONFIG issue --contact CONTACT_ID --replace-issuance ISSUANCE_ID

The replacement reserves a new instance, retains the old attempt and its
orphan/history mapping, and records the replacement link. It never transfers
old owner links or reuses the old instance. No broad IPC administration or
second RPC profile opener is used. Pending automatic work is limited to 64
claims per profile/account; saturation retains a durable held outcome instead
of dropping a completion event.

The owner web process uses a private Unix socket for fresh instance
attestation rather than opening another core profile. Both endpoints enforce
the expected service UID, bounded frames/timeouts and the sole operation
``attest(registered instance ID)``. The daemon resolves all IDs and key/contact
context itself. The socket may be in a private runtime directory: its payloads
are kernel-memory IPC, not stored secret files. Storage guards apply to every
request. There is no general RPC, shell or admin endpoint on this socket.

Migration and shutdown boundary
-------------------------------

Before a separately authorized production migration, stop every archive
writer, unlock the enrolled destination, take a consistent SQLite backup and
copy the relevant state, verify it, update all configurations and restart the
dependent services. Preserve the original state and its recovery path. Do not
move a live SQLite database by copying its main file alone, or silently point
one component at a second empty database. No existing database has been moved
by this change.

Order and bind web, worker and Manager units after the independent mount
service. Stop dependents before normal unmount. The core and application UID
must not have access to the root-only ciphertext/configuration tree through
its ordinary path. Runtime restart does not supply an alternative plaintext
location if storage or the wallet is unavailable.

The packaged ``chatmail-archive-state.service.example`` and
``chatmail-archive-manager.service.example`` are optional references. The
Manager example has no capabilities and runs as the archive service UID.
The root mount helper is the sole privileged process. Its dependent units
must share its mount namespace: do not copy ``PrivateTmp``, ``ProtectSystem``
or other private-mount-namespace settings from the legacy archive examples
without an explicitly shared namespace design. Those legacy examples remain
valid for their original non-Manager configuration, but are not drop-in
Manager units. Web, worker and guarded metrics must use the same configuration,
UID/GID and shared namespace as Manager. They must bind/order after the state
service, have zero capabilities and ``NoNewPrivileges=yes``, and permit writes
only in the intended encrypted state and existing ownership-proof Maildir.

``Type=simple`` ordering alone does not establish mount readiness. Guards
refuse early opens, and dependent reference services retry with bounded
delays until a valid attestation is present. No service creates a replacement
database or profile while waiting. For shutdown, stop all dependents, close
their held descriptors and use an ordinary unmount; a busy mount is a stop
failure to investigate. Do not use lazy/forced unmount, automated permission
changes or a fallback state directory to make shutdown succeed.

Status, audit and limits
------------------------

Use ``chatmail-fsreport --archive-config CONFIG`` for live guarded metrics.
The legacy bare ``--archive-database`` path is a noncreating, nonmigrating
read-only snapshot interface and refuses Manager/protected state or active
journal/WAL state. It cannot provide live-writer consistency.

The existing ledger/metrics expose queue/refusal/replay/serial gaps, authority
changes, pairing transitions and expiry, signing/publication and ambiguous
send outcomes, transport exits/stalls, detail omissions and storage failures.
When storage is inaccessible only bounded aggregate counters remain in
process memory; they may be lost if the process exits. There is no plaintext
fallback queue or ledger. Random security tokens are not logged or sampled;
choice-distribution analysis is not applicable to deterministic scheduling.

Signed snapshots distinguish real remote archive verification from idle
no-change captures, current eligible jobs from consent/generation-blocked work,
and eligible unresolved sources from held retries. Unknown coverage does not
mean a verified archive exists. Optional recent-job detail is trimmed to the
wire budget with explicit omitted counts; all supported mailbox choices and
controls remain present.

Commands are limited to the issuing instance, expected link/binding revisions
and short purpose-bound leases. Read-only refresh/status and pairing requests
can recover fresh signed state after offline periods without a lease; they do
not authorize archive mutation. Comparison codes authorize only their live
context-bound challenge; the stored hash is authoritative, while the private
presentation copy supports restart until expiry. Every pairing confirmation
rechecks session, owner, generation, incarnation and fresh RPC context.

Every app-exposed lease expires no later than its signed snapshot, even if
snapshot creation is delayed. Revoked and quarantined command history remains
in the ledger/database but does not consume active admission capacity.
Definitive context denials revoke authority and hold responses without a send
retry; unknown transport outcomes retain separate ambiguity/retry accounting.

Update reconciliation processes bounded serial prefixes and commits only
processed entries or explicit refusals. A history beyond the supported bounded
reader capacity is durably quarantined, preserving its cursor and audit
history. Reissue an app under the same protected peer context and repeat owner
pairing; do not advance over an unprocessed history or transfer old leases.

Required acceptance
-------------------

Run the synthetic unit and protocol/UI suites in the isolated image, then the
explicit real-mail and physical storage harnesses. They require the exact
reviewed RPC and gocryptfs binaries. They use only local synthetic identities,
private pipes and disposable state. The real-mail harness must prove actual
SecureJoin, key-pinned protected core metadata, PGP-encrypted control MIME,
browser pairing, an archive-service mutation and a signed response. The
physical harness must prove real encrypted persistence, active DELETE/WAL
transactions, racing opens and RPC restart during lost storage, an empty
plaintext underlay, and successful remount recovery. Counters or a mock mount
record alone do not establish these outcomes.

Final release qualification also includes clean declared-extra tox bootstrap,
installed wheel app/vendor/worker assets, the existing independent recovery
tool's source-free acceptance and adversarial review of the exact staged
diff. Production enrollment, real Google consent/uploads and a live client
exercise remain separately authorized activation work.
