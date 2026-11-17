Optional encrypted Google Drive archives
=======================================

This downstream feature is optional and is **not activated by cmdeploy**.
No current mailbox, Google account, legacy archive, service or timer is changed
by installing this source. The existing operator GCS archive stays independent.
Drive archives are additive: this implementation never deletes local messages,
prunes Drive files, runs doveadm or shares a Drive folder.

Owner flow
----------

The new ``/archive/`` portal signs in with verified Google OpenID Connect and
then asks the signed-in person to prove an **existing** mailbox password.
Google sign-in cannot provision a mailbox and cannot enter legacy admin routes.
The immutable ownership key is Google's verified issuer/subject pair, not the
profile email. A mailbox has only one personal owner; a separately authorized
operator binding may coexist with its own credentials, generation and receipts.

Once proof succeeds, personal archiving defaults enabled in ``pending`` state.
Proof holds the existing mailbox and password descriptors, then atomically
creates/reads a private **nonsecret** incarnation marker. Authority includes
mailbox/marker/password inode identities and a digest of the password verifier;
no password or verifier is persisted in the archive database. The worker never
creates or repairs a marker. Normal last-login timestamp touches are allowed.
Password replacement, marker loss, or address expiry/recreation requires fresh
proof. The former binding is retired with its original owner and recovery
history intact; a newly proven incarnation gets a new binding ID. Workers check
the held namespace against fresh paths before reads and each upload request.
An explicit incremental ``drive.file`` / offline authorization is still required.
The callback must have the same verified subject, nonce and single-use state;
the actual granted scope and Drive permissionId are checked. Declining,
expiration or revocation pauses archiving while keeping Google sign-in separate.
Opt-out advances the binding generation and stops future work and retries;
existing Drive files remain. Re-enabling asks for consent again.

All existing messages in INBOX and folder ``cur`` and ``new`` directories are
eligible, including Maildir++ ``.Sent`` / ``.Archive.2026`` and filesystem folder
layouts, small, recent and gzip-compressed messages. Newly created folders are
included in later reconciliation sweeps. ``tmp``, password files and Dovecot control
files are excluded. New messages are discovered by periodic content/path
reconciliation after the initial batches. This is a mailbox-message archive,
not a full relay configuration or credential backup. A capture window gives
per-message consistency; it is **not** a point-in-time mailbox snapshot.
Messages that clients delete before a capture cannot be recovered by this tool.
Regular hardlinks are accepted because Dovecot COPY can legitimately create
them; distinct mailbox paths remain distinct archive entries. Confinement
rejects symlinks, devices and traversal, and assumes that the relay's trusted
filesystem administrators control Maildir writers. It cannot establish the
origin of a hardlinked inode against a malicious filesystem administrator.

Identity, credentials and recovery
----------------------------------

The SQLite database contains bindings, opaque credential references, job states,
verified content IDs and reason-code ledger entries. Tokens never enter it or
cookies. Cookies contain opaque session IDs; stored IDs are hashed, cookies are
Secure/HttpOnly/SameSite, and all mutating portal routes require CSRF proof.
OAuth callback codes are excluded from application and sample proxy access logs.
The current unreleased database schema is v3. The narrow v2 migration preserves
bindings, jobs, receipts and login sessions/challenges. It invalidates only
pending Drive challenges whose old credential baseline is unknowable, and
ledgers that count; users can begin consent again. Earlier development v1
databases are rejected. Never point this config at a relay or Dovecot database.
The proxy overwrites ``X-Chatmail-Archive-Client`` with its
canonical peer IP. Only the fixed loopback proxy's dedicated header is trusted;
arbitrary X-Forwarded-For is ignored. Client/verified-owner quotas are independent
of the larger aggregate capacity bound.

The first successful destination initialization wins atomically. Later consent
cannot silently replace its key, recipient or folder. Every job and receipt pins
those exact recovery references, independently of later credential reconnection.
``receipt JOB`` exposes the historical opaque references to the local operator.
New credential/key/folder references are ledgered as candidates, then marked
used atomically with successful consent. Losing or failed callbacks retain
explicit unused artifact records; unknown folder-create completion is ledgered
as uncertain. Nothing deletes an authoritative mapping or an unused artifact.

Consent, decline and missing-scope callbacks compare the exact nullable
credential reference captured when their OAuth transaction began. Every new
credential gets a new wallet reference; a stale outcome cannot pause or replace
a newer grant. Workers snapshot the exact reference for each attempt, then
resolve failures against current job/binding state in one short transaction.
Stale credential outcomes preserve the existing ciphertext and preallocated
Drive ID for reconciliation under the new grant.

Worker execution, CLI verification and explicit retry share one nonblocking
per-binding operation lock under the private database directory. They reload
the job after claiming it, and failure handling finishes before releasing the
lock. Consent, opt-out, retirement and policy transactions stay short and may
run concurrently; no database transaction spans file, broker or network I/O.
Verified receipts are terminal and verification is idempotent: late failures,
retries or old verification results cannot rewrite their pins, cursor or success
count. Busy operations are refused and counted.

All archive processes and CLI commands must run as the same dedicated Unix
account that owns the private database directory and database. Administrators
invoke commands as that account (for example, ``sudo -u vmail ...``), and optional
``operator.uid`` names that archive control account. The examples use ``vmail``.
A privileged command under the wrong effective UID is refused before it can
create a root-owned lock. The state/operation directories are private 0700 and
locks are 0600; there is no automatic chown or broad-write fallback.

The fixed-argv JSON-stdin broker stores refresh tokens and age identities through
``kwsecret put --stdin`` and checks wallet persistence. Reads use
``kwsecret exec`` and a private pipe. There is no ADC, plaintext credential-file,
or global operator-account fallback. The included broker runs next to KWallet
on procreator. A relay on another machine needs an explicitly configured,
restricted broker transport implementing the same protocol. **No such remote
transport is installed by this change.** An unavailable broker leaves archives
pending or paused. A broker transport must authenticate its relay, restrict
operations and references, and protect stdin/stdout and the wallet session.

The operator's KWallet retains archive identities. A personal owner can also
export a private recovery kit and recover downloaded archives without the
relay, its database, wallet or broker. This is shared key custody: the operator
still has the keys and can decrypt archives. It is not exclusive owner custody
or a zero-knowledge service. Losing every copy of the required identity makes
its encrypted archives unrecoverable.

The existing broker-backed operator recovery command remains separate. All
recovery writes to a newly created private quarantine, never directly to a live
Maildir. Original message bytes are preserved, including compressed gzip bytes;
the incarnation marker is never archived or restored.

Personal recovery kit
---------------------

Request the download through the authenticated owner portal before losing
access to the operator. ``POST /archive/recovery`` requires the verified Google
issuer/subject session, CSRF proof, the personal binding ID and a fresh existing
mailbox password. It does not accept an arbitrary address, create a mailbox,
authorize operator bindings or grant access from a matching profile email.
The session must own the current, nonretired binding and mailbox incarnation.
The prominent keys-only action (``mode=keys``) includes all authorized retained
keys and the tool with explicit ``receipt_coverage: none``. Its availability
does not depend on the number of historical jobs. It recovers authenticated v2
archives; legacy v1 additionally requires its historical receipt part.

The historical action creates a ten-minute nonsecret paging snapshot, scoped to
the current owner, binding, generation and incarnation. Its append-only receipt
catalog freezes a sequence high-water mark and total count; later uploads do
not shift the selected range. Each bounded part includes all snapshot keys and
the tool, plus snapshot/part/count/total/included/cutoff and partial-coverage
metadata. Reload the portal after part 1 to select any remaining part. Every
part repeats fresh password, session and CSRF authorization. Browser selectors
are opaque snapshot ID and numeric part, never broker or job references.
Expired or stale snapshots require a fresh export. Missing legacy parts cannot
authenticate their unlisted v1 archives. An initially unallocated Drive file ID
may remain null in a receipt: digest, size, run and key pin the ciphertext, while
the catalog does not assert a remote upload exists or remains available.

The export shares the per-binding operation guard with archive work. It checks
held mailbox/password descriptors against the fresh namespace, resolves eligible
historical keys outside the database transaction, then performs a final short
authorization transaction over session, owner, generation, incarnation and
history. Session logout, revocation, retirement or generation changes detected
at these checkpoints refuse the in-flight export. The authorization commit is
the response's boundary: an action after that commit cannot retract private
bytes already released to the client.

A fresh authorized request may recover history after archive opt-out or Drive
consent expiry/revocation; it does not reactivate uploads. A retired or recycled
mailbox binding cannot be exported through the current owner flow. History is
selected by immutable binding ID, including actual pinned keys across its job
generations, without joining by mailbox address or including unused credential
and key candidates. Keep already exported kits when ownership is still current;
do not rely on later access to a retired binding.

The response is an in-memory private ZIP containing exactly ``recovery.json``,
the standalone ``restore.py``, ``README.txt`` and ``checksums.json``. It contains
private native age identities and eligible pinned archive metadata. It excludes
OAuth tokens, mailbox passwords/verifiers, incarnation proof digests, wallet or
broker references. The server does not stage the kit on disk and sends no-store
headers. Successful response delivery does **not** prove that a browser saved
the kit. Save and independently retain it privately before operator loss. The
ZIP is not itself password-encrypted; anyone obtaining its identities can read
the corresponding archives. Its checksums detect corruption, not an independently
trusted publisher or an operator who already holds the same keys.

An exported identity also authenticates **later** v2 archives from the same
binding and recipient. A normal consent renewal or binding-generation change
that retains those keys does not require a new kit or a per-upload server
receipt. A genuinely new encryption key or a new binding requires a new export
for its archives. Keep older kits needed for older keys.

V2 archives use standard RFC 5869 HKDF-SHA256 to derive a manifest MAC key from
the normalized single native age identity, with domain separation for the
binding and public recipient. An RFC 2104 HMAC-SHA256 authenticates the entire
canonical manifest inside the age ciphertext, including message paths, sizes
and hashes. The worker receives the derived MAC through the restricted broker's
private pipe; routine uploads do not export the private age identity. The
offline tool derives the same MAC from the privately retained kit. Possession
of the public age recipient alone cannot forge that manifest authentication.

Legacy v1 archives lack this manifest MAC. They are accepted only when the kit
already pins their exact ciphertext SHA-256, size, run ID and key. An older kit
cannot authenticate later unlisted v1 uploads. Neither age nor v2 authentication
proves that the supplied set is newest or complete: a valid older archive may
be replayed, and omitted or never-captured messages remain absent.

Offline owner recovery
----------------------

Download the desired encrypted archives from Drive using your own account and
retain the private kit. The recovery helper makes no network request. Its
dependencies are Python 3's standard library on POSIX/Linux and the genuine
``/usr/bin/age`` and ``/usr/bin/age-keygen`` executables; no Relay installation,
Python extra, database, wallet, broker or running server is needed.

The standalone implementation is
:repofile:`recovery_tool.py <chatmaild/src/chatmaild/backup/recovery_tool.py>`;
the kit exports those exact tool bytes as ``restore.py``. Use that supplied
tool. After placing it in
an appropriately private working directory, the invocation is::

    python3 -I restore.py --kit recovery.zip --output /private-parent/NEW downloaded-1.age downloaded-2.age

The private ZIP must be owned by the invoking Unix user and have no group/other
permissions, for example mode 0600. ``--kit-fd FD`` instead accepts an already
open private regular-file or pipe descriptor, avoiding a separately staged kit
file when appropriate. Never put an identity or password in a command argument.
Repeat ``--kit part-1.zip --kit part-2.zip`` (or ``--kit-fd``) to combine parts.
The tool accepts only the same binding and consistent keys and immutable receipt
pins; conflicting duplicates fail. Existing unpaged kits remain supported.

``--output`` must be an absolute, nonexistent immediate child of a pre-existing
directory owned by that user with mode 0700. Use a dedicated quarantine parent
outside every live mail root. Ancestors must have safe root/current-user
ownership and no group/world writes; root-owned sticky ``/tmp`` is the narrow
ancestor exception. The helper follows no symlink ancestors, rejects known
mail roots and mailbox/control markers, and uses descriptor-relative exclusive
writes. It cannot discover every custom mail-root path or defend against a
malicious process with the same Unix authority; selecting a genuinely separate
quarantine remains your responsibility.

The tool validates age decryption, manifest authentication or legacy pins,
archive paths/types/counts, message sizes and hashes. Sparse representations,
links, traversal and unexpected members are rejected. Output has separate
run-ID directory trees preserving folder paths, ``cur``/``new``, filenames and
flags. Different capture windows remain separate rather than overwriting
versions of a message. Identical ciphertext inputs are deduplicated
deterministically; conflicting archives claiming the same run ID are rejected.

Only exit status 0, a final ``completion.json`` and absence of ``.incomplete``
indicate successful processing of the supplied inputs. Completion is written
last. Failure or interruption returns nonzero and leaves any partial output
private and incomplete; do not import it. A failed input before output creation
may leave no destination. Never merge this quarantine automatically into a live
Maildir. Recovery restores archived message files, not account identity,
credentials, indexes, deleted messages or a point-in-time snapshot.

The independent tool currently bounds each invocation to sixteen kit parts,
4 MiB per part and 16 MiB total, 64 distinct keys, 4,096 pinned receipts per
part and 4,096 input archives, 71 MiB per ciphertext, 70 MiB per
decrypted archive, 256 messages per archive, and 1 GiB of aggregate recovered
message bytes. Manifests are bounded to 1 MiB and individual messages to 32 MiB.
For larger recoveries, select bounded batches and use a different fresh private
quarantine for each invocation, combining the parts required for those legacy
inputs. Parts beyond one invocation's aggregate kit limit can be processed in
another fresh quarantine. More than 64 retained distinct keys still needs an
explicit operator-supported recovery plan. The completion manifest records the
provided receipt-part coverage and never asserts missing parts were supplied.

Separate optional operator Drive mode
------------------------------------

``operator-consent --identity NAME --mailbox ADDRESS`` additionally requires the
configured OS UID, an explicit trusted administrator identity, an exact mailbox
allowlist, and a configured Google subject. It uses its own loopback OAuth
consent flow and verifies that subject and the Drive principal. Ordinary Google
login never confers this authority, and owner portal routes cannot authorize an
operator binding. Select only mailboxes for which the operator already has
administrative archival authority. The mode is absent unless configured.
Explicit enrollment may initialize the nonsecret marker under that checked
administrative authority while holding the existing mailbox/password FDs; it
does not create a mailbox. The worker re-reads current trusted operator config
before capture, retry and every upload request. Removing the mode or selected
mailbox disables it immediately at the next checkpoint. Namespace changes require
explicit reenrollment. ``operator-revoke --identity NAME --mailbox ADDRESS``
disables future work without changing existing Drive history. Ordinary owner
routes cannot operate on operator bindings even when the Google subject matches.

Manual setup boundary
----------------------

Before a separately authorized activation, register an OAuth web client with
``https://YOUR-RELAY/archive/callback`` (and the optional operator client's
``http://127.0.0.1:8766/callback``), configure Google's consent screen for
``openid`` and ``drive.file``, arrange the approved broker, and install the
``backup`` extra from the exact reviewed downstream ``chatmaild`` source,
plus the standard ``age`` and ``age-keygen`` executables.
The fixed broker command can be ``python3 -m chatmaild.backup.credentials``
on the wallet host. Its interpreter/module and transport must be operator
controlled. Never place OAuth client secrets or refresh tokens in JSON config.

The recovery response carries private keys. Every proxy on that path must pass
it without disk buffering, caching, storage or body logging. The nginx example
sets ``proxy_buffering off``, ``proxy_max_temp_file_size 0``, ``proxy_cache off``
and ``proxy_store off``; the application also sends ``X-Accel-Buffering: no``.
Do not ignore that header. ``Cache-Control: no-store`` alone does not prevent
proxy temporary files. These requirements follow nginx's documented
`buffering behavior <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering>`_
and `temporary-file controls <https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_max_temp_file_size>`_.
Verify the complete proxy path before activation; these examples are not
installed by this change.

Example **secret-free** config (paths and public client ID are placeholders)::

    {
      "database": "/var/lib/chatmail-archive/state.sqlite",
      "spool": "/var/lib/chatmail-archive/spool",
      "chatmail_ini": "/usr/local/lib/chatmaild/chatmail.ini",
      "public_url": "https://YOUR-RELAY",
      "web_port": 10090,
      "google_client_id": "PUBLIC-CLIENT-ID",
      "google_client_secret_ref": "archive-client-secret",
      "broker_argv": ["/path/to/restricted-wallet-broker"]
    }

The referenced client-secret wallet value is JSON with a ``client_secret``
field, placed into KWallet through stdin. A separate optional ``operator``
object contains ``uid``, ``identity``, ``google_sub`` and ``mailboxes``.
No email allowlist substitutes for that subject or administrator authority.

Commands take ``chatmail-archive --config PATH COMMAND``:

* ``web`` starts only the loopback portal.
* ``worker`` starts only the bounded background reconciliation worker.
* ``prepare BINDING`` durably enqueues an active binding; it does not upload.
* ``retry JOB`` explicitly resumes a stopped job with its original Drive file
  ID. Exhausted jobs with a preallocated ID block automatic replacement;
  reconnecting consent or manual retry resumes the same durable object.
* ``upload`` processes one bounded selection of already queued jobs.
* ``status`` prints aggregate state and key-custody information.
* ``receipt JOB`` reports pinned opaque recovery references for that job.
* ``retry-sources BINDING`` explicitly releases held source retries. Personal
  owners can also retry their unresolved entries through the protected portal.
* ``verify JOB`` downloads ciphertext again and checks its receipt, resolving
  a previously uncertain receipt only after verification succeeds.
* ``restore-to-empty-staging CIPHERTEXT KEY_REF NEW_DIRECTORY`` authenticates,
  validates and writes an isolated quarantine. No live restoration is automatic.

The restore destination must be a new immediate child of a pre-created private
``quarantine_root`` (default: ``quarantine`` beside the state database), outside
the configured live Maildir tree. The command refuses existing destinations.

The example systemd and nginx files in ``backup/integration/`` are deliberately
outside automatic deployment registration. Review permissions, paths, wallet
transport, OAuth publication and retention before separately enabling them.
The web service and worker must have independent processes.
The web service's marker-write exception must match the configured Maildir root;
the worker keeps read-only source access. The state directory
is private and the spool contains ciphertext only. Worker captures use bounded
memory (64 MiB per batch, 32 MiB per message, at most 256 messages and 1,024
processed entries per capture window). A durable numeric enumeration cursor
advances only after verification, then wraps for another sweep; directory
changes before a cursor are found on a later sweep. The cursor contains no
message path. Folder traversal is limited to 16 levels and 4,096 directories;
exceeding a bound is explicit incomplete/failed status, not silent exclusion.
Oversized, nonregular, unsafe or changing entries are recorded as durable opaque
unresolved entries while valid messages in the same window continue to verified
receipts. Coverage stays **INCOMPLETE** in the owner portal and metrics until
the unresolved entries are successfully captured and verified. After eight
attempts an entry is held for explicit retry; it cannot starve later entries.
An entry that disappears before recovery remains unresolved. A verified batch
never asserts that the entire mailbox is complete. Ciphertext spool retention is
explicitly operator-managed; no cleanup schedule is installed here.

Each fresh capture atomically snapshots the cursor and its revision. Successful
verification advances that cursor only if its revision still matches, then
increments the revision; using the numeric maximum would break intentional
wraps. Older receipts still record verified message content but cannot move a
newer cursor backward. A separate scan sequence fences unresolved-entry updates
and resolution, so an old healthy scan cannot erase a newer failure observation.
Migrated spooled jobs with unknown baselines never advance the current cursor.

Integrity and analysis surface
------------------------------

.. mermaid::

    graph LR
        GoogleOIDC --> verifiedSubject
        verifiedSubject --> existingMailboxProof
        existingMailboxProof --> immutableBinding
        immutableBinding --> heldMailboxIncarnation
        currentOperatorPolicy -. optional delegation .-> heldMailboxIncarnation
        immutableBinding --> explicitDriveConsent
        explicitDriveConsent --> walletBroker
        immutableBinding --> generationCheck
        walletBroker --> captureCurAndNew
        generationCheck --> heldMailboxIncarnation
        heldMailboxIncarnation --> captureCurAndNew
        captureCurAndNew --> canonicalV2Manifest
        walletBroker --> boundManifestMAC
        canonicalV2Manifest --> boundManifestMAC
        boundManifestMAC --> ageCiphertext
        captureCurAndNew --> ageCiphertext
        ageCiphertext --> DriveSamePrincipal
        DriveSamePrincipal --> downloadedChecksumVerification
        downloadedChecksumVerification --> durableReceipt
        durableReceipt --> privateQuarantineRestore
        workerVerifyRetryGuard --> captureCurAndNew
        versionedCredentialCAS --> walletBroker
        downloadedChecksumVerification --> terminalReceiptAndCursorFence
        terminalReceiptAndCursorFence --> durableReceipt
        captureCurAndNew --> unresolvedEntryLedger
        walletBroker --> unusedArtifactLedger
        verifiedSubject --> freshRecoveryMailboxProof
        freshRecoveryMailboxProof --> recoveryOperationGuard
        recoveryOperationGuard --> finalRecoveryAuthorization
        heldMailboxIncarnation --> finalRecoveryAuthorization
        walletBroker --> finalRecoveryAuthorization
        immutableBinding --> pinnedBindingKeyHistory
        pinnedBindingKeyHistory --> finalRecoveryAuthorization
        finalRecoveryAuthorization --> privateOwnerKit
        durableReceipt -. legacy v1 pins .-> privateOwnerKit
        privateOwnerKit --> offlineFormatAuthentication
        downloadedDriveFiles --> offlineFormatAuthentication
        offlineFormatAuthentication --> descriptorPrivateQuarantine
        descriptorPrivateQuarantine --> completionWrittenLast

Observe: existing logging records opaque reason codes, and
``chatmail-fsreport --archive-database PATH --textfile DIRECTORY`` adds aggregate
job, byte, message, retry, stall, failure and last-verification metrics to the
existing Prometheus file. No subject/mailbox/token labels are exposed.
Recovery uses this same ledger/metrics surface for request, denial,
authorization, response completion/abort, key/receipt counts, duration and
operation-lock stalls. Offline completion summarizes only supplied run/message
counts; format/authentication failures return opaque reasons and nonzero status.
Response completion is transport evidence, not proof of a privately saved kit.

Audit: rejected proofs, ownership conflicts, missing scopes, changed sources,
unsafe paths, quota failures, expired upload sessions, uncertain commits and
stale generations have durable reason-code ledger entries. Bounded retries use
the same preallocated Drive file ID, and uncertain completion must reconcile
metadata then verify downloaded ciphertext before a receipt advances content
IDs. Upload session URIs remain in memory only.
Recovery audit records opaque failure reasons and format-authentication
outcomes, never identities, keys, tokens, passwords, decrypted content or owner
labels. Exported plaintext identities belong only in the explicitly requested
private owner kit. A valid recovered archive is not an assertion of newest or
complete mailbox coverage.

Distribute: capture follows filesystem enumeration and capped exponential
backoff is deterministic; neither uses generative/probabilistic routing.
Cryptographic
randomness supplies opaque IDs and age nonces, not behavioral choices.

The strict legacy TSV reader recognizes only size/SHA256/relative-path records,
ignores absolute columns and labels coverage ``legacy-selected-subset``. It does
not import pruning logic, infer a full backup, or restore any file automatically.

The normal tox Python environment installs the declared ``backup`` extra, and
the normal CI chatmaild job provisions age before tox. Tests require the real
binaries and do not silently skip archive acceptance when dependencies are absent.
Validation uses synthetic Maildirs, a real age binary, fake Google/Drive
transports, and isolated rootless containers. Live Google consent, actual Drive
quota/resume behavior, restricted remote broker deployment, and an operator
recovery exercise remain activation acceptance checks, not claims made here.
The personal-kit follow-up adds separate acceptance contracts for export
authorization/races, independent offline recovery, later v2 uploads after kit
export, ordinary consent renewal without key rotation, legacy v1 pins, and
failure-safe quarantine output. Earlier archive/relay test totals do not prove
these new contracts; use the follow-up's exact integration receipts before
claiming acceptance.
