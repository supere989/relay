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

Current key custody is the operator's KWallet. The owner portal discloses this;
independent owner key export/recovery is not implemented. Losing the wallet
identity makes the encrypted archive unrecoverable. Recovery is an explicit
operator action into a newly created private quarantine directory, never into
a live Maildir. Age authenticates decryption before tar entries, paths, types,
counts and message hashes are validated. Original message bytes are preserved.
Tar validation streams a maximum of 257 members, rejects GNU/PAX sparse
representations, and bounds both aggregate declared and actual bytes before
message allocation. The incarnation marker is never archived or restored.

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

Observe: existing logging records opaque reason codes, and
``chatmail-fsreport --archive-database PATH --textfile DIRECTORY`` adds aggregate
job, byte, message, retry, stall, failure and last-verification metrics to the
existing Prometheus file. No subject/mailbox/token labels are exposed.

Audit: rejected proofs, ownership conflicts, missing scopes, changed sources,
unsafe paths, quota failures, expired upload sessions, uncertain commits and
stale generations have durable reason-code ledger entries. Bounded retries use
the same preallocated Drive file ID, and uncertain completion must reconcile
metadata then verify downloaded ciphertext before a receipt advances content
IDs. Upload session URIs remain in memory only.

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
