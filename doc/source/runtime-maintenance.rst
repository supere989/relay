Runtime security maintenance
============================

This downstream work starts from upstream relay 1.13.0, commit
``4ffb501c5e15e4c2d9a801f4baff1d214ce1fbed``. The existing EL10 branch
``f6e7d162f9697733d23a941200de00b9ee6df18b`` is preserved. Its platform intent
is carried explicitly; its unverified stock ``dovecot-lua`` dependency, old
plugin release and catch-all DNF fallback are not reused.

Ownership and analysis map
--------------------------

.. mermaid::

   flowchart LR
     A[Primary upstream disclosures and releases] --> B[Read-only intake facts]
     C[Signed source and binary evidence] --> D[Versioned runtime lock]
     B --> E[Offline security checker]
     D --> E
     E --> F[Private candidate source and target diff]
     F --> G[Exact isolated build]
     G --> H[Offline authentication and notification tests]
     H --> I[Explicit promotion review]

The lock owns profiles, exact package identities, source/binary digest linkage,
required modules, authentication/configuration contracts and promotion gaps.
The linked ``dovecot-el10-plugins`` build owns module/runtime provenance and its
actual test receipts. One repository must not independently choose a different
"latest" native runtime for the same profile.

The checker returns separate fixed, not-applicable, affected and unknown states.
It distinguishes source inspection from an exact signed binary relationship,
rejects stale/failed discovery and does not infer fixes from an old version
string. The complete 25-CVE August 2026 disclosure is inventoried: missing
dispositions remain unknown instead of disappearing behind a vendor advisory's
smaller package subset. Debian's upstream Dovecot pin is unchanged and its
current security coverage remains an explicit separate gap.

Observe uses the existing CI log/artifact surface: counts, release drift,
source/profile mismatches and gate outcomes are in the JSON audit report and
Actions summary. The intake ledger retains failed/unknown fetches. The build
ledger retains preparation, build and runtime failures. This map binds those
surfaces to the deployment guard. No probabilistic route is introduced;
distribution instrumentation is not applicable.

Candidate boundaries
--------------------

The live runtime uses chatmaild 0.2 dictionary authentication. Relay 1.13.0 uses
chatmaild 0.3 with Lua/HTTP authentication. A passing legacy notification test
does not qualify the newer authentication/provisioning contract. Both profiles
are distinct, and full EL10 deployment refuses before any pyinfra mutation
until its package, startup, SELinux, auth, notification, metadata, archive and
rollback contracts are qualified. Direct Dovecot stage calls have the same
preflight. Debian ``policy-rc.d`` is never presented as EL10 service suppression.

The current Alma security NVR plus rebuilt Lua addon is an intermediate
compatibility/remediation candidate. It is not proof that all current upstream
vulnerabilities are fixed. The required full-parity path is a coherent upstream
Dovecot/Pigeonhole 2.4.5 runtime with matching Lua support and a version-specific
relay configuration, separate from Alma's old module directory and service.
That path also needs the explicit 2.4.5 storage format setting and tested
mail-state transition; a changed version label alone is insufficient.

Faster intake without unattended production replacement
-------------------------------------------------------

``python3 -m cmdeploy.runtime_intake`` refreshes authoritative release/disclosure
facts and never edits a pin. ``cmdeploy-runtime-audit --gate`` reports the current security
matrix and unresolved promotion contracts. Fetch failures become unknown, never
fresh success. A new disclosure is added to the inventory automatically, but
requires a source/binary/applicability disposition before promotion.

The linked native build workflow obtains structured Alma core and Pigeonhole
RPM facts, verifies common epoch/version/release/architecture/source-RPM identity,
and generates a private candidate workspace, target diff and hashed source
context. It builds and runs real offline LMTP/Lua tests. Same-branch vendor
updates can be evaluated without editing the main checkout; a 2.4 branch change
is refused until the runtime migration path is explicitly selected and tested.
Detected, built, tested and promotable are distinct states.

The selected full-runtime path additionally uses the linked native repository's
``runtime24.yml`` workflow. It discovers official stable 2.4 point releases,
verifies the pinned primary signer, builds a coherent core/Pigeonhole/Lua pair,
and runs native plus real IMAP/LMTP/Lua HTTP authentication, metadata/notifier and
storage-transition tests. The source profile can advance independently of the
reviewed configuration/storage policy; an unsupported branch or changed key
requires review. Its exact ``relay_oid`` or ``CHATMAIL_RUNTIME_RELAY_OID`` must
refer to the reviewed published relay integration source. An absent OID is
unknown, not a branch fallback or successful integration test.

The ``upstream-2.4.5-alma10-x86_64`` lock profile consumes the frozen 43-CVE source
disposition file from the native repository. Audit options ``--build-manifest``,
``--runtime-rpm`` and ``--regression`` verify exact source, binary and runtime
receipt linkage. Source dispositions alone cannot qualify an artifact. A
security-qualified local candidate may remain unsigned, unpromoted and blocked
for full EL10 deployment; those are separate, visible outcomes.

CI publishes artifacts and status only. It creates no production-consumable
release, performs no remote activation and sends no messages. This matters
because the deployed legacy updater consumes the historical plugin release
namespace and can install packages even while the core is versionlocked.

Draft pull requests skip CI jobs, including candidate artifact publication.
Marking a draft ready for review triggers normal checks; relay CI also targets
the maintained ``el10-support`` branch.

GitHub schedules run from the repository's default branch. Since this fork's
maintained ``el10-support`` branch is not its default branch, daily relay intake
also needs a separately reviewed default-branch workflow entry that checks out
an exact reviewed relay commit, or an approved isolated runner. Source PR
publication leaves that activation pending. See `GitHub's schedule rules
<https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule>`_.

The optional owner Drive archive has a separate identity, consent, capture and
verification boundary documented in :doc:`drive-archive`; runtime maintenance
does not activate it or change the existing shared GCS archive/pruning path.
