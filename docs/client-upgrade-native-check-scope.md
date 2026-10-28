# Native initial check scope

This direct T27 prerequisite gives fresh Windows host installations a protected
installation identifier and initial channel record. It does not complete
SourceFacts, online update checks, channel switching or legacy migration.

The actual first-install owner generates a separate 32-byte BCrypt random
`installId`, encoded as 64 lowercase hexadecimal characters. It differs from
the actual installationScopeId and original install operation ID. These IDs
are correlation data, not authentication. The new owner belongs to the existing
product/component/target/profile installation scope. All users of that machine
installation share its protected native64 registry state; it does not create a
product-wide identity shared with unrelated component/profile installations.

The private `check-scope-v1` key contains exactly `Genesis` and `Head` binary
values and no children. Each canonical closed object is bounded to 4096 bytes.
Genesis binds the generated ID to the original Seed, manifest, scope and install
operation. A separate Head binds the initial channel and revision to the exact
Genesis digest. Stable is the specified default channel; the first revision is
1. The reader uses persisted bytes, and never fills a missing record with these
defaults.

Version 1 has only a real initial-head producer. It accepts only that produced
Stable/revision-1 state. A hand-written Beta/Internal or higher-revision Head
does not establish an approved channel transition. T40 still needs administrator
confirmation, audit and atomic workflow invalidation before a switch can be
exposed. A future transition must update the current setting without restoring
it from the original Genesis.

Initialization joins the existing outer protected registration/catalog/owner
transaction. Staged readback, committed fresh-handle flush and recovery checks
include the new owner. A precommit failure publishes no partial scope. An
uncertain commit or failed postcommit verification remains StateCommitUnknown;
recovery reads the existing owner and never generates a replacement ID for an
existing registration. Later revisions, restart and the existing same-build
tombstone reinstall retain the ID and owner bytes.

Fresh registrations explicitly include `native-check-scope-v1` in their ordered
owner namespace set. The prior complete owner set remains initialized for the
existing metadata, time and preparation operations; the old lab bootstrap-only
set remains distinct. Existing registrations never acquire the new namespace
through an ordinary update. Recognized legacy absence yields SourceUnavailable
for scope inspection. A claimed new owner with missing, malformed, substituted
or extra state refuses; an unexpected owner on a legacy registration is not
migration consent. Original v2/v3 installer and registration bytes are not
rewritten.

Retained image inspection joins the current registration and protected scope
read, then pins the owner across the actual image/inventory/SCM checks and later
refreshes. Changed owner state cannot silently replace facts belonging to an
earlier operation. Failed or cancelled refresh invalidates the projection. The
scope JSON accessor refreshes before returning the exact seven-field API scope:
product, component, installId, installationScopeId, channel, channelRevision and
targetKey. Returned bytes are historical inspection DATA. A future complete
NativeSourceFacts producer must retain and recheck the actual native source
across network waits; deserializing JSON cannot confer source authority.

Verification uses the existing isolated native component fixture and immutable
profiles. Its actual reopened owner projection is checked by the existing
frozen `api/scope` schema oracle in the required Windows component job. Native
registry DATA tests do not construct a live installed-image or service context.
Real installed scope/SCM refresh and multi-user behavior remain unverified in
the local unelevated environment, whose direct first TxR operation fails with
ERROR_RM_NOT_ACTIVE (6801). Compilation and pure DATA checks do not replace that
execution. No E2E or deployment was run.
