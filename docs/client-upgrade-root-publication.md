# Protected Root publication

This T27 component joins the actual Windows TimeOwner's verified response to a
single protected V2 publication transaction. It does not implement the
application update check, grant installation authority, or complete T27.

## Entry and evidence

Every nonempty RootScratch uses this operation, including streams beyond 4096
objects. RootScratch shards remain bounded; 4096 is not a total stream limit.
The legacy member writer rejects changes to its Root sequence. Zero-successor
refreshes preserve the accepted Root and check the member's own policy and
catch-up cursor, without applying another member's current metadata policy to
previously accepted Root history.

Only TimeOwner's actual network-verification branch constructs PendingRootTime.
It owns the verified Evidence and retains the genuine native send/verification
counter samples, exact running-service and scratch bindings, and predecessor
Root identity. Neither serialized inputs nor fixture constructors mint it.
Evidence.received remains the original observation bracket.

## Transaction and active set

The writer acquires BootstrapGuard, ProductGuard and one outer TxR transaction.
It reauthenticates the service and expected issuer state, incarnation, policy,
budget/time floor, catch-up cursor and actual shared Root predecessor. Existing
history undergoes full Root/time and captured-metadata replay. Unprovable V1
metadata witnesses and nonempty legacy member Roots under shared genesis refuse
advancement with SourceUnavailable; missing originals never imply an empty set.

StagedV2Batch uses a requester-private sibling outside the product subtree in
the same transaction. Complete before/after time and metadata censuses pin all
current members and their retained originals. Each member's global denial list
is checked separately, without inventing a capped union. The final signed Root
must still verify every latest accepted graph. Cached metadata body expiry does
not prevent Root recovery and does not grant current metadata-use rights.

The fixed V2 batch records the actual issuer pre-state, member metadata/policy
ceilings, original Root stream and signed time evidence. Source and staging
checks precede copying it into the product history. Product Root Head, history
Head and issuer CleanupPending time successor are written in the same TxR;
catch-up is consumed there. Staging is removed before final replay. A fresh
native view checks the new lineage, captured active sets and all member time
states rather than reusing a fingerprint of the old product subtree.

## Late acceptance and uncertain outcomes

After expensive replay and Root decoding, the owner privately constructs a
transaction-bound registration view from actual retained keys. A Root-only
native sampler checks its bounded registration pins, ACLs and actual SCM identity
on both sides of another genuine service counter sample. It does not call the
generic sampler's Store::read, which could replay all accepted Root history after
the counter observation. Native incarnation continuity and advance_interval move
the signed bounds to that sample, then check the candidate Root's validity
window. The private LateRootAcceptance cannot become a current-time DTO or a
general clock capability. A bounded budget successor retains its lower floor in
the same outer transaction without creating spending-window authority. Only
bounded finalization, service/cancellation checks and commit follow this sample.
The evidence does not claim UTC validity at the physical commit instant.

After commit, the writer flushes and reopens actual protected storage, verifies
the intended Root Head, final Root, issuer revision, budget floor, complete
lineage and captured metadata. Commit, flush or readback uncertainty returns
StateCommitUnknown. It never returns a success receipt from a staged-only view.

## Verification boundary

The public signed fixture contains a nonempty five-role graph and three Roots.
Its independent protocol oracle accepts the graph at its original observation,
rejects a fresh use after expiry, accepts Root recovery under retained dual
trust, and refuses removal of the old signing key while that graph is active.
The native DATA fixture uses real journals and abandoned TxR transactions for
source/stage tampering, successful V2 capture, rejected key exit, historical
prefix policy isolation and rollback checks. It does not forge a running service
or positive native clock, commit a Root, or exercise the production owner.

The CI component job pins the public Seed/Root hashes and requires both the
ordinary component marker and the signed nonempty Root fixture marker. The
test-only build feature continues to reject production profiles and arbitrary
fixture inputs.

Local first-operation HKCU TxR tests fail with ERROR_RM_NOT_ACTIVE (6801).
Actual privileged fixture execution, simultaneous native scratch/index/outer
TxR behavior, SCM-bound publication, interrupted commit/restart, and full
application integration remain unverified. Compile, protocol or source-review
evidence must not be reported as those runtime scenarios passing. No E2E or
deployment was run.
