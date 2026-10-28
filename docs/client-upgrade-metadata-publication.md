# Windows historical metadata publication

The native metadata owner can publish checked historical observations and reload
their receipts. This is passive trust-cache storage, not online qualification,
current eligibility, an upgrade Session or installation permission. No IPC or
application update-check route has been enabled by this component. Product Root
promotion still requires the separate complete active-set transition and keeps
its existing emptiness gate.

`Store::publish_metadata` takes an actual started-service context and bounded
raw Timestamp, Snapshot and member originals. It acquires its own bootstrap and
product guards and registry transaction. Root, current time, policy and prior
waters come from that native source; the caller cannot supply their authority.
Member readers must enforce the one-MiB object limit before allocation. The
owner rejects oversized returned data and does not retain the entire collection.

Originals first enter a protected staging sibling in the same transaction.
The existing waterlog remains unchanged while complete signatures, graph,
rollback/equivocation and Release renewal checks use replayed prior waters.
Each staged read is pinned to its original digest. After the old prefix and
exact current policies are rechecked, the final originals are copied and reread,
and staging is deleted before commit. An unlinked new waterlog row is never
introduced while prior lookups still expect the old complete inventory.

The final observation refreshes the genuine same-source native counter witness.
It must advance both original bounds monotonically, and its latest bound must
remain strictly before the earliest expiry of Root and every expiring metadata
object. Package has no expiry. The complete graph has already been verified on
the immutable originals; its remaining time-varying checks are those windows.
The final sample, exact global and role policies, original-byte journal, active
graph reference and metadata history/head are committed together. The same
transaction also retains the observed trusted lower bound in the existing
budget floor owner, so a successful publication cannot lose that knowledge on
restart. No numeric caller-provided floor or serialized sample is accepted.

Role-deny knowledge is retained across admitted snapshots and by current native
policy. Removing a key, moving its denial to another role, omitting a role or
resetting known lists fails closed. Later denials do not retroactively replace
the historical policies used to verify older accepted graphs. No policy mutation
port is added.

Cancellation before native commit rolls back the transaction. A commit failure
or any failure during committed flush and exact readback returns
`StateCommitUnknown`, with no successful receipt. Restart/retry loads actual
committed history and replays it; missing, partial or corrupt state is never
healed into empty state. Strict first-install/genesis checks remain separate.

A receipt exposes only historical revision, head digest and sampled interval.
The interval describes the actual counter observation, not physical commit or
return time. Scheduling and commit latency are not assumed bounded. Any future
current-use consumer must obtain its own fresh trusted checks and required
cleanup completion. Passive caching preserves CleanupPending and grants no
permission to clear the barrier or begin a dependent upgrade action.

The focused tests exercise expiry boundaries, source errors, canonical history
binding, bounded inputs and cumulative role policies. The existing public native
fixture includes staging mutation, bottom-up deletion and partial-construction
rollback followed by a new transaction; it does not forge a service context or
execute the complete Store publisher. Complete staging/delete/commit/readback, scratch interaction and
SCM/restart execution remain unverified on this device because the first native
registry transaction operation fails with ERROR_RM_NOT_ACTIVE (6801). Hosted CI
and production MSVC packaging are not validated by these local checks. No E2E
or deployment is included.
