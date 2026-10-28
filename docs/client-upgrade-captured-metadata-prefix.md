# Captured member metadata prefixes

This T27 component verifies historical metadata under an authenticated native
Root batch's captured member ceiling. It is DATA verification, with no running
service, current clock, Root commit, update-check or installation capability.
Production Root promotion gates remain closed.

## Explicit witnesses and provenance

V2 member snapshots require five separately bounded blobs: bootstrap record,
metadata genesis, publication Head, waterlog Head and metadata-role Policy.
Existing enrollment, Host, original Root, time header/evidence and global Policy
remain bound to the enclosing member record. Graph bodies are retained in their
native journals and are not duplicated into the snapshot.

V1 bytes retain their existing canonical encoding and Root/time-lineage reader.
V1 cannot satisfy a captured metadata assertion: the captured reader returns
SourceUnavailable rather than interpreting missing fields as an empty set.
Unknown versions and missing, null or partial V2 descriptors fail closed. A real
advanced V1 store would need a separately justified compatibility path; this
component does not backfill absent evidence. Production advancement was gated.

Only the completed native Root/time-lineage owner mints CapturedRootMember from
the actual fixed batch/member path, complete member chain and retained product
fingerprint. A DTO, a key and an arbitrary expected record cannot mint it. The
capability derives its predecessor Root prefix internally. Raw snapshot readers
return DATA and do not mint this capability.

## Historical ceilings

The captured time reader binds the actual retained profile path, bootstrap,
original Root and Host-history ancestor to the captured registration. Today's
Host epoch and time Head may have advanced. They remain source pins, while
semantic time/evidence replay stops at the captured header. Later time rows
undergo canonical header/payload-shape and hash-chain checks without resolving
future compact Roots under the older prefix. Recorded samples must select a
signed observation within the captured ceiling.

The waterlog worker checks the whole current structural journal and its exact
counts twice, exposing only the captured prefix to callbacks. It reaches the
captured terminal hash and permits a legitimate retained suffix. Publication
records must end at the captured metadata Head and agree with that waterlog
prefix. Missing namespaces never become genesis.

The captured metadata reader shares historical time, graph/signature, prior-water
and cumulative role-denial replay with the current/live owner. Its active set is
the latest graph at the captured ceiling, with that snapshot's global and role
denials. Today's policy never replaces historical authority. Expired cached
bodies may undergo final-Root signature compatibility checks without gaining
fresh metadata-use rights.

Batch metadata visits compare complete validated censuses before, during and
after callbacks, including the separate profiles holding retained originals.
A Root snapshot fingerprint alone would not pin those profile sources. Native
Root batch verification reuses the same historical signed-time verification,
retains its final Root proof and checks every captured member's active graph.
Root/time lineage and metadata completeness remain separate checks.

## Validation and remaining integration

The existing lab-only native runner now prepares V2 descriptors outside the
product subtree, stages a real public signed Root/time batch in an uncommitted
TxR and reconstructs the native lineage capability before reading the captured
empty metadata prefix. It checks V1 refusal, V2 blob mutation, source restoration
and batch-level metadata verification. The fixture never constructs SCM proof,
samples a live clock or commits a product Root. It covers one member and an
empty graph, not a nonempty publication/restart or two-member interleaving.

On this device direct TxR tests fail at RegCreateKeyTransactedW with
ERROR_RM_NOT_ACTIVE (6801). New native cases remain compile-only until that
prerequisite works. Unit execution and compilation must be reported separately
from protected native runtime acceptance. Retained-history workload latency and
peak native scratch memory remain unmeasured.

The production publisher still writes its existing snapshots and remains gated.
It must adopt V2 sibling staging, complete current census, final-Root active
checks, atomic product/issuer Head updates and complete post-write/readback
verification before promotion can be enabled. The application check is still
unsupported. No E2E, deployment or Linux/macOS upgrade work is included.
