# Windows historical Root, time and metadata sources

This T27 component retains and replays protected Windows product Root history,
member snapshots and time observations one bounded object at a time. It does
not enable Root promotion, a production metadata acceptance writer, online
qualification or installation. Existing production gates remain closed.

The native time read set owns the profile binding and borrows its original
product guard, private key and registry transaction. Historical time replay
checks every retained header through the captured current Head, separated
evidence, signatures, transitions and the requested exact historical position.
A cached historical anchor replays the entire source again before and after
sample verification. Checking only the current Head is insufficient if another
holder writes an earlier separated response in the same transaction.

`visit_metadata_time` opens the fixed metadata namespace from that actual time
read set. Private-key and transaction identity are checked explicitly; equal
Rust lifetimes do not establish transaction identity. Samples are loaded from
actual waterlog batches bound to their Record and complete Head chain, not from
a caller-supplied serialized sample. The sample's exact historical time revision,
incarnation and counters reproduce its recorded interval. Global policy must
match the observation's admission policy exactly; role policy is canonically
parsed against the same owner binding. Visitor observations remain provisional
until complete waterlog and historical-time rechecks succeed. A later visitor
cannot invalidate an earlier consumed time source unnoticed.

Metadata replay checks each batch's full signed graph and high-water comparisons
using that historical Root, interval and denial state. Only earlier successful
batches supply priors. A native protected scratch index retains contexts and
high waters in its own transaction, which is never committed. Release originals
and their accepting historical Roots are separate bounded objects, loaded one
prior at a time. Idempotent Release observations preserve the original accepting
Root; advancing revisions use the shared authenticated renewal rules. Failed
queries remain errors rather than absence, and a failed construction returns no
partial replay. The completed result borrows its exact original source; later
reads recheck complete metadata/time history and the original native position.

This replay reconstructs historical DATA. Production publication still needs
genuine live-sample capture into the same batch transaction, exact current
policy/read-set rechecks, atomic originals/waters/active-reference persistence,
ambiguous-commit recovery and the complete product-wide active-set transition.
The current metadata bootstrap and Root-transition emptiness gates deliberately
do not accept nonempty history. No standalone hash, DTO or scratch index may be
used as permission or as a substitute for those remaining owner checks.

The component uses existing standalone host tests and the isolated native
metadata fixture. Native gnullvm compilation is distinct from MSVC production
packaging. The fixture compiles with the fixed public historical test Seed and
Root; this is not production trust or successful privileged execution. Ordinary
Windows unit tests exercise signed historical evidence and sample/policy/header
checks. Two direct HKCU transaction tests currently fail on this device at the
first `RegCreateKeyTransactedW` with `ERROR_RM_NOT_ACTIVE` (6801); the registry
resource-manager cause remains unresolved. Real protected scratch, TxR/SCM,
compact-Root and restart/recovery execution remain unverified. No E2E or
deployment is included, and no aggregate download timeout is introduced.
