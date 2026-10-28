# Current catalog member metadata source

This T27 component reads historical DATA for every current protected product
member, including components whose service is stopped. It does not construct a
running service context, sample a live clock, publish a product Root, accept a
new metadata graph, or enable the application update check.

## Source and replay

The owner supplies its actual Seed, product guard and held native transaction.
The factory visits the protected product directory and opens each member's fixed
profile path. Bootstrap binding comes from that member's enrollment, original
Root and actual Host registration, rather than from the requesting component's
Seed. Missing namespaces or unknown layouts fail; they never mean an empty set.

Live-owner and read-only member paths share one historical time replay kernel.
It traverses every retained header, separated evidence and transition to the
exact pinned Head. An Unknown current state can be valid retained history, but
cannot itself supply a signed historical observation. Each metadata batch's
actual same-transaction stored Sample selects its authenticated recorded time
state; no caller-supplied sample becomes current time authority.

Advanced compact time states resolve through an opaque signature-lineage prefix
minted by completed product Root history replay. It binds the exact Seed, guard,
transaction and complete protected product subtree bytes. A restricted prefix
can resolve only already authenticated ancestor positions. This proof concerns
Root/time lineage; it does not attest to metadata completeness or promotion.

Metadata history uses the same graph/signature/high-water decision and protected,
never-committed scratch index as the live owner. The reader checks publication
records, complete waterlog structure, historical samples, original graphs and
cumulative role-denial retention. It streams only the latest accepted graph as
the current cached active set, releasing originals individually. Callback
observations remain provisional until all traversal and source rechecks succeed.
Both factories compare complete validated member censuses before callbacks,
during callbacks and after callbacks. The metadata census additionally binds
each metadata Head and role policy, so a later callback cannot silently replace
an earlier member's cached source. Fingerprints are framed and streamed; no
aggregate history-body collection is built.

The streamed signed time-response proof can check an active envelope against its
privately retained final Root. This reuses the existing Schema, complete-context
and signature checks, including streams beyond 4096 Root successors. Cached
metadata body expiry is not reinterpreted as a reason to reject Root recovery;
historical cache does not grant fresh metadata-use or installation authority.

## Remaining integration

Root promotion gates remain closed. The production Root publisher, its complete
read-set census and persisted per-batch member snapshots still require explicit
integration of this metadata source. Current-member sources are not factories
for historical member snapshots. In particular, a current time Head may refer
to a later Root than an earlier captured batch; a historical-ceiling factory
must prove that source separately rather than silently substituting current
state. The existing product Root snapshot format does not yet bind nonempty
metadata history.

The application check still returns unsupported. No IPC publication route,
installation permission, server change, Linux/macOS upgrade work, E2E or
deployment is part of this component.

## Validation boundaries

Native Windows gnullvm builds and deterministic tests are separate from real
protected runtime evidence. On this device the first HKCU
`RegCreateKeyTransactedW` fails with `ERROR_RM_NOT_ACTIVE` (6801). Native mutation
fixtures are compile-only until that registry transaction prerequisite works;
ordinary registry access and successful compilation do not prove TxR behavior.
The catalog-member fixture covers one actual member's exact empty genesis,
post-view Head/policy mutation, propagated callback failure and restored-source
reuse. It is compile-only on this device. It does not exercise two-member
callback interleavings, a nonempty member graph, or captured historical sources.
The existing fixture also does not execute the full SCM-bound metadata Store
publisher/restart pipeline. No service context is forged to bypass this gap.

Independent component review and execution evidence must apply to the fixed
delivery tree. Hosted CI and merge/release eligibility remain separate gates.
