# Supplied source metadata decisions

The T27 source component adds `verify_public_chain_source_interval` and
`decide_public_metadata_source`. Their readers return one bounded original per
call instead of materializing the entire member collection. The existing slice
interfaces remain available. `decide_public_metadata_owned` also permits one
owned historical high-water item to be released before reading the next.

The verifier authenticates Timestamp and Snapshot at both inclusive supplied
time endpoints, pins inventory references to the signed Snapshot before retaining
them, and checks each repeated member read against its exact original-byte
reference. Every member receives signature, context, semantic, denial and graph
checks at both endpoints. Missing, extra, duplicate, unreachable or changed
objects and failed reads cannot produce a successful result.

The decision source then rereads the complete inventory, verifies each original
again at both endpoints and applies the same prior-water comparison as the slice
API. A callback error returns no decision. Advancing Release revisions require
the exact previous original, its recorded digest and authenticated historical
Root, with unchanged business content under the renewal rules. Package originals
participate in graph verification but do not create version high waters.

Readers must enforce the byte limit **before allocating** their returned vector.
The component retains bounded references, contexts and proposed water updates;
nested graph checks can hold several bounded bodies simultaneously. This is not
a claim of one live allocation or a measured production peak. It adds neither an
aggregate download size limit nor a total download deadline.

These APIs accept supplied data. Their results establish no protected storage,
trusted clock, current qualification or installation authority. Before using a
decision, the Windows owner must authenticate and preserve the complete source,
historical time, Root and deny state, prove absence rather than treating storage
failure as absence, and atomically recheck and commit originals, references and
waters. Complete waterlog replay, product-wide Root migration, production owner
integration and the full active set remain unfinished. Root promotion and
production metadata writing remain gated.

Local Windows validation uses the standalone locked Cargo manifests for
`protocol/verify` and `metadata-owner`, with the project's Node 22 reference
oracle dependencies installed using `npm ci` in `specs/upgrade/v1`. The new tests
cover reread replacement/failure, endpoint expiry and denials, signed graph
oracle agreement, historical Release renewal and per-item prior release. Large
independent member tests demonstrate collections exceeding one MiB without
returning their bodies in the result; they do not measure protected scratch or
peak memory. No E2E or deployment is included.
