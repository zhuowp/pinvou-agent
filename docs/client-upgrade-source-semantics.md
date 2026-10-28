# Image-bound source declarations

This T27 prerequisite carries explicit build declarations through the existing
Windows host installer manifest and retained installed-image inspection. It
does not produce complete current SourceFacts or enable an online update check.

The supported project build entry reads optional `PINVOU_HOST_SOURCE_SEMANTICS`,
an absolute path to a public canonical JSON object of at most 64 KiB. It requires
the existing explicit Seed/Root profile. The declaration is loaded before native
build effects and retained independently of later changes to the input file.
No identity, publisher, ownership, data or migration labels have defaults.

The closed object has `sourceSemanticsVersion: 1`; `product`, `component`,
`targetKey`, `profileKind`, `profileId`, `buildId`, `layoutId`, `appVersion` and
`seedSha256` must equal the selected Seed context. Its `application`, `helper`
and `launcher` objects each contain exactly `identity` and `publisher`. These
are logical identifiers, not certificate names or Windows CompanyName values.
`supportedOwnershipProtocols`, `supportedDataFormats` and
`supportedMigrationProtocols` are arrays of zero through 64 unique identifiers.
Every identifier is 1–128 ASCII characters matching
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Comparison is case sensitive; array order is
retained. Empty support arrays declare no supported values.

Supplying this input emits explicit host manifest v3 with an inline
`sourceSemantics` object. The existing complete manifest resource 34101 and
inventory shards bind it to the actual final role hashes and full application
inventory. No additional PE resource or image self-hash is introduced. The
native resource adapter and Rust protected-manifest reader reject missing,
unknown, substituted or mismatched declarations. Omitting the input preserves
the exact v2 producer format and existing installation behavior. V2 forbids the
new member; v3 requires it. Unknown manifest versions refuse.

After actual retained native image, inventory, version, registration and SCM
checks, `InstalledImageObservation::source_semantics_json()` returns canonical
declaration DATA from the last completed inspection. Refresh checks the same
declaration and manifest context. This accessor does not grant freshness or
current qualification: v2 returns SourceUnavailable, and callers must preserve
the existing inspection and refresh contract. Existing v2 time and metadata
operations do not require a declaration or rewrite their genesis.

These declared supported values cannot certify the actual installed ownership
protocol, all-user data format, migration protocol, time mode, installation ID,
channel revision or four SourceFacts digest preimages. Those need their real
state owners and consumers. Diagnostic output continues to report
source_facts_produced, current_qualification and installation_permission false.

Verification includes closed/context-bound DATA negatives, exact v2 bytes,
actual JS-producer/Rust-reader fixture interoperability and disposable Windows
PE resource mutation/readback with positive controls. The PE copies are never
executed or trusted as host roles. The fixed interoperability test runs
explicitly with the allowlisted metadata component Seed/Root; the default host
suite leaves it ignored. CI routes declaration and native packaging changes to
the existing required Windows component gate.

An actual installed v3 SCM/TxR pipeline remains unverified in the local
environment. Existing direct TxR tests fail at their first operation with
ERROR_RM_NOT_ACTIVE (6801). Native file-resource testing, pure DATA and compilation
do not replace that acceptance. No E2E or deployment was run.
