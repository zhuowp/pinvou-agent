# Windows manual updates

The first delivery supports Windows x64, Stable, a full NSIS installer, and an
explicit user action for both download and installation. Other platforms and
builds with an upgrade-host profile continue to report unsupported.

The managed update check is controlled at build time by
PINVOU_MANUAL_UPDATE_CHECK_URL. It must be an HTTPS endpoint such as
`https://updates.example.com/v1/updates/manual/check`. The client sends the
current stable version and a persisted, randomly generated 64-character
lowercase hexadecimal device ID. The service returns `204 No Content` when no
eligible update is assigned, or `200 OK` with the existing `latest.json` schema
for the assigned Windows x64 NSIS artifact. A managed check failure is surfaced
to the user and never falls back to another feed. Local builds without this
backend URL report an unconfigured update source. Startup does not request it.

The service response supplies the artifact download URL, exact size, and
SHA-256; the client downloads that URL and verifies the installer's exact
size and SHA-256. It does not implement the full protocol's signed metadata,
trusted-time, Session authorization or installation-wide ownership. It must not
be used to infer those permissions from ordinary JSON or process exit.

## User flow

1. Check explicitly from Settings.
2. Download the selected full installer. Progress reports actual received bytes;
   the verified result is separate from receiving the final byte.
3. Save work and finish running tasks, then choose Install and quit.
4. Confirm Windows elevation and complete the ordinary installer.
5. On the next startup, compare the running version with the pending target.
   This is a local observation, not proof of installer completion or a server ACK.

The backend owns selection IDs and download receipts. URLs, checksums and paths
sent back by the webview cannot select another executable. It rechecks the held
file before native launch. UAC cancellation keeps the downloaded selection
retryable. Downloads use an inactivity timeout, with no hard total duration.

This first mode checks local activity but does not freeze every user or service.
Users must finish background work before installation. Data-schema migrations,
silent installation, forced updates and automatic cross-user termination are
outside this delivery.

## Backend distribution

The operator uploads the reviewed Windows x64 NSIS installer through the update
management backend. The backend verifies the product version, exact size and
SHA-256, stores the immutable bytes, and serves the update check and download
routes. Clients do not request GitHub or another public release feed.

Configure `PINVOU_MANUAL_UPDATE_CHECK_URL` at build time with the backend check
endpoint, for example `https://updates.example.com/v1/updates/manual/check`.
The response contains the backend artifact URL, exact size and SHA-256. The
client checks those bindings again while downloading and before native launch.
A `204 No Content` response means this installation is not currently selected.

A release remains unavailable until an operator has uploaded and the backend has
verified it, then started or resumed its rollout. Pausing affects later checks;
it does not revoke an already downloaded installer.
