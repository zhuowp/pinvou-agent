# Windows manual updates

The first delivery supports Windows x64, Stable, a full NSIS installer, and an
explicit user action for both download and installation. Other platforms and
builds with an upgrade-host profile continue to report unsupported.

The download source is controlled at build time by PINVOU3_UPDATE_URL. The
Windows release build sets it to the current repository's HTTPS
releases/latest/download/latest.json asset. Local builds without a configured
feed report an unconfigured update source. Startup does not request that feed.

This mode trusts the HTTPS release publisher and verifies the installer's exact
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

## Build and publish the feed

The existing release-packages workflow produces the Windows NSIS installer,
its SHA-256 sidecar and latest.json in the same Windows Actions artifact.
An Actions artifact is not a public Release asset. The publisher must complete
the following publication step before the compiled feed URL works.

Download that Windows artifact to a local directory. Publish only a reviewed
source version with a new, matching stable tag. The tag must already point to
the installer build's source commit; do not reuse or move a historical tag.
The following commands deliberately require that existing tag:

~~~powershell
$repo = 'OWNER/REPOSITORY'
$version = 'NEW.STABLE.VERSION'
$installer = "pinvou-agent_$version-windows-x64-setup.exe"
$feed = Get-Content -LiteralPath latest.json -Raw | ConvertFrom-Json
$asset = $feed.platforms.'windows-x64'
if ($feed.latest_version -ne $version -or $asset.version -ne $version) { throw 'Version mismatch' }
if ($asset.format -ne 'nsis') { throw 'Wrong installer format' }
if ($asset.url -ne "https://github.com/$repo/releases/download/v$version/$installer") { throw 'Wrong release URL' }
if ((Get-Item -LiteralPath $installer).Length -ne $asset.size) { throw 'Size mismatch' }
if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256) { throw 'SHA256 mismatch' }
gh release create "v$version" $installer "$installer.sha256" latest.json --repo $repo --verify-tag --latest --title "Pinvou $version" --notes "Windows x64 manual update"
if ($LASTEXITCODE -ne 0) { throw 'Release publication failed' }
~~~

This last command publishes the release. For preparation and review, add
--draft and remove --latest; draft assets cannot serve the public update feed.
Do not report the feed as deployed until latest.json and the selected installer
are actually available from the configured HTTPS URLs.

For a locally built, canonically named installer, generate matching metadata with:

~~~text
node scripts/build-windows-update-manifest.mjs --installer PATH --repository OWNER/REPOSITORY --output latest.json
~~~

The generator reads VERSION, checks the filename and PE executable header, hashes
the actual bytes, and refuses to overwrite an existing output. Its unit fixture
is synthetic and does not certify a working installer.
