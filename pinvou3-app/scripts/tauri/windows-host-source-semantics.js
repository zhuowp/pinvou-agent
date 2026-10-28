// Public image-bound declarations only, never current SourceFacts or mode proof.
const { IDENTIFIER, exactObject, parseCanonical, canonicalBytes, readPublicFile, refuse } = require("./windows-host-profile.js");

const MAXIMUM_SOURCE_SEMANTICS_BYTES = 64 * 1024;
const CONTEXT = ["product", "component", "targetKey", "profileKind", "profileId", "buildId", "layoutId", "appVersion", "seedSha256"];
const ROLES = ["application", "helper", "launcher"];
const SUPPORT = ["supportedOwnershipProtocols", "supportedDataFormats", "supportedMigrationProtocols"];

function validate(profile, value) {
  exactObject(value, ["sourceSemanticsVersion", ...CONTEXT, ...ROLES, ...SUPPORT]);
  if (value.sourceSemanticsVersion !== 1) refuse("HOST_BUILD_SOURCE_SEMANTICS_INVALID");
  for (const key of CONTEXT) {
    const expected = key === "seedSha256" ? profile.seedSha256 : profile.seed[key];
    if (value[key] !== expected) refuse("HOST_BUILD_SOURCE_SEMANTICS_CONTEXT");
  }
  const identifier = (item) => typeof item === "string" && IDENTIFIER.test(item);
  for (const role of ROLES) {
    exactObject(value[role], ["identity", "publisher"]);
    if (!identifier(value[role].identity) || !identifier(value[role].publisher)) {
      refuse("HOST_BUILD_SOURCE_SEMANTICS_INVALID");
    }
  }
  for (const key of SUPPORT) {
    const entries = value[key];
    if (!Array.isArray(entries) || entries.length > 64 || !entries.every(identifier)
        || new Set(entries).size !== entries.length) refuse("HOST_BUILD_SOURCE_SEMANTICS_INVALID");
  }
  return value;
}

async function snapshotSourceSemantics(profile, value) {
  // An independent canonical copy cannot drift while file hashing/signing awaits.
  return validate(profile, await parseCanonical(await canonicalBytes(value), MAXIMUM_SOURCE_SEMANTICS_BYTES));
}

async function loadSourceSemantics(profile, environment = process.env) {
  const file = environment.PINVOU_HOST_SOURCE_SEMANTICS;
  if (file === undefined) return null;
  if (!profile) refuse("HOST_BUILD_SOURCE_SEMANTICS_PROFILE_REQUIRED");
  return validate(profile, await parseCanonical(readPublicFile(file, MAXIMUM_SOURCE_SEMANTICS_BYTES), MAXIMUM_SOURCE_SEMANTICS_BYTES));
}

module.exports = { MAXIMUM_SOURCE_SEMANTICS_BYTES, snapshotSourceSemantics, loadSourceSemantics };
