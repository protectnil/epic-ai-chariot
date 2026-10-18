#!/usr/bin/env node
/**
 * @epicai/chariot — REST credential-map generator
 *
 * Defect: `chariot add`/`chariot health` compute required env-keys from
 * `rest.envKey` (adapter.rest) and `effectiveEnvKeys()` (MCP env-keys +
 * CANONICAL_CREDENTIALED_BRANDS fallback). Neither surface knows about the
 * per-field constructor requirements of REST adapters whose auth needs MORE
 * than a single bearer token (e.g. paypal: clientId+clientSecret; acumatica:
 * clientId+clientSecret+username+password+instanceUrl). None of the 6,229
 * catalog rows carries `rest.envKey`, so `chariot add` never prompts for
 * these fields, `chariot health` reports the adapter healthy, and dispatch
 * (src/engine/server/toolHandlers.ts REST branch) constructs the adapter
 * with only `{apiKey, baseUrl}` — the constructor's own required-field
 * checks then throw "<field> is required" on every customer call.
 *
 * This script is the single source of truth generator for
 * src/engine/types/rest-credential-map.generated.ts — it reads every
 * src/engine/mcp-servers/*.ts module backing a catalog row that declares
 * `rest.module` + `rest.authType` (453 rows at generation time — the REST
 * adapters that need per-field credentials, as opposed to the 623 rows with
 * `rest.authType` absent/null, which need none), and produces one
 * RestCredentialEntry per adapter:
 *
 *   { required: Field[], alternatives: Field[][], optional: Field[] }
 *
 *   - required     every field in this list must be present.
 *   - alternatives at least one FULL group must be present (e.g. a
 *     constructor accepting `bearerToken` OR `username`+`password`).
 *     Empty array = no alternative-credential requirement.
 *   - optional     passed through to the adapter when set; never blocks
 *     'configured'/'fully-credentialed' status.
 *
 * TWO sources feed the map:
 *
 *   1. AUTOMATIC extraction (413/453 modules) — deterministic regex over
 *      two constructor shapes:
 *        LOOP      `for (const __k of (['a','b'] as Array<keyof typeof
 *                  config>)) { if (config[__k] === undefined || ...) throw
 *                  ...}` — the bracketed list IS `required`.
 *        SINGLE-IF one or more independent `if (config.X === undefined ||
 *                  config.X === null || config.X === '') { throw ... }`
 *                  checks, each naming exactly one required field.
 *      A completeness audit then re-scans the WHOLE constructor body for
 *      any OTHER credential-shaped field reference (apiKey, accessToken,
 *      username, password, bearerToken, clientId, clientSecret, token,
 *      sessionToken, secret, refreshToken, privateKey, certificate,
 *      sessionCookie) that automatic extraction did not capture. If found,
 *      the id is NOT auto-mapped — it falls to the HAND-CURATED table below
 *      instead of being mapped with an incomplete/wrong subset.
 *
 *   2. HAND-CURATED overrides (`MANUAL_OVERRIDES` below) — every id the
 *      automatic pass could not resolve deterministically (OR-logic,
 *      function-typed fields, or a completeness-audit miss) was read BY
 *      HAND, constructor by constructor (2026-09-30 audit), and classified
 *      into required/alternatives/optional by what the constructor's OWN
 *      code actually does with the field — not by regex shape:
 *        - a field the constructor throws on if absent -> required
 *        - a field used inside a throwing if/else-if/else auth-selection
 *          chain (e.g. `bearerToken` OR `username`+`password`) -> one
 *          alternatives[] group per branch
 *        - a field the constructor accepts, uses unchecked, and does NOT
 *          throw on if absent, but which the OPERATION genuinely cannot
 *          function without (e.g. qualys builds a Basic-auth header from
 *          `username`/`password` with no validation — silently broken,
 *          not silently fine) -> required, overriding the constructor's
 *          own missing validation, because leaving it optional would
 *          reproduce the exact "false-green, breaks at call time" defect
 *          this fix exists to close
 *        - a field genuinely optional in operation (a public API that
 *          works unauthenticated, or a supplementary/refresh-flow field
 *          not needed for the primary call path) -> optional
 *        - a field whose declared TYPE cannot be represented as a string
 *          env var (e.g. a caller-supplied signing CALLBACK) -> left OUT
 *          of the entry entirely; cited by exact file:line in this file's
 *          header comment on that override, and reported unresolved by
 *          the generator's summary `manualUnmappable` list (never
 *          silently dropped). redshift originally fell in this bucket
 *          (`signRequest`, a SigV4 callback) — fixed 2026-09-30 by making
 *          the ADAPTER build its own SigV4 signer from
 *          accessKeyId/secretAccessKey internally (see the redshift
 *          MANUAL_OVERRIDES entry below), the same pattern the sibling AWS
 *          adapters already used, rather than leaving the map unable to
 *          express it — a caller may still inject its own `signRequest`
 *          callback, which takes priority when supplied.
 *
 * Env-var naming: `<ADAPTER_ID upper, non-alnum→_>_<field UPPER_SNAKE>`,
 * e.g. paypal.clientId -> PAYPAL_CLIENT_ID.
 *
 * Run: node scripts/gen-rest-credential-map.mjs
 * Writes: src/engine/types/rest-credential-map.generated.ts
 * Prints a summary to stdout — read it; it is the report, not just a log.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const bundle = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'chariot-adapter-bundle.json'), 'utf8'));
const cat = bundle.catalog;

// rest.module present AND rest.authType truthy == the REST-with-required-
// credentials cohort (453 rows) — rows with rest.module but no authType
// (623) declare no auth and correctly need no env vars.
const restRows = cat.filter(r => r.rest && r.rest.module && r.rest.authType);
const byId = new Map();
for (const r of restRows) if (!byId.has(r.id)) byId.set(r.id, r);

function snake(field) {
  return field.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
}
function prefixFor(id) {
  return id.toUpperCase().replace(/[^A-Z0-9]/g, '_');
}
function f(id, field) {
  return { field, envVar: `${prefixFor(id)}_${snake(field)}` };
}

// ─── HAND-CURATED OVERRIDES (2026-09-30, read constructor-by-constructor) ──
//
// Each entry cites the field, its treatment, and why — see the header
// comment above for the classification rule.
const MANUAL_OVERRIDES = {
  // ── OR-logic: exactly one full alternative group required ──
  bizzabo: {
    // constructor: `if (!config.apiToken && !(config.clientId &&
    // config.clientSecret)) throw 'requires either apiToken or clientId +
    // clientSecret'`. accountId/baseUrl unchecked+optional.
    required: [], alternatives: [[f('bizzabo', 'apiToken')], [f('bizzabo', 'clientId'), f('bizzabo', 'clientSecret')]], optional: [],
  },
  pandadoc: {
    // constructor: `if (!config.apiKey && !config.accessToken) throw
    // 'requires either apiKey or accessToken'`. baseUrl optional.
    required: [], alternatives: [[f('pandadoc', 'apiKey')], [f('pandadoc', 'accessToken')]], optional: [],
  },
  'oracle-erp-cloud': {
    // constructor: baseUrl is checked with its own throw (unconditional).
    // Then `if (config.accessToken) ... else if (config.username &&
    // config.password) ... else throw 'requires either accessToken or
    // username+password'`.
    required: [f('oracle-erp-cloud', 'baseUrl')],
    alternatives: [[f('oracle-erp-cloud', 'accessToken')], [f('oracle-erp-cloud', 'username'), f('oracle-erp-cloud', 'password')]],
    optional: [],
  },
  'elastic-apm': {
    // kibanaUrl has its own throw (unconditional). Then `if (config.apiKey)
    // ... else if (config.username && config.password) ... else throw
    // 'requires either apiKey or username+password'`.
    required: [f('elastic-apm', 'kibanaUrl')],
    alternatives: [[f('elastic-apm', 'apiKey')], [f('elastic-apm', 'username'), f('elastic-apm', 'password')]],
    optional: [],
  },
  'elastic-security': {
    // Same shape as elastic-apm; spaceId optional (not credential).
    required: [f('elastic-security', 'kibanaUrl')],
    alternatives: [[f('elastic-security', 'apiKey')], [f('elastic-security', 'username'), f('elastic-security', 'password')]],
    optional: [],
  },
  'servicenow-grc': {
    // `instance` required via the __k loop. Then `if (config.bearerToken)
    // ... else if (config.username && config.password) ... else throw
    // 'authentication required. Provide either bearerToken or both
    // username and password.'`. baseUrl derived-optional.
    required: [f('servicenow-grc', 'instance')],
    alternatives: [[f('servicenow-grc', 'bearerToken')], [f('servicenow-grc', 'username'), f('servicenow-grc', 'password')]],
    optional: [],
  },
  'servicenow-itsm': {
    // Same shape as servicenow-grc.
    required: [f('servicenow-itsm', 'instance')],
    alternatives: [[f('servicenow-itsm', 'bearerToken')], [f('servicenow-itsm', 'username'), f('servicenow-itsm', 'password')]],
    optional: [],
  },
  xmatters: {
    // `baseUrl` required via the __k loop. Then `if (config.apiToken) ...
    // else if (config.username && config.password) ... else throw 'supply
    // apiToken or username+password'`.
    required: [f('xmatters', 'baseUrl')],
    alternatives: [[f('xmatters', 'apiToken')], [f('xmatters', 'username'), f('xmatters', 'password')]],
    optional: [],
  },
  splunk: {
    // `host` required via the __k loop. Then `if (config.token) ... else
    // if (config.username && config.password) ... else throw
    // 'SplunkConfig requires either token or username+password'`.
    required: [f('splunk', 'host')],
    alternatives: [[f('splunk', 'token')], [f('splunk', 'username'), f('splunk', 'password')]],
    optional: [],
  },

  // ── Required + genuinely optional fields (AWS temp-credential STS token, refresh-flow fields, etc.) ──
  adp: {
    // clientId+clientSecret required via __k loop. accessToken is a
    // "pre-obtained Bearer token (if you manage token refresh externally)"
    // — an alternative convenience the constructor never requires;
    // clientId+clientSecret alone are sufficient to operate. Optional.
    required: [f('adp', 'clientId'), f('adp', 'clientSecret')], alternatives: [], optional: [f('adp', 'accessToken')],
  },
  'amazon-bedrock': {
    // region/accessKeyId/secretAccessKey required via __k loop.
    // sessionToken is ONLY needed for temporary STS credentials —
    // permanent IAM access keys work without it. Optional.
    required: [f('amazon-bedrock', 'region'), f('amazon-bedrock', 'accessKeyId'), f('amazon-bedrock', 'secretAccessKey')],
    alternatives: [], optional: [f('amazon-bedrock', 'sessionToken')],
  },
  'aws-s3': {
    // Same STS-token reasoning as amazon-bedrock.
    required: [f('aws-s3', 'accessKeyId'), f('aws-s3', 'secretAccessKey'), f('aws-s3', 'region')],
    alternatives: [], optional: [f('aws-s3', 'sessionToken')],
  },
  'aws-textract': {
    // accessKeyId/secretAccessKey required via __k loop (region has a
    // 'us-east-1' default, not credential-shaped, left unmapped).
    // sessionToken optional (STS), same reasoning.
    required: [f('aws-textract', 'accessKeyId'), f('aws-textract', 'secretAccessKey')],
    alternatives: [], optional: [f('aws-textract', 'sessionToken')],
  },
  'apicurio-registry': {
    // baseUrl required via __k loop. token/username/password are all
    // unchecked — Apicurio Registry commonly runs with auth disabled;
    // constructor's own authHeader-building code (not shown here) treats
    // these as optional. Optional.
    required: [f('apicurio-registry', 'baseUrl')], alternatives: [],
    optional: [f('apicurio-registry', 'token'), f('apicurio-registry', 'username'), f('apicurio-registry', 'password')],
  },
  blackbaud: {
    // accessToken+subscriptionKey required via __k loop. clientId/
    // clientSecret/refreshToken are for the OAuth refresh flow — not
    // needed for calls made with a pre-obtained accessToken. Optional.
    required: [f('blackbaud', 'accessToken'), f('blackbaud', 'subscriptionKey')], alternatives: [],
    optional: [f('blackbaud', 'clientId'), f('blackbaud', 'clientSecret'), f('blackbaud', 'refreshToken')],
  },
  'carbon-black': {
    // Constructor validates ONLY orgKey via the __k loop; apiKey/
    // connectorId are concatenated into authToken UNVALIDATED
    // (`` `${config.apiKey}/${config.connectorId}` ``) — omitting either
    // silently produces a broken "undefined/..." auth token. Overridden
    // to required (closing the exact false-green gap this fix exists
    // for), not left to the constructor's own incomplete validation.
    required: [f('carbon-black', 'apiKey'), f('carbon-black', 'connectorId'), f('carbon-black', 'orgKey')], alternatives: [], optional: [],
  },
  cribl: {
    // baseUrl required via __k loop. clientId+clientSecret (OAuth2
    // client_credentials) and bearerToken (pre-fetched token) are BOTH
    // legitimately optional — an on-prem Cribl instance with auth
    // disabled needs neither. Optional (not forced alternatives, unlike
    // splunk/xmatters/etc. which throw when neither is supplied — cribl's
    // constructor never throws on their absence).
    required: [f('cribl', 'baseUrl')], alternatives: [],
    optional: [f('cribl', 'clientId'), f('cribl', 'clientSecret'), f('cribl', 'bearerToken')],
  },
  elasticsearch: {
    // baseUrl required via __k loop. apiKey/username+password are
    // explicitly optional in the constructor's own code (`authHeader =
    // null` in the else branch, NOT a throw) — unauthenticated
    // Elasticsearch instances are a real, supported configuration.
    required: [f('elasticsearch', 'baseUrl')], alternatives: [],
    optional: [f('elasticsearch', 'apiKey'), f('elasticsearch', 'username'), f('elasticsearch', 'password')],
  },
  plaid: {
    // clientId+secret required via __k loop. accessToken is a
    // per-linked-account token obtained via a separate Link flow, not a
    // startup credential — optional.
    required: [f('plaid', 'clientId'), f('plaid', 'secret')], alternatives: [], optional: [f('plaid', 'accessToken')],
  },
  securonix: {
    // Constructor validates ONLY baseUrl via the __k loop; token/
    // username/password all default to '' UNVALIDATED. Per the module's
    // own doc comment ("Pre-generated auth token. If omitted, username +
    // password are used to obtain one.") the API genuinely needs one of
    // the two — overridden to an alternatives requirement (closing the
    // same false-green gap as carbon-black), not left fully optional.
    required: [f('securonix', 'baseUrl')],
    alternatives: [[f('securonix', 'token')], [f('securonix', 'username'), f('securonix', 'password')]],
    optional: [],
  },
  stackoverflow: {
    // apiKey required via __k loop. accessToken is only for write
    // operations / authenticated reads — read-only usage works with
    // apiKey alone. Optional.
    required: [f('stackoverflow', 'apiKey')], alternatives: [], optional: [f('stackoverflow', 'accessToken')],
  },
  teamcity: {
    // token+baseUrl required via __k loop. username is used only when
    // authType==='basic', a secondary/legacy mode — token-based auth
    // (the default, authType='token') needs no username. Optional.
    required: [f('teamcity', 'token'), f('teamcity', 'baseUrl')], alternatives: [], optional: [f('teamcity', 'username')],
  },

  // ── "no-deterministic-required-fields": genuinely all-optional (public/unauthenticated APIs) ──
  bloomerang: {
    // Constructor has NO required-field check at all — every field
    // defaults via `?? null`. apiToken/clientId+clientSecret are all
    // optional per the constructor's own code.
    required: [], alternatives: [], optional: [f('bloomerang', 'apiToken'), f('bloomerang', 'clientId'), f('bloomerang', 'clientSecret')],
  },
  'census-gov': {
    // No required-field check; apiKey raises the public rate limit but
    // the API works unauthenticated. Optional.
    required: [], alternatives: [], optional: [f('census-gov', 'apiKey')],
  },
  'data-gov': {
    // No required-field check; apiKey is for the api.gsa.gov proxy only.
    // Optional.
    required: [], alternatives: [], optional: [f('data-gov', 'apiKey')],
  },
  'open-fda': {
    // No required-field check; apiKey raises the public rate limit but
    // the API works unauthenticated. Optional.
    required: [], alternatives: [], optional: [f('open-fda', 'apiKey')],
  },
  substack: {
    // No required-field check; sessionCookie is "required for subscriber
    // management, optional for public post/publication reads" per the
    // module's own doc comment. Optional.
    required: [], alternatives: [], optional: [f('substack', 'sessionCookie')],
  },
  youtube: {
    // No required-field check; apiKey (public read-only) and accessToken
    // (authenticated/write) are independently optional per the module's
    // own doc comments — neither is enforced, both usable.
    required: [], alternatives: [], optional: [f('youtube', 'apiKey'), f('youtube', 'accessToken')],
  },
  'ollama-api': {
    // Verified: constructor takes ONLY an optional baseUrl override
    // (defaults to http://localhost:11434) and declares NO credential
    // field of any kind — local server, no auth. Correctly maps to an
    // explicit empty entry (verified-no-credentials), not "unresolved".
    required: [], alternatives: [], optional: [],
  },
  prometheus: {
    // Constructor throws only when BOTH baseUrl is absent AND host is
    // absent (`if (!config.baseUrl && (!config.host || config.host ===
    // '')) throw`) — baseUrl OR host is required (alternatives, not a
    // credential per se but the connection target the constructor
    // enforces). bearerToken/username/password are all optional
    // (`this.bearerToken = config.bearerToken` etc., unchecked, and
    // Prometheus instances commonly run unauthenticated).
    required: [], alternatives: [[f('prometheus', 'baseUrl')], [f('prometheus', 'host')]],
    optional: [f('prometheus', 'bearerToken'), f('prometheus', 'username'), f('prometheus', 'password')],
  },
  qualys: {
    // Constructor validates ONLY baseUrl via its own throw; username/
    // password are passed UNVALIDATED into `btoa(\`${username}:
    // ${password}\`)` for every request's Basic-auth header — omitting
    // either silently sends `Basic <base64 of "undefined:undefined">` to
    // every call. Overridden to required (closing the exact false-green
    // gap this fix exists for), not left to the constructor's own
    // incomplete validation.
    required: [f('qualys', 'baseUrl'), f('qualys', 'username'), f('qualys', 'password')], alternatives: [], optional: [],
  },

  // ── redshift: adapter now self-signs (2026-09-30 follow-up) ──
  redshift: {
    // Original defect: `signRequest` was the ONLY way to authenticate — a
    // caller-supplied SigV4 callback, function-typed, unrepresentable as a
    // string env var, so no customer without their own signer could ever
    // use this adapter (missingRestFields would always include a field
    // that no env var could satisfy). Fixed at the SOURCE, not worked
    // around here: src/engine/mcp-servers/redshift.ts's constructor now
    // builds its own SigV4 signer from accessKeyId/secretAccessKey(+
    // optional sessionToken) — the SAME hmac/sha256/getSigningKey pattern
    // as the sibling AWS adapters (aws-cloudwatch.ts, aws-dynamodb.ts,
    // aws-cost-explorer.ts; service name 'redshift-data' instead of
    // 'monitoring'/'dynamodb'/'ce') — when no `signRequest` callback is
    // injected. An injected callback still takes priority (existing
    // callers unaffected). region/accessKeyId/secretAccessKey required
    // (constructor's own `hasAccessKeyId`/`hasSecretAccessKey` throw);
    // sessionToken optional (STS temp credentials only, same reasoning as
    // amazon-bedrock/aws-s3/aws-textract above).
    required: [f('redshift', 'region'), f('redshift', 'accessKeyId'), f('redshift', 'secretAccessKey')],
    alternatives: [], optional: [f('redshift', 'sessionToken')],
  },
};

// ─── AUTOMATIC extraction for the remaining 421 (unchanged from the prior pass) ──
const LOOP_RE = /for \(const __k of \(\[([^\]]+)\]/;
const SINGLE_RE_G = /if \(config\.(\w+) === undefined \|\| config\.\1 === null \|\| config\.\1 === ''\) \{/g;
const OR_INDICATORS = [
  /\|\|\s*!\(config\./,
  /&&\s*!\(config\./,
  /!config\.\w+\s*&&\s*!config\.\w+/,
  /!config\.\w+\s*&&\s*!\(config\./,
  /throw[\s\S]{0,200}?requires?\s+(?:either|one of)/i,
];
const CRED_FIELD_RE = /\bconfig\.(apiKey|apiToken|accessToken|clientId|clientSecret|username|password|bearerToken|sessionToken|secret|token|refreshToken|privateKey|certificate|sessionCookie)\b/g;

const result = {};
const manualUnmappable = [];
const missingSrc = [];
const autoIds = [];
const manualIds = [];

for (const [id, row] of byId) {
  const srcPath = path.join(REPO_ROOT, row.rest.module.replace('./dist/', 'src/').replace(/\.js$/, '.ts'));
  if (!fs.existsSync(srcPath)) { missingSrc.push({ id, srcPath }); continue; }

  if (Object.prototype.hasOwnProperty.call(MANUAL_OVERRIDES, id)) {
    const { unmappable, ...entry } = MANUAL_OVERRIDES[id];
    result[id] = entry;
    manualIds.push(id);
    if (unmappable) manualUnmappable.push({ id, srcPath, unmappable });
    continue;
  }

  const src = fs.readFileSync(srcPath, 'utf8');
  const ctorIdx = src.indexOf('constructor(config');
  let body = src;
  if (ctorIdx !== -1) {
    let depth = 0, start = src.indexOf('{', ctorIdx), i = start, end = -1;
    for (; i < src.length; i++) {
      if (src[i] === '{') depth++;
      else if (src[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end !== -1) body = src.slice(start, end + 1);
  }

  const hasOr = OR_INDICATORS.some(re => re.test(body));
  const ifaceMatch = src.match(/interface \w*Config \{([\s\S]*?)\n\}/);
  const hasFnField = ifaceMatch ? /:\s*\([^)]*\)\s*=>/.test(ifaceMatch[1]) : false;

  let fields = [];
  const loopMatch = body.match(LOOP_RE);
  if (!hasOr && !hasFnField && loopMatch) {
    fields = [...loopMatch[1].matchAll(/'([^']+)'/g)].map(m => m[1]);
  } else if (!hasOr && !hasFnField) {
    let m;
    SINGLE_RE_G.lastIndex = 0;
    while ((m = SINGLE_RE_G.exec(body))) fields.push(m[1]);
  }

  if (hasOr || hasFnField || fields.length === 0) {
    // Every id reaching here MUST already be one of the 32 hand-curated
    // above (this pass is expected to fully partition the 453). If not,
    // that is a NEW unresolved id this generator has never seen — fail
    // loudly instead of silently dropping it from the map.
    throw new Error(`gen-rest-credential-map: "${id}" is neither automatically extractable nor in MANUAL_OVERRIDES — read src/engine/mcp-servers/${id}.ts by hand and add it to MANUAL_OVERRIDES.`);
  }

  const seenCredFields = new Set([...body.matchAll(CRED_FIELD_RE)].map(m => m[1]));
  const uncaptured = [...seenCredFields].filter(x => !fields.includes(x));
  if (uncaptured.length > 0) {
    throw new Error(`gen-rest-credential-map: "${id}" auto-extraction is incomplete (uncaptured: ${uncaptured.join(', ')}) and it is not in MANUAL_OVERRIDES — read src/engine/mcp-servers/${id}.ts by hand and add it.`);
  }

  result[id] = { required: fields.map(x => f(id, x)), alternatives: [], optional: [] };
  autoIds.push(id);
}

// ─── Emit ───────────────────────────────────────────────────────────────
const sortedIds = Object.keys(result).sort();
function emitFieldArray(arr, indent) {
  const entries = arr.map(x => `{ field: ${JSON.stringify(x.field)}, envVar: ${JSON.stringify(x.envVar)} }`).join(', ');
  return `[${entries}]`;
}
function emitGroupArray(groups, indent) {
  if (groups.length === 0) return '[]';
  return `[${groups.map(g => emitFieldArray(g)).join(', ')}]`;
}

const lines = [];
lines.push('/**');
lines.push(' * @epicai/chariot — GENERATED. Do not hand-edit.');
lines.push(' * Source: scripts/gen-rest-credential-map.mjs — regenerate with');
lines.push(' *   `node scripts/gen-rest-credential-map.mjs`');
lines.push(' *');
lines.push(' * Per-adapter REST credential requirements: for every catalog row whose');
lines.push(' * rest.module constructor needs credentials beyond (or other than) the');
lines.push(' * single legacy `rest.envKey` -> apiKey field. `required` fields must ALL');
lines.push(' * be present; at least one FULL group in `alternatives` must be present;');
lines.push(' * `optional` fields are passed through when set but never block');
lines.push(' * \'configured\'/\'fully-credentialed\' status. Consumed by:');
lines.push(' *   - restEnvKeys/credentialStatus (canonical-credentialed-brands.ts) —');
lines.push(' *     chariot add prompts for these, chariot health checks them.');
lines.push(' *   - toolHandlers.ts REST dispatch — builds adapterConfig from these');
lines.push(' *     instead of only {apiKey, baseUrl}.');
lines.push(' *');
lines.push(` * Generated ${new Date().toISOString()} — ${sortedIds.length}/${byId.size} adapters mapped`);
lines.push(` * (${autoIds.length} automatic extraction, ${manualIds.length} hand-curated —`);
lines.push(' * see scripts/gen-rest-credential-map.mjs MANUAL_OVERRIDES for the');
lines.push(' * per-adapter reasoning). 0 left unresolved/unmapped;');
lines.push(
  manualUnmappable.length === 0
    ? ' * 0 adapters mapped partially — every field of every mapped adapter is'
    : ` * ${manualUnmappable.length} adapter(s) mapped PARTIALLY with a cited unmappable`,
);
lines.push(
  manualUnmappable.length === 0
    ? ' * representable as an env var (see the generator summary\'s `manualUnmappable`).'
    : ' * field (see the generator summary\'s `manualUnmappable` for the citation).',
);
lines.push(' *');
lines.push(' * Built on the Epic AI® Intelligence Platform');
lines.push(' * Copyright 2026 protectNIL Inc. Elastic-2.0');
lines.push(' */');
lines.push('');
lines.push('export interface RestCredentialField {');
lines.push('  /** Constructor config property name (e.g. \'clientId\'). */');
lines.push('  field: string;');
lines.push('  /** Env-var name chariot prompts for / reads (e.g. \'PAYPAL_CLIENT_ID\'). */');
lines.push('  envVar: string;');
lines.push('}');
lines.push('');
lines.push('export interface RestCredentialEntry {');
lines.push('  /** ALL of these must be present. */');
lines.push('  required: readonly RestCredentialField[];');
lines.push('  /** At least one FULL group must be present. [] = no alternative-credential requirement. */');
lines.push('  alternatives: readonly (readonly RestCredentialField[])[];');
lines.push('  /** Passed through to the adapter when set; never required. */');
lines.push('  optional: readonly RestCredentialField[];');
lines.push('}');
lines.push('');
lines.push('export const REST_CREDENTIAL_MAP: Record<string, RestCredentialEntry> = {');
for (const id of sortedIds) {
  const e = result[id];
  lines.push(`  ${JSON.stringify(id)}: { required: ${emitFieldArray(e.required)}, alternatives: ${emitGroupArray(e.alternatives)}, optional: ${emitFieldArray(e.optional)} },`);
}
lines.push('};');
lines.push('');

const outPath = path.join(REPO_ROOT, 'src/engine/types/rest-credential-map.generated.ts');
fs.writeFileSync(outPath, lines.join('\n'));

const totalFields = Object.values(result).reduce(
  (a, e) => a + e.required.length + e.alternatives.reduce((b, g) => b + g.length, 0) + e.optional.length,
  0,
);
const summary = {
  totalRestAuthRows: byId.size,
  mappedAdapters: sortedIds.length,
  automaticExtraction: autoIds.length,
  handCurated: manualIds.length,
  totalFields,
  unresolvedCount: 0,
  manualUnmappable,
  missingSrc,
  wrote: outPath,
};
console.log(JSON.stringify(summary, null, 2));
