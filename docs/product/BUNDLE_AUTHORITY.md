# Catalog Bundle Authority

## The rule

The four signed catalog artifacts in this repository:

- `chariot-adapter-bundle.json` + `chariot-adapter-bundle.json.sig`
- `chariot-adapter-catalog.json` + `chariot-adapter-catalog.json.sig`
- `chariot-mcp-registry.json`     (no `.sig` — derivative of bundle)

are **emitted by a single writer** — the catalog materializer in the
sibling publisher repository.

The materializer:

1. Reads the publication-eligible adapter set from MongoDB.
2. Builds the bundle in memory.
3. Signs it with the operator-held Ed25519 catalog-signing key.
4. Writes the `.json` and `.sig` files atomically into the chariot
   repo root.

There is no other sanctioned write path. Direct editing of any of these
files — `vim`, `sed`, `python json.dump`, `jq`, `cat > file`, any tool —
is **a forbidden operation** because the `.sig` file will not be
refreshed and the customer-side signature gate at
`src/engine/keys/verifyCatalogSignature.ts` will reject the resulting
artifact at install time.

## Why this matters

Every CLI invocation that loads the catalog passes the bytes through
`verifyAndReadArtifact()`. If the bundle has been edited but the `.sig`
not regenerated, every customer command — `chariot search`,
`chariot add`, `chariot query`, `chariot list` — returns
`No adapters matched` because the catalog load returns `null`.

This is not a degraded mode. The customer sees zero adapters. The
product appears completely broken.

## Incident reference

**3.0.6 publish, 2026-05-22.** Commit `5d3fdc5` edited the bundle for
the wayback packageName fix using `python json.dump`. The matching
`.sig` was not refreshed. CI shipped the broken pair to npm. Every
fresh install of `@epicai/chariot@3.0.6` returned
`epicai.catalog.artifacts ERROR: catalog signature gate failed
reason=signature-verification-failed` followed by
`No adapters matched` on every query.

Recovery required a deprecate + republish cycle.

## Gates that enforce this rule

1. **Pre-commit hook** (`scripts/hooks/pre-commit`): refuses any commit
   that stages a signed `.json` without also staging the matching
   `.sig`.
2. **CI release validate job** (`.github/workflows/release.yml`): runs
   `scripts/verify-catalog-signature-prepublish.mjs` against every
   committed catalog artifact before any build/publish step.
3. **CI release lineage check**: refuses to publish if the last
   commit that modified any signed `.json` did not also modify the
   matching `.sig` — catches history rewrites that would otherwise
   slip through.
4. **`prepublishOnly`**: same signature gate runs on local
   `npm publish`.
5. **Post-publish probe** (`test/external-adversarial-probe.sh`):
   runs against the freshly-published tarball; signature break is
   the first probe and triggers automatic deprecation.

## How to legitimately update the bundle

Run the materializer as the materializer-service user against the
populated MongoDB collection (operator runbook lives in the
publisher repo). The materializer writes the `.json` and `.sig` into
this repo root atomically.

Then stage BOTH files together in the same commit, e.g.

    git add chariot-adapter-bundle.json chariot-adapter-bundle.json.sig
    git add chariot-adapter-catalog.json chariot-adapter-catalog.json.sig
    git add chariot-mcp-registry.json

Any commit that stages `chariot-adapter-bundle.json` alone is going
to be rejected by the pre-commit hook. That is the intended
behavior — fix it by running the materializer, not by force-staging.
