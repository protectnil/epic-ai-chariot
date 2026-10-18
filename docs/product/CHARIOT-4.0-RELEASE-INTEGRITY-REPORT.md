# Chariot 4.0 release-integrity record

Date: 2026-10-18

## Materialization

The authorized operator ran the sanctioned catalog materializer in commit mode
as the designated service account, using AWS KMS Key 1 in `us-east-2` and
`--commit --commit-confirm`.

- Candidates read: 5,493
- Entries materialized: 5,005
- Dropped IDs: none
- Baseline entries: 5,005
- Promoted version hash: `bda8b9c087bb4b90279e066f7224c436e5cd053ebff20a1e1531a3a68f62905b`
- KMS bundle signing payload: 204 bytes
- KMS catalog signing payload: SHA-512 digest, 64 bytes

The materializer reported `signed` and `promoted` with exit code 0.

## Artifact verification

`node scripts/verify-catalog-signature-prepublish.mjs` passed both signature
checks:

- Bundle: verified with `chariot-catalog-prod-2026-08-06-kms`
- Catalog: verified with `chariot-catalog-prod-2026-08-06-kms`
- Registry: promoted atomically with the signed bundle/catalog set
- All five promoted files compare byte-for-byte with the version directory
- Generated files retain the designated service-account ownership

`chariot-current.json` remains tracked and self-contained (`versionDir: "."`).

## Gates

- `npm run typecheck`: PASS
- `cargo check --manifest-path native/Cargo.toml`: PASS
- `git diff --check`: PASS
- `npm run verify:splade-artifact`: NOT PASS; the required
  `CHARIOT_SPLADE_ARTIFACT_DIR` environment variable was not set.

## 9d4ec33 review

`git diff-tree --no-commit-id --name-only -r 9d4ec33 | wc -l` reports **28**
files, despite the earlier 29-file description. The count discrepancy is
recorded rather than silently corrected. The exact authoritative file list is
available from that command.

## Commits and push

- KMS digest-signing fix: `6097d56`
- Promoted signed artifacts: `90264ea`
- Pushed without force to: `feature/chariot-4.0.0-kms-signed`
- The pre-existing divergent `feature/chariot-4.0.0-cli` branch was not
  rewritten.
