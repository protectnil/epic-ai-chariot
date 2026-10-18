# Producing sealed EdgeShard snapshots

Build TypeScript and the current native addon before running the offline
producer. The native addon must expose `sealEdgeSnapshotFile`,
`unsealAndVerifySnapshotToFile` and shard `close`.
Provide local BIEN 768-dimensional document and SPLADE document ONNX models,
their four tokenizer/config files, and ONNX Runtime 1.24.4. The producer pins
the qualified model and tokenizer SHA-256 values, rejecting substitute bytes. No model download
or embedding service is used.

## Pinned SPLADE artifact

CHARIOT-SPEC §5.6 delegates the byte-level sparse pin to the shared
`shared/splade/artifact-pin.ts`. For 4.0.0 the only admitted artifact is
`Qdrant/Splade_PP_en_v1` revision
`efcd182bc7eb351e81a9445752d4388c2bab500b`: `model.onnx` SHA-256
`65adbad0d7e1bc882c867d534821d52e60d6f666a91662be3f58457d08d25bf3`,
with tokenizer/config hashes enforced by the producer. Its graph signature is
exactly three rank-2 `int64` inputs, in order — `input_ids`, `attention_mask`,
`token_type_ids` — and one rank-3 `float32` output named `logits`.

The model identity `prithivida/Splade_PP_en_v1` does not authorize another
ONNX export. In particular, the `0934583a…` export with `input_mask`,
`segment_ids`, and `output` is rejected both by the producer's byte pin and by
native graph admission. The native loader never maps aliases or defers a graph
mismatch until the first embed.

```sh
ORT_DYLIB_PATH=/path/to/libonnxruntime.so \
node scripts/build-edgeshard-snapshot.mjs \
  --bundle chariot-adapter-bundle.json \
  --dense-model /models/bien/dim_768/model.onnx \
  --dense-tokenizer-dir /models/bien \
  --splade-dir /models/splade \
  --security-epoch 7 \
  --license /secure/chariot.license \
  --watermark-dir /secure/edgeshard-release-watermark \
  --out artifacts/edgeshard/catalog.edgeshard.sealed
```

`--license` is required. It names the recipient's licence envelope
(`{ jwt, renewal_secret, seal_secret? }`). The producer verifies the licence
JWT and refuses to seal unless its `catalog_version` claim equals the
decimal string of the bundle's signed `catalogVersion`.

The seal secret root is the envelope's `seal_secret` when present (standard
padded base64 of exactly 32 bytes, generated once when the licence is first
issued and never rotated by renewal). If the envelope has no `seal_secret`,
the root is `ENTERPRISE_MASTER_KEY` from the release environment, which must
decode to at least 32 secret bytes. Inject `CHARIOT_SEAL_SIGNING_SEED_B64`
through the release environment as well: it is the 32-byte Ed25519 seed for
the consumer's pinned snapshot verifying key. No secret is accepted on the
command line or written into an artifact. Catalog and snapshot signatures use different trust
anchors. The existing native seal primitive performs HKDF-SHA256 with info
`chariot-edge-snapshot-seal-v1`, a fresh random 12-byte IV, AES-256-GCM with
its trailing 16-byte tag, then Ed25519 signing over the ciphertext.

The producer verifies the bundle's adjacent `.sig` with Chariot's existing
version-selected catalog verifier before parsing records. It embeds catalog
tools once, using the native document serializer and both local encoders,
then flushes and packages the Edge shard. Registry duplicates and inactive or
revoked adapters do not add points. Tool names without actual tool records do
not become invented documents. An available signed retrieval manifest must
match the complete compiled retrieval contract, tool count and serializer hash. A legacy bundle without a retrieval
manifest is rejected. Have the upstream publisher produce and sign the 4.0
retrieval manifest before running this producer; the producer never edits or
re-signs the adapter bundle. Catalogs with
capability residual records require the capability-record producer extension;
the current producer refuses a signed manifest whose total differs from its
tool count.

The output is two files in the `--out` directory (CHARIOT-SPEC §5.7
"Envelope fields", file-reference form, amended 2026-10-14):

- `catalog.edgeshard.sealed.ciphertext` (the `--out` basename plus
  `.ciphertext`): the raw AES-256-GCM ciphertext with its trailing 16-byte
  tag, mode 0600.
- `catalog.edgeshard.sealed` (the `--out` path): an independent JSON
  descriptor `{ "ciphertext": { "file": "catalog.edgeshard.sealed.ciphertext",
  "sha256": "<hex>" }, "iv", "signature", "salt", "aad", "ivB64",
  "signatureB64" }`. `sha256` is the lowercase hex SHA-256 of the ciphertext
  file. `ivB64` and `signatureB64` repeat `iv` and `signature` for the
  consumer; CI checks that each alias equals its canonical field. The
  descriptor carries no inline ciphertext.

A real catalog archive is about 505 MB, beyond the maximum JavaScript string
length, so the archive and ciphertext never pass through JavaScript as base64.
The native addon seals file to file (`sealEdgeSnapshotFile`) and the consumer
unseals file to file (`unsealAndVerifySnapshotToFile`). The consumer resolves
`ciphertext.file` in the descriptor's own directory. It must be a bare
basename naming a regular file, not a symbolic link, whose SHA-256 equals
`ciphertext.sha256`. A legacy descriptor that carries the ciphertext inline as
`ciphertextB64` is still accepted. A descriptor that carries both forms is
refused.

The descriptor is never inserted into or used to re-sign the adapter bundle. Salt is the decimal string
of the signed `catalogVersion`; AAD is `<salt>|epoch=<security-epoch>`. The
security epoch is an explicit u32 release counter, not the bundle's Unix
millisecond `epoch`.

Before publishing the output, the producer always reads it back with the
same licence: a file-to-file unseal of the staged ciphertext with native
signature/license verification, anti-rollback/context validation,
receipt-checked unpack and manifest-checked shard loading. It also re-hashes
the staged ciphertext file and refuses to publish if the hash differs from
the one the sealer reported. Its
watermark persists in `--watermark-dir`, defaulting to `.edgeshard-watermark`
beside the output; reuse that directory across releases to enforce
monotonicity.
The consumer derives its expected context from the verified licence's
`catalog_version` claim, which matches the producer's catalog-version salt.
A licence without `catalog_version` is refused for sealed access. There is
no fallback to `tenant_id` or `sub`. The consumer uses the same root
precedence as the producer: envelope `seal_secret`, then
`ENTERPRISE_MASTER_KEY`. A shard sealed under a licence's `seal_secret` opens
only on an installation holding that licence envelope. A shard sealed under
`ENTERPRISE_MASTER_KEY` opens only where the same key is set.

To deliver the shard to one recipient, place both files in that recipient's
offline kit: `kit/edgeshard/catalog.edgeshard.sealed` and
`kit/edgeshard/catalog.edgeshard.sealed.ciphertext`, together with their
`kit/chariot.license`. List all three in `kit/kit-manifest.json` with their
SHA-256 hashes. Kit files must be regular files, not symbolic links. The setup
wizard installs the descriptor to
`~/.epic-ai/edgeshard/catalog.edgeshard.sealed` and the ciphertext beside it
at `~/.epic-ai/edgeshard/catalog.edgeshard.sealed.ciphertext`. Build the
recipient's tarball with `npm pack` only. `npm publish` refuses while `kit/`
exists.

Publish both files on the matching release, as `catalog.edgeshard.sealed`
and `catalog.edgeshard.sealed.ciphertext`. The marketplace workflow downloads
both in the guard and image build jobs. It validates the descriptor's
structure and catalog-version scope, and checks that the ciphertext file is a
regular file whose SHA-256 matches the descriptor. This preflight is not
signature verification; runtime native verification remains mandatory. The
Dockerfile copies both files to `/app/artifacts/edgeshard/`
(`EDGESHARD_SNAPSHOT` and `EDGESHARD_SNAPSHOT_CIPHERTEXT`, which defaults to
`${EDGESHARD_SNAPSHOT}.ciphertext`). Stage SPLADE, BIEN, reranker and ONNX
Runtime under their existing Dockerfile build-context paths separately. They
remain required by CI.

Production temporarily writes plaintext shard/archive data in a private
staging directory, explicitly closes native handles, and removes that tree.
The producer seals into a private staging directory inside the output
directory. It then publishes the ciphertext first and the descriptor last,
each by an atomic rename, so a descriptor is never visible before the file it
names. If the producer is interrupted between the two renames, an older
descriptor may be left naming the new ciphertext. Its `sha256` then no longer
matches, so the consumer refuses it. Use encrypted local storage if
plaintext temporary files are outside the installation's at-rest policy.

Validation after building TypeScript:

```sh
CHARIOT_SPLADE_ARTIFACT_DIR=/models/splade \
ORT_DYLIB_PATH=/opt/onnxruntime-1.24.4/libonnxruntime.so \
npm run verify:splade-artifact
CHARIOT_REQUIRE_SPLADE_ARTIFACT=1 \
CHARIOT_SPLADE_ARTIFACT_DIR=/models/splade \
ORT_DYLIB_PATH=/opt/onnxruntime-1.24.4/libonnxruntime.so \
node --test dist/engine/bin/build-edgeshard-snapshot.sparse-contract.test.js
node --test dist/engine/bin/build-edgeshard-snapshot.test.js \
  dist/engine/bin/build-edgeshard-snapshot.capability-records.test.js \
  dist/engine/retrieval/sealedShardConfig.test.js \
  dist/engine/server/ChariotState.sealed-shard.test.js \
  dist/engine/server/ChariotState.sealed-shard-staging.test.js \
  dist/cli/offline-kit.test.js \
  dist/engine/retrieval/overlay/CompositeEdgeShard.test.js \
  dist/iam/masterKeyConsumers.test.js
node --test evals/napi-seam-conformance.mjs
cd native
cargo test --lib edge_snapshot::tests::
```

`verify:splade-artifact` is the unskippable positive-artifact release gate and
is wired into `prepublishOnly`; it fails when its explicit artifact directory,
ONNX Runtime, or the current verified native binary is absent. The following
contract test additionally uses the on-host `0934583a…` export as a negative
control. It proves byte admission, negative-pin rejection, real-model load and
non-empty deterministic embedding. The ordinary portable test run may skip
that integration test on development hosts that do not carry the 532 MB
artifacts; such a skip is never release evidence.

The TypeScript fixture test passes producer output through the actual config
loader and composite query consumer with fixture encoders/storage. The Rust
integration test uses the TypeScript archive packer, real Edge shard data,
the production sealer, the full unseal pipeline with fixture trust roots,
receipt-checked unpack and native shard load. The Rust `file_*` tests run the
file-to-file seal and unseal with fixture trust roots. They check the
ciphertext SHA-256, mode 0600 outputs, and refusal of an existing or
symbolic-link output path, a symbolic-link input and a tampered or truncated
ciphertext. No production private key is required by the tests; the
production CLI still enforces its pinned key.
