# Audit Chain Signing Key — Custody & Rotation Runbook

Governs the Ed25519 key that signs the Chariot IAM/audit hash chain's
length attestations and (via the same trust root) every artifact that
depends on it. Implements CHARIOT-SPEC.md §9.8.1, "Trust root and key
custody."

> The IAM chain's trust root is an Ed25519 signing key held under
> operator key custody.

## 0. What actually consumes the configured backend

Every live signer/verifier of the audit trust root goes through this
abstraction — there is no direct read of a plaintext signing key
anywhere (there is no plaintext backend at all — see §1):

- **`chariot serve`'s periodic attest cadence** (`src/engine/audit/auditCadence.ts`,
  §9.8.4/CH-45) — signs each periodic length attestation via
  `createChainSigner()`, constructed once on the first attest tick.
  Attestation is "configured" (the cadence becomes active) once a
  custody backend is either explicitly selected (`kms`/`vault-transit`)
  or, for the default `sealed-store`, actually provisioned
  (`isSealedStoreProvisioned()`).
- **`chariot audit attest`**, **`chariot audit custody import-key`**,
  **`chariot audit custody-check`**, and **`chariot audit rotate-key`**
  (`src/bin/chariot.ts`, `cmdAudit`) — same abstraction, on demand.
- **`chariot audit verify-length`** (`src/bin/chariot.ts`) and the
  **`GET /enterprise/{tenantId}/admin/audit-logs`** export route
  (`src/iam/routes/admin.ts`, via `reconcileChainLength`) — both verify
  against the CH-03 multi-key set (`resolveVerifyKeys()`), which merges
  the **persistent verify-key store** (§3), `CHARIOT_AUDIT_VERIFY_KEYS`,
  and the legacy single `CHARIOT_AUDIT_VERIFY_KEY`/`CHARIOT_AUDIT_SIGNING_KEY`
  var — so a length attestation signed under a RETIRED-but-still-retained
  key still verifies, and one signed under a key absent from every source
  fails closed.

## 1. Custody backends

Select a backend with `CHARIOT_AUDIT_SIGNER_BACKEND`. There are exactly
**three** — `kms`, `vault-transit`, `sealed-store` — and **no plaintext
backend in any mode**. CHARIOT §9.8.1's "Plaintext key material MUST NOT
be stored on the application host filesystem" is unconditional, not a
carve-out for single-user installs; an earlier revision of this document
described a fourth `env` backend that was refused only in enterprise
mode — that backend has been removed entirely.

| Backend | Env | Where the private key lives | Notes |
|---|---|---|---|
| `kms` | `CHARIOT_AUDIT_SIGNER_BACKEND=kms` | Inside AWS KMS only — the private key never leaves KMS, encrypted or otherwise | **True remote signing.** AWS KMS supports Ed25519 natively via key spec `ECC_NIST_EDWARDS25519` ("Signing and verification... The private key that generates signatures never leaves AWS KMS unencrypted" — AWS KMS developer guide). Create the key with that key spec (usage: SIGN_VERIFY), set `CHARIOT_AUDIT_KMS_KEY_ID` (id or ARN) and optionally `CHARIOT_AUDIT_KMS_REGION`. Every signature is a live `kms:Sign` call (`SigningAlgorithm=ED25519_SHA_512`, `MessageType=RAW`); the public key comes from `kms:GetPublicKey`, whose `KeySpec` is verified to be `ECC_NIST_EDWARDS25519` — any other key spec is refused. Requires the optional `@aws-sdk/client-kms` package (not a hard dependency — install it yourself) and `kms:Sign` + `kms:GetPublicKey` + `kms:GetKeyPolicy` IAM permissions on the key. |
| `vault-transit` | `CHARIOT_AUDIT_SIGNER_BACKEND=vault-transit` | Vault transit engine — private key never leaves Vault | Vault's `ed25519` transit key type is used directly for remote signing over `POST /v1/transit/sign/<key>`. Configure `CHARIOT_AUDIT_VAULT_ADDR`, `CHARIOT_AUDIT_VAULT_TOKEN`, `CHARIOT_AUDIT_VAULT_KEY_NAME`. Like `kms`, no key material — plaintext or encrypted — ever touches the application host. |
| `sealed-store` (**default**) | `CHARIOT_AUDIT_SIGNER_BACKEND=sealed-store` (or unset) | AES-256-GCM ciphertext on disk under `<packageRoot>/audit/signing-key.<kid>.sealed.json`, sealed with `ENTERPRISE_MASTER_KEY` (the same CH-10/§12.2 vault primitive used for IAM adapter credentials) | Use when no external KMS/Vault is available. Requires `ENTERPRISE_MASTER_KEY` to be set — this is `src/iam/crypto.ts`'s own unconditional requirement (single-user OR enterprise), not something this backend adds. Provision by importing an existing PEM (`chariot audit custody import-key`) or minting a fresh one via rotation (`rotateSigningKey()`, `src/engine/audit/keyRotation.ts`). Plaintext exists only in process memory after decrypt — this is the one backend where the private key transits application process memory at all. |

`kms` and `vault-transit` are the strongest options: the private key never
exists outside the KMS/Vault boundary, not even transiently in application
process memory.

### No custody backend provisioned yet

A fresh single-user install has no sealed-store key and no
`CHARIOT_AUDIT_SIGNER_BACKEND` override — `chariot audit attest` and the
periodic cadence both report `SIGNING_KEY_NOT_CONFIGURED`, naming all
three backends and how to provision each. There is no silent fallback to
a plaintext key; attestation is simply unavailable until an operator
provisions one. To provision the default sealed-store backend from an
existing PEM:

```
chariot audit custody import-key --file /path/to/existing-key.pem
# or, piped:
cat /path/to/existing-key.pem | chariot audit custody import-key
```

This seals the key and prints the sealed artifact's path and kid. **The
command does NOT delete the plaintext source file** — it never deletes a
file it did not create. Delete `/path/to/existing-key.pem` yourself
immediately after a successful import; leaving it in place defeats the
custody guarantee this backend exists to provide.

Every backend emits one JSON audited-access log line to stderr per key
use (`{event:"audit.signing_key.access", backend, kid, action, principal}`),
so "who used the signing key and when" is reconstructable from the
process's log stream / your log aggregator. Logging is NOT the MFA/RBAC
gate itself — see §2.

## 2. Access gating (MFA / RBAC)

CHARIOT §9.8.1: *"Key access MUST be gated by the same MFA and RBAC
controls used for production database root credentials. An operator's
compromise of the signing key is operationally equivalent to a
compromise of the audit store's root credentials — treat the risk
identically."*

**In enterprise mode, `createChainSigner()` runs an application-enforced
custody check BEFORE constructing a signer** (`src/engine/audit/custodyCheck.ts`)
and refuses to construct if it fails — logging alone was found
insufficient (a caller-identity log line proves who signed, not that only
MFA-authenticated, RBAC-scoped principals COULD sign). Run the same check
standalone, in any mode, with:

```
chariot audit custody-check kms
chariot audit custody-check vault-transit
chariot audit custody-check sealed-store
```

### What each backend's check actually verifies (and its limits)

- **kms** (fully mechanical): fetches the key's policy (`kms:GetKeyPolicy`)
  and requires that **every** `Allow` statement covering `kms:Sign` (or a
  wildcard `kms:*`/`*` action) carries
  `Condition.Bool["aws:MultiFactorAuthPresent"] == "true"`. A single
  ungated Allow-Sign statement fails the whole check — SOME principal
  could sign without MFA, which defeats the "gated the same as production
  DB root" requirement. A key with no Allow-Sign statement at all also
  fails (nothing reachable to confirm MFA gating against). Accepted
  policy shape (informal): a KMS key policy statement of the form —
  ```json
  {
    "Sid": "AllowSignWithMfa",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<account>:role/<audit-signer-role>" },
    "Action": "kms:Sign",
    "Resource": "*",
    "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
  }
  ```
- **vault-transit** (fully mechanical): login MFA enforcement lives at
  `identity/mfa/login-enforcement` (LIST the collection, READ each by
  name) — quoting developer.hashicorp.com/vault/api-docs/secret/identity/mfa/login-enforcement:
  "creates or updates a login enforcement that specifies which MFA
  methods should be used when logging into Vault." (`sys/mfa/...` is a
  DIFFERENT feature — Enterprise step-up MFA for individual request
  paths, not login MFA; do not confuse the two.) The check:
  1. Resolves the signing token's own auth mount: `auth/token/lookup-self`
     returns `data.path` (Vault's doc: "path — Path by which this token
     was created", e.g. `auth/approle/login`); the mount segment
     (`approle/`) is looked up in `sys/auth` to get its `type`/`accessor`.
  2. Requires at least one login-enforcement whose `auth_method_accessors`
     or `auth_method_types` covers that mount. (Per-identity enforcement —
     `identity_group_ids`/`identity_entity_ids` — is out of scope for a
     service-token custody check.)
  3. Fetches each of the token's non-default/root policies
     (`sys/policies/acl/<name>`) and parses the returned ACL text's
     `path "<pattern>" { capabilities = [...] }` blocks (a targeted regex
     extractor for the standard block shape — not a full HCL parser;
     `sudo`, `deny`, and Sentinel RGP/EGP policy composition are not
     modeled — a documented simplification, not a silent gap).
  4. **Passes** only if some policy grants `update` or `create` on a
     pattern covering `transit/sign/<keyName>` (exact match, a trailing
     `*` glob, or Vault's `+` single-segment wildcard), **and** no policy
     grants `delete` on a pattern covering `transit/keys/<keyName>`, and
     no policy grants read/update/create on a pattern covering
     `transit/export/*` — either would let the token destroy or
     exfiltrate the key material itself, which exceeds "gated the same as
     production DB root" scoping.

  Accepted policy shape (informal example — sign-only, no broader
  control):
  ```hcl
  path "transit/sign/audit-key" {
    capabilities = ["update"]
  }
  ```
- **sealed-store** (NOT mechanically checkable at all): there is no API
  this process can query to determine who is authorized to read/rotate
  `ENTERPRISE_MASTER_KEY` — bootstrap already fail-fast-validates the
  key's presence/shape at startup (CHARIOT §18.3::1 / CH-19), but that
  says nothing about MFA/RBAC on the key's OWN custody. The check
  therefore requires an **explicit operator attestation**:
  `CHARIOT_AUDIT_CUSTODY_ATTESTED=1`. Set this ONLY after confirming, out
  of band, that the same MFA/RBAC gate protecting production database
  root credentials also protects whoever can read or rotate
  `ENTERPRISE_MASTER_KEY` (secrets-manager IAM policy, Vault policy, HSM
  custody procedure — whatever actually holds it in your deployment).
  This is an attestation, not a verification; it does not, on its own,
  prove the gate exists.

Outside enterprise mode (single-user, CHARIOT_ENTERPRISE unset — CHARIOT
§18.2::1) this check does not apply and always passes: single-user
installs have no MFA/RBAC control to gate.

Audit this gate at the same cadence you audit production database
root-credential access.

## 3. The persistent verify-key store (rotation's publication path)

CHARIOT §9.8.1::3's "publish the new public key via the same distribution
path as the old one" is a concrete file:
`<epicAiDir>/audit/verify-keys.json` (`src/engine/audit/verifyKeyStore.ts`),
`{ [kid]: { publicKeyPem, addedAt, retiredAt? } }`. `rotateSigningKey()`
appends the new key to this file ATOMICALLY (write-to-temp + fsync +
rename) in the SAME call that records the `audit.signing_key.rotated`
chain event. `resolveVerifyKeys(epicAiDir)` reads this store and merges
it with `CHARIOT_AUDIT_VERIFY_KEYS` (env overlay) and the legacy single
`CHARIOT_AUDIT_VERIFY_KEY`/`CHARIOT_AUDIT_SIGNING_KEY` var — so a fresh
process picks up a rotation with **no operator env-var wiring required**.

This store only ever grows. `retiredAt` (stamped by `retireVerifyKey()`)
is operator bookkeeping only — it never removes a key's ability to
verify historical records signed under it.

## 4. Rotation

Rotation is **forward-only** (CHARIOT §9.8.1): a lost key can never be
un-lost, so rotation always adds a new key, never replaces history.
`rotateSigningKey()` (`src/engine/audit/keyRotation.ts`) is
**backend-specific and never returns private key material for any
backend**:

- **sealed-store**: generates a fresh Ed25519 keypair in memory and seals
  it immediately (`sealSigningKey()`) — the private PEM exists only in a
  local variable inside `rotateSigningKey()`'s own stack frame.
- **kms**: KMS has no in-place "rotate" for an asymmetric key — the
  operator creates a NEW key out-of-band (KeySpec=`ECC_NIST_EDWARDS25519`)
  and passes its key id as `newKmsKeyId`; `rotateSigningKey()` only
  fetches and validates that key's PUBLIC half.
- **vault-transit**: calls Vault's native transit rotate endpoint
  (`POST /v1/transit/keys/<name>/rotate`), which bumps `latest_version`
  IN Vault — the private key material never leaves Vault, let alone this
  process.

In every case, `rotateSigningKey()`:

1. Mints/points at the new key per the backend rules above.
2. Appends the new public key to the persistent verify-key store (§3)
   ATOMICALLY — this happens BEFORE the chain record, so a crash between
   the two steps leaves a published-but-unrecorded key (inert, safe)
   rather than a recorded-but-unpublished one (which nothing could
   verify).
3. Appends a `audit.signing_key.rotated` record to the live hash chain
   (same mechanism as `federation.adapter.revoked` — a real chain record,
   not a side-channel log line) carrying the old kid, new kid, and new
   public key.

**Never delete an entry from the persistent verify-key store.** Historical
records signed under a retired key remain verifiable only as long as its
public key stays in the store.

### CLI: `chariot audit rotate-key`

```
chariot audit rotate-key --backend sealed-store
chariot audit rotate-key --backend kms --kms-key-id <new-key-id-or-arn>
chariot audit rotate-key --backend vault-transit --vault-key <name>
```

Invokes `rotateSigningKey()` end to end: mints/points at the new key,
publishes it to the persistent verify-key store, and appends the chain
record — then prints/returns the new kid, old kid (`null` on a first-ever
rotation), and the chain record id. **Never prints or returns private key
material for any backend.** `--backend` defaults to
`CHARIOT_AUDIT_SIGNER_BACKEND` (or `sealed-store` if that's also unset).
`--kms-key-id` is required for `kms` (the NEW key, created out-of-band).
`--vault-key` overrides `CHARIOT_AUDIT_VAULT_KEY_NAME` for `vault-transit`
(`CHARIOT_AUDIT_VAULT_ADDR`/`CHARIOT_AUDIT_VAULT_TOKEN` still required from
the environment). The command also makes a best-effort attempt to fetch
the CURRENT key's public half before rotating (so the chain record's
`oldKid` is populated) — this is skipped silently on a first-ever
rotation, where there is no current key to fetch.

### Rotation cadence

- **Routine**: every 365 days.
- **Event-driven**: immediately upon departure of any operator who held
  access to the signing key (per the MFA/RBAC gate in §2).

### Emergency rotation procedure

Triggered by suspected compromise of the signing key or its custody
backend:

1. Immediately revoke the compromised key's access at the custody layer
   (KMS key policy / Vault transit deny / rotate `ENTERPRISE_MASTER_KEY`
   for sealed-store) — this stops further signing under the compromised
   key even before a replacement exists.
2. Run the rotation flow in §4 to mint and publish a new key.
3. File an incident record noting the compromised kid, the time window
   during which it was live, and every chain record signed under it —
   those records remain **cryptographically valid** (the key really did
   sign them) but their **provenance is now suspect**; downstream
   consumers of the chain should be notified to treat that window as
   reduced-trust, per their own risk posture. This runbook does not
   retract or re-sign those records — CHARIOT §9.8.1 is explicit that
   "loss of the signing key = loss of historical trust" and rotation is
   forward-only, never retroactive.
4. Confirm `detectTruncation`/reconciliation (`length-attestation.ts`)
   still passes against the post-rotation chain before resuming normal
   operation.

## 5. Historical verification — where prior public keys live

- **The persistent verify-key store (§3)** is the authoritative record for
  every key `rotateSigningKey()` has ever minted — this is what
  `resolveVerifyKeys()` actually consults in production.
- **sealed-store**: every sealed artifact is ALSO retained (never deleted)
  at `<packageRoot>/audit/signing-key.<kid>.sealed.json` — the `kid` is
  derived deterministically from the public key (`computeKid()` in
  `chainSigner.ts`), so any historical record's kid maps back to its
  artifact.
- **kms / vault-transit**: retain the historical public key material
  wherever your organization already retains historical secrets
  metadata (secrets-manager tags, a config-management repo, etc.) in
  ADDITION to the persistent verify-key store — belt-and-suspenders in
  case the store itself is ever lost.
- **In all cases**: treat loss of an entry from the persistent verify-key
  store as equivalent to losing the ability to verify every record signed
  under that key.

## 6. No plaintext fallback, in any mode

There is no `CHARIOT_AUDIT_SIGNER_BACKEND=env` (or equivalent) escape
hatch. Setting `CHARIOT_AUDIT_SIGNING_KEY` alone, with no custody backend
provisioned, does nothing — no code path reads it as a signing source.
`chariot audit custody import-key` is the only supported way to bring an
existing plaintext PEM into custody; once imported, delete the plaintext
source yourself.
