/**
 * Operational-telemetry export (C4AMD §8::7, §8::8, §8::9).
 *
 * Governing clause bytes (traceability.spec_nodes, C4AMD::§8::7):
 *   "For air-gapped deployments, opted-in operational telemetry MAY be
 *   collected locally."
 * Governing clause bytes (C4AMD::§8::8):
 *   "Opted-in operational telemetry for air-gapped deployments SHALL
 *   leave the environment only through a deliberate, customer-controlled,
 *   redacted and signed export."
 * Governing clause bytes (C4AMD::§8::9):
 *   "No automatic egress or fallback transmission SHALL be permitted for
 *   air-gapped operational telemetry."
 * Governing ruling (item 93, 2026-09-04): "v4.0 telemetry has NO automatic
 * transport in any mode — local store plus a deliberate, customer-
 * triggered, redacted, signed export everywhere; the export signature is
 * a distinct artifact type using the existing Ed25519 primitive, never
 * the catalog bundle's .sig."
 *
 * WHAT THIS MODULE DOES NOT DO: transmit anything anywhere. `exportBundle`
 * reads the tenant's already-redacted local events (`capture.ts`'s
 * `getStoredEvents`), re-validates each one through `redactEvent` as a
 * second, independent enforcement of the §8::3/§8::5 closed schema
 * (defense in depth — nothing exported can carry an extra field even if
 * a stored document were somehow tampered with between capture and
 * export), signs the resulting bundle, and WRITES IT TO A LOCAL FILE at a
 * path the CALLER supplies. Getting that file off the host — to a laptop,
 * a support ticket, wherever the customer chooses — is the customer's own
 * deliberate action (§8::8's "customer-controlled"), never this module's.
 * `egress-guard.test.ts` grep-guards this whole directory for any
 * fetch/http/https import; this file imports only `node:fs`, `node:path`,
 * `node:crypto` (via the reused signer), and this package's own modules.
 *
 * SIGNING — reuses `src/engine/audit/chainSigner.ts`'s `createChainSigner`,
 * the same pluggable Ed25519 primitive (`kms` / `vault-transit` /
 * `sealed-store` backends, CHARIOT §9.8.1 key custody: "Plaintext key
 * material MUST NOT be stored on the application host filesystem")
 * already proven for audit-chain attestation. The export bundle is
 * EXPLICITLY its own artifact type — `artifactType:
 * 'operational-telemetry-export'` is stamped into the signed payload
 * itself precisely so it can never be confused with, or substituted for,
 * the (the catalog publisher-side, out of this repo's scope entirely) catalog bundle's
 * own `.sig`.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalStringify } from '../../util/canonical-json.js';
import { createChainSigner, type CreateChainSignerOpts } from '../../engine/audit/chainSigner.js';
import { redactEvent, type OperationalTelemetryEvent } from './redact.js';
import { getStoredEvents } from './capture.js';

export const EXPORT_ARTIFACT_TYPE = 'operational-telemetry-export' as const;

export interface ExportBundle {
  artifactType: typeof EXPORT_ARTIFACT_TYPE;
  tenantId: string;
  generatedAt: string;
  events: OperationalTelemetryEvent[];
}

export interface SignedExportBundle {
  bundle: ExportBundle;
  bundleHash: string;
  signature: {
    kid: string;
    algorithm: 'ed25519';
    /** base64 */
    sig: string;
  };
}

/**
 * Build, re-validate, and sign one tenant's export bundle. Pure w.r.t. I/O
 * except the local DB read (`getStoredEvents`) and the signer call — does
 * NOT write a file; see `exportToFile` for the deliberate, path-explicit
 * write step, kept separate so a caller can inspect/hash-compare the
 * bundle before choosing where (or whether) to persist it.
 */
export async function buildSignedExport(
  tenantId: string,
  signerOpts: CreateChainSignerOpts = {},
): Promise<SignedExportBundle> {
  if (!tenantId) throw new Error('buildSignedExport: tenantId must be a non-empty string');

  const stored = await getStoredEvents(tenantId);
  // Second, independent pass through the closed-schema allowlist (see
  // module doc) — every exported event is re-derived field-by-field from
  // the stored record, never spread wholesale.
  const events = stored.map((e) =>
    redactEvent({
      tenantId: e.tenantId,
      canonicalToolId: e.canonicalToolId,
      outcome: e.outcome,
      latencyMs: e.latencyMs,
      failureStage: e.failureStage,
      hourBucket: e.hourBucket,
      productVersion: e.productVersion,
      platform: e.platform,
      catalogEpoch: e.catalogEpoch,
    }),
  );

  const bundle: ExportBundle = {
    artifactType: EXPORT_ARTIFACT_TYPE,
    tenantId,
    generatedAt: new Date().toISOString(),
    events,
  };

  const canonical = canonicalStringify(bundle);
  const bundleHash = createHash('sha256').update(canonical).digest('hex');

  const signer = await createChainSigner(signerOpts);
  const sigBytes = await signer.sign(Buffer.from(canonical, 'utf8'));
  const { kid } = await signer.getKeyInfo();

  return {
    bundle,
    bundleHash,
    signature: { kid, algorithm: 'ed25519', sig: sigBytes.toString('base64') },
  };
}

/**
 * The one deliberate, customer-triggered step that produces an artifact
 * capable of leaving the environment (§8::8) — writes the signed bundle
 * to a LOCAL file at `destPath`. Never transmits it; moving the file off
 * the host is the customer's own subsequent action. Creates parent
 * directories as needed. No-clobber/atomic-write semantics are NOT
 * enforced here (a plain overwrite) — callers that need that should
 * check `destPath` themselves before calling, matching this module's "do
 * exactly what was asked, nothing automatic" posture.
 */
export async function exportToFile(
  tenantId: string,
  destPath: string,
  signerOpts: CreateChainSignerOpts = {},
): Promise<SignedExportBundle> {
  const signed = await buildSignedExport(tenantId, signerOpts);
  mkdirSync(dirname(destPath), { recursive: true });
  writeFileSync(destPath, JSON.stringify(signed, null, 2), { encoding: 'utf8' });
  return signed;
}
