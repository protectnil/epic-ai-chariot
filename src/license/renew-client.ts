/**
 * `chariot license renew-now` client per portal spec §10.3 +
 * chariot-billing-service-april-2026.md §6.
 *
 * POSTs the renewal proof to https://epic-ai.io/api/license/renew with:
 *   { company_id, current_jti, nonce, ts, proof }
 *   proof = HMAC-SHA256(renewal_secret, company_id || current_jti || nonce || ts)
 * (NUL-separated fields per the renewal-token primitive on the server side.)
 *
 * The JWT `iss` claim stays `license.epic-ai.io` (identity, not URL).
 *
 * Response handling:
 *   200 + { jwt, renewal_secret } → atomic write, return new claims
 *   304                           → no new billing yet, leave file unchanged
 *   401 / 404 / 410               → distinct outcomes for clear CLI messages
 *   anything else                 → kind=server_error, surface status text
 */

import { createHmac, randomBytes } from 'node:crypto';
import { writeLicenseEnvelopeAtomic } from './activate.js';
import {
  verifyAndDecode,
  readLicenseEnvelope,
  licenseFilePath,
  revalidateLicense,
  type VerifiedClaims,
} from './loader.js';

export type RenewOutcome =
  | { kind: 'renewed'; status: 200; claims: VerifiedClaims; writtenPath: string }
  | { kind: 'no_new_billing'; status: 304 }
  | { kind: 'unauthorized'; status: 401; message: string }
  | { kind: 'unknown_company'; status: 404; message: string }
  | { kind: 'jwt_stale'; status: 410; message: string }
  | { kind: 'no_local_license'; status: 0; message: string }
  | { kind: 'server_error'; status: number; message: string }
  | { kind: 'network_error'; status: 0; message: string }
  | { kind: 'invalid_response'; status: number; message: string };

const NUL = Buffer.from([0]);

interface ProofInput {
  companyId: string;
  currentJti: string;
  nonce: string;
  ts: number;
}

function buildProofInput(input: ProofInput): Buffer {
  return Buffer.concat([
    Buffer.from(input.companyId, 'utf-8'),
    NUL,
    Buffer.from(input.currentJti, 'utf-8'),
    NUL,
    Buffer.from(input.nonce, 'utf-8'),
    NUL,
    Buffer.from(String(input.ts), 'utf-8'),
  ]);
}

export function computeRenewalProof(
  renewalSecret: Buffer,
  input: ProofInput,
): string {
  const h = createHmac('sha256', renewalSecret);
  h.update(buildProofInput(input));
  return h.digest('base64url');
}

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

export const DEFAULT_RENEW_URL = 'https://epic-ai.io/api/license/renew';

function defaultRenewUrl(): string {
  return process.env.CHARIOT_LICENSE_URL || DEFAULT_RENEW_URL;
}

export interface RenewNowOptions {
  /** Override the renew URL; defaults to env CHARIOT_LICENSE_URL or https://epic-ai.io/api/license/renew. */
  url?: string;
  /** Inject a fetch implementation (tests). Default: globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Fetch timeout in ms. Default: 20_000. */
  timeoutMs?: number;
  /** Inject the destination path (tests). Default: licenseFilePath(). */
  destPath?: string;
  /** Override clock for testable ts (defaults to Date.now()/1000). */
  nowSec?: number;
  /** Inject a nonce generator (tests). */
  nonceFn?: () => string;
}

export async function renewNow(
  options: RenewNowOptions = {},
): Promise<RenewOutcome> {
  const envelope = readLicenseEnvelope();
  if (!envelope) {
    return {
      kind: 'no_local_license',
      status: 0,
      message: `No license file found at ${licenseFilePath()}.`,
    };
  }

  const claims = verifyAndDecode(envelope.jwt);
  if (!claims) {
    return {
      kind: 'no_local_license',
      status: 0,
      message: 'Local license file did not verify — re-activate before renewing.',
    };
  }
  if (!claims.jti) {
    return {
      kind: 'no_local_license',
      status: 0,
      message: 'Local license JWT is missing the jti claim — re-activate to recover.',
    };
  }

  let renewalSecret: Buffer;
  try {
    renewalSecret = Buffer.from(envelope.renewal_secret, 'base64url');
  } catch (err) {
    return {
      kind: 'no_local_license',
      status: 0,
      message: `Could not decode renewal_secret: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }

  const ts = options.nowSec ?? Math.floor(Date.now() / 1000);
  const nonce = (options.nonceFn ?? generateNonce)();
  const proof = computeRenewalProof(renewalSecret, {
    companyId: claims.companyId,
    currentJti: claims.jti,
    nonce,
    ts,
  });

  const body = JSON.stringify({
    company_id: claims.companyId,
    current_jti: claims.jti,
    nonce,
    ts,
    proof,
  });

  const url = options.url ?? defaultRenewUrl();
  const fetchImpl = options.fetchImpl ?? fetch;
  // enforce a fetch timeout — an unresponsive renewal endpoint
  // must not hang `chariot license renew-now` indefinitely (the CLI
  // blocks the shell until this returns). 20 seconds is generous for a
  // single-shot POST against license.epic-ai.io and matches our other
  // CLI HTTP call sites.
  const timeoutMs = options.timeoutMs ?? 20_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  // honor HTTPS_PROXY / HTTP_PROXY when set. Node's global
  // fetch (undici) reads these via ProxyAgent; install one if either
  // env is set and the caller did not supply their own fetchImpl.
  let dispatcher: unknown = undefined;
  if (!options.fetchImpl) {
    const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy
      || process.env.HTTP_PROXY || process.env.http_proxy;
    if (proxyUrl) {
      try {
        // Node 22 bundles undici internally for global fetch but does
        // not expose it as a package import in all builds. Resolve
        // lazily and tolerate failure rather than failing the renewal.
        const undiciMod = await import(/* webpackIgnore: true */ 'undici' as string).catch(() => null);
        const ProxyAgent = undiciMod ? (undiciMod as { ProxyAgent?: new (u: string) => unknown }).ProxyAgent : undefined;
        if (ProxyAgent) {
          dispatcher = new ProxyAgent(proxyUrl);
        }
      } catch {
        // undici not resolvable — fall back to direct connect.
      }
    }
  }
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal: controller.signal,
      ...(dispatcher ? { dispatcher } : {}),
    } as RequestInit);
  } catch (err) {
    return {
      kind: 'network_error',
      status: 0,
      message: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }

  if (res.status === 304) {
    return { kind: 'no_new_billing', status: 304 };
  }

  if (res.status === 200) {
    let json: unknown;
    try {
      json = await res.json();
    } catch (err) {
      return {
        kind: 'invalid_response',
        status: 200,
        message: `200 with non-JSON body: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
    if (!json || typeof json !== 'object') {
      return {
        kind: 'invalid_response',
        status: 200,
        message: '200 with non-object body',
      };
    }
    const r = json as { jwt?: unknown; renewal_secret?: unknown };
    if (
      typeof r.jwt !== 'string' ||
      typeof r.renewal_secret !== 'string'
    ) {
      return {
        kind: 'invalid_response',
        status: 200,
        message: '200 missing jwt or renewal_secret in body',
      };
    }
    const newClaims = verifyAndDecode(r.jwt);
    if (!newClaims) {
      return {
        kind: 'invalid_response',
        status: 200,
        message: 'New JWT signature did not verify against embedded keys.',
      };
    }
    const destPath = options.destPath ?? licenseFilePath();
    try {
      writeLicenseEnvelopeAtomic(
        { jwt: r.jwt, renewal_secret: r.renewal_secret },
        destPath,
      );
    } catch (err) {
      return {
        kind: 'invalid_response',
        status: 200,
        message: `Failed to write renewed license: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
    // Flush the new license_epoch to disk immediately. validateLicense has a
    // 60s cache, so we bypass it — otherwise the epoch file stays stale until
    // the next command that runs through the normal validate code path.
    // Always invalidate; revalidateLicense re-reads from licenseFilePath().
    // validateLicense now surfaces an epoch-floor write failure as
    // mode=unlicensed. Renewal MUST NOT declare success in that case,
    // because on the next process restart the new JWT will be rejected
    // as a rollback against the stale floor. Treat any non-licensed
    // outcome as a failed renewal so operators see and fix it now.
    const post = revalidateLicense();
    if (post.mode !== 'licensed' && post.mode !== 'grace') {
      return {
        kind: 'invalid_response',
        status: 200,
        message:
          'Renewed JWT was written to disk but post-renewal validation ' +
          `returned mode=${post.mode}: ${post.reason ?? 'no reason given'}. ` +
          'The renewal is NOT considered committed until the validation ' +
          'returns licensed/grace. Remediate and retry.',
      };
    }
    return {
      kind: 'renewed',
      status: 200,
      claims: newClaims,
      writtenPath: destPath,
    };
  }

  // Read body once for the remaining branches (best-effort).
  let detail = '';
  try {
    detail = await res.text();
  } catch {
    // ignore
  }

  if (res.status === 401) {
    return {
      kind: 'unauthorized',
      status: 401,
      message: detail || 'Auth failed, replay detected, or stale ts.',
    };
  }
  if (res.status === 404) {
    return {
      kind: 'unknown_company',
      status: 404,
      message: detail || 'Server does not recognize this company_id.',
    };
  }
  if (res.status === 410) {
    return {
      kind: 'jwt_stale',
      status: 410,
      message:
        detail ||
        'current_jti is stale — re-download your license from the portal.',
    };
  }
  return {
    kind: 'server_error',
    status: res.status,
    message: detail || res.statusText || 'unknown error',
  };
}
