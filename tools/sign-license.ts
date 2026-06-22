#!/usr/bin/env npx tsx

/**
 * Dev license signing tool — emits the JWT envelope used by the Chariot loader.
 *
 * Usage:
 *   npx tsx tools/sign-license.ts \
 *     --company-id "01985a2e-7c4c-7000-8000-000000000001" \
 *     --company-name "Acme Corp" \
 *     --tier chariot-25 \
 *     --seats 25 \
 *     --days 45 \
 *     --license-epoch 1 \
 *     --min-security-epoch 0 \
 *     --kid <sha256-fingerprint> \
 *     --key <path-to-Ed25519-PEM> \
 *     --output ./test.license
 *
 * Optional:
 *     --sla none|standard|premium    (default: none)
 *     --topology public-llm|hybrid|air-gapped  (default: public-llm)
 *     --renewal-secret <base64url>   (default: random 32 bytes)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';

interface Args {
  companyId: string;
  companyName: string;
  tier: string;
  seats: number;
  days: number;
  licenseEpoch: number;
  minSecurityEpoch: number;
  kid: string;
  keyPath: string;
  outputPath: string;
  sla: 'none' | 'standard' | 'premium';
  topology: 'public-llm' | 'hybrid' | 'air-gapped';
  renewalSecret: Buffer;
}

function parseArgs(): Args {
  const args = process.argv.slice(2);
  const get = (flag: string): string => {
    const idx = args.indexOf(flag);
    if (idx === -1 || idx + 1 >= args.length) {
      throw new Error(`Missing required argument: ${flag}`);
    }
    return args[idx + 1];
  };
  const opt = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    if (idx === -1 || idx + 1 >= args.length) return undefined;
    return args[idx + 1];
  };

  const slaRaw = opt('--sla') ?? 'none';
  if (slaRaw !== 'none' && slaRaw !== 'standard' && slaRaw !== 'premium') {
    throw new Error(`--sla must be one of: none, standard, premium`);
  }
  const topoRaw = opt('--topology') ?? 'public-llm';
  if (topoRaw !== 'public-llm' && topoRaw !== 'hybrid' && topoRaw !== 'air-gapped') {
    throw new Error(`--topology must be one of: public-llm, hybrid, air-gapped`);
  }

  const renewalRaw = opt('--renewal-secret');
  const renewalSecret = renewalRaw
    ? Buffer.from(renewalRaw, 'base64url')
    : randomBytes(32);

  return {
    companyId: get('--company-id'),
    companyName: get('--company-name'),
    tier: get('--tier'),
    seats: parseInt(get('--seats'), 10),
    days: parseInt(get('--days'), 10),
    licenseEpoch: parseInt(get('--license-epoch'), 10),
    minSecurityEpoch: parseInt(get('--min-security-epoch'), 10),
    kid: get('--kid'),
    keyPath: get('--key'),
    outputPath: get('--output'),
    sla: slaRaw,
    topology: topoRaw,
    renewalSecret,
  };
}

async function main(): Promise<void> {
  const opts = parseArgs();

  const pem = readFileSync(opts.keyPath, 'utf-8');
  const key = await importPKCS8(pem, 'EdDSA');

  const now = Math.floor(Date.now() / 1000);
  const exp = now + opts.days * 86400;
  const jti = randomUUID();
  const renewalTokenHash =
    'sha256:' + createHash('sha256').update(opts.renewalSecret).digest('base64url');

  const jwt = await new SignJWT({
    iss: 'license.epic-ai.io',
    sub: opts.companyId,
    tier: opts.tier,
    seats: opts.seats,
    license_epoch: opts.licenseEpoch,
    min_security_epoch: opts.minSecurityEpoch,
    nbf: now,
    exp,
    grace_days: 14,
    topology: opts.topology,
    company_name: opts.companyName,
    sla_tier: opts.sla,
    renewal_token_hash: renewalTokenHash,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: opts.kid })
    .setIssuedAt(now)
    .setJti(jti)
    .sign(key);

  const envelope = {
    jwt,
    renewal_secret: opts.renewalSecret.toString('base64url'),
  };

  writeFileSync(opts.outputPath, JSON.stringify(envelope, null, 2) + '\n', 'utf-8');
  console.log(`License written to ${opts.outputPath}`);
  console.log(`  Subject:  ${opts.companyName} (${opts.companyId})`);
  console.log(`  Tier:     ${opts.tier}`);
  console.log(`  Seats:    ${opts.seats}`);
  console.log(`  SLA:      ${opts.sla}`);
  console.log(`  Topology: ${opts.topology}`);
  console.log(`  Expires:  ${new Date(exp * 1000).toISOString()} (${opts.days} days)`);
  console.log(`  jti:      ${jti}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
