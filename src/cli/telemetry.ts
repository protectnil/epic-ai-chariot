/**
 * `chariot telemetry status|enable|disable|export` — the agent-operable
 * control surface for operational telemetry (C4AMD §8, amended 2026-10-12:
 * "The AI is the user interface").
 *
 * Every outcome is ONE typed envelope (CH-31/CH-32). No prompt, no TTY
 * dependency. These are CLI commands listed in `chariot capabilities
 * --json`; they are NOT MCP tools (C4AMD §2::1: the client-visible MCP
 * surface stays exactly chariot_query / chariot_call / chariot_list).
 *
 * CONSENT EVIDENCE: `enable` requires `--statement "<the user's own
 * words>"`. An agent must obtain the user's explicit yes in conversation
 * and pass it through; the words are recorded with the consent version
 * (C4AMD §8::6 "auditable"). The tool never enables telemetry on its own.
 */

import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { fail, ok, EXIT, type ChariotEnvelope } from './envelope.js';
import { getConsentHistory, getCurrentConsent, setConsent } from '../iam/services/telemetry-consent.js';
import { hasMongoClient } from '../iam/db.js';
import { getStoredEvents } from '../observability/operational-telemetry/capture.js';
import { exportToFile } from '../observability/operational-telemetry/export.js';
import { readUploadState, type TelemetryTransport } from '../observability/operational-telemetry/local-store.js';
import { evaluateConnectedLicenseGate, evaluateUploadEligibility } from '../telemetry-upload/uploader.js';

const SURFACE = 'cli:telemetry';

export function telemetryTenantId(): string {
  const t = process.env.CHARIOT_TENANT_ID;
  return t !== undefined && t.length > 0 ? t : 'local';
}

function packageRoot(): string {
  // src/cli -> package root, and dist/cli -> package root: same depth.
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function flagValue(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  if (i === -1) return undefined;
  const v = argv[i + 1];
  return v !== undefined && !v.startsWith('--') ? v : undefined;
}

function usage(cause: string, agentMessage: string, remediation: string[]): ChariotEnvelope {
  return fail(SURFACE, 'USAGE_ERROR', {
    severity: 'error',
    exit_code: EXIT.USAGE,
    cause,
    agent_message: agentMessage,
    remediation,
  });
}

async function cmdStatus(tenantId: string): Promise<ChariotEnvelope> {
  const consent = await getCurrentConsent(tenantId);
  const history = await getConsentHistory(tenantId);
  let eventCount: number | null = null;
  try {
    eventCount = (await getStoredEvents(tenantId)).length;
  } catch {
    eventCount = null; // store unreadable: report UNKNOWN, never 0
  }
  const upload = await evaluateUploadEligibility(tenantId);
  const state = readUploadState(tenantId);
  const sentence = !consent.enabled
    ? 'Operational telemetry is OFF (the default). Nothing is collected.'
    : consent.transport === 'auto'
      ? upload.eligible
        ? 'Operational telemetry is ON with automatic upload to license.epic-ai.io.'
        : `Operational telemetry is ON; automatic upload is selected but not currently possible (${upload.eligible ? '' : upload.code}).`
      : 'Operational telemetry is ON, stored locally; it leaves this machine only if you export it.';
  return ok(SURFACE, {
    human_message: sentence,
    data: {
      sub: 'status',
      tenantId,
      enabled: consent.enabled,
      transport: consent.transport,
      consentVersion: consent.version,
      changedAt: consent.version === 0 ? null : consent.changedAt.toISOString(),
      changedBy: consent.version === 0 ? null : consent.changedBy,
      consentVersions: history.length,
      store: hasMongoClient() ? 'mongodb' : 'local-file',
      eventsStored: eventCount,
      automaticUpload: upload.eligible
        ? { possible: true }
        : { possible: false, code: upload.code, reason: upload.reason },
      lastUpload: { lastAttemptAt: state.lastAttemptAt, lastResult: state.lastResult },
      fields: ['tenantId', 'canonicalToolId', 'outcome', 'latencyMs', 'failureStage', 'hourBucket', 'productVersion', 'platform', 'catalogEpoch'],
      never_collected: ['secrets', 'credentials', 'authorization material', 'tool arguments', 'tool results', 'training examples'],
    },
  });
}

async function cmdEnable(tenantId: string, argv: readonly string[]): Promise<ChariotEnvelope> {
  const statement = flagValue(argv, '--statement');
  if (statement === undefined || statement.trim().length === 0) {
    return usage(
      'enable requires --statement with the user\'s own words authorizing telemetry.',
      'Do NOT enable telemetry on your own initiative. Ask the user whether they want to turn on operational telemetry (nine non-sensitive fields: tool id, success/failure, latency, failure stage, hour, version, platform, catalog epoch — never arguments, results or credentials). If they agree, re-run with their words in --statement.',
      ['Run: chariot telemetry enable --statement "<the user\'s words>" [--transport export-only|auto] --json'],
    );
  }
  const transportRaw = flagValue(argv, '--transport') ?? 'export-only';
  if (transportRaw !== 'export-only' && transportRaw !== 'auto') {
    return usage(`Unknown --transport "${transportRaw}".`, 'Use --transport export-only or --transport auto.', [
      'Run: chariot telemetry enable --statement "<words>" --transport export-only --json',
    ]);
  }
  const transport = transportRaw as TelemetryTransport;

  if (transport === 'auto') {
    const gate = evaluateConnectedLicenseGate();
    if (!gate.eligible) {
      return fail(SURFACE, 'TELEMETRY_AUTO_NOT_PERMITTED', {
        severity: 'blocked',
        exit_code: EXIT.FAILURE,
        cause: gate.reason,
        agent_message:
          'Automatic upload is only available for connected (public-LLM or hybrid) deployments with a verified license. Offer export-only instead; do not retry --transport auto.',
        remediation: ['Run: chariot telemetry enable --statement "<words>" --transport export-only --json'],
        must_not: ['claim telemetry is enabled with automatic upload', 'retry with the same arguments'],
        data: { code: gate.code },
      });
    }
  }

  const rec = await setConsent(tenantId, true, process.env.USER ?? process.env.USERNAME ?? 'cli', { transport, statement });
  return ok(SURFACE, {
    human_message:
      transport === 'auto'
        ? 'Operational telemetry is ON with automatic upload to license.epic-ai.io (nine non-sensitive metadata fields). Disable any time with: chariot telemetry disable'
        : 'Operational telemetry is ON and stored locally. It leaves this machine only if you export it: chariot telemetry export',
    data: { sub: 'enable', tenantId, enabled: true, transport: rec.transport, consentVersion: rec.version },
  });
}

async function cmdDisable(tenantId: string): Promise<ChariotEnvelope> {
  const rec = await setConsent(tenantId, false, process.env.USER ?? process.env.USERNAME ?? 'cli');
  return ok(SURFACE, {
    human_message: 'Operational telemetry is OFF. Collection and upload have stopped; previously stored events remain until you delete them.',
    data: { sub: 'disable', tenantId, enabled: false, transport: rec.transport, consentVersion: rec.version },
  });
}

async function cmdExport(tenantId: string, argv: readonly string[]): Promise<ChariotEnvelope> {
  const consent = await getCurrentConsent(tenantId);
  const outArg = flagValue(argv, '--out');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = resolve(
    outArg ?? join(process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai'), 'exports', `telemetry-${stamp}.json`),
  );
  if (existsSync(dest)) {
    return usage(`Refusing to overwrite existing file ${dest}.`, 'Choose a new path with --out.', [
      'Run: chariot telemetry export --out <new-path> --json',
    ]);
  }
  try {
    const signed = await exportToFile(tenantId, dest, { packageRoot: packageRoot() });
    return ok(SURFACE, {
      human_message: `Wrote a signed export of ${signed.bundle.events.length} event(s) to ${dest}. Sending it to Epic AI is your decision.`,
      data: {
        sub: 'export',
        tenantId,
        path: dest,
        eventCount: signed.bundle.events.length,
        bundleHash: signed.bundleHash,
        signatureKid: signed.signature.kid,
        consentEnabled: consent.enabled,
      },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/SIGNING_KEY|sealed|packageRoot|ENTERPRISE_MASTER_KEY|CHARIOT_AUDIT_/i.test(msg)) {
      return fail(SURFACE, 'SIGNING_KEY_NOT_CONFIGURED', {
        severity: 'blocked',
        cause: 'No audit-signing key is configured on this host, so a signed export cannot be produced.',
        agent_message:
          'A signed export needs an audit-signing key (kms, vault-transit or sealed-store). If this is a connected licensed deployment, enable automatic upload instead so no file transfer is needed.',
        remediation: [
          'Connected licensed deployments: chariot telemetry enable --statement "<words>" --transport auto --json (no file transfer is needed).',
          'Managed signer (no key file on this host): set CHARIOT_AUDIT_SIGNER_BACKEND=kms or vault-transit and its settings, as described in docs/product/AUDIT-SIGNING-KEY-RUNBOOK.md.',
          'Sealed-store signer: set ENTERPRISE_MASTER_KEY and provision the sealed key as described in docs/product/AUDIT-SIGNING-KEY-RUNBOOK.md, then retry the export.',
        ],
        must_not: ['report the export as written', 'fall back to an unsigned file'],
        data: { detail: msg.slice(0, 300) },
      });
    }
    return fail(SURFACE, 'INTERNAL_ERROR', { cause: msg.slice(0, 300), retryable: true });
  }
}

/** Dispatch `chariot telemetry <sub> …`. `argv` is everything after the word `telemetry`. */
export async function runTelemetryCommand(argv: readonly string[]): Promise<ChariotEnvelope> {
  // Order-independent: an agent may place flags before the subcommand.
  const KNOWN = ['status', 'enable', 'disable', 'export'];
  const sub = argv.find((a) => KNOWN.includes(a)) ?? argv.find((a) => !a.startsWith('-')) ?? 'status';
  const tenantId = telemetryTenantId();
  try {
    switch (sub) {
      case 'status':
        return await cmdStatus(tenantId);
      case 'enable':
        return await cmdEnable(tenantId, argv);
      case 'disable':
        return await cmdDisable(tenantId);
      case 'export':
        return await cmdExport(tenantId, argv);
      default:
        return usage(`Unknown subcommand: telemetry ${sub}`, 'Valid: status | enable | disable | export.', [
          'Run: chariot capabilities --json',
        ]);
    }
  } catch (err) {
    return fail(SURFACE, 'TELEMETRY_STORE_UNAVAILABLE', {
      cause: err instanceof Error ? err.message.slice(0, 300) : String(err).slice(0, 300),
      agent_message: 'The telemetry store could not be read or written; nothing was changed. Do not report telemetry as enabled.',
      retryable: true,
    });
  }
}
