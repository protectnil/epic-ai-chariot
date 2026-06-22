#!/usr/bin/env node
/**
 * @epicai/chariot — Attribute-Trace Scorer
 *
 * Operator-invoked tool that loads an exported audit trail, filters records
 * for a given traceId, and asks a real LLM judge to identify which step
 * introduced the error. Uses selectLlmClient() directly (not ensembleJudge)
 * because ensembleJudge normalizes responses to PASS/FAIL/ABSTAIN; this
 * scorer needs the raw structured reply with STEP_ID and KIND lines.
 *
 * Usage:
 *   node scripts/attribute-trace.mjs <trace.json> <traceId>
 *
 *   trace.json   — JSONL audit chain export (output of `chariot audit export
 *                  --format jsonl`) OR a JSON array of ActionRecord objects.
 *                  When append-only JSONL is used, status-update lines that
 *                  share an `id` with an earlier `record` line are coalesced.
 *   traceId      — UUID v4 to filter on
 *
 * Output (stdout, JSON):
 *   {
 *     "traceId": "...",
 *     "attributedStepId": "...",        // null if no clear attribution
 *     "errorKind": "tool-output",       // one of: reasoning|tool-selection|
 *                                       //         parameter|tool-output|propagation|unknown
 *     "confidence": 1.0,                // 1.0 when judge produced a parseable
 *                                       // response, 0.0 when no judge available
 *     "judge": { "kind": "...", "model": "...", "raw": "..." }
 *   }
 *
 * Exit:
 *   0 — scoring completed (attribution may be null if judge refused or
 *       returned NONE)
 *   1 — fatal: file read failure, no records for traceId, no judge keys, or
 *       judge call threw
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { selectLlmClient, loadBackendEnv } from '../test/ai-evals/harness.mjs';

const ERROR_KINDS = ['reasoning', 'tool-selection', 'parameter', 'tool-output', 'propagation', 'unknown'];

function usage() {
  console.error('Usage: node scripts/attribute-trace.mjs <trace.json> <traceId>');
  console.error('');
  console.error('  trace.json  — JSONL audit export OR JSON array of ActionRecord objects');
  console.error('  traceId     — UUID v4 to filter on');
  process.exit(1);
}

function loadRecords(path) {
  const abs = resolve(path);
  if (!existsSync(abs)) {
    console.error(`Trace file not found: ${abs}`);
    process.exit(1);
  }
  const raw = readFileSync(abs, 'utf-8').trim();
  if (raw.length === 0) {
    console.error(`Trace file is empty: ${abs}`);
    process.exit(1);
  }
  // Try JSON array first
  try {
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) return arr;
  } catch { /* fall through to JSONL */ }
  // JSONL — coalesce status-update lines by `id`. Append-only JSONLAdapter
  // writes a record line first, then later updateStatus lines that share
  // the same id but carry only {id, status, output, durationMs, updatedAt}.
  // The trace-filter needs the merged view of each id.
  const byId = new Map();
  const order = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    let obj;
    try {
      obj = JSON.parse(trimmed);
    } catch (err) {
      console.error(`JSONL parse error on line: ${trimmed.slice(0, 120)}... — ${err.message}`);
      process.exit(1);
    }
    if (!obj || typeof obj.id !== 'string') {
      // No id — emit as-is, no coalescing.
      order.push(obj);
      continue;
    }
    if (byId.has(obj.id)) {
      // Merge: original record line stays anchor; later lines overlay status/output/durationMs/failureMode/etc.
      const existing = byId.get(obj.id);
      byId.set(obj.id, { ...existing, ...obj });
    } else {
      byId.set(obj.id, obj);
      order.push(obj.id);
    }
  }
  const merged = [];
  for (const item of order) {
    if (typeof item === 'string') merged.push(byId.get(item));
    else merged.push(item);
  }
  return merged;
}

function filterByTraceId(records, traceId) {
  return records
    .filter((r) => r && r.traceId === traceId)
    .sort((a, b) => (a.sequenceNumber ?? 0) - (b.sequenceNumber ?? 0));
}

function summarizeStep(r) {
  const status = r.status ?? 'unknown';
  const kind = r.stepKind ?? r.action ?? 'unknown';
  const id = r.id ?? '<no-id>';
  const out = typeof r.output === 'object' ? JSON.stringify(r.output) : String(r.output ?? '');
  const trimmedOut = out.length > 200 ? out.slice(0, 200) + '…' : out;
  return `[${id}] kind=${kind} status=${status} output=${trimmedOut}`;
}

function buildPrompt(steps) {
  const stepList = steps.map((s, i) => `  ${i + 1}. ${summarizeStep(s)}`).join('\n');
  return [
    'You are analyzing a multi-step agent trace for the step that most likely',
    'introduced an error that propagated to the final wrong answer. Classify',
    'the error kind as exactly one of:',
    `  ${ERROR_KINDS.join(' | ')}`,
    '',
    'Steps:',
    stepList,
    '',
    'Reply in EXACTLY this format on two lines, no other text:',
    '  STEP_ID: <id of the responsible step from the list, or NONE if none>',
    '  KIND: <one of the listed kinds>',
  ].join('\n');
}

function parseReply(text) {
  if (typeof text !== 'string') return { stepId: null, kind: 'unknown' };
  const stepMatch = text.match(/STEP_ID:\s*(\S+)/i);
  const kindMatch = text.match(/KIND:\s*([a-z\-]+)/i);
  const stepId = stepMatch && stepMatch[1].toUpperCase() !== 'NONE' ? stepMatch[1] : null;
  let kind = kindMatch ? kindMatch[1].toLowerCase() : 'unknown';
  if (!ERROR_KINDS.includes(kind)) kind = 'unknown';
  return { stepId, kind };
}

// ── Main ──────────────────────────────────────────────────────────────────

if (process.argv.length < 4) usage();

const tracePath = process.argv[2];
const traceId = process.argv[3];

// Hydrate env via the harness convention (loads backend env file when set
// in CHARIOT_EVAL_ENV_FILE or any other harness-known location).
loadBackendEnv();

const records = loadRecords(tracePath);
const steps = filterByTraceId(records, traceId);
if (steps.length === 0) {
  console.error(`No records found for traceId=${traceId} in ${tracePath}`);
  process.exit(1);
}

let client;
try {
  client = await selectLlmClient({ purpose: 'attribute-trace' });
} catch (err) {
  console.error(`Cannot select LLM client: ${err?.message ?? err}`);
  console.error('No judge is available. Set ANTHROPIC_API_KEY or OPENAI_API_KEY,');
  console.error('or run a local Ollama instance reachable at the harness default URL.');
  process.exit(1);
}
if (!client) {
  console.error('No judge is available. Set ANTHROPIC_API_KEY or OPENAI_API_KEY,');
  console.error('or run a local Ollama instance reachable at the harness default URL.');
  process.exit(1);
}

const prompt = buildPrompt(steps);
let reply;
try {
  const resp = await client.callChat({
    messages: [
      { role: 'system', content: 'You are an impartial diagnostic analyst.' },
      { role: 'user', content: prompt },
    ],
  });
  reply = resp?.content ?? '';
} catch (err) {
  console.error(`Judge call failed: ${err?.message ?? err}`);
  process.exit(1);
}

const parsed = parseReply(reply);

const result = {
  traceId,
  attributedStepId: parsed.stepId,
  errorKind: parsed.kind,
  confidence: parsed.stepId !== null ? 1.0 : 0.0,
  judge: {
    kind: client.kind ?? null,
    model: client.model ?? null,
    raw: typeof reply === 'string' ? reply.slice(0, 500) : null,
  },
};

console.log(JSON.stringify(result, null, 2));
process.exit(0);
