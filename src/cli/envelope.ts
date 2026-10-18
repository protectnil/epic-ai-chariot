/**
 * @epicai/chariot — Typed CLI outcome envelope (CH-31 / CH-32).
 *
 * The single honest-signal contract for every CLI command. A real failure
 * MUST NOT present as exit-0 / ✓ / "configured" / "healthy" (CH-31). Every
 * terminal outcome flows through `emit()`, which:
 *   - in agent mode (`--json` flag or CHARIOT_AGENT=1) prints the envelope as
 *     one line of JSON to stdout, and
 *   - always sets process.exitCode to the typed exit_code.
 *
 * This module is the umbrella referenced by CH-11/CH-12/CH-19 fail-fast
 * clauses — it does not restate them; it gives every surface one envelope
 * shape and one set of exit codes so an agent can branch on the BODY, not
 * just the exit code (the 3.1.2 dogfood gap: 5 different error grammars,
 * `--json` variously rejected / ignored / absent).
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** Severity ladder. `ok`/`info` are non-failures; the rest are failures. */
export type Severity = 'ok' | 'info' | 'warning' | 'blocked' | 'error';

/**
 * Canonical CLI exit codes. Kept stable for agent/CI branching:
 *   0 success · 1 generic failure · 2 usage/validation · 4 STDIN_REQUIRED
 * (a non-TTY interactive prompt). These match the codes already emitted by
 * the 3.1.2 CLI so existing callers and tests keep working.
 */
export const EXIT = {
  OK: 0,
  FAILURE: 1,
  USAGE: 2,
  STDIN_REQUIRED: 4,
} as const;

/** Stable machine codes used across CLI surfaces. */
export type EnvelopeCode =
  | 'OK'
  | 'INTERACTIVE_PROMPT_IN_NON_TTY'
  | 'ADAPTER_NOT_FOUND'
  | 'ADAPTER_REQUIRES_CREDENTIAL'
  | 'CREDENTIAL_UNVALIDATED'
  | 'INSTALL_PERMISSION_DENIED'
  | 'INSTALL_FAILED'
  | 'USAGE_ERROR'
  | 'NOT_CONFIGURED'
  | 'NO_MATCH'
  | 'DISPATCH_FAILED'
  | 'CONFIG_WRITE_FAILED'
  | 'CONFIG_VERIFY_FAILED'
  | 'UNHEALTHY'
  | 'INTERNAL_ERROR'
  | string;

export interface NonInteractiveHint {
  available: boolean;
  /** The exact non-interactive command an agent should run instead. */
  command?: string;
  example?: string;
}

/**
 * The typed outcome. Superset of the CH-31 envelope
 * ({ok,code,severity,cause,remediation,must_not,retryable,exit_code}) and the
 * dogfood-proposed agent envelope (surface / human_message / agent_message /
 * noninteractive / docs / data).
 */
export interface ChariotEnvelope {
  ok: boolean;
  code: EnvelopeCode;
  /** e.g. `cli:add`, `cli:health` — the command that produced this. */
  surface: string;
  severity: Severity;
  /** Why the outcome happened (one sentence). */
  cause?: string;
  human_message?: string;
  agent_message?: string;
  noninteractive?: NonInteractiveHint;
  remediation?: string[];
  /** Things an agent MUST NOT conclude/do from this outcome. */
  must_not?: string[];
  docs?: string;
  retryable: boolean;
  exit_code: number;
  /** Command-specific structured payload (adapters, counts, etc.). */
  data?: Record<string, unknown>;
}

/** True when the CLI is being driven by an agent and must speak JSON. */
export function agentMode(argv: readonly string[] = process.argv.slice(2)): boolean {
  return argv.includes('--json') || process.env.CHARIOT_AGENT === '1';
}

/**
 * True when a `--help`/`-h` flag appears ANYWHERE in the args — the universal
 * non-invasive help signal (CH-32). `--help` must never execute a
 * side-effecting action (today `discover --help` runs a scan, `add --help`
 * misroutes).
 */
export function helpRequested(argv: readonly string[] = process.argv.slice(2)): boolean {
  return argv.some((a) => a === '--help' || a === '-h');
}

/**
 * A typed CLI error. Throwing this from a command lets the central dispatcher
 * catch it and `emit()` a single envelope — instead of each command calling
 * `process.exit()` with an ad-hoc message (the silent/ad-hoc failure source).
 */
export class ChariotError extends Error {
  readonly envelope: ChariotEnvelope;
  constructor(envelope: ChariotEnvelope) {
    super(envelope.cause ?? envelope.human_message ?? String(envelope.code));
    this.name = 'ChariotError';
    this.envelope = { ...envelope, ok: false };
  }
}

/** Build a success envelope. */
export function ok(
  surface: string,
  opts: { human_message?: string; data?: Record<string, unknown>; code?: EnvelopeCode } = {},
): ChariotEnvelope {
  return {
    ok: true,
    code: opts.code ?? 'OK',
    surface,
    severity: 'ok',
    retryable: false,
    exit_code: EXIT.OK,
    ...(opts.human_message !== undefined ? { human_message: opts.human_message } : {}),
    ...(opts.data !== undefined ? { data: opts.data } : {}),
  };
}

/** Build a failure envelope with sane defaults (exit 1, error severity). */
export function fail(
  surface: string,
  code: EnvelopeCode,
  partial: Partial<Omit<ChariotEnvelope, 'ok' | 'surface' | 'code'>> = {},
): ChariotEnvelope {
  return {
    ok: false,
    code,
    surface,
    severity: partial.severity ?? 'error',
    retryable: partial.retryable ?? false,
    exit_code: partial.exit_code ?? EXIT.FAILURE,
    ...(partial.cause !== undefined ? { cause: partial.cause } : {}),
    ...(partial.human_message !== undefined ? { human_message: partial.human_message } : {}),
    ...(partial.agent_message !== undefined ? { agent_message: partial.agent_message } : {}),
    ...(partial.noninteractive !== undefined ? { noninteractive: partial.noninteractive } : {}),
    ...(partial.remediation !== undefined ? { remediation: partial.remediation } : {}),
    ...(partial.must_not !== undefined ? { must_not: partial.must_not } : {}),
    ...(partial.docs !== undefined ? { docs: partial.docs } : {}),
    ...(partial.data !== undefined ? { data: partial.data } : {}),
  };
}

/**
 * Typed "this command needs a TTY and stdin is not one" outcome (CH-32 / M1).
 * Carries the EXACT non-interactive command the agent should run instead so
 * the agent self-corrects rather than hanging or false-negativing.
 */
export function interactiveInNonTty(
  surface: string,
  noninteractiveCommand: string,
  cause: string,
): ChariotEnvelope {
  return fail(surface, 'INTERACTIVE_PROMPT_IN_NON_TTY', {
    severity: 'blocked',
    exit_code: EXIT.STDIN_REQUIRED,
    retryable: true,
    cause,
    agent_message: `stdin is not a TTY; this prompt cannot be answered. Re-run non-interactively: ${noninteractiveCommand}`,
    noninteractive: { available: true, command: noninteractiveCommand },
    remediation: [`Re-run: ${noninteractiveCommand}`],
    must_not: ['report the feature as unsupported', 'treat exit 0 as success'],
  });
}

/**
 * Terminal emit. In agent mode, prints the envelope as one JSON line on
 * stdout. In human mode, a non-ok envelope prints a concise diagnostic to
 * stderr (the human-facing surfaces keep their own rich rendering and pass
 * `humanAlreadyRendered: true`). ALWAYS sets process.exitCode so a real
 * failure can never present as exit-0 (CH-31).
 */
export function emit(
  env: ChariotEnvelope,
  opts: { json?: boolean; humanAlreadyRendered?: boolean } = {},
): ChariotEnvelope {
  const json = opts.json ?? agentMode();
  if (json) {
    process.stdout.write(JSON.stringify(env) + '\n');
  } else if (!env.ok && !opts.humanAlreadyRendered) {
    const head = env.human_message ?? env.cause ?? env.code;
    process.stderr.write(`✗ ${head}\n`);
    for (const r of env.remediation ?? []) process.stderr.write(`  → ${r}\n`);
  }
  process.exitCode = env.exit_code;
  return env;
}
