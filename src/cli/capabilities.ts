/**
 * @epicai/chariot — Machine-readable capability manifest (CH-32).
 *
 * Single source of truth for:
 *   - `chariot capabilities --json` — the "AI UI" surface: every command's
 *     non-interactive invocation + arg schema, so an agent can drive the CLI
 *     without scraping `--help` prose.
 *   - the universal non-invasive `--help` (CH-32): `chariot <cmd> --help`
 *     prints this command's spec and NEVER executes a side-effecting action.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export interface CapabilityArg {
  name: string;
  type: 'string' | 'boolean' | 'enum' | 'kv';
  required: boolean;
  description: string;
  enum?: string[];
}

export interface CommandCapability {
  name: string;
  summary: string;
  usage: string;
  /** A non-interactive invocation an agent can run unattended (no TTY). */
  noninteractive: { available: boolean; command?: string };
  /** True when the command opens an interactive (clack) prompt on a TTY. */
  interactive: boolean;
  args: CapabilityArg[];
  /** Stable outcome codes this command can emit (subset of EnvelopeCode). */
  codes: string[];
}

export interface CapabilityManifest {
  schemaVersion: 1;
  product: 'epic-ai-chariot';
  version: string;
  agentMode: { flag: '--json'; env: 'CHARIOT_AGENT=1' };
  globalFlags: CapabilityArg[];
  exitCodes: Record<string, number>;
  commands: CommandCapability[];
}

const GLOBAL_FLAGS: CapabilityArg[] = [
  { name: '--json', type: 'boolean', required: false, description: 'Emit a typed JSON outcome envelope on stdout (agent mode). Equivalent to CHARIOT_AGENT=1.' },
  { name: '--help', type: 'boolean', required: false, description: 'Print this command\'s help and exit without side effects (works on any command).' },
  { name: '--yes', type: 'boolean', required: false, description: 'Assume defaults for interactive prompts (non-interactive).' },
];

const COMMANDS: CommandCapability[] = [
  {
    name: 'query',
    summary: 'Route a natural-language question to your adapters and return the result.',
    usage: 'chariot query "<question>" [--json]',
    noninteractive: { available: true, command: 'chariot query "<question>" --json' },
    interactive: false,
    args: [{ name: 'question', type: 'string', required: true, description: 'The natural-language question to route.' }],
    codes: ['OK', 'NOT_CONFIGURED', 'NO_MATCH', 'DISPATCH_FAILED'],
  },
  {
    name: 'list',
    summary: 'Show curated + custom adapters with their bundle tool counts.',
    usage: 'chariot list [term] [--json]',
    noninteractive: { available: true, command: 'chariot list --json' },
    interactive: false,
    args: [{ name: 'term', type: 'string', required: false, description: 'Optional search term (delegates to search).' }],
    codes: ['OK'],
  },
  {
    name: 'search',
    summary: 'Search all available adapters by id, name, category, or description.',
    usage: 'chariot search <term> [--json]',
    noninteractive: { available: true, command: 'chariot search <term> --json' },
    interactive: false,
    args: [{ name: 'term', type: 'string', required: false, description: 'Search term.' }],
    codes: ['OK', 'NO_MATCH'],
  },
  {
    name: 'add',
    summary: 'Add an adapter; supply credentials non-interactively with --token KEY=VAL.',
    usage: 'chariot add <id> [--token KEY=VAL ...] [--json]',
    noninteractive: { available: true, command: 'chariot add <id> --token KEY=VALUE --json' },
    interactive: true,
    args: [
      { name: 'id', type: 'string', required: true, description: 'Adapter id (run `chariot search <term>` to find one).' },
      { name: '--token', type: 'kv', required: false, description: 'Credential KEY=VALUE; repeatable; non-interactive.' },
    ],
    codes: ['OK', 'ADAPTER_NOT_FOUND', 'ADAPTER_REQUIRES_CREDENTIAL', 'CREDENTIAL_UNVALIDATED', 'INSTALL_PERMISSION_DENIED', 'INSTALL_FAILED'],
  },
  {
    name: 'remove',
    summary: 'Remove an adapter AND purge its credential + MCP client-config entries (no residue).',
    usage: 'chariot remove <id> [--json]',
    noninteractive: { available: true, command: 'chariot remove <id> --json' },
    interactive: false,
    args: [{ name: 'id', type: 'string', required: true, description: 'Adapter id to remove.' }],
    codes: ['OK', 'NOT_CONFIGURED'],
  },
  {
    name: 'health',
    summary: 'Report adapter health: callable tools + credential validity (0-tool / unvalidated never show green).',
    usage: 'chariot health [--json]',
    noninteractive: { available: true, command: 'chariot health --json' },
    interactive: false,
    args: [],
    codes: ['OK', 'UNHEALTHY', 'NOT_CONFIGURED'],
  },
  {
    name: 'configure',
    summary: 'Interactively scan for credentials and wire adapters.',
    usage: 'chariot configure',
    noninteractive: { available: false },
    interactive: true,
    args: [],
    codes: ['OK', 'INTERACTIVE_PROMPT_IN_NON_TTY'],
  },
  {
    name: 'discover',
    summary: 'Scan a codebase for internal APIs and emit discovered adapters.',
    usage: 'chariot discover [--path <dir>] [--config <file>] [--rescan] [--json]',
    noninteractive: { available: true, command: 'chariot discover --config <file> --json' },
    interactive: true,
    args: [
      { name: '--path', type: 'string', required: false, description: 'Codebase directory to scan.' },
      { name: '--config', type: 'string', required: false, description: 'Non-interactive discovery config file.' },
      { name: '--rescan', type: 'boolean', required: false, description: 'Rescan and show changes.' },
    ],
    codes: ['OK', 'INTERACTIVE_PROMPT_IN_NON_TTY'],
  },
  {
    name: 'serve',
    summary: 'Start the MCP server (stdio default; --http / --rest).',
    usage: 'chariot serve [--http [port]] [--rest [port]] [--stop] [--status]',
    noninteractive: { available: true, command: 'chariot serve --http 3550' },
    interactive: false,
    args: [
      { name: '--http', type: 'string', required: false, description: 'Bind Streamable-HTTP MCP (default port 3550).' },
      { name: '--rest', type: 'string', required: false, description: 'Bind REST JSON API (default port 3551).' },
      { name: '--stop', type: 'boolean', required: false, description: 'Stop a running listener.' },
      { name: '--status', type: 'boolean', required: false, description: 'Report listener status.' },
    ],
    codes: ['OK'],
  },
  {
    name: 'capabilities',
    summary: 'Print this machine-readable capability manifest (the agent UI).',
    usage: 'chariot capabilities [--json]',
    noninteractive: { available: true, command: 'chariot capabilities --json' },
    interactive: false,
    args: [],
    codes: ['OK'],
  },
  {
    name: 'version',
    summary: 'Print the installed Chariot version.',
    usage: 'chariot version',
    noninteractive: { available: true, command: 'chariot version' },
    interactive: false,
    args: [],
    codes: ['OK'],
  },
  {
    name: 'help',
    summary: 'Show the command list.',
    usage: 'chariot help',
    noninteractive: { available: true, command: 'chariot help' },
    interactive: false,
    args: [],
    codes: ['OK'],
  },
  {
    name: 'status',
    summary: 'Report whether a Chariot HTTP server is listening and which pid holds the port.',
    usage: 'chariot status [--http [port]]',
    noninteractive: { available: true, command: 'chariot status' },
    interactive: false,
    args: [{ name: '--http', type: 'string', required: false, description: 'Port to check (default 3550).' }],
    codes: ['OK'],
  },
  {
    name: 'license',
    summary: 'Show license status, activate a license file, or force an immediate renewal.',
    usage: 'chariot license [status|activate <path>|renew-now]',
    noninteractive: { available: true, command: 'chariot license --json' },
    interactive: false,
    args: [
      { name: 'subcommand', type: 'enum', required: false, description: 'License subcommand.', enum: ['status', 'activate', 'renew-now'] },
      { name: 'path', type: 'string', required: false, description: 'License file path (required for activate).' },
    ],
    codes: ['OK'],
  },
  {
    name: 'telemetry',
    summary: 'Operational telemetry controls: status, enable (needs the user\'s own words), disable, signed export. Off by default; nine non-sensitive fields only.',
    usage: 'chariot telemetry [status|enable|disable|export] [--statement <words>] [--transport export-only|auto] [--out <path>] [--json]',
    noninteractive: { available: true, command: 'chariot telemetry status --json' },
    interactive: false,
    args: [
      { name: 'subcommand', type: 'enum', required: false, description: 'Telemetry subcommand (default status).', enum: ['status', 'enable', 'disable', 'export'] },
      { name: '--statement', type: 'string', required: false, description: 'Required for enable: the user\'s own words authorizing telemetry. Ask the user first; never enable on your own initiative.' },
      { name: '--transport', type: 'enum', required: false, description: 'enable only: export-only (default) or auto (connected licensed deployments upload to license.epic-ai.io).', enum: ['export-only', 'auto'] },
      { name: '--out', type: 'string', required: false, description: 'export only: destination file (must not exist).' },
    ],
    codes: ['OK', 'USAGE_ERROR', 'TELEMETRY_AUTO_NOT_PERMITTED', 'SIGNING_KEY_NOT_CONFIGURED', 'TELEMETRY_STORE_UNAVAILABLE'],
  },
  {
    name: 'audit',
    summary: 'Operate on the RFC-3161 audit chain (anchor, attest, verify-anchor, verify-length).',
    usage: 'chariot audit <anchor|attest|verify-anchor <tsr>|verify-length> [--chain-id <id>] [--json]',
    noninteractive: { available: true, command: 'chariot audit <subcommand> --json' },
    interactive: false,
    args: [
      { name: 'subcommand', type: 'enum', required: true, description: 'Audit subcommand.', enum: ['anchor', 'attest', 'verify-anchor', 'verify-length'] },
      { name: '--chain-id', type: 'string', required: false, description: 'Chain identifier (default "default"). No path separators or "..".' },
      { name: '--cert', type: 'string', required: false, description: 'PEM certificate path for verify-anchor.' },
    ],
    codes: ['OK', 'TSA_NOT_CONFIGURED', 'CHAIN_FILE_NOT_FOUND', 'VERIFY_ANCHOR_FAILED', 'CHAIN_TRUNCATION_DETECTED', 'USAGE_ERROR'],
  },
  {
    name: 'approve',
    summary: 'Interactively approve a CLI-bridge adapter for tool dispatch (AS §1.5).',
    usage: 'chariot approve <adapter-id>',
    noninteractive: { available: false },
    interactive: true,
    args: [{ name: 'id', type: 'string', required: true, description: 'CLI-bridge adapter id to approve.' }],
    codes: ['OK', 'APPROVAL_REFUSED', 'ADAPTER_NOT_FOUND', 'ADAPTER_TYPE_MISMATCH', 'INTERACTIVE_PROMPT_IN_NON_TTY'],
  },
  {
    name: 'approvals',
    summary: 'List all currently approved CLI-bridge adapters.',
    usage: 'chariot approvals [--json]',
    noninteractive: { available: true, command: 'chariot approvals --json' },
    interactive: false,
    args: [],
    codes: ['OK'],
  },
  {
    name: 'revoke',
    summary: 'Revoke a prior CLI-bridge adapter approval. Exits non-zero when the adapter has no active approval.',
    usage: 'chariot revoke <adapter-id> [--json]',
    noninteractive: { available: true, command: 'chariot revoke <adapter-id> --json' },
    interactive: false,
    args: [{ name: 'id', type: 'string', required: true, description: 'Adapter id whose approval to revoke.' }],
    codes: ['OK', 'NOT_FOUND', 'USAGE_ERROR'],
  },
  {
    name: 'resume',
    summary: 'Read the latest checkpoint for a traceId from the SQLite checkpoint store.',
    usage: 'chariot resume <traceId> [--json]',
    noninteractive: { available: true, command: 'chariot resume <traceId> --json' },
    interactive: false,
    args: [{ name: 'traceId', type: 'string', required: true, description: 'UUID or arbitrary trace identifier (max 256 chars).' }],
    codes: ['OK', 'NOT_FOUND', 'USAGE_ERROR'],
  },
  {
    name: 'trace',
    summary: 'Step-by-step breakdown of an audit-chain trace with optional LLM attribution scoring.',
    usage: 'chariot trace explain <traceId> [audit.jsonl] [--json]',
    noninteractive: { available: true, command: 'chariot trace explain <traceId> --json' },
    interactive: false,
    args: [
      { name: 'subcommand', type: 'enum', required: true, description: 'Trace subcommand.', enum: ['explain'] },
      { name: 'traceId', type: 'string', required: true, description: 'UUID v4 to filter on.' },
      { name: 'auditFile', type: 'string', required: false, description: 'Explicit audit-chain JSONL file path (defaults to .chariot/audit/chain.jsonl).' },
    ],
    codes: ['OK', 'NOT_FOUND', 'AUDIT_FILE_NOT_FOUND', 'USAGE_ERROR'],
  },
];

/** All command names recognised by the manifest. */
export function commandNames(): string[] {
  return COMMANDS.map((c) => c.name);
}

/** Look up one command's capability spec (by name or alias). */
export function getCommand(name: string | undefined): CommandCapability | undefined {
  if (!name) return undefined;
  const n = name.replace(/^--?/, '');
  return COMMANDS.find((c) => c.name === n);
}

/** Build the full manifest. */
export function buildManifest(version: string): CapabilityManifest {
  return {
    schemaVersion: 1,
    product: 'epic-ai-chariot',
    version,
    agentMode: { flag: '--json', env: 'CHARIOT_AGENT=1' },
    globalFlags: GLOBAL_FLAGS,
    exitCodes: { OK: 0, FAILURE: 1, USAGE: 2, STDIN_REQUIRED: 4 },
    commands: COMMANDS,
  };
}

/** Render one command's help as plain lines (universal non-invasive --help). */
export function renderCommandHelp(cmd: CommandCapability): string[] {
  const lines: string[] = [
    '',
    `  chariot ${cmd.name} — ${cmd.summary}`,
    '',
    `  Usage: ${cmd.usage}`,
  ];
  if (cmd.args.length > 0) {
    lines.push('', '  Arguments:');
    for (const a of cmd.args) {
      const req = a.required ? 'required' : 'optional';
      const en = a.enum ? ` (${a.enum.join('|')})` : '';
      lines.push(`    ${a.name}${en}  [${req}]  ${a.description}`);
    }
  }
  lines.push('', `  Interactive: ${cmd.interactive ? 'yes (TTY)' : 'no'}`);
  if (cmd.noninteractive.available && cmd.noninteractive.command) {
    lines.push(`  Non-interactive: ${cmd.noninteractive.command}`);
  } else if (!cmd.noninteractive.available) {
    lines.push('  Non-interactive: not available (requires a TTY)');
  }
  lines.push('');
  return lines;
}
