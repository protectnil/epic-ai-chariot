/**
 * @epicai/chariot — MCP Client Detection and Config Writing
 * Detects 11 MCP clients (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code,
 * Codex, Gemini, Cline, Continue, Goose, Roo Code) and writes a Chariot entry into
 * each client's MCP config. The serve invocation differs between the outer Chariot
 * CLI (`serve`) and the engine setup CLI (`--serve`), so writeMcpConfig takes the
 * entry as a parameter rather than hardcoding it.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { closeSync, constants as fsConstants, existsSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { commandExists, expandHome } from './paths.js';
import { isNodeVersionSupported, detectRuntimes, detectHardware } from './hardware.js';
import type { McpClientInfo, SystemInfo } from './types.js';

export interface McpEntry {
  command: string;
  args: string[];
}

export function detectMcpClients(): McpClientInfo[] {
  const isMac = process.platform === 'darwin';
  return [
    {
      // CH-48: Claude Code reads `~/.claude.json` (top-level `mcpServers`),
      // NOT `~/.claude/mcp.json` — the 3.1.2 wizard wrote a path the client
      // never consults (silent no-op). Corrected to the real target.
      id: 'claude-code',
      name: 'Claude Code CLI',
      detected: existsSync(expandHome('~/.claude.json')) || existsSync(expandHome('~/.claude')) || commandExists('claude'),
      configPath: expandHome('~/.claude.json'),
      configKey: 'mcpServers',
      format: 'json',
    },
    {
      id: 'claude-desktop',
      name: 'Claude Desktop',
      detected: isMac
        ? existsSync(expandHome('~/Library/Application Support/Claude'))
        : existsSync(expandHome('~/.config/Claude')),
      configPath: isMac
        ? expandHome('~/Library/Application Support/Claude/claude_desktop_config.json')
        : expandHome('~/.config/Claude/claude_desktop_config.json'),
      configKey: 'mcpServers',
    },
    {
      id: 'cursor',
      name: 'Cursor',
      detected: existsSync(expandHome('~/.cursor')) || (isMac && existsSync('/Applications/Cursor.app')),
      configPath: expandHome('~/.cursor/mcp.json'),
      configKey: 'mcpServers',
    },
    {
      id: 'windsurf',
      name: 'Windsurf',
      detected: existsSync(expandHome('~/.codeium/windsurf')),
      configPath: expandHome('~/.codeium/windsurf/mcp_config.json'),
      configKey: 'mcpServers',
    },
    {
      id: 'vscode',
      name: 'VS Code (Copilot)',
      detected: commandExists('code') || (isMac && existsSync('/Applications/Visual Studio Code.app')),
      configPath: expandHome('~/.vscode/mcp.json'),
      configKey: 'servers',
      hint: 'Per-project: .vscode/mcp.json',
    },
    {
      // CH-48: Codex reads TOML at `~/.codex/config.toml`
      // (`[mcp_servers.<name>]`), NOT JSON at `~/.codex/config.json`. The
      // 3.1.2 wizard wrote a JSON file Codex never loads. Corrected to the
      // real path + format.
      id: 'codex',
      name: 'Codex CLI',
      detected: existsSync(expandHome('~/.codex')) || commandExists('codex'),
      configPath: expandHome('~/.codex/config.toml'),
      configKey: 'mcp_servers',
      format: 'toml',
    },
    {
      id: 'gemini',
      name: 'Gemini CLI',
      detected: existsSync(expandHome('~/.gemini')) || commandExists('gemini'),
      configPath: expandHome('~/.gemini/settings.json'),
      configKey: 'mcpServers',
      format: 'json',
    },
    {
      id: 'cline',
      name: 'Cline',
      detected: isMac
        ? existsSync(expandHome('~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev'))
        : existsSync(expandHome('~/.config/Code/User/globalStorage/saoudrizwan.claude-dev')),
      configPath: isMac
        ? expandHome('~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json')
        : expandHome('~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json'),
      configKey: 'mcpServers',
    },
    {
      id: 'continue',
      name: 'Continue',
      detected: existsSync(expandHome('~/.continue')),
      configPath: expandHome('~/.continue/config.json'),
      configKey: 'mcpServers',
    },
    {
      id: 'goose',
      name: 'Goose',
      detected: commandExists('goose'),
      configPath: expandHome('~/.config/goose/config.yaml'),
      configKey: 'mcpServers',
      hint: 'YAML config — manual setup recommended',
    },
    {
      id: 'roo-code',
      name: 'Roo Code',
      detected: isMac
        ? existsSync(expandHome('~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline'))
        : false,
      configPath: isMac
        ? expandHome('~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json')
        : '',
      configKey: 'mcpServers',
    },
  ];
}

const SERVER_NAME = 'chariot';

/** Resolve a client's on-disk format (CH-48), defaulting by extension. */
function clientFormat(client: McpClientInfo): 'json' | 'toml' | 'yaml' {
  if (client.format) return client.format;
  if (client.configPath.endsWith('.toml')) return 'toml';
  if (client.configPath.endsWith('.yaml') || client.configPath.endsWith('.yml')) return 'yaml';
  return 'json';
}

/** Atomic same-directory write preserving file mode. */
function atomicWrite(path: string, payload: string, mode: number): void {
  let tmpPath: string | null = `${path}.tmp.${process.pid}.${Date.now()}`;
  let fd: number | null = null;
  try {
    mkdirSync(join(path, '..'), { recursive: true });
    fd = openSync(tmpPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, mode);
    writeSync(fd, payload, 0, 'utf-8');
    closeSync(fd);
    fd = null;
    renameSync(tmpPath, path);
    tmpPath = null;
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* already closed */ } }
    if (tmpPath !== null) { try { unlinkSync(tmpPath); } catch { /* may not exist */ } }
  }
}

/** Render a minimal Codex `[mcp_servers.<name>]` TOML table. */
function renderTomlTable(table: string, name: string, entry: McpEntry): string {
  const argsLiteral = '[' + entry.args.map((a) => JSON.stringify(a)).join(', ') + ']';
  return [
    `[${table}.${name}]`,
    `command = ${JSON.stringify(entry.command)}`,
    `args = ${argsLiteral}`,
    '',
  ].join('\n');
}

/** True when a TOML file already declares `[<table>.<name>]`. */
function tomlHasTable(text: string, table: string, name: string): boolean {
  const re = new RegExp(`^\\s*\\[${table.replace(/\./g, '\\.')}\\.${name}\\]\\s*$`, 'm');
  return re.test(text);
}

/**
 * Write the Chariot MCP entry into a client's config in the path AND format
 * the client actually reads (CH-48). JSON clients merge a `mcpServers.chariot`
 * object; Codex merges a `[mcp_servers.chariot]` TOML table. Atomic, mode-
 * preserving, and non-destructive to other entries.
 */
export function writeMcpConfig(client: McpClientInfo, entry: McpEntry): { success: boolean; error?: string } {
  const format = clientFormat(client);
  if (format === 'yaml') {
    return { success: false, error: 'YAML config — add manually' };
  }
  try {
    let existingMode = 0o644;
    if (existsSync(client.configPath)) existingMode = (statSync(client.configPath).mode & 0o777) || 0o644;

    if (format === 'toml') {
      // Codex restricts config.toml to mode 600 in practice; default new
      // files to 0o600 to match. Merge by targeted table append.
      const mode = existsSync(client.configPath) ? existingMode : 0o600;
      const raw = existsSync(client.configPath) ? readFileSync(client.configPath, 'utf-8') : '';
      if (tomlHasTable(raw, client.configKey, SERVER_NAME)) {
        return { success: true, error: 'already configured' };
      }
      const sep = raw.length === 0 || raw.endsWith('\n') ? '' : '\n';
      const payload = raw + sep + (raw.length ? '\n' : '') + renderTomlTable(client.configKey, SERVER_NAME, entry);
      atomicWrite(client.configPath, payload, mode);
      return { success: true };
    }

    // JSON path (Claude Code ~/.claude.json, Gemini settings.json, etc.)
    let config: Record<string, unknown> = {};
    if (existsSync(client.configPath)) {
      const raw = readFileSync(client.configPath, 'utf-8').trim();
      if (raw) config = JSON.parse(raw) as Record<string, unknown>;
    }
    const key = client.configKey;
    if (!config[key] || typeof config[key] !== 'object') config[key] = {};
    const servers = config[key] as Record<string, unknown>;
    if (servers[SERVER_NAME]) return { success: true, error: 'already configured' };
    servers[SERVER_NAME] = entry;
    atomicWrite(client.configPath, JSON.stringify(config, null, 2) + '\n', existingMode);
    return { success: true };
  } catch (err: unknown) {
    return { success: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Re-read the client config and confirm the Chariot entry is actually present
 * and loadable in the right path+format (CH-48). The wizard MUST call this
 * before reporting ✓ — a write to a path the client never reads is a silent
 * no-op (CH-31), so "configured ✓" is only honest after verify-load.
 */
export function verifyMcpConfigLoaded(client: McpClientInfo): { loaded: boolean; reason?: string } {
  const format = clientFormat(client);
  if (!existsSync(client.configPath)) return { loaded: false, reason: 'config file not found after write' };
  let raw: string;
  try {
    raw = readFileSync(client.configPath, 'utf-8');
  } catch (err) {
    return { loaded: false, reason: `unreadable: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (format === 'toml') {
    if (!tomlHasTable(raw, client.configKey, SERVER_NAME)) {
      return { loaded: false, reason: `[${client.configKey}.${SERVER_NAME}] table absent` };
    }
    if (!/command\s*=/.test(raw)) return { loaded: false, reason: 'table present but no command' };
    return { loaded: true };
  }
  let config: Record<string, unknown>;
  try {
    config = JSON.parse(raw.trim() || '{}') as Record<string, unknown>;
  } catch (err) {
    return { loaded: false, reason: `invalid JSON: ${err instanceof Error ? err.message : String(err)}` };
  }
  const servers = config[client.configKey];
  if (!servers || typeof servers !== 'object') return { loaded: false, reason: `"${client.configKey}" key absent` };
  if (!(SERVER_NAME in (servers as Record<string, unknown>))) {
    return { loaded: false, reason: `"${SERVER_NAME}" entry absent under ${client.configKey}` };
  }
  return { loaded: true };
}

/**
 * Remove the Chariot MCP entry from a client config (CH-38). Returns whether
 * an entry was actually removed. Non-destructive to other entries; atomic.
 */
export function removeMcpConfig(client: McpClientInfo): { removed: boolean; error?: string } {
  const format = clientFormat(client);
  if (!existsSync(client.configPath)) return { removed: false };
  try {
    const existingMode = (statSync(client.configPath).mode & 0o777) || (format === 'toml' ? 0o600 : 0o644);
    const raw = readFileSync(client.configPath, 'utf-8');
    if (format === 'toml') {
      if (!tomlHasTable(raw, client.configKey, SERVER_NAME)) return { removed: false };
      // Drop the `[mcp_servers.chariot]` table and its body up to the next
      // table header or EOF.
      const lines = raw.split('\n');
      const out: string[] = [];
      const header = new RegExp(`^\\s*\\[${client.configKey.replace(/\./g, '\\.')}\\.${SERVER_NAME}\\]\\s*$`);
      let skipping = false;
      for (const line of lines) {
        if (header.test(line)) { skipping = true; continue; }
        if (skipping) {
          if (/^\s*\[/.test(line)) skipping = false; // next table starts — stop skipping
          else continue; // skip body line
        }
        out.push(line);
      }
      let next = out.join('\n').replace(/\n{3,}/g, '\n\n').replace(/\n+$/, '');
      if (next.length > 0) next += '\n';
      atomicWrite(client.configPath, next, existingMode);
      return { removed: true };
    }
    const config = JSON.parse(raw.trim() || '{}') as Record<string, unknown>;
    const servers = config[client.configKey] as Record<string, unknown> | undefined;
    if (!servers || typeof servers !== 'object' || !(SERVER_NAME in servers)) return { removed: false };
    delete servers[SERVER_NAME];
    atomicWrite(client.configPath, JSON.stringify(config, null, 2) + '\n', existingMode);
    return { removed: true };
  } catch (err: unknown) {
    return { removed: false, error: err instanceof Error ? err.message : String(err) };
  }
}

const LOCAL_BACKENDS = [
  { port: 8080, name: 'llama.cpp' },
  { port: 11434, name: 'Ollama' },
  { port: 8000, name: 'vLLM' },
] as const;

function isModelsResponse(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  const b = body as Record<string, unknown>;
  // OpenAI-compatible /v1/models returns { data: [...] } or { models: [...] }
  return Array.isArray(b['data']) || Array.isArray(b['models']);
}

export async function detectSystem(): Promise<SystemInfo> {
  const results = await Promise.all(LOCAL_BACKENDS.map(async (b) => {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 2000);
    try {
      const resp = await fetch(`http://localhost:${b.port}/v1/models`, { signal: controller.signal });
      if (!resp.ok) return null;
      const ct = resp.headers.get('content-type') ?? '';
      if (!ct.includes('application/json')) return null;
      // Keep the abort timer alive until the body parse resolves — a service
      // that returns JSON headers and then stalls the body stream must not be
      // able to hang detectSystem indefinitely.
      let body: unknown;
      try { body = await resp.json(); } catch { return null; }
      return isModelsResponse(body) ? b : null;
    } catch { return null; }
    finally { clearTimeout(t); }
  }));
  const hit = results.find((r) => r !== null);
  return {
    nodeVersion: process.version,
    // CHARIOT::§17.2::1 — detect AND validate >=20.
    nodeVersionSupported: isNodeVersionSupported(process.version),
    platform: process.platform,
    arch: process.arch,
    localPort: hit?.port ?? null,
    localBackend: hit?.name ?? null,
    mcpClients: detectMcpClients(),
    // CHARIOT::§17.2::2
    runtimes: detectRuntimes(),
    // CHARIOT::§17.2::3
    hardware: detectHardware(),
  };
}
