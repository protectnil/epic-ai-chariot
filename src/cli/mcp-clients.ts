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
import type { McpClientInfo, SystemInfo } from './types.js';

export interface McpEntry {
  command: string;
  args: string[];
}

export function detectMcpClients(): McpClientInfo[] {
  const isMac = process.platform === 'darwin';
  return [
    {
      id: 'claude-code',
      name: 'Claude Code CLI',
      detected: existsSync(expandHome('~/.claude')) || commandExists('claude'),
      configPath: expandHome('~/.claude/mcp.json'),
      configKey: 'mcpServers',
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
      id: 'codex',
      name: 'Codex CLI',
      detected: existsSync(expandHome('~/.codex')) || commandExists('codex'),
      configPath: expandHome('~/.codex/config.json'),
      configKey: 'mcpServers',
    },
    {
      id: 'gemini',
      name: 'Gemini CLI',
      detected: existsSync(expandHome('~/.gemini')) || commandExists('gemini'),
      configPath: expandHome('~/.gemini/settings.json'),
      configKey: 'mcpServers',
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

export function writeMcpConfig(client: McpClientInfo, entry: McpEntry): { success: boolean; error?: string } {
  if (client.configPath.endsWith('.yaml') || client.configPath.endsWith('.yml')) {
    return { success: false, error: 'YAML config — add manually' };
  }
  // Atomic write: tmp in target dir, mode preserved from existing file
  // (or 0o644 if new), then renameSync. Protects user's other MCP entries
  // in shared client configs from truncation on SIGINT mid-write.
  let tmpPath: string | null = null;
  let fd: number | null = null;
  try {
    mkdirSync(join(client.configPath, '..'), { recursive: true });
    let config: Record<string, unknown> = {};
    let existingMode = 0o644;
    if (existsSync(client.configPath)) {
      existingMode = (statSync(client.configPath).mode & 0o777) || 0o644;
      const raw = readFileSync(client.configPath, 'utf-8').trim();
      if (raw) config = JSON.parse(raw) as Record<string, unknown>;
    }
    const key = client.configKey;
    if (!config[key] || typeof config[key] !== 'object') config[key] = {};
    const servers = config[key] as Record<string, unknown>;
    if (servers['chariot']) return { success: true, error: 'already configured' };
    servers['chariot'] = entry;
    const payload = JSON.stringify(config, null, 2) + '\n';

    tmpPath = `${client.configPath}.tmp.${process.pid}.${Date.now()}`;
    fd = openSync(tmpPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, existingMode);
    writeSync(fd, payload, 0, 'utf-8');
    closeSync(fd);
    fd = null;
    renameSync(tmpPath, client.configPath);
    tmpPath = null;
    return { success: true };
  } catch (err: unknown) {
    if (fd !== null) {
      try { closeSync(fd); } catch { /* fd already closed */ }
    }
    if (tmpPath !== null) {
      try { unlinkSync(tmpPath); } catch { /* tmp may not exist */ }
    }
    return { success: false, error: err instanceof Error ? err.message : String(err) };
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
    platform: process.platform,
    arch: process.arch,
    localPort: hit?.port ?? null,
    localBackend: hit?.name ?? null,
    mcpClients: detectMcpClients(),
  };
}
