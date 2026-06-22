/**
 * Feodo Tracker MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: Feodo Tracker by abuse.ch — botnet C&C IP blocklist (public, no auth).
//
// Base URL (feed): https://feodotracker.abuse.ch/downloads
// Auth: None — public feed, no API key required.
// Docs: https://feodotracker.abuse.ch/
// Rate limits: Fair-use; upstream feed refreshes every ~5 minutes.
// Category: security

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface FeodoTrackerConfig {
  /** Optional base URL override (default: https://feodotracker.abuse.ch/downloads) */
  baseUrl?: string;
}

type FeodoEntry = {
  ip_address: string;
  port?: number;
  status?: string;
  hostname?: string | null;
  as_number?: number;
  as_name?: string;
  country?: string;
  first_seen?: string;
  last_online?: string;
  malware?: string;
};

export class FeodoTrackerMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: FeodoTrackerConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Feodo Tracker: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://feodotracker.abuse.ch/downloads';
  }

  static catalog() {
    return {
      name: 'feodotracker',
      displayName: 'Feodo Tracker — abuse.ch',
      version: '1.0.0',
      category: 'security',
      keywords: [
        'feodo', 'feodotracker', 'abuse.ch', 'botnet', 'c2', 'c&c',
        'command and control', 'blocklist', 'ip blocklist', 'malware',
        'dridex', 'emotet', 'qakbot', 'trickbot', 'threat intelligence',
        'ioc', 'indicator of compromise', 'cybersecurity', 'infosec',
      ],
      toolNames: ['list', 'check_ip', 'recent', 'aggressive'],
      description: 'Feodo Tracker botnet C&C IP blocklist by abuse.ch: list or filter active command-and-control IPs by malware family or status, check whether a given IPv4 is listed, retrieve recently added entries, and fetch the full aggressive blocklist.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'list',
        description: 'Current Feodo Tracker C&C blocklist with optional malware-family and status filters.',
        inputSchema: {
          type: 'object',
          properties: {
            family: {
              type: 'string',
              description: 'Malware family name filter (e.g. "Dridex", "Emotet", "Qakbot", "TrickBot"). Case-insensitive.',
            },
            status: {
              type: 'string',
              description: 'Entry status filter (e.g. "online", "offline"). Case-insensitive.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return. Range: 1–5000. Default: 500.',
            },
          },
        },
      },
      {
        name: 'check_ip',
        description: 'Check whether a given IPv4 address is on the current Feodo Tracker blocklist.',
        inputSchema: {
          type: 'object',
          properties: {
            ip: {
              type: 'string',
              description: 'IPv4 address in dotted-quad notation (e.g. "1.2.3.4").',
            },
          },
          required: ['ip'],
        },
      },
      {
        name: 'recent',
        description: 'Fetch the most recently first-seen Feodo Tracker blocklist entries (newest first). Optionally restrict to a look-back window in hours.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of newest entries to return (1-50). Default: 10.',
            },
            hours: {
              type: 'number',
              description: 'Optional look-back window in hours; when omitted, the newest entries are returned regardless of age.',
            },
          },
        },
      },
      {
        name: 'aggressive',
        description: 'Fetch the full Feodo Tracker aggressive blocklist, which includes older and lower-confidence C&C IPs in addition to the standard set.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list':       return this.listEntries(args);
        case 'check_ip':   return this.checkIp(args);
        case 'recent':     return this.recent(args);
        case 'aggressive': return this.aggressive();
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async fetchFeed(): Promise<FeodoEntry[]> {
    const url = `${this.baseUrl}/ipblocklist.json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Feodo Tracker feed error: ${response.status} ${errText}`);
    }
    const json = await response.json() as FeodoEntry[];
    return Array.isArray(json) ? json : [];
  }

  private async listEntries(args: Record<string, unknown>): Promise<ToolResult> {
    const entries = await this.fetchFeed();
    const family = typeof args.family === 'string' ? args.family.toLowerCase() : undefined;
    const status = typeof args.status === 'string' ? args.status.toLowerCase() : undefined;
    const limit = Math.min(5000, Math.max(1, typeof args.limit === 'number' ? args.limit : 500));

    const filtered = entries.filter((e) => {
      if (family && (e.malware ?? '').toLowerCase() !== family) return false;
      if (status && (e.status ?? '').toLowerCase() !== status) return false;
      return true;
    });

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          total: entries.length,
          matches: filtered.length,
          results: filtered.slice(0, limit),
        }),
      }],
      isError: false,
    };
  }

  private async checkIp(args: Record<string, unknown>): Promise<ToolResult> {
    const ip = args.ip;
    if (typeof ip !== 'string' || !ip.trim()) {
      return {
        content: [{ type: 'text', text: 'check_ip: required argument "ip" is missing. Pass an IPv4 address like "1.2.3.4".' }],
        isError: true,
      };
    }
    if (!/^[0-9.]+$/.test(ip)) {
      return {
        content: [{ type: 'text', text: 'check_ip: "ip" must be an IPv4 dotted-quad address (e.g. "1.2.3.4").' }],
        isError: true,
      };
    }
    const entries = await this.fetchFeed();
    const hits = entries.filter((e) => e.ip_address === ip);
    return {
      content: [{
        type: 'text',
        text: this.truncate({ ip, listed: hits.length > 0, entries: hits }),
      }],
      isError: false,
    };
  }

  private async recent(args: Record<string, unknown>): Promise<ToolResult> {
    // The feed lists currently-active C2s, not a rolling additions log — its
    // newest first_seen can be months old (verified 2026-06-09: newest entry
    // 2026-03-04), so a fixed look-back window is structurally empty most of
    // the time. Semantics: return the N most-recently-first-seen entries;
    // `hours` is an OPTIONAL additional filter.
    const limit = Math.min(50, Math.max(1, typeof args.limit === 'number' ? args.limit : 10));
    const hours = typeof args.hours === 'number' ? Math.max(1, args.hours) : null;
    const entries = await this.fetchFeed();

    const dated = entries
      .filter((e) => e.first_seen && Number.isFinite(Date.parse(e.first_seen)))
      .sort((a, b) => Date.parse(b.first_seen!) - Date.parse(a.first_seen!));
    const windowed = hours === null
      ? dated
      : dated.filter((e) => Date.parse(e.first_seen!) >= Date.now() - hours * 3_600_000);
    const results = windowed.slice(0, limit);

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          limit,
          hours: hours ?? 'none (newest-first, unwindowed)',
          newest_first_seen: dated[0]?.first_seen ?? null,
          count: results.length,
          results,
        }),
      }],
      isError: false,
    };
  }

  private async aggressive(): Promise<ToolResult> {
    // The aggressive feed is not available in JSON format; abuse.ch only publishes
    // it as CSV (ipblocklist_aggressive.csv) and plain-text.  Parse the CSV here.
    // CSV columns: "first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
    const url = `${this.baseUrl}/ipblocklist_aggressive.csv`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'text/csv, text/plain' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Feodo Tracker aggressive feed error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const csv = await response.text();
    const entries: FeodoEntry[] = [];
    for (const raw of csv.split('\n')) {
      const line = raw.trim();
      // Skip comment lines and the header row
      if (!line || line.startsWith('#') || line.startsWith('"first_seen_utc"')) continue;
      // CSV columns are all double-quoted; strip quotes and split on '","'
      const stripped = line.replace(/^"|"$/g, '');
      const cols = stripped.split('","');
      if (cols.length < 6) continue;
      const [first_seen, ip_address, portStr, status, last_online, malware] = cols;
      const port = parseInt(portStr, 10);
      entries.push({
        ip_address,
        port: Number.isFinite(port) ? port : undefined,
        status: status || undefined,
        first_seen: first_seen || undefined,
        last_online: last_online || undefined,
        malware: malware || undefined,
      });
    }
    return {
      content: [{ type: 'text', text: this.truncate({ total: entries.length, results: entries }) }],
      isError: false,
    };
  }
}
