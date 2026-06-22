/**
 * AlienVault OTX (Open Threat Exchange) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://otx.alienvault.com/api/v1
// Auth: X-OTX-API-KEY header (free registration at https://otx.alienvault.com)
// Docs: https://otx.alienvault.com/api
// Category: security
// Rate limits: community tier — no hard-published cap; be reasonable

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AlienVaultOTXConfig {
  apiKey: string;
  baseUrl?: string;
}

interface PulseSummary {
  id?: string;
  name?: string;
  description?: string;
  author_name?: string;
  created?: string;
  modified?: string;
  tags?: string[];
  targeted_countries?: string[];
  malware_families?: string[];
  attack_ids?: string[];
  industries?: string[];
  indicators?: { count?: number } | unknown[];
}

export class AlienVaultOTXMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AlienVaultOTXConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('AlienVault OTX: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('AlienVault OTX: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://otx.alienvault.com/api/v1';
  }

  static catalog() {
    return {
      name: 'alienvault-otx',
      displayName: 'AlienVault OTX (Open Threat Exchange)',
      version: '1.0.0',
      category: 'security',
      keywords: [
        'alienvault', 'otx', 'open threat exchange', 'threat intelligence',
        'pulses', 'indicators of compromise', 'ioc', 'malware', 'ip reputation',
        'domain reputation', 'file hash', 'cybersecurity', 'threat feed',
        'attack ids', 'mitre', 'ttp',
      ],
      toolNames: ['search_pulses', 'get_pulse', 'lookup_indicator'],
      description: 'AlienVault OTX: search community threat-intel pulses, fetch full pulse detail with indicators, and look up IPv4/domain/URL/file-hash context — directly via the OTX REST API.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search_pulses',
        description:
          'Search OTX threat-intel pulses by keyword. Returns pulse ID, name, description preview, tags, targeted countries, malware families, attack IDs, and indicator count.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search term' },
            limit: { type: 'number', description: '1-50 (default 20)' },
            page: { type: 'number', description: '1-based page (default 1)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_pulse',
        description:
          'Fetch a single OTX pulse: full description, references, indicators, attack IDs, targeted countries, malware families, industries, and creation/modification dates.',
        inputSchema: {
          type: 'object',
          properties: {
            pulse_id: { type: 'string', description: 'OTX pulse ID (hex string)' },
          },
          required: ['pulse_id'],
        },
      },
      {
        name: 'lookup_indicator',
        description:
          'Look up an indicator (IPv4, domain, URL, or file hash) in OTX. Returns pulses referencing the indicator and observed-context fields. Type is auto-detected when omitted.',
        inputSchema: {
          type: 'object',
          properties: {
            indicator: {
              type: 'string',
              description: 'IPv4, domain, URL, or file hash (md5/sha1/sha256)',
            },
            type: {
              type: 'string',
              description: 'Force a type instead of auto-detecting',
              enum: ['IPv4', 'IPv6', 'domain', 'hostname', 'url', 'file'],
            },
          },
          required: ['indicator'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_pulses':  return this.searchPulses(args);
        case 'get_pulse':      return this.getPulse(String(args.pulse_id));
        case 'lookup_indicator':
          return this.lookupIndicator(
            String(args.indicator),
            args.type as string | undefined,
          );
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

  private async otxRequest<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'X-OTX-API-KEY': this.apiKey,
        Accept: 'application/json',
      },
    });
    if (response.status === 401 || response.status === 403) {
      throw new Error('OTX: unauthorized — check the API key');
    }
    if (response.status === 404) {
      throw new Error('OTX: not found');
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`OTX error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  private normalizePulse(p: PulseSummary, full = false): Record<string, unknown> {
    const indicatorsCount = Array.isArray(p.indicators)
      ? p.indicators.length
      : (p.indicators as { count?: number } | undefined)?.count ?? null;
    const base: Record<string, unknown> = {
      id: p.id ?? null,
      name: p.name ?? null,
      description: p.description
        ? String(p.description).slice(0, full ? 8000 : 400)
        : null,
      author: p.author_name ?? null,
      created: p.created ?? null,
      modified: p.modified ?? null,
      tags: p.tags ?? [],
      targeted_countries: p.targeted_countries ?? [],
      malware_families: p.malware_families ?? [],
      attack_ids: p.attack_ids ?? [],
      industries: p.industries ?? [],
      indicators_count: indicatorsCount,
      otx_url: p.id ? `https://otx.alienvault.com/pulse/${p.id}` : null,
    };
    if (full && Array.isArray(p.indicators)) {
      base.indicators = p.indicators;
    }
    return base;
  }

  private detectType(indicator: string): string {
    if (/^https?:\/\//i.test(indicator)) return 'url';
    if (/^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i.test(indicator)) return 'file';
    if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(indicator)) return 'IPv4';
    if (/^[0-9a-f:]+$/i.test(indicator) && indicator.includes(':')) return 'IPv6';
    return 'domain';
  }

  private async searchPulses(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      q: String(args.query),
      limit: String(Math.min(50, Math.max(1, Number(args.limit ?? 20)))),
      page: String(Math.max(1, Number(args.page ?? 1))),
    });
    const data = await this.otxRequest<{ count?: number; results?: PulseSummary[] }>(
      `/search/pulses?${params}`,
    );
    const result = {
      total: data.count ?? 0,
      returned: data.results?.length ?? 0,
      pulses: (data.results ?? []).map((p) => this.normalizePulse(p, false)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPulse(pulseId: string): Promise<ToolResult> {
    const data = await this.otxRequest<PulseSummary>(
      `/pulses/${encodeURIComponent(pulseId)}`,
    );
    return { content: [{ type: 'text', text: this.truncate(this.normalizePulse(data, true)) }], isError: false };
  }

  private async lookupIndicator(indicator: string, type?: string): Promise<ToolResult> {
    const t = type ?? this.detectType(indicator);
    const safe = encodeURIComponent(indicator);
    const data = await this.otxRequest<{
      pulse_info?: { count?: number; pulses?: PulseSummary[] };
      [key: string]: unknown;
    }>(`/indicators/${t}/${safe}/general`);

    const result = {
      indicator,
      type: t,
      pulse_count: data.pulse_info?.count ?? 0,
      pulses: (data.pulse_info?.pulses ?? []).map((p) => this.normalizePulse(p, false)),
      context: Object.fromEntries(
        Object.entries(data).filter(([k]) => k !== 'pulse_info'),
      ),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
