/**
 * ThreatFox MCP Adapter — abuse.ch IOC feed
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://threatfox-api.abuse.ch/api/v1/
 * Auth: Auth-Key header (free, register at https://auth.abuse.ch)
 * Docs: https://threatfox.abuse.ch/api/
 * Category: security
 *
 * Tools:
 *   search_ioc      — look up a specific indicator (IP, domain, URL, hash)
 *   recent_iocs     — IOCs added in the last N days
 *   search_hash     — IOCs associated with a specific file hash
 *   search_malware  — IOCs tagged to a malware family
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface ThreatFoxConfig {
  apiKey: string;
  baseUrl?: string;
}

export class ThreatFoxMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: ThreatFoxConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('ThreatFox: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('ThreatFox: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://threatfox-api.abuse.ch/api/v1/';
  }

  static catalog() {
    return {
      name: 'threatfox',
      displayName: 'ThreatFox (abuse.ch)',
      version: '1.0.0',
      category: 'security',
      keywords: [
        'threatfox', 'abuse.ch', 'ioc', 'indicator of compromise', 'malware',
        'threat intel', 'threat intelligence', 'ip reputation', 'domain reputation',
        'hash lookup', 'cobalt strike', 'emotet', 'qakbot', 'ttp', 'misp',
        'c2', 'command and control', 'botnet', 'phishing', 'ransomware',
      ],
      toolNames: ['search_ioc', 'recent_iocs', 'search_hash', 'search_malware'],
      description: 'ThreatFox (abuse.ch): search indicators of compromise by value, file hash, or malware family; retrieve recently added IOCs — free API key required.',
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
        name: 'search_ioc',
        description:
          'Look up a specific indicator of compromise (IP, domain, URL, hash, etc.). Returns matching IOCs with malware family, confidence, threat-type, first/last seen, tags, and references.',
        inputSchema: {
          type: 'object',
          properties: {
            indicator: {
              type: 'string',
              description: 'IP address, domain, URL, or hash to look up',
            },
            exact_match: {
              type: 'boolean',
              description: 'Require an exact match (default true)',
            },
          },
          required: ['indicator'],
        },
      },
      {
        name: 'recent_iocs',
        description:
          'Retrieve IOCs added to ThreatFox in the last N days. Useful for daily threat-intel ingestion pipelines.',
        inputSchema: {
          type: 'object',
          properties: {
            days: {
              type: 'number',
              description: 'Lookback window in days (1–7, default 3)',
            },
          },
        },
      },
      {
        name: 'search_hash',
        description: 'Retrieve IOCs associated with a specific file hash (MD5, SHA-1, or SHA-256).',
        inputSchema: {
          type: 'object',
          properties: {
            hash: {
              type: 'string',
              description: 'MD5, SHA-1, or SHA-256 hash value',
            },
          },
          required: ['hash'],
        },
      },
      {
        name: 'search_malware',
        description:
          'Retrieve IOCs tagged to a malware family (e.g. "Cobalt Strike", "Emotet", "QakBot"). Accepts malware family names and MISP aliases.',
        inputSchema: {
          type: 'object',
          properties: {
            malware: {
              type: 'string',
              description: 'Malware family name or MISP alias',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of records to return (default 1000)',
            },
          },
          required: ['malware'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_ioc':    return this.searchIoc(args);
        case 'recent_iocs':   return this.recentIocs(args);
        case 'search_hash':   return this.searchHash(args);
        case 'search_malware': return this.searchMalware(args);
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

  private async post(body: Record<string, unknown>): Promise<ToolResult> {
    const response = await this.fetchWithRetry(this.baseUrl, {
      method: 'POST',
      headers: {
        'Auth-Key': this.apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: `ThreatFox: unauthorized (${response.status}) — verify the API key` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ThreatFox API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      query_status?: string;
      data?: unknown[];
      [key: string]: unknown;
    };

    if (
      data.query_status &&
      data.query_status !== 'ok' &&
      data.query_status !== 'no_result'
    ) {
      return {
        content: [{ type: 'text', text: `ThreatFox: ${data.query_status}` }],
        isError: true,
      };
    }

    const result = {
      query: body.query,
      status: data.query_status ?? null,
      count: Array.isArray(data.data) ? data.data.length : 0,
      results: Array.isArray(data.data) ? data.data : [],
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private async searchIoc(args: Record<string, unknown>): Promise<ToolResult> {
    const indicator = this.reqStr(args, 'indicator', '"1.2.3.4" or "evil.example.com"');
    return this.post({
      query: 'search_ioc',
      search_term: indicator,
      exact_match: args.exact_match !== false,
    });
  }

  private async recentIocs(args: Record<string, unknown>): Promise<ToolResult> {
    const days = Math.min(7, Math.max(1, (args.days as number) ?? 3));
    return this.post({ query: 'get_iocs', days });
  }

  private async searchHash(args: Record<string, unknown>): Promise<ToolResult> {
    const hash = this.reqStr(args, 'hash', '"<md5|sha1|sha256>"');
    return this.post({ query: 'search_hash', hash });
  }

  private async searchMalware(args: Record<string, unknown>): Promise<ToolResult> {
    const malware = this.reqStr(args, 'malware', '"Cobalt Strike"');
    return this.post({
      query: 'malwareinfo',
      malware,
      limit: (args.limit as number) ?? 1000,
    });
  }
}
