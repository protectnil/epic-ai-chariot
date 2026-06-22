/**
 * URLhaus MCP Adapter — abuse.ch URLhaus malware URL database
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://urlhaus-api.abuse.ch/v1
 * Auth: None (free, public API — no API key required)
 * Docs: https://urlhaus-api.abuse.ch/
 * Category: security
 *
 * All endpoints use HTTP POST with application/x-www-form-urlencoded.
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://urlhaus-api.abuse.ch/v1';

export class URLhausMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'urlhaus',
      displayName: 'URLhaus',
      version: '1.0.0',
      category: 'security',
      keywords: [
        'urlhaus', 'abuse.ch', 'malware', 'malware url', 'threat intelligence',
        'url lookup', 'host lookup', 'payload hash', 'phishing', 'botnet',
        'ioc', 'indicator of compromise', 'cybersecurity', 'threat feed',
      ],
      toolNames: ['lookup_url', 'lookup_host', 'get_recent', 'lookup_payload'],
      description: 'URLhaus by abuse.ch: look up URLs, hosts, and malware payload hashes against the URLhaus malware database, and retrieve recently submitted malicious URLs.',
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
        name: 'lookup_url',
        description:
          'Look up a URL in the URLhaus malware database to check if it is known to host or distribute malware. Returns threat category, status, blacklist status, and tags.',
        inputSchema: {
          type: 'object',
          properties: {
            url: {
              type: 'string',
              description: 'The full URL to look up (e.g. "http://example.com/malware.exe").',
            },
          },
          required: ['url'],
        },
      },
      {
        name: 'lookup_host',
        description:
          'Look up a hostname or IP address in the URLhaus database to find associated malware URLs. Returns all known malicious URLs hosted on that host.',
        inputSchema: {
          type: 'object',
          properties: {
            host: {
              type: 'string',
              description:
                'Hostname or IP address to look up (e.g. "example.com" or "192.168.1.1").',
            },
          },
          required: ['host'],
        },
      },
      {
        name: 'get_recent',
        description:
          'Get a list of recently submitted malware URLs from URLhaus. Useful for monitoring the latest threats.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of recent URLs to return (default 10, max 1000).',
            },
          },
        },
      },
      {
        name: 'lookup_payload',
        description:
          'Look up a malware payload file by its MD5 or SHA256 hash in the URLhaus database. Returns file type, size, first/last seen dates, and associated delivery URLs.',
        inputSchema: {
          type: 'object',
          properties: {
            md5_hash: {
              type: 'string',
              description: 'MD5 hash of the payload to look up (32 hex characters).',
            },
            sha256_hash: {
              type: 'string',
              description: 'SHA256 hash of the payload to look up (64 hex characters).',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'lookup_url':
          return this.lookupUrl(args.url as string);
        case 'lookup_host':
          return this.lookupHost(args.host as string);
        case 'get_recent':
          return this.getRecent((args.limit as number | undefined) ?? 10);
        case 'lookup_payload': {
          const md5 = args.md5_hash as string | undefined;
          const sha256 = args.sha256_hash as string | undefined;
          if (!md5 && !sha256) {
            return {
              content: [{ type: 'text', text: 'Either md5_hash or sha256_hash is required.' }],
              isError: true,
            };
          }
          return this.lookupPayload(md5, sha256);
        }
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async postForm(endpoint: string, body: Record<string, string>): Promise<ToolResult> {
    const url = `${BASE_URL}${endpoint}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async lookupUrl(url: string): Promise<ToolResult> {
    const result = await this.postForm('/url/', { url });
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text);
      const out = {
        query_status: raw.query_status,
        id: raw.id ?? null,
        url_status: raw.url_status ?? null,
        date_added: raw.date_added ?? null,
        threat: raw.threat ?? null,
        tags: raw.tags ?? null,
        blacklists: raw.blacklists ?? null,
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async lookupHost(host: string): Promise<ToolResult> {
    const result = await this.postForm('/host/', { host });
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text);
      const out = {
        query_status: raw.query_status,
        urlhaus_reference: raw.urlhaus_reference ?? null,
        blacklists: raw.blacklists ?? null,
        url_count: (raw.urls ?? []).length,
        urls: (raw.urls ?? []).map((u: Record<string, unknown>) => ({
          id: u.id,
          url: u.url,
          url_status: u.url_status,
          date_added: u.date_added,
          threat: u.threat,
          tags: u.tags,
        })),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getRecent(limit: number): Promise<ToolResult> {
    const result = await this.postForm('/urls/recent/', {
      limit: String(Math.min(limit, 1000)),
    });
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text);
      const out = {
        query_status: raw.query_status,
        count: (raw.urls ?? []).length,
        urls: (raw.urls ?? []).map((u: Record<string, unknown>) => ({
          id: u.id,
          url: u.url,
          url_status: u.url_status,
          date_added: u.date_added,
          threat: u.threat,
          tags: u.tags,
          urlhaus_reference: u.urlhaus_reference,
        })),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async lookupPayload(md5?: string, sha256?: string): Promise<ToolResult> {
    const body: Record<string, string> = {};
    if (md5) body['md5_hash'] = md5;
    else if (sha256) body['sha256_hash'] = sha256;
    const result = await this.postForm('/payload/', body);
    if (result.isError) return result;
    try {
      const raw = JSON.parse(result.content[0].text);
      const out = {
        query_status: raw.query_status,
        md5_hash: raw.md5_hash ?? null,
        sha256_hash: raw.sha256_hash ?? null,
        file_type: raw.file_type ?? null,
        file_size_bytes: raw.file_size ?? null,
        signature: raw.signature ?? null,
        first_seen: raw.firstseen ?? null,
        last_seen: raw.lastseen ?? null,
        url_count: raw.url_count ?? null,
        delivery_urls: raw.urls_on_this_payload ?? [],
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }
}
