/**
 * IPInfo MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://ipinfo.io
// Auth: none required for basic usage (free tier, unauthenticated)
// Docs: https://ipinfo.io/developers
// Category: networking
// Tools: lookup_ip, get_my_ip

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://ipinfo.io';

interface IpInfoResponse {
  ip: string;
  city?: string;
  region?: string;
  country?: string;
  loc?: string;
  org?: string;
  postal?: string;
  timezone?: string;
  error?: { status: string; message: string };
}

export class IPInfoMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('IPInfoMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'ipinfo',
      displayName: 'IPInfo',
      version: '1.0.0',
      category: 'networking',
      keywords: [
        'ipinfo', 'ip', 'geolocation', 'ip address', 'ip lookup',
        'network', 'geo', 'location', 'city', 'country', 'region',
        'timezone', 'org', 'asn', 'isp', 'coordinates',
      ],
      toolNames: ['lookup_ip', 'get_my_ip'],
      description: 'IPInfo: look up geolocation and network information for any IP address, or detect the current request origin IP — free and unauthenticated.',
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
        name: 'lookup_ip',
        description:
          'Get geolocation and network information for a specific IP address. Returns city, region, country, coordinates, org, postal code, and timezone.',
        inputSchema: {
          type: 'object',
          properties: {
            ip: {
              type: 'string',
              description: 'IPv4 or IPv6 address to look up (e.g., "8.8.8.8")',
            },
          },
          required: ['ip'],
        },
      },
      {
        name: 'get_my_ip',
        description:
          "Get geolocation and network information for the current request's originating IP address.",
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
        case 'lookup_ip':  return this.lookupIp(args);
        case 'get_my_ip':  return this.getMyIp();
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private formatResponse(data: IpInfoResponse): Record<string, unknown> {
    if (data.error) {
      throw new Error(`ipinfo.io error: ${data.error.message}`);
    }
    const [latitude, longitude] = (data.loc ?? '').split(',').map(Number);
    return {
      ip: data.ip,
      city: data.city ?? null,
      region: data.region ?? null,
      country: data.country ?? null,
      latitude: isNaN(latitude!) ? null : latitude,
      longitude: isNaN(longitude!) ? null : longitude,
      org: data.org ?? null,
      postal: data.postal ?? null,
      timezone: data.timezone ?? null,
    };
  }

  private async lookupIp(args: Record<string, unknown>): Promise<ToolResult> {
    const ip = args.ip as string;
    if (!ip || typeof ip !== 'string') {
      return { content: [{ type: 'text', text: 'lookup_ip: ip parameter is required' }], isError: true };
    }
    const url = `${this.baseUrl}/${encodeURIComponent(ip)}/json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as IpInfoResponse;
    const result = this.formatResponse(data);
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getMyIp(): Promise<ToolResult> {
    const url = `${this.baseUrl}/json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as IpInfoResponse;
    const result = this.formatResponse(data);
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
