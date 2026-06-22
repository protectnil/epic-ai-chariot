/**
 * IP Lookup MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: ip-api.com (free, no auth required for basic usage)
// Base URL: http://ip-api.com
// Docs: https://ip-api.com/docs
// Category: networking
// Rate limits: Free tier — 45 requests/minute per IP; no API key required

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'http://ip-api.com';
const FIELDS = 'status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query';

interface IpApiResponse {
  status: string;
  message?: string;
  country?: string;
  countryCode?: string;
  regionName?: string;
  city?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string;
  query?: string;
}

export class IpLookupMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('IpLookupMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'iplookup',
      displayName: 'IP Lookup',
      version: '1.0.0',
      category: 'networking',
      keywords: [
        'ip', 'ip address', 'geolocation', 'geo', 'ipv4', 'ipv6',
        'isp', 'timezone', 'country', 'city', 'latitude', 'longitude',
        'network', 'lookup', 'ip-api', 'batch geolocate',
      ],
      toolNames: ['geolocate_ip', 'batch_geolocate'],
      description: 'IP Lookup: geolocate a single IP address or up to 100 IPs in one batch request — returns country, region, city, coordinates, timezone, ISP, and AS number. Free and unauthenticated via ip-api.com.',
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
        name: 'geolocate_ip',
        description:
          'Look up the geolocation, ISP, and network information for a single IP address (IPv4 or IPv6). Returns country, region, city, coordinates, timezone, ISP, and AS number.',
        inputSchema: {
          type: 'object',
          properties: {
            ip: {
              type: 'string',
              description: 'IPv4 or IPv6 address to look up (e.g., "8.8.8.8", "2001:4860:4860::8888")',
            },
          },
          required: ['ip'],
        },
      },
      {
        name: 'batch_geolocate',
        description:
          'Look up geolocation for multiple IP addresses in a single request. Accepts up to 100 IPs. Returns an array of results in the same order as the input.',
        inputSchema: {
          type: 'object',
          properties: {
            ips: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of IPv4 or IPv6 addresses to look up (maximum 100)',
            },
          },
          required: ['ips'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'geolocate_ip':   return this.geolocateIp(args);
        case 'batch_geolocate': return this.batchGeolocate(args);
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

  private formatResult(data: IpApiResponse): Record<string, unknown> {
    if (data.status === 'fail') {
      throw new Error(`IP lookup failed: ${data.message ?? 'unknown error'}`);
    }
    return {
      ip: data.query ?? null,
      country: data.country ?? null,
      country_code: data.countryCode ?? null,
      region: data.regionName ?? null,
      city: data.city ?? null,
      postal_code: data.zip ?? null,
      latitude: data.lat ?? null,
      longitude: data.lon ?? null,
      timezone: data.timezone ?? null,
      isp: data.isp ?? null,
      organization: data.org ?? null,
      as_number: data.as ?? null,
    };
  }

  private async geolocateIp(args: Record<string, unknown>): Promise<ToolResult> {
    const ip = args.ip as string;
    if (!ip || typeof ip !== 'string') {
      return { content: [{ type: 'text', text: 'geolocate_ip: ip (string) is required' }], isError: true };
    }

    const url = `${this.baseUrl}/json/${encodeURIComponent(ip)}?fields=${FIELDS}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ip-api.com error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as IpApiResponse;
    const result = this.formatResult(data);
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async batchGeolocate(args: Record<string, unknown>): Promise<ToolResult> {
    const ips = args.ips as string[];
    if (!Array.isArray(ips) || ips.length === 0) {
      return { content: [{ type: 'text', text: 'batch_geolocate: ips must be a non-empty array of IP addresses' }], isError: true };
    }
    if (ips.length > 100) {
      return { content: [{ type: 'text', text: 'batch_geolocate: maximum 100 IPs per batch request' }], isError: true };
    }

    const body = ips.map((ip) => ({ query: ip, fields: FIELDS }));
    const url = `${this.baseUrl}/batch`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `ip-api.com batch error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as IpApiResponse[];
    const results = data.map((entry) => {
      if (entry.status === 'fail') {
        return { ip: entry.query ?? null, error: entry.message ?? 'lookup failed' };
      }
      return this.formatResult(entry);
    });

    return {
      content: [{ type: 'text', text: this.truncate({ count: data.length, results }) }],
      isError: false,
    };
  }
}
