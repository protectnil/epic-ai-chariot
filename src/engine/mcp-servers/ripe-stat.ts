/**
 * RIPE Stat MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://stat.ripe.net/data
// Auth: None — public API, no key required
// Docs: https://stat.ripe.net/docs/02.data-api/
// Rate limits: ~1000 req / 10 min / source IP (unauthenticated)
// Category: networking

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://stat.ripe.net/data';

const ENDPOINT_MAP: Record<string, string> = {
  whois:           'whois',
  network_info:    'network-info',
  as_overview:     'as-overview',
  asn_neighbours:  'asn-neighbours',
  bgp_state:       'bgp-state',
  abuse_contact:   'abuse-contact-finder',
  geoloc:          'geoloc',
  prefix_overview: 'prefix-overview',
};

export class RipeStatMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('RipeStatMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'ripe-stat',
      displayName: 'RIPE Stat',
      version: '1.0.0',
      category: 'networking',
      keywords: [
        'ripe', 'ripe stat', 'ip', 'asn', 'bgp', 'whois', 'geoloc',
        'prefix', 'routing', 'abuse contact', 'network info', 'internet registry',
        'autonomous system', 'bgp state', 'rir', 'ip lookup',
      ],
      toolNames: [
        'whois',
        'network_info',
        'as_overview',
        'asn_neighbours',
        'bgp_state',
        'abuse_contact',
        'geoloc',
        'prefix_overview',
      ],
      description: 'RIPE Stat API: look up whois records, BGP routing state, ASN neighbours, abuse contacts, geolocation, and prefix overviews for IPs, prefixes, and AS numbers.',
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
        name: 'whois',
        description: 'Whois data for an IP, prefix, or ASN. Aggregates across RIRs.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'IP address, prefix, or AS number (e.g. "8.8.8.8", "8.8.8.0/24", "AS15169")',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'network_info',
        description: 'Network info (allocated prefix, ASN) for an IP.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'IPv4 or IPv6 address',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'as_overview',
        description: 'ASN summary — holder, country, type, block range.',
        inputSchema: {
          type: 'object',
          properties: {
            asn: {
              type: 'string',
              description: 'AS number (e.g. "AS15169" or "15169")',
            },
          },
          required: ['asn'],
        },
      },
      {
        name: 'asn_neighbours',
        description: 'BGP neighbours of an AS — observed via RIS route collectors.',
        inputSchema: {
          type: 'object',
          properties: {
            asn: {
              type: 'string',
              description: 'AS number (e.g. "AS15169" or "15169")',
            },
          },
          required: ['asn'],
        },
      },
      {
        name: 'bgp_state',
        description: 'Current BGP routing state for a resource — origin ASNs and path lengths.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'IP address, prefix, or AS number',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'abuse_contact',
        description: 'Abuse contact email(s) for a resource (from inetnum / aut-num records).',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'IP address, prefix, or AS number',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'geoloc',
        description: 'Country geolocation of an IP or prefix from RIR registration.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'IP address or prefix (e.g. "8.8.8.8" or "8.8.8.0/24")',
            },
          },
          required: ['resource'],
        },
      },
      {
        name: 'prefix_overview',
        description: 'Comprehensive prefix overview — announcements, origins, allocation.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'Prefix (e.g. "8.8.8.0/24")',
            },
          },
          required: ['resource'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'whois':          return this.queryEndpoint('whois', args, 'resource');
        case 'network_info':   return this.queryEndpoint('network-info', args, 'resource');
        case 'as_overview':    return this.queryEndpoint('as-overview', args, 'asn');
        case 'asn_neighbours': return this.queryEndpoint('asn-neighbours', args, 'asn');
        case 'bgp_state':      return this.queryEndpoint('bgp-state', args, 'resource');
        case 'abuse_contact':  return this.queryEndpoint('abuse-contact-finder', args, 'resource');
        case 'geoloc':         return this.queryEndpoint('geoloc', args, 'resource');
        case 'prefix_overview':return this.queryEndpoint('prefix-overview', args, 'resource');
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

  private async queryEndpoint(
    endpoint: string,
    args: Record<string, unknown>,
    resourceKey: string,
  ): Promise<ToolResult> {
    const resource = args[resourceKey];
    if (!resource || typeof resource !== 'string' || !resource.trim()) {
      return {
        content: [{ type: 'text', text: `Required argument "${resourceKey}" is missing or empty.` }],
        isError: true,
      };
    }
    const params = new URLSearchParams({ resource: resource.trim() });
    const url = `${this.baseUrl}/${endpoint}/data.json?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `RIPE Stat API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
