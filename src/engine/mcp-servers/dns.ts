/**
 * DNS MCP Adapter — DNS and network lookup tools
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://dns.google/resolve (Google DNS-over-HTTPS)
// Auth: none — public unauthenticated endpoint
// Docs: https://developers.google.com/speed/public-dns/docs/doh/json
// Category: developer-tools

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const GOOGLE_DOH = 'https://dns.google/resolve';

const DNS_TYPE_NAMES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  257: 'CAA',
};

const DNS_STATUS: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

interface DohRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: { name: string; type: number }[];
  Answer?: DohRecord[];
  Authority?: DohRecord[];
  Comment?: string;
}

export class DnsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DnsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? GOOGLE_DOH;
  }

  static catalog() {
    return {
      name: 'dns',
      displayName: 'DNS Lookup',
      version: '1.0.0',
      category: 'developer-tools',
      keywords: [
        'dns', 'domain', 'lookup', 'network', 'records', 'mx', 'ns', 'txt',
        'cname', 'aaaa', 'ptr', 'reverse dns', 'dns-over-https', 'doh',
        'nameserver', 'ip', 'hostname', 'domain resolution',
      ],
      toolNames: ['dns_lookup', 'dns_lookup_all', 'reverse_dns'],
      description: 'DNS lookup tools using Google DNS-over-HTTPS: query individual record types, retrieve all record types at once, or perform reverse PTR lookups for IP addresses.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'dns_lookup',
        description:
          'Look up DNS records for a domain using Google DNS-over-HTTPS. Returns records of the requested type with TTLs and data values.',
        inputSchema: {
          type: 'object',
          properties: {
            domain: {
              type: 'string',
              description: 'Domain name to look up (e.g., "example.com", "mail.google.com")',
            },
            type: {
              type: 'string',
              description:
                'DNS record type to query (e.g., "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"). Defaults to "A".',
            },
          },
          required: ['domain'],
        },
      },
      {
        name: 'dns_lookup_all',
        description:
          'Look up multiple DNS record types for a domain in one call. Queries A, AAAA, MX, NS, TXT, and CNAME records simultaneously and returns all results grouped by type.',
        inputSchema: {
          type: 'object',
          properties: {
            domain: {
              type: 'string',
              description: 'Domain name to look up (e.g., "example.com")',
            },
          },
          required: ['domain'],
        },
      },
      {
        name: 'reverse_dns',
        description:
          'Perform a reverse DNS lookup for an IP address. Returns the PTR record (hostname) associated with the IP, if one exists.',
        inputSchema: {
          type: 'object',
          properties: {
            ip: {
              type: 'string',
              description: 'IPv4 address to reverse-lookup (e.g., "8.8.8.8")',
            },
          },
          required: ['ip'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'dns_lookup':
          return this.dnsLookup(args.domain as string, (args.type as string) ?? 'A');
        case 'dns_lookup_all':
          return this.dnsLookupAll(args.domain as string);
        case 'reverse_dns':
          return this.reverseDns(args.ip as string);
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

  private async dohQuery(name: string, type: string): Promise<DohResponse> {
    const params = new URLSearchParams({ name, type });
    const url = `${this.baseUrl}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/dns-json' },
    });
    if (!response.ok) {
      throw new Error(`Google DNS-over-HTTPS error: ${response.status}`);
    }
    return (await response.json()) as DohResponse;
  }

  private async dnsLookup(domain: string, type: string): Promise<ToolResult> {
    const recordType = type.toUpperCase();
    const data = await this.dohQuery(domain, recordType);
    const status = DNS_STATUS[data.Status] ?? `RCODE ${data.Status}`;

    if (data.Status !== 0) {
      return {
        content: [{ type: 'text', text: this.truncate({ domain, type: recordType, status, records: [] }) }],
        isError: false,
      };
    }

    const records = (data.Answer ?? []).map((r) => ({
      name: r.name,
      type: DNS_TYPE_NAMES[r.type] ?? `TYPE${r.type}`,
      ttl_seconds: r.TTL,
      value: r.data,
    }));

    return {
      content: [{ type: 'text', text: this.truncate({ domain, type: recordType, status, records, record_count: records.length }) }],
      isError: false,
    };
  }

  private async dnsLookupAll(domain: string): Promise<ToolResult> {
    const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'];

    const results = await Promise.allSettled(types.map((t) => this.dohQuery(domain, t)));

    const grouped: Record<string, { ttl_seconds: number; value: string }[]> = {};

    for (let i = 0; i < types.length; i++) {
      const result = results[i];
      const recordType = types[i];

      if (result.status === 'rejected') {
        grouped[recordType] = [];
        continue;
      }

      const dohData = result.value;
      if (dohData.Status !== 0 || !dohData.Answer) {
        grouped[recordType] = [];
        continue;
      }

      grouped[recordType] = dohData.Answer.filter(
        (r) => DNS_TYPE_NAMES[r.type] === recordType,
      ).map((r) => ({
        ttl_seconds: r.TTL,
        value: r.data,
      }));
    }

    return {
      content: [{ type: 'text', text: this.truncate({ domain, records: grouped }) }],
      isError: false,
    };
  }

  private async reverseDns(ip: string): Promise<ToolResult> {
    const parts = ip.split('.');
    if (parts.length !== 4 || parts.some((p) => isNaN(Number(p)))) {
      return {
        content: [{ type: 'text', text: 'Invalid IPv4 address. Provide a valid IPv4 address (e.g., "8.8.8.8").' }],
        isError: true,
      };
    }

    const reversedName = `${parts[3]}.${parts[2]}.${parts[1]}.${parts[0]}.in-addr.arpa`;
    const data = await this.dohQuery(reversedName, 'PTR');
    const status = DNS_STATUS[data.Status] ?? `RCODE ${data.Status}`;

    const hostnames = (data.Answer ?? [])
      .filter((r) => r.type === 12)
      .map((r) => r.data.replace(/\.$/, ''));

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          ip,
          reverse_name: reversedName,
          status,
          hostnames,
          primary_hostname: hostnames[0] ?? null,
        }),
      }],
      isError: false,
    };
  }
}
