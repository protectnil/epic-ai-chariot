/**
 * NVD (NIST National Vulnerability Database) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://nvd.nist.gov/developers/vulnerabilities
 * Base URL: https://services.nvd.nist.gov/rest/json
 * Auth: none (public, no-auth-verified)
 * Docs: https://nvd.nist.gov/developers/vulnerabilities
 * Category: security
 * Rate limits: ~50 requests/30s unauthenticated; 300 requests/30s with API key
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://services.nvd.nist.gov/rest/json';

export class NvdMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NvdMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'nvd',
      displayName: 'NVD — NIST National Vulnerability Database',
      version: '1.0.0',
      category: 'security',
      keywords: [
        'nvd', 'nist', 'cve', 'vulnerability', 'security', 'cvss',
        'national vulnerability database', 'exploit', 'patch', 'severity',
        'common vulnerabilities', 'exposures', 'infosec', 'cybersecurity',
      ],
      toolNames: ['search_cves', 'get_cve', 'recent_cves'],
      description: 'NVD (NIST National Vulnerability Database): search CVE vulnerabilities by keyword, fetch a specific CVE by ID, and retrieve CVEs published within a date range — free public API, no authentication required.',
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
        name: 'search_cves',
        description:
          'Search CVE vulnerabilities by keyword. Returns CVE ID, description, severity, and CVSS score.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword(s) to search in CVE descriptions',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default 10, max 2000)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_cve',
        description:
          'Fetch a specific CVE by its ID (e.g. "CVE-2021-44228"). Returns full details including description, severity, and affected products.',
        inputSchema: {
          type: 'object',
          properties: {
            cve_id: {
              type: 'string',
              description: 'CVE identifier, e.g. "CVE-2021-44228"',
            },
          },
          required: ['cve_id'],
        },
      },
      {
        name: 'recent_cves',
        description:
          'Fetch CVEs published within a date range. Dates must be ISO 8601 format with timezone (e.g. "2024-01-01T00:00:00.000Z").',
        inputSchema: {
          type: 'object',
          properties: {
            start: {
              type: 'string',
              description: 'Start date in ISO 8601 format (e.g. "2024-01-01T00:00:00.000Z")',
            },
            end: {
              type: 'string',
              description: 'End date in ISO 8601 format (e.g. "2024-01-31T23:59:59.000Z")',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default 10, max 2000)',
            },
          },
          required: ['start', 'end'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_cves':
          return this.searchCves(args.query as string, (args.limit as number) ?? 10);
        case 'get_cve':
          return this.getCve(args.cve_id as string);
        case 'recent_cves':
          return this.recentCves(
            args.start as string,
            args.end as string,
            (args.limit as number) ?? 10,
          );
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private formatCve(item: CveItem): FormattedCve {
    const cve = item.cve;
    const desc = cve.descriptions.find((d) => d.lang === 'en')?.value ?? '';
    const v31 = cve.metrics?.cvssMetricV31?.[0];
    const v2 = cve.metrics?.cvssMetricV2?.[0];
    const score = v31?.cvssData.baseScore ?? v2?.cvssData.baseScore ?? null;
    const severity = v31?.cvssData.baseSeverity ?? v2?.baseSeverity ?? null;

    return {
      id: cve.id,
      published: cve.published,
      last_modified: cve.lastModified,
      status: cve.vulnStatus,
      description: desc,
      cvss_score: score,
      severity,
    };
  }

  private async searchCves(query: string, limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({
      keywordSearch: query,
      resultsPerPage: String(Math.min(2000, Math.max(1, limit))),
    });

    const url = `${this.baseUrl}/cves/2.0?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NVD API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      totalResults: number;
      vulnerabilities: CveItem[];
    };

    const result = {
      total_results: data.totalResults,
      returned: data.vulnerabilities.length,
      cves: data.vulnerabilities.map((item) => this.formatCve(item)),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCve(cveId: string): Promise<ToolResult> {
    const params = new URLSearchParams({ cveId });
    const url = `${this.baseUrl}/cves/2.0?${params.toString()}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NVD API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      totalResults: number;
      vulnerabilities: CveItem[];
    };

    if (data.totalResults === 0 || data.vulnerabilities.length === 0) {
      return {
        content: [{ type: 'text', text: `CVE not found: ${cveId}` }],
        isError: true,
      };
    }

    return {
      content: [{ type: 'text', text: this.truncate(this.formatCve(data.vulnerabilities[0])) }],
      isError: false,
    };
  }

  private async recentCves(start: string, end: string, limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({
      pubStartDate: start,
      pubEndDate: end,
      resultsPerPage: String(Math.min(2000, Math.max(1, limit))),
    });

    const url = `${this.baseUrl}/cves/2.0?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NVD API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      totalResults: number;
      vulnerabilities: CveItem[];
    };

    const result = {
      total_results: data.totalResults,
      returned: data.vulnerabilities.length,
      cves: data.vulnerabilities.map((item) => this.formatCve(item)),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

interface CveItem {
  cve: {
    id: string;
    published: string;
    lastModified: string;
    vulnStatus: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{
        cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
      }>;
      cvssMetricV2?: Array<{
        cvssData: { baseScore: number; vectorString: string };
        baseSeverity: string;
      }>;
    };
  };
}

interface FormattedCve {
  id: string;
  published: string;
  last_modified: string;
  status: string;
  description: string;
  cvss_score: number | null;
  severity: string | null;
}
