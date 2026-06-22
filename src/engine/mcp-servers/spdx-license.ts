/**
 * SPDX License List MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://raw.githubusercontent.com/spdx/license-list-data/main/json
// Auth: none (public GitHub raw content mirror of the SPDX license-list-data repo)
// Source: https://github.com/spdx/license-list-data
// Category: legal
// Rate limits: GitHub raw content CDN — effectively unlimited for read-only JSON blobs

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://raw.githubusercontent.com/spdx/license-list-data/main/json';
const UA = 'epic-ai-chariot/spdx-license (+https://epicai.com)';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

type LicenseEntry = {
  reference: string;
  isDeprecatedLicenseId: boolean;
  detailsUrl: string;
  referenceNumber: number;
  name: string;
  licenseId: string;
  seeAlso: string[];
  isOsiApproved: boolean;
  isFsfLibre?: boolean;
};

type LicenseListCache = {
  at: number;
  licenses: LicenseEntry[];
  releaseDate: string;
  licenseListVersion: string;
};

export class SpdxLicenseMCPServer extends MCPAdapterBase {
  private listCache: LicenseListCache | null = null;

  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'spdx-license',
      displayName: 'SPDX License List',
      version: '1.0.0',
      category: 'legal',
      keywords: [
        'spdx', 'license', 'open source', 'osi', 'fsf', 'free software',
        'copyleft', 'permissive', 'MIT', 'Apache', 'GPL', 'BSD',
        'license id', 'license text', 'software license',
      ],
      toolNames: ['list_licenses', 'get_license', 'get_license_text', 'search'],
      description: 'SPDX License List: browse, search, and retrieve full text for any SPDX standard software license (OSI-approved, FSF Free/Libre, deprecated flags included).',
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
        name: 'list_licenses',
        description: 'List SPDX licenses with optional filters (OSI-approved, FSF Free/Libre, deprecated).',
        inputSchema: {
          type: 'object',
          properties: {
            osiApproved: {
              type: 'boolean',
              description: 'When true, return only OSI-approved licenses. When false, return only non-OSI-approved. Omit to return all.',
            },
            fsfLibre: {
              type: 'boolean',
              description: 'When true, return only FSF Free/Libre licenses. When false, return only non-FSF. Omit to return all.',
            },
            deprecated: {
              type: 'boolean',
              description: 'Include deprecated license IDs in results. Default false.',
            },
          },
        },
      },
      {
        name: 'get_license',
        description: 'Get metadata and descriptors for one SPDX license id (e.g. "MIT", "Apache-2.0", "GPL-3.0-or-later").',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'SPDX license identifier, e.g. "MIT", "Apache-2.0", "GPL-3.0-or-later".',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_license_text',
        description: 'Get the full license text for a single SPDX license id (returns standard text and cross-references).',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'SPDX license identifier, e.g. "MIT", "Apache-2.0".',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search',
        description: 'Substring search across SPDX license id and full license name (case-insensitive).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search term to match against license id and name, e.g. "apache", "creative commons".',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_licenses':  return this.listLicenses(args);
        case 'get_license':    return this.getLicense(args);
        case 'get_license_text': return this.getLicenseText(args);
        case 'search':         return this.searchLicenses(args);
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

  private async loadList(): Promise<LicenseListCache> {
    const now = Date.now();
    if (this.listCache && now - this.listCache.at < CACHE_TTL_MS) return this.listCache;
    const response = await this.fetchWithRetry(`${BASE_URL}/licenses.json`, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': UA },
    });
    if (!response.ok) {
      throw new Error(`SPDX license list fetch failed: ${response.status} ${response.statusText}`);
    }
    const json = (await response.json()) as {
      licenses: LicenseEntry[];
      releaseDate: string;
      licenseListVersion: string;
    };
    this.listCache = { at: now, ...json };
    return this.listCache;
  }

  private async fetchDetails(id: string): Promise<unknown> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/details/${encodeURIComponent(id)}.json`,
      {
        method: 'GET',
        headers: { Accept: 'application/json', 'User-Agent': UA },
      },
    );
    if (response.status === 404) {
      throw new Error(`SPDX: license id "${id}" not found. Try the search tool to find the correct identifier.`);
    }
    if (!response.ok) {
      const body = await response.text().then((t) => t.slice(0, 200)).catch(() => '');
      throw new Error(`SPDX details fetch failed: ${response.status} ${body}`);
    }
    return response.json();
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private async listLicenses(args: Record<string, unknown>): Promise<ToolResult> {
    const data = await this.loadList();
    const includeDeprecated = args.deprecated === true;
    const osiFilter = args.osiApproved as boolean | undefined;
    const fsfFilter = args.fsfLibre as boolean | undefined;

    const filtered = data.licenses.filter((l) => {
      if (!includeDeprecated && l.isDeprecatedLicenseId) return false;
      if (osiFilter !== undefined && l.isOsiApproved !== osiFilter) return false;
      if (fsfFilter !== undefined && (l.isFsfLibre ?? false) !== fsfFilter) return false;
      return true;
    });

    const result = {
      licenseListVersion: data.licenseListVersion,
      releaseDate: data.releaseDate,
      count: filtered.length,
      licenses: filtered.map((l) => ({
        licenseId: l.licenseId,
        name: l.name,
        isOsiApproved: l.isOsiApproved,
        isFsfLibre: l.isFsfLibre ?? false,
        isDeprecatedLicenseId: l.isDeprecatedLicenseId,
        reference: l.reference,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getLicense(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.reqStr(args, 'id', '"MIT"');
    const data = await this.fetchDetails(id);
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getLicenseText(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.reqStr(args, 'id', '"MIT"');
    const details = (await this.fetchDetails(id)) as Record<string, unknown>;
    const result = {
      licenseId: details.licenseId,
      name: details.name,
      licenseText: details.licenseText,
      standardLicenseHeader: details.standardLicenseHeader ?? null,
      seeAlso: details.seeAlso ?? [],
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchLicenses(args: Record<string, unknown>): Promise<ToolResult> {
    const q = this.reqStr(args, 'query', '"apache"').toLowerCase();
    const data = await this.loadList();
    const matches = data.licenses.filter(
      (l) => l.licenseId.toLowerCase().includes(q) || l.name.toLowerCase().includes(q),
    );
    const result = { query: q, count: matches.length, results: matches };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
