/**
 * USAJOBS MCP Adapter — US federal job postings
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://data.usajobs.gov/api
// Auth: two headers required —
//   Authorization-Key: <auth_key from developer.usajobs.gov>
//   User-Agent: <registered email>
// The adapter accepts the combined credential as "<auth_key>:<email>" via apiKey.
// Docs: https://developer.usajobs.gov/
// Category: government
// Rate limits: per developer.usajobs.gov registration terms

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const SEARCH_HOST = 'https://data.usajobs.gov/api';
const CODES_HOST = 'https://data.usajobs.gov/api/codelist';

interface UsajobsConfig {
  /** Combined credential: "<authorization_key>:<registered_email>" */
  apiKey: string;
  baseUrl?: string;
}

export class UsajobsMCPServer extends MCPAdapterBase {
  private readonly authKey: string;
  private readonly userAgent: string;
  private readonly baseUrl: string;

  constructor(config: UsajobsConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('USAJOBS: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('USAJOBS: ' + __k + ' is required');
      }
    }
    const raw = config.apiKey.trim();
    const colon = raw.indexOf(':');
    this.authKey = colon === -1 ? raw : raw.slice(0, colon);
    this.userAgent = colon === -1 ? '' : raw.slice(colon + 1);
    if (!this.authKey) {
      throw new Error('USAJOBS: Authorization-Key is empty — pass "<auth_key>:<email>" as apiKey');
    }
    if (!this.userAgent) {
      throw new Error(
        'USAJOBS: User-Agent email is required — pass "<auth_key>:<email>" as apiKey. ' +
        'Register at https://developer.usajobs.gov/',
      );
    }
    this.baseUrl = config.baseUrl ?? SEARCH_HOST;
  }

  static catalog() {
    return {
      name: 'usajobs',
      displayName: 'USAJOBS — US Federal Job Postings',
      version: '1.0.0',
      category: 'government' as const,
      keywords: [
        'usajobs', 'federal jobs', 'government jobs', 'job search', 'usa jobs',
        'civil service', 'GS pay grade', 'federal hiring', 'agency', 'vacancy',
        'announcement', 'occupational series', 'remote federal', 'telework',
      ],
      toolNames: [
        'search',
        'get_job',
        'list_agencies',
        'list_pay_grades',
        'list_occupational_series',
      ],
      description:
        'USAJOBS: search US federal job announcements, fetch individual postings by announcement number, and retrieve reference code lists for agencies, pay grades, and occupational series. Requires a free developer.usajobs.gov API key.',
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
        name: 'search',
        description:
          'Search USAJOBS announcements. Returns title, agency, location, salary band, posting/closing dates.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Free-text — matched against title, description, and agency name',
            },
            location: {
              type: 'string',
              description: 'City/state (e.g. "San Francisco, CA")',
            },
            position_title: {
              type: 'string',
              description: 'Restrict match to job title field only',
            },
            organization: {
              type: 'string',
              description: 'Agency code or name (e.g. "VATA" or "Veterans")',
            },
            pay_grade_low: {
              type: 'string',
              description: 'Minimum pay grade (e.g. "GS5", "GS9", "SES")',
            },
            pay_grade_high: {
              type: 'string',
              description: 'Maximum pay grade (e.g. "GS12")',
            },
            remote: {
              type: 'boolean',
              description: 'If true, return telework/remote-only positions',
            },
            results_per_page: {
              type: 'number',
              description: 'Results per page, 1–500 (default 25)',
            },
            page: {
              type: 'number',
              description: '1-based page number (default 1)',
            },
          },
        },
      },
      {
        name: 'get_job',
        description: 'Fetch a single announcement by USAJOBS announcement number.',
        inputSchema: {
          type: 'object',
          properties: {
            announcement_number: {
              type: 'string',
              description: 'USAJOBS announcement number (e.g. "AF-DHA-2024-12345")',
            },
          },
          required: ['announcement_number'],
        },
      },
      {
        name: 'list_agencies',
        description: 'Retrieve the full list of federal agency and sub-element reference codes.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_pay_grades',
        description: 'Retrieve pay grade reference codes (GS, GG, ES, SES, etc.).',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_occupational_series',
        description:
          'Retrieve occupational series reference codes (e.g. 2210 Information Technology).',
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
        case 'search':
          return this.search(args);
        case 'get_job':
          return this.getJob(args);
        case 'list_agencies':
          return this.codesGet('/agencysubelement');
        case 'list_pay_grades':
          return this.codesGet('/paygrades');
        case 'list_occupational_series':
          return this.codesGet('/occupationalseries');
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
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

  // ── Private helpers ────────────────────────────────────────────────────────

  private authHeaders(): Record<string, string> {
    return {
      Host: 'data.usajobs.gov',
      'User-Agent': this.userAgent,
      'Authorization-Key': this.authKey,
      Accept: 'application/json',
    };
  }

  private async usajobsFetch(url: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.authHeaders(),
    });
    if (response.status === 401) {
      return {
        content: [
          {
            type: 'text',
            text: 'USAJOBS: unauthorized (HTTP 401) — check Authorization-Key and User-Agent email registration at https://developer.usajobs.gov/',
          },
        ],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USAJOBS API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const resultsPerPage = Math.min(500, Math.max(1, (args.results_per_page as number) ?? 25));
    const page = Math.max(1, (args.page as number) ?? 1);
    const params = new URLSearchParams({
      ResultsPerPage: String(resultsPerPage),
      Page: String(page),
    });
    if (args.keyword) params.set('Keyword', String(args.keyword));
    if (args.location) params.set('LocationName', String(args.location));
    if (args.position_title) params.set('PositionTitle', String(args.position_title));
    if (args.organization) params.set('Organization', String(args.organization));
    if (args.pay_grade_low) params.set('PayGradeLow', String(args.pay_grade_low));
    if (args.pay_grade_high) params.set('PayGradeHigh', String(args.pay_grade_high));
    if (args.remote === true) params.set('RemoteIndicator', 'True');
    return this.usajobsFetch(`${SEARCH_HOST}/search?${params.toString()}`);
  }

  private async getJob(args: Record<string, unknown>): Promise<ToolResult> {
    const annNum = args.announcement_number;
    if (typeof annNum !== 'string' || !annNum.trim()) {
      return {
        content: [
          {
            type: 'text',
            text: 'Required argument "announcement_number" is missing or empty. Pass a string like "AF-DHA-2024-12345".',
          },
        ],
        isError: true,
      };
    }
    // USAJOBS search API — filter by announcement number keyword; returns matching postings.
    const params = new URLSearchParams({
      Keyword: annNum.trim(),
      ResultsPerPage: '5',
    });
    return this.usajobsFetch(`${SEARCH_HOST}/search?${params.toString()}`);
  }

  private async codesGet(path: string): Promise<ToolResult> {
    return this.usajobsFetch(`${CODES_HOST}${path}`);
  }
}
