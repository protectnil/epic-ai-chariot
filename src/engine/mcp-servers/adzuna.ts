/**
 * Adzuna Job Board MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.adzuna.com/v1/api/jobs
// Auth: app_id + app_key — both required, passed as query parameters.
//       Register at https://developer.adzuna.com/ to obtain credentials.
//       Free tier: 250 calls/month.
// Docs: https://developer.adzuna.com/docs/search
// Rate limits: 250 calls/month on free tier; higher on paid plans.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AdzunaConfig {
  /** Adzuna application ID (from developer.adzuna.com) */
  appId: string;
  /** Adzuna application key (from developer.adzuna.com) */
  appKey: string;
  /** Optional base URL override (default: https://api.adzuna.com/v1/api/jobs) */
  baseUrl?: string;
}

export class AdzunaMCPServer extends MCPAdapterBase {
  private readonly appId: string;
  private readonly appKey: string;
  private readonly baseUrl: string;

  constructor(config: AdzunaConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Adzuna: configuration object is required');
    }
    for (const k of (['appId', 'appKey'] as Array<keyof AdzunaConfig>)) {
      if (!config[k] || (config[k] as string).trim() === '') {
        throw new Error(`Adzuna: ${k} is required`);
      }
    }
    this.appId = config.appId;
    this.appKey = config.appKey;
    this.baseUrl = config.baseUrl ?? 'https://api.adzuna.com/v1/api/jobs';
  }

  static catalog() {
    return {
      name: 'adzuna',
      displayName: 'Adzuna Job Board',
      version: '1.0.0',
      category: 'misc' as const,
      keywords: [
        'adzuna', 'jobs', 'job board', 'employment', 'careers', 'hiring',
        'salary', 'job search', 'recruitment', 'labour market', 'wage',
        'job listings', 'vacancies', 'workforce', 'job categories',
        'job history', 'regional jobs', 'top companies',
      ],
      toolNames: [
        'search',
        'categories',
        'salary_histogram',
        'top_companies',
        'history',
        'regional_stats',
      ],
      description: 'Adzuna Job Board API v1: search jobs globally, list job categories, retrieve salary histograms, top hiring companies, historical job-volume/salary time series, and regional job-count geodata — all via the official Adzuna REST API.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil' as const,
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search',
        description: 'Search jobs in a country. country is required (ISO-style code: gb, us, ca, de, fr, au, br, in, nz, pl, ru, sg, za, …).',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO-style country code (e.g. "gb", "us", "ca", "de", "fr")',
            },
            what: {
              type: 'string',
              description: 'Free-text query matching job title and description',
            },
            what_phrase: {
              type: 'string',
              description: 'Exact-phrase variant of `what`',
            },
            where: {
              type: 'string',
              description: 'Location (city or region, e.g. "London", "New York")',
            },
            distance: {
              type: 'number',
              description: 'Search radius from `where` in km',
            },
            results_per_page: {
              type: 'number',
              description: 'Number of results per page (1–50, default 20)',
            },
            page: {
              type: 'number',
              description: '1-based page number (default 1)',
            },
            salary_min: {
              type: 'number',
              description: 'Minimum salary filter in local currency',
            },
            salary_max: {
              type: 'number',
              description: 'Maximum salary filter in local currency',
            },
            full_time: {
              type: 'boolean',
              description: 'Restrict to full-time positions',
            },
            permanent: {
              type: 'boolean',
              description: 'Restrict to permanent positions',
            },
            sort: {
              type: 'string',
              description: 'Sort order: "default" | "hybrid" | "date" | "salary" | "relevance"',
            },
            max_days_old: {
              type: 'number',
              description: 'Restrict to jobs posted within the last N days',
            },
          },
          required: ['country'],
        },
      },
      {
        name: 'categories',
        description: "Retrieve Adzuna's normalized job-category list for a given country.",
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO-style country code (e.g. "gb", "us")',
            },
          },
          required: ['country'],
        },
      },
      {
        name: 'salary_histogram',
        description: 'Retrieve wage distribution (salary histogram) for jobs matching a query in a given country.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO-style country code',
            },
            what: {
              type: 'string',
              description: 'Job title / keyword filter',
            },
            where: {
              type: 'string',
              description: 'Location filter (city or region)',
            },
            location_filter: {
              type: 'string',
              description: 'Adzuna location id (e.g. "London")',
            },
          },
          required: ['country'],
        },
      },
      {
        name: 'top_companies',
        description: 'List the companies posting the most jobs matching the given filters in a country.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO-style country code',
            },
            what: {
              type: 'string',
              description: 'Job title / keyword filter',
            },
            where: {
              type: 'string',
              description: 'Location filter',
            },
          },
          required: ['country'],
        },
      },
      {
        name: 'history',
        description: 'Retrieve a historical monthly time series of job volume and mean salary for a country, optionally filtered by location and category.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO-style country code',
            },
            months: {
              type: 'number',
              description: 'Number of months of history to return (1–100, default 12)',
            },
            location: {
              type: 'string',
              description: 'Location filter (Adzuna location id)',
            },
            category: {
              type: 'string',
              description: 'Job category tag as returned by the `categories` tool',
            },
          },
          required: ['country'],
        },
      },
      {
        name: 'regional_stats',
        description: 'Retrieve current job counts broken down by region (geodata) for a country.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'ISO-style country code',
            },
            location_filter: {
              type: 'string',
              description: 'Adzuna location id to restrict the region breakdown',
            },
            category: {
              type: 'string',
              description: 'Job category tag to restrict the breakdown',
            },
          },
          required: ['country'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':         return this.search(args);
        case 'categories':     return this.categories(args);
        case 'salary_histogram': return this.salaryHistogram(args);
        case 'top_companies':  return this.topCompanies(args);
        case 'history':        return this.history(args);
        case 'regional_stats': return this.regionalStats(args);
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

  /** Build base auth params shared by every request. */
  private authParams(): URLSearchParams {
    return new URLSearchParams({
      app_id: this.appId,
      app_key: this.appKey,
      'content-type': 'application/json',
    });
  }

  private requireCountry(args: Record<string, unknown>): string {
    const v = args.country;
    if (typeof v !== 'string' || v.trim() === '') {
      throw new Error('Required argument "country" is missing. Pass an ISO-style country code such as "us" or "gb".');
    }
    return v.trim().toLowerCase();
  }

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: `Adzuna: unauthorized — check app_id / app_key (HTTP ${response.status})` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Adzuna API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const country = this.requireCountry(args);
    const page = Math.max(1, Number(args.page ?? 1));
    const params = this.authParams();
    params.set('results_per_page', String(Math.min(50, Math.max(1, Number(args.results_per_page ?? 20)))));
    if (args.what)            params.set('what',          String(args.what));
    if (args.what_phrase)     params.set('what_phrase',   String(args.what_phrase));
    if (args.where)           params.set('where',         String(args.where));
    if (args.distance != null) params.set('distance',     String(args.distance));
    if (args.salary_min != null) params.set('salary_min', String(args.salary_min));
    if (args.salary_max != null) params.set('salary_max', String(args.salary_max));
    if (args.full_time === true)  params.set('full_time', '1');
    if (args.permanent === true)  params.set('permanent', '1');
    if (args.sort)            params.set('sort_by',       String(args.sort));
    if (args.max_days_old != null) params.set('max_days_old', String(args.max_days_old));
    return this.get(`/${country}/search/${page}?${params}`);
  }

  private async categories(args: Record<string, unknown>): Promise<ToolResult> {
    const country = this.requireCountry(args);
    return this.get(`/${country}/categories?${this.authParams()}`);
  }

  private async salaryHistogram(args: Record<string, unknown>): Promise<ToolResult> {
    const country = this.requireCountry(args);
    const params = this.authParams();
    if (args.what)            params.set('what',      String(args.what));
    if (args.where)           params.set('where',     String(args.where));
    if (args.location_filter) params.set('location0', String(args.location_filter));
    return this.get(`/${country}/histogram?${params}`);
  }

  private async topCompanies(args: Record<string, unknown>): Promise<ToolResult> {
    const country = this.requireCountry(args);
    const params = this.authParams();
    if (args.what)  params.set('what',  String(args.what));
    if (args.where) params.set('where', String(args.where));
    return this.get(`/${country}/top_companies?${params}`);
  }

  private async history(args: Record<string, unknown>): Promise<ToolResult> {
    const country = this.requireCountry(args);
    const params = this.authParams();
    params.set('months', String(Math.min(100, Math.max(1, Number(args.months ?? 12)))));
    if (args.location) params.set('location0', String(args.location));
    if (args.category) params.set('category',  String(args.category));
    return this.get(`/${country}/history?${params}`);
  }

  private async regionalStats(args: Record<string, unknown>): Promise<ToolResult> {
    const country = this.requireCountry(args);
    const params = this.authParams();
    if (args.location_filter) params.set('location0', String(args.location_filter));
    if (args.category)        params.set('category',  String(args.category));
    return this.get(`/${country}/geodata?${params}`);
  }
}
