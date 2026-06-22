/**
 * USAspending.gov MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.usaspending.gov/api/v2
// Auth: None (public government API, no key required)
// Docs: https://api.usaspending.gov/
// Category: government
// Rate limits: Free, no stated hard cap

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.usaspending.gov/api/v2';

export class USASpendingMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'usaspending',
      displayName: 'USAspending.gov',
      version: '1.0.0',
      category: 'government' as const,
      keywords: [
        'usaspending', 'federal spending', 'government contracts', 'awards',
        'procurement', 'NAICS', 'PSC', 'contractor', 'agency', 'fiscal year',
        'federal budget', 'grants', 'USA spending', 'defense', 'set-aside',
        'small business', 'federal procurement', 'contract awards', 'recipient',
      ],
      toolNames: [
        'usa_spending_by_agency',
        'usa_award_search',
        'usa_spending_by_category',
        'usa_recipient_profile',
        'usa_spending_trends',
      ],
      description: 'USAspending.gov: search and analyze U.S. federal spending data — contract awards, agency spending breakdowns, spending by category (NAICS/PSC/recipient), contractor profiles, and spending trends over time. Public API, no authentication required.',
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
        name: 'usa_spending_by_agency',
        description:
          'Get federal spending breakdown by agency for a given fiscal year and optional quarter. Shows how much each agency has spent.',
        inputSchema: {
          type: 'object',
          properties: {
            fiscal_year: {
              type: 'string',
              description: 'Four-digit fiscal year (e.g., "2025"). Defaults to current year.',
            },
            quarter: {
              type: 'number',
              description: 'Fiscal quarter (1-4). Omit for full year.',
            },
          },
        },
      },
      {
        name: 'usa_award_search',
        description:
          'Search federal contract awards by keywords, agency, date range, and NAICS code. Returns recipient, amount, dates, agency, and description. Award types: A=BPA Call, B=Purchase Order, C=Delivery Order, D=Definitive Contract.',
        inputSchema: {
          type: 'object',
          properties: {
            keywords: {
              type: 'array',
              items: { type: 'string' },
              description: 'Search keywords (e.g., ["cybersecurity", "cloud"])',
            },
            agency: {
              type: 'string',
              description: 'Awarding agency name (e.g., "Department of Defense")',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
            naics: {
              type: 'string',
              description: 'NAICS code to filter by (e.g., "541512")',
            },
            set_aside: {
              type: 'string',
              description: 'Set-aside type filter',
            },
            limit: {
              type: 'number',
              description: 'Number of results (1-100, default 10)',
            },
          },
          required: ['keywords', 'start_date', 'end_date'],
        },
      },
      {
        name: 'usa_spending_by_category',
        description:
          'Get federal spending broken down by category: NAICS code, PSC (product/service code), recipient, awarding agency, or awarding subagency. Useful for market analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description:
                'Category to group by: naics, psc, recipient, awarding_agency, awarding_subagency',
            },
            keywords: {
              type: 'array',
              items: { type: 'string' },
              description: 'Optional keywords to filter spending',
            },
            agency: {
              type: 'string',
              description: 'Optional awarding agency name filter',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
            limit: {
              type: 'number',
              description: 'Number of results (1-100, default 10)',
            },
          },
          required: ['category', 'start_date', 'end_date'],
        },
      },
      {
        name: 'usa_recipient_profile',
        description:
          "Get a specific contractor or recipient's federal spending profile. Shows all contract awards for the named recipient within a date range.",
        inputSchema: {
          type: 'object',
          properties: {
            recipient_name: {
              type: 'string',
              description: 'Recipient/contractor name to search for (e.g., "Lockheed Martin")',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
            limit: {
              type: 'number',
              description: 'Number of results (1-100, default 10)',
            },
          },
          required: ['recipient_name', 'start_date', 'end_date'],
        },
      },
      {
        name: 'usa_spending_trends',
        description:
          'Get federal spending over time for given keywords or agency. Returns spending grouped by fiscal year, quarter, or month. Useful for trend analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            keywords: {
              type: 'array',
              items: { type: 'string' },
              description: 'Keywords to track spending for (e.g., ["artificial intelligence"])',
            },
            agency: {
              type: 'string',
              description: 'Optional awarding agency name',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
            group: {
              type: 'string',
              description:
                'Time grouping: fiscal_year, quarter, or month (default fiscal_year)',
            },
          },
          required: ['keywords', 'start_date', 'end_date'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'usa_spending_by_agency':   return this.spendingByAgency(args);
        case 'usa_award_search':         return this.awardSearch(args);
        case 'usa_spending_by_category': return this.spendingByCategory(args);
        case 'usa_recipient_profile':    return this.recipientProfile(args);
        case 'usa_spending_trends':      return this.spendingTrends(args);
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

  private async post(path: string, body: unknown): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USAspending API error (${response.status}): ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private buildFilters(args: Record<string, unknown>): Record<string, unknown> {
    const filters: Record<string, unknown> = {};

    if (args.keywords) {
      filters.keywords = args.keywords;
    }

    if (args.start_date && args.end_date) {
      filters.time_period = [
        { start_date: args.start_date as string, end_date: args.end_date as string },
      ];
    }

    if (args.agency) {
      filters.agencies = [
        { type: 'awarding', tier: 'toptier', name: args.agency as string },
      ];
    }

    if (args.naics) {
      filters.naics_codes = [args.naics as string];
    }

    if (args.set_aside) {
      filters.set_aside_type = [args.set_aside as string];
    }

    // Default to contract award types (exclude grants, loans, etc.)
    filters.award_type_codes = ['A', 'B', 'C', 'D'];

    return filters;
  }

  private async spendingByAgency(args: Record<string, unknown>): Promise<ToolResult> {
    const fiscalYear = (args.fiscal_year as string) ?? String(new Date().getFullYear());
    const body: Record<string, unknown> = {
      type: 'agency',
      filters: { fy: fiscalYear },
    };
    if (args.quarter) {
      (body.filters as Record<string, unknown>).quarter = String(args.quarter);
    }

    return this.post('/spending/', body);
  }

  private async awardSearch(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 10));
    const filters = this.buildFilters(args);

    const body = {
      filters,
      fields: [
        'Award ID',
        'Recipient Name',
        'Award Amount',
        'Total Outlays',
        'Start Date',
        'End Date',
        'Awarding Agency',
        'Awarding Sub Agency',
        'Description',
        'NAICS Code',
        'Contract Award Type',
      ],
      limit,
      page: 1,
      sort: 'Award Amount',
      order: 'desc',
    };

    return this.post('/search/spending_by_award/', body);
  }

  private async spendingByCategory(args: Record<string, unknown>): Promise<ToolResult> {
    const category = args.category as string;
    const validCategories = ['naics', 'psc', 'recipient', 'awarding_agency', 'awarding_subagency'];
    if (!validCategories.includes(category)) {
      return {
        content: [{ type: 'text', text: `Invalid category "${category}". Must be one of: ${validCategories.join(', ')}` }],
        isError: true,
      };
    }

    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 10));
    const filters = this.buildFilters(args);

    const body = {
      filters,
      limit,
      page: 1,
    };

    return this.post(`/search/spending_by_category/${category}/`, body);
  }

  private async recipientProfile(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 10));
    const filters: Record<string, unknown> = {
      keywords: [args.recipient_name as string],
      award_type_codes: ['A', 'B', 'C', 'D'],
    };

    if (args.start_date && args.end_date) {
      filters.time_period = [
        { start_date: args.start_date as string, end_date: args.end_date as string },
      ];
    }

    const body = {
      filters,
      fields: [
        'Award ID',
        'Recipient Name',
        'Award Amount',
        'Total Outlays',
        'Start Date',
        'End Date',
        'Awarding Agency',
        'Awarding Sub Agency',
        'Description',
        'NAICS Code',
        'Contract Award Type',
      ],
      limit,
      page: 1,
      sort: 'Award Amount',
      order: 'desc',
    };

    return this.post('/search/spending_by_award/', body);
  }

  private async spendingTrends(args: Record<string, unknown>): Promise<ToolResult> {
    const group = (args.group as string) ?? 'fiscal_year';
    const validGroups = ['fiscal_year', 'quarter', 'month'];
    if (!validGroups.includes(group)) {
      return {
        content: [{ type: 'text', text: `Invalid group "${group}". Must be one of: ${validGroups.join(', ')}` }],
        isError: true,
      };
    }

    const filters = this.buildFilters(args);

    const body = {
      group,
      filters,
    };

    return this.post('/search/spending_over_time/', body);
  }
}
