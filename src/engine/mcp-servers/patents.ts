/**
 * PatentsView API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.patentsview.org
// Auth: None — public API, no key required
// Docs: https://patentsview.org/apis/api-endpoints/patents
// Category: legal
// Rate limits: Reasonable use; no published hard cap

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.patentsview.org';

export class PatentsMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'patents',
      displayName: 'PatentsView US Patents',
      version: '1.0.0',
      category: 'legal' as const,
      keywords: [
        'patents', 'patent', 'USPTO', 'patent search', 'inventors',
        'patent number', 'patent abstract', 'assignee', 'intellectual property',
        'IP', 'patent law', 'patent data', 'PatentsView',
      ],
      toolNames: ['search_patents', 'get_patent', 'search_inventors'],
      description: 'PatentsView US Patents: search US patents by keyword, retrieve full patent details by number, and search inventors by last name — free public API, no authentication required.',
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
        name: 'search_patents',
        description:
          'Search US patents by keyword. Matches against patent abstracts. Returns patent number, title, date, inventors, and assignee organization.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword or phrase to search in patent abstracts',
            },
            per_page: {
              type: 'number',
              description: 'Number of results to return (default 10, max 25)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_patent',
        description:
          'Get full details for a specific US patent by patent number. Returns title, abstract, date, type, inventors, and assignee.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'string',
              description: 'Patent number (e.g. "7654321")',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'search_inventors',
        description:
          'Search US patent inventors by last name. Returns inventor name, location, and associated patent numbers.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Inventor last name to search for',
            },
            per_page: {
              type: 'number',
              description: 'Number of results to return (default 10, max 25)',
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
        case 'search_patents':
          return this.searchPatents(
            args.query as string,
            (args.per_page as number | undefined) ?? 10,
          );
        case 'get_patent':
          return this.getPatent(args.number as string);
        case 'search_inventors':
          return this.searchInventors(
            args.query as string,
            (args.per_page as number | undefined) ?? 10,
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

  private async post(path: string, body: unknown): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
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

  private async searchPatents(query: string, perPage: number): Promise<ToolResult> {
    const body = {
      q: { _text_any: { patent_abstract: query } },
      f: [
        'patent_number',
        'patent_title',
        'patent_date',
        'inventor_first_name',
        'inventor_last_name',
        'assignee_organization',
      ],
      o: { per_page: perPage },
    };
    return this.post('/patents/query', body);
  }

  private async getPatent(number: string): Promise<ToolResult> {
    const body = {
      q: { patent_number: number },
      f: [
        'patent_number',
        'patent_title',
        'patent_abstract',
        'patent_date',
        'patent_type',
        'inventor_first_name',
        'inventor_last_name',
        'assignee_organization',
      ],
    };
    return this.post('/patents/query', body);
  }

  private async searchInventors(query: string, perPage: number): Promise<ToolResult> {
    const body = {
      q: { _text_any: { inventor_last_name: query } },
      f: [
        'inventor_first_name',
        'inventor_last_name',
        'inventor_city',
        'inventor_state',
        'patent_number',
      ],
      o: { per_page: perPage },
    };
    return this.post('/inventors/query', body);
  }
}
