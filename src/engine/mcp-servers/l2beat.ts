/**
 * L2BEAT MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Native REST adapter for the L2BEAT public API.
// No authentication required — all endpoints are public.
//
// Base URL: https://l2beat.com/api
// Auth: none (public)
// Docs: https://l2beat.com/api/
// Category: blockchain
// Rate limits: unspecified; no auth tier

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://l2beat.com/api';

export class L2BeatMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('L2BeatMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'l2beat',
      displayName: 'L2BEAT',
      version: '1.0.0',
      category: 'blockchain',
      keywords: [
        'l2beat', 'layer 2', 'l2', 'ethereum', 'rollup', 'optimistic rollup',
        'zk rollup', 'validium', 'optimium', 'sidechain', 'tvs', 'tvl',
        'total value secured', 'scaling', 'activity', 'transactions',
        'arbitrum', 'optimism', 'base', 'starknet', 'zkSync', 'polygon',
        'blockchain analytics', 'defi', 'on-chain data',
      ],
      toolNames: [
        'list_projects',
        'get_project',
        'tvs_breakdown',
        'tvs_history',
        'activity',
      ],
      description: 'L2BEAT: explore Layer 2 and Layer 3 scaling projects on Ethereum — list all tracked projects, inspect project details (risks, stage, milestones, contracts), and retrieve TVS breakdowns, TVS history, and daily transaction-count activity.',
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
        name: 'list_projects',
        description: 'List all L2BEAT-tracked projects (rollups, validiums, optimiums, sidechains).',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_project',
        description: 'Full project record by slug — risks, stage, milestones, contracts.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'L2BEAT slug (e.g. "arbitrum", "optimism", "base")',
            },
          },
          required: ['slug'],
        },
      },
      {
        name: 'tvs_breakdown',
        description: 'TVS breakdown by token category and project today.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Specific project slug (default: all projects aggregate)',
            },
          },
        },
      },
      {
        name: 'tvs_history',
        description: 'Historical TVS time series.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Specific project slug (default: all projects aggregate)',
            },
            range: {
              type: 'string',
              description: '7d | 30d | 90d | 180d | 1y | max (default 30d)',
            },
          },
        },
      },
      {
        name: 'activity',
        description: 'Daily transaction counts (and UOPS where available).',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Specific project slug (default: all projects aggregate)',
            },
            range: {
              type: 'string',
              description: '7d | 30d | 90d | 180d | 1y | max (default 30d)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_projects':  return this.listProjects();
        case 'get_project':    return this.getProject(args);
        case 'tvs_breakdown':  return this.tvsBreakdown(args);
        case 'tvs_history':    return this.tvsHistory(args);
        case 'activity':       return this.activity(args);
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

  private async l2beatGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epic-ai-chariot/1.0',
      },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: `L2BEAT: not found (${path})` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `L2BEAT API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async listProjects(): Promise<ToolResult> {
    return this.l2beatGet('/scaling/summary');
  }

  private async getProject(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = args.slug;
    if (typeof slug !== 'string' || !slug.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "slug" is missing. Pass a string like "arbitrum".' }],
        isError: true,
      };
    }
    return this.l2beatGet(`/projects/${encodeURIComponent(slug.trim())}`);
  }

  private async tvsBreakdown(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = typeof args.slug === 'string' ? args.slug.trim() : undefined;
    return slug
      ? this.l2beatGet(`/scaling/tvs/${encodeURIComponent(slug)}`)
      : this.l2beatGet('/scaling/tvs');
  }

  private async tvsHistory(args: Record<string, unknown>): Promise<ToolResult> {
    const range = typeof args.range === 'string' ? args.range.trim() : '30d';
    const slug = typeof args.slug === 'string' ? args.slug.trim() : undefined;
    return slug
      ? this.l2beatGet(`/scaling/tvs/${encodeURIComponent(slug)}?range=${encodeURIComponent(range)}`)
      : this.l2beatGet(`/scaling/tvs?range=${encodeURIComponent(range)}`);
  }

  private async activity(args: Record<string, unknown>): Promise<ToolResult> {
    const range = typeof args.range === 'string' ? args.range.trim() : '30d';
    const slug = typeof args.slug === 'string' ? args.slug.trim() : undefined;
    return slug
      ? this.l2beatGet(`/scaling/activity/${encodeURIComponent(slug)}?range=${encodeURIComponent(range)}`)
      : this.l2beatGet(`/scaling/activity?range=${encodeURIComponent(range)}`);
  }
}
