/**
 * Open Collective MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://opencollective.com
// Auth: none (public read endpoints)
// Docs: https://docs.opencollective.com/help/contributing/development/api
// Category: finance
// Rate limits: public, no documented hard limit

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class OpenCollectiveMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('OpenCollectiveMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://opencollective.com';
  }

  static catalog() {
    return {
      name: 'opencollective',
      displayName: 'Open Collective',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'opencollective', 'open collective', 'open source', 'funding',
        'donations', 'backers', 'sponsors', 'collectives', 'transactions',
        'events', 'members', 'contributors', 'nonprofit', 'community',
      ],
      toolNames: ['collective', 'members', 'transactions', 'events'],
      description: 'Open Collective: fetch public collective info, members, transactions, and events for open-source and community projects — no authentication required.',
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
        name: 'collective',
        description: 'Public collective info by slug (name, balance, currency, sponsors).',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Collective slug, e.g. "babel", "webpack", "preact"',
            },
          },
          required: ['slug'],
        },
      },
      {
        name: 'members',
        description: 'Members (backers / sponsors / admins / contributors) for a collective.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Collective slug',
            },
            role: {
              type: 'string',
              description: 'Filter by role: BACKER | SPONSOR | ADMIN | CONTRIBUTOR (default: all roles)',
            },
          },
          required: ['slug'],
        },
      },
      {
        name: 'transactions',
        description: 'Transaction list for a collective.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Collective slug',
            },
            type: {
              type: 'string',
              description: 'Filter by transaction type: CREDIT | DEBIT (default: both)',
            },
            limit: {
              type: 'number',
              description: 'Number of transactions to return, 1–1000 (default: 100)',
            },
          },
          required: ['slug'],
        },
      },
      {
        name: 'events',
        description: 'Events for a collective.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: {
              type: 'string',
              description: 'Collective slug',
            },
          },
          required: ['slug'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'collective':    return this.getCollective(args);
        case 'members':       return this.getMembers(args);
        case 'transactions':  return this.getTransactions(args);
        case 'events':        return this.getEvents(args);
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

  private parseSlug(args: Record<string, unknown>): string {
    const v = args.slug;
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error('Required argument "slug" is missing or empty.');
    }
    const s = v.trim().toLowerCase();
    if (!/^[a-z0-9-]+$/.test(s)) {
      throw new Error(`Invalid slug "${s}". Use lowercase alphanumerics and dashes only.`);
    }
    return s;
  }

  private async ocGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epic-ai-chariot/1.0',
      },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Open Collective: collective not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Collective API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getCollective(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.parseSlug(args);
    return this.ocGet(`/${slug}.json`);
  }

  private async getMembers(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.parseSlug(args);
    const role = (args.role as string | undefined)?.toLowerCase();
    const path = role
      ? `/${slug}/members/${encodeURIComponent(role)}.json`
      : `/${slug}/members.json`;
    return this.ocGet(path);
  }

  private async getTransactions(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.parseSlug(args);
    const rawLimit = args.limit as number | undefined;
    const limit = rawLimit !== undefined ? Math.min(1000, Math.max(1, rawLimit)) : 100;
    const type = (args.type as string | undefined)?.toUpperCase();
    if (type !== undefined && type !== 'CREDIT' && type !== 'DEBIT') {
      return {
        content: [{ type: 'text', text: 'Invalid "type" value. Must be CREDIT or DEBIT.' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({ limit: String(limit) });
    if (type) params.set('type', type);
    return this.ocGet(`/${slug}/transactions.json?${params}`);
  }

  private async getEvents(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.parseSlug(args);
    return this.ocGet(`/${slug}/events.json`);
  }
}
