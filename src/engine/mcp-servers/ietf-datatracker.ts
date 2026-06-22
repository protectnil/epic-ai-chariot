/**
 * IETF Datatracker MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://datatracker.ietf.org/api/v1
// Auth: none — public API, no key required
// Docs: https://datatracker.ietf.org/doc/help/api/
// Category: developer-tools
// Rate limits: none published — be courteous

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://datatracker.ietf.org/api/v1';

export class IetfDatatrackerMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'ietf-datatracker',
      displayName: 'IETF Datatracker',
      version: '1.0.0',
      category: 'developer-tools' as const,
      keywords: [
        'ietf', 'rfc', 'internet', 'standards', 'draft', 'working group',
        'datatracker', 'protocol', 'specification', 'network', 'document',
        'internet standard', 'wg', 'charter', 'person', 'author',
      ],
      toolNames: ['rfc', 'document', 'documents_search', 'wg', 'wgs_search', 'person'],
      description: 'IETF Datatracker: look up RFCs, internet-drafts, working groups, and contributors directly from the IETF public API — no authentication required.',
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
        name: 'rfc',
        description: 'RFC by number.',
        inputSchema: {
          type: 'object',
          properties: {
            number: { type: 'number', description: 'The RFC number (e.g. 9000).' },
          },
          required: ['number'],
        },
      },
      {
        name: 'document',
        description: 'Document by name (e.g. "rfc9000", "draft-ietf-quic-transport").',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Document name, e.g. "rfc9000" or "draft-ietf-quic-transport".' },
          },
          required: ['name'],
        },
      },
      {
        name: 'documents_search',
        description: 'Search documents.',
        inputSchema: {
          type: 'object',
          properties: {
            states: { type: 'string', description: 'Comma-sep state ids (e.g. "active").' },
            type: { type: 'string', description: 'draft | rfc | charter | conflrev | …' },
            name__contains: { type: 'string', description: 'Substring filter on the name.' },
            limit: { type: 'number', description: '1-1000 (default 20).' },
            offset: { type: 'number', description: 'Pagination offset (default 0).' },
          },
        },
      },
      {
        name: 'wg',
        description: 'Working group by acronym.',
        inputSchema: {
          type: 'object',
          properties: {
            acronym: { type: 'string', description: 'Working group acronym, e.g. "quic".' },
          },
          required: ['acronym'],
        },
      },
      {
        name: 'wgs_search',
        description: 'List working groups.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'number', description: '1-1000 (default 20).' },
            offset: { type: 'number', description: 'Pagination offset (default 0).' },
          },
        },
      },
      {
        name: 'person',
        description: 'Person by datatracker id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'number', description: 'Numeric datatracker person ID.' },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'rfc':             return this.getRfc(args);
        case 'document':       return this.getDocument(args);
        case 'documents_search': return this.searchDocuments(args);
        case 'wg':             return this.getWg(args);
        case 'wgs_search':     return this.searchWgs(args);
        case 'person':         return this.getPerson(args);
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

  private async ietfGet(path: string): Promise<ToolResult> {
    const separator = path.includes('?') ? '&' : '?';
    const url = `${BASE_URL}${path}${separator}format=json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'IETF Datatracker: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getRfc(args: Record<string, unknown>): Promise<ToolResult> {
    const num = (args.number as number) | 0;
    if (!num) throw new Error('Required argument "number" must be a positive RFC number.');
    const params = new URLSearchParams({ rfc: String(num) });
    return this.ietfGet(`/doc/document/?${params}`);
  }

  private async getDocument(args: Record<string, unknown>): Promise<ToolResult> {
    const name = this.requireString(args, 'name', '"rfc9000"');
    const params = new URLSearchParams({ name });
    return this.ietfGet(`/doc/document/?${params}`);
  }

  private async searchDocuments(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      limit: String(Math.min(1000, Math.max(1, (args.limit as number) ?? 20))),
      offset: String(Math.max(0, (args.offset as number) ?? 0)),
    });
    if (args.states) params.set('states__slug__in', String(args.states));
    if (args.type) params.set('type', String(args.type));
    if (args.name__contains) params.set('name__contains', String(args.name__contains));
    return this.ietfGet(`/doc/document/?${params}`);
  }

  private async getWg(args: Record<string, unknown>): Promise<ToolResult> {
    const acronym = this.requireString(args, 'acronym', '"quic"');
    const params = new URLSearchParams({ acronym });
    return this.ietfGet(`/group/group/?${params}`);
  }

  private async searchWgs(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      type__slug: 'wg',
      limit: String(Math.min(1000, Math.max(1, (args.limit as number) ?? 20))),
      offset: String(Math.max(0, (args.offset as number) ?? 0)),
    });
    return this.ietfGet(`/group/group/?${params}`);
  }

  private async getPerson(args: Record<string, unknown>): Promise<ToolResult> {
    const id = (args.id as number) | 0;
    if (!id) throw new Error('Required argument "id" must be a positive person ID.');
    return this.ietfGet(`/person/person/${id}/`);
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }
}
