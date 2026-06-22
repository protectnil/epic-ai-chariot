/**
 * GovTrack MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://www.govtrack.us/developers/api
// Auth: none (public, IP rate-limited, no documented quota)
// Docs: https://www.govtrack.us/developers/api
// Category: government
// Rate limits: none documented — IP rate-limited, no published quota

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.govtrack.us/api/v2';

export class GovTrackMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('GovTrackMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'govtrack',
      displayName: 'GovTrack',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'govtrack', 'congress', 'legislation', 'bills', 'senate', 'house',
        'representative', 'senator', 'votes', 'roll-call', 'federal',
        'us congress', 'lawmakers', 'prognosis', 'ideology score',
        'leadership score', 'political data', 'public policy',
      ],
      toolNames: [
        'search_bills',
        'get_bill',
        'search_members',
        'get_member',
        'search_votes',
        'get_vote_detail',
      ],
      description:
        'GovTrack: federal US congressional data including bills, members, and roll-call votes with ideology scores, leadership scores, and bill survival prognosis.',
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
        name: 'search_bills',
        description:
          'Search federal congressional bills. Filter by congress (e.g., 118 = 2023-2024), current_status, sponsor person ID, free-text query. Returns title, status, sponsor, dates, prognosis if available.',
        inputSchema: {
          type: 'object',
          properties: {
            q: { type: 'string', description: 'Free-text search across title' },
            congress: { type: 'number', description: 'Congress number (e.g., 118)' },
            current_status: {
              type: 'string',
              description:
                'introduced | referred | reported | passed_simple_resolution | enacted_signed | etc. Comma-separated for OR.',
            },
            sponsor: { type: 'number', description: 'Sponsor person ID' },
            bill_type: {
              type: 'string',
              description:
                'house_bill | house_resolution | house_concurrent_resolution | house_joint_resolution | senate_bill | senate_resolution | senate_concurrent_resolution | senate_joint_resolution',
            },
            order_by: {
              type: 'string',
              description: 'Sort field (prefix - for desc), e.g. "-current_status_date"',
            },
            limit: { type: 'number', description: '1-100 (default 20)' },
            offset: { type: 'number', description: 'Pagination offset' },
          },
        },
      },
      {
        name: 'get_bill',
        description:
          'Fetch a single bill by GovTrack numeric ID. Returns full status history, cosponsors, related bills, action timeline.',
        inputSchema: {
          type: 'object',
          properties: {
            bill_id: { type: 'number', description: 'GovTrack bill ID (numeric)' },
          },
          required: ['bill_id'],
        },
      },
      {
        name: 'search_members',
        description:
          'Search current and historical congressional members. Filter by role_type (senator | representative), state, party, current (true/false).',
        inputSchema: {
          type: 'object',
          properties: {
            role_type: { type: 'string', description: 'senator | representative' },
            state: { type: 'string', description: '2-letter state code' },
            party: { type: 'string', description: 'Democrat | Republican | Independent' },
            current: { type: 'boolean', description: 'Restrict to currently-serving members' },
            congress: {
              type: 'number',
              description: 'Restrict to members serving in a specific congress',
            },
            district: { type: 'number', description: 'House district number' },
            limit: { type: 'number', description: '1-100 (default 20)' },
            offset: { type: 'number', description: 'Pagination offset' },
          },
        },
      },
      {
        name: 'get_member',
        description:
          'Fetch a person record by GovTrack person ID. Returns full role history, ideology score, leadership score, twitterid, website.',
        inputSchema: {
          type: 'object',
          properties: {
            person_id: { type: 'number', description: 'GovTrack person ID' },
          },
          required: ['person_id'],
        },
      },
      {
        name: 'search_votes',
        description:
          'Search roll-call votes. Filter by congress, chamber, category (passage | nomination | amendment | etc.), date range. Returns vote ID, motion, result, totals by party.',
        inputSchema: {
          type: 'object',
          properties: {
            congress: { type: 'number', description: 'Congress number' },
            chamber: { type: 'string', description: 'house | senate' },
            category: { type: 'string', description: 'Vote category filter' },
            related_bill: {
              type: 'number',
              description: 'Restrict to votes on a specific bill ID',
            },
            created__gte: { type: 'string', description: 'YYYY-MM-DD lower bound' },
            created__lte: { type: 'string', description: 'YYYY-MM-DD upper bound' },
            order_by: {
              type: 'string',
              description: 'Sort field (e.g., "-created" for latest first)',
            },
            limit: { type: 'number', description: '1-100 (default 20)' },
            offset: { type: 'number', description: 'Pagination offset' },
          },
        },
      },
      {
        name: 'get_vote_detail',
        description:
          'Fetch how each member voted on a roll-call vote. Returns per-member vote options (Yea / Nay / Present / Not Voting).',
        inputSchema: {
          type: 'object',
          properties: {
            vote_id: { type: 'number', description: 'GovTrack vote ID' },
          },
          required: ['vote_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_bills':    return this.listAt(args, '/bill');
        case 'get_bill':        return this.getAt(this.requireNumber(args, 'bill_id'), '/bill');
        case 'search_members':  return this.listAt(args, '/role');
        case 'get_member':      return this.getAt(this.requireNumber(args, 'person_id'), '/person');
        case 'search_votes':    return this.listAt(args, '/vote');
        case 'get_vote_detail': return this.getVoteDetail(this.requireNumber(args, 'vote_id'));
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

  private requireNumber(args: Record<string, unknown>, key: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a finite number.`);
    }
    return v;
  }

  private buildParams(args: Record<string, unknown>): URLSearchParams {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (k.startsWith('_') || v == null) continue;
      if (typeof v === 'boolean') {
        params.set(k, v ? 'true' : 'false');
      } else {
        params.set(k, String(v));
      }
    }
    if (!params.has('limit')) params.set('limit', '20');
    return params;
  }

  private async gtFetch(path: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'GovTrack: not found (HTTP 404)' }],
        isError: true,
      };
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

  private async listAt(args: Record<string, unknown>, path: string): Promise<ToolResult> {
    const params = this.buildParams(args);
    const qs = params.toString();
    return this.gtFetch(`${path}${qs ? `?${qs}` : ''}`);
  }

  private async getAt(id: number, path: string): Promise<ToolResult> {
    return this.gtFetch(`${path}/${id}`);
  }

  private async getVoteDetail(voteId: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/vote/${voteId}/details`,
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
      },
    );
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'GovTrack: vote not found (HTTP 404)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const raw = (await response.json()) as {
      id?: number;
      voters?: {
        person?: { id?: number; name?: string; party?: string; state?: string };
        option?: { value?: string; key?: string };
        created?: string;
      }[];
    };
    const result = {
      vote_id: raw.id ?? voteId,
      voter_count: raw.voters?.length ?? 0,
      voters: (raw.voters ?? []).map((v) => ({
        person_id: v.person?.id ?? null,
        name: v.person?.name ?? null,
        party: v.person?.party ?? null,
        state: v.person?.state ?? null,
        vote: v.option?.value ?? v.option?.key ?? null,
        created: v.created ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
