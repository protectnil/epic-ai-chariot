/**
 * Codeforces MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://codeforces.com/api
// Auth: none — all endpoints used here are public read-only.
// Docs: https://codeforces.com/apiHelp
// Category: developer-tools

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://codeforces.com/api';

export class CodeforcesMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CodeforcesMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'codeforces',
      displayName: 'Codeforces',
      version: '1.0.0',
      category: 'developer-tools',
      keywords: [
        'codeforces', 'competitive programming', 'programming contests',
        'algorithm', 'data structures', 'problemset', 'user rating',
        'contest standings', 'submissions', 'blog', 'gym', 'cp',
      ],
      toolNames: [
        'user',
        'user_rating',
        'user_status',
        'contest_list',
        'contest_standings',
        'problemset',
        'recent_actions',
        'blog_entry_view',
      ],
      description: 'Codeforces public API: look up user profiles, rating history, submissions, contest standings, problemsets, and blog entries on the Codeforces competitive-programming platform.',
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
        name: 'user',
        description: 'Fetch public profile data for one or more Codeforces users (up to 10,000 handles).',
        inputSchema: {
          type: 'object',
          properties: {
            handles: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of Codeforces handles (1–10,000). Example: ["tourist", "Petr"].',
            },
          },
          required: ['handles'],
        },
      },
      {
        name: 'user_rating',
        description: 'Full rating-change history for a Codeforces user.',
        inputSchema: {
          type: 'object',
          properties: {
            handle: { type: 'string', description: 'Codeforces handle, e.g. "tourist".' },
          },
          required: ['handle'],
        },
      },
      {
        name: 'user_status',
        description: 'Recent submissions (verdicts) for a Codeforces user.',
        inputSchema: {
          type: 'object',
          properties: {
            handle: { type: 'string', description: 'Codeforces handle.' },
            from: { type: 'number', description: '1-based starting index (default 1).' },
            count: { type: 'number', description: 'Number of submissions to return, 1–10,000 (default 50).' },
          },
          required: ['handle'],
        },
      },
      {
        name: 'contest_list',
        description: 'List all Codeforces contests. Set gym=true to list gym (training) contests instead.',
        inputSchema: {
          type: 'object',
          properties: {
            gym: { type: 'boolean', description: 'If true, return gym contests; otherwise return regular contests.' },
          },
        },
      },
      {
        name: 'contest_standings',
        description: 'Standings and problem list for a Codeforces contest. Optionally filter to a subset of handles.',
        inputSchema: {
          type: 'object',
          properties: {
            contest_id: { type: 'number', description: 'Numeric Codeforces contest ID.' },
            from: { type: 'number', description: '1-based starting rank (default 1).' },
            count: { type: 'number', description: 'Number of rows to return, 1–1,000 (default 100).' },
            handles: {
              type: 'array',
              items: { type: 'string' },
              description: 'Optional list of handles to filter standings to.',
            },
          },
          required: ['contest_id'],
        },
      },
      {
        name: 'problemset',
        description: 'Retrieve the Codeforces problemset with per-problem submission statistics. Optionally filter by tags.',
        inputSchema: {
          type: 'object',
          properties: {
            tags: {
              type: 'array',
              items: { type: 'string' },
              description: 'Filter problems by tags, e.g. ["dp", "graphs"]. Multiple tags are ANDed.',
            },
            problemset_name: {
              type: 'string',
              description: 'Name of a custom problemset (rarely used; omit for the default global set).',
            },
          },
        },
      },
      {
        name: 'recent_actions',
        description: 'Global recent-actions feed on Codeforces (blog posts, comments, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            max_count: { type: 'number', description: 'Maximum actions to return, 1–100 (default 30).' },
          },
        },
      },
      {
        name: 'blog_entry_view',
        description: 'Retrieve a full Codeforces blog entry by its numeric ID.',
        inputSchema: {
          type: 'object',
          properties: {
            blog_id: { type: 'number', description: 'Numeric blog-entry ID.' },
          },
          required: ['blog_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'user':           return this.getUser(args);
        case 'user_rating':    return this.getUserRating(args);
        case 'user_status':    return this.getUserStatus(args);
        case 'contest_list':   return this.getContestList(args);
        case 'contest_standings': return this.getContestStandings(args);
        case 'problemset':     return this.getProblemset(args);
        case 'recent_actions': return this.getRecentActions(args);
        case 'blog_entry_view': return this.getBlogEntryView(args);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async cfRequest(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Codeforces API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as { status?: string; comment?: string; result?: unknown };
    if (data.status === 'FAILED') {
      return {
        content: [{ type: 'text', text: `Codeforces request failed: ${data.comment ?? 'unknown error'}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" must be a non-empty string.`);
    }
    return v.trim();
  }

  private requireStringArray(args: Record<string, unknown>, key: string): string[] {
    const v = args[key];
    if (!Array.isArray(v) || v.length === 0) {
      throw new Error(`Required argument "${key}" must be a non-empty array of strings.`);
    }
    return (v as unknown[]).filter((s): s is string => typeof s === 'string');
  }

  private async getUser(args: Record<string, unknown>): Promise<ToolResult> {
    const handles = this.requireStringArray(args, 'handles').slice(0, 10_000).join(';');
    return this.cfRequest(`/user.info?handles=${encodeURIComponent(handles)}`);
  }

  private async getUserRating(args: Record<string, unknown>): Promise<ToolResult> {
    const handle = this.requireString(args, 'handle');
    return this.cfRequest(`/user.rating?handle=${encodeURIComponent(handle)}`);
  }

  private async getUserStatus(args: Record<string, unknown>): Promise<ToolResult> {
    const handle = this.requireString(args, 'handle');
    const from = Math.max(1, typeof args.from === 'number' ? args.from : 1);
    const count = Math.min(10_000, Math.max(1, typeof args.count === 'number' ? args.count : 50));
    const params = new URLSearchParams({
      handle,
      from: String(from),
      count: String(count),
    });
    return this.cfRequest(`/user.status?${params.toString()}`);
  }

  private async getContestList(args: Record<string, unknown>): Promise<ToolResult> {
    const gym = args.gym === true;
    return this.cfRequest(`/contest.list?gym=${gym ? 'true' : 'false'}`);
  }

  private async getContestStandings(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.contest_id !== 'number') {
      throw new Error('Required argument "contest_id" must be a number.');
    }
    const params = new URLSearchParams({
      contestId: String(Math.trunc(args.contest_id)),
      from: String(Math.max(1, typeof args.from === 'number' ? args.from : 1)),
      count: String(Math.min(1_000, Math.max(1, typeof args.count === 'number' ? args.count : 100))),
    });
    if (Array.isArray(args.handles) && args.handles.length > 0) {
      const filtered = (args.handles as unknown[]).filter((s): s is string => typeof s === 'string');
      if (filtered.length > 0) params.set('handles', filtered.join(';'));
    }
    return this.cfRequest(`/contest.standings?${params.toString()}`);
  }

  private async getProblemset(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (Array.isArray(args.tags) && args.tags.length > 0) {
      const filtered = (args.tags as unknown[]).filter((s): s is string => typeof s === 'string');
      if (filtered.length > 0) params.set('tags', filtered.join(';'));
    }
    if (typeof args.problemset_name === 'string' && args.problemset_name.trim()) {
      params.set('problemsetName', args.problemset_name.trim());
    }
    const qs = params.toString();
    return this.cfRequest(`/problemset.problems${qs ? `?${qs}` : ''}`);
  }

  private async getRecentActions(args: Record<string, unknown>): Promise<ToolResult> {
    const maxCount = Math.min(100, Math.max(1, typeof args.max_count === 'number' ? args.max_count : 30));
    return this.cfRequest(`/recentActions?maxCount=${maxCount}`);
  }

  private async getBlogEntryView(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.blog_id !== 'number') {
      throw new Error('Required argument "blog_id" must be a number.');
    }
    return this.cfRequest(`/blogEntry.view?blogEntryId=${Math.trunc(args.blog_id)}`);
  }
}
