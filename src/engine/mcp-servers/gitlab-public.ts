/**
 * GitLab Public MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://gitlab.com/api/v4
// Auth: None (public endpoints, no authentication required)
// Docs: https://docs.gitlab.com/ee/api/rest/
// Category: developer-tools
// Rate limits: Unauthenticated: 500 requests per minute per IP

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://gitlab.com/api/v4';

export class GitLabPublicMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'gitlab-public',
      displayName: 'GitLab Public API',
      version: '1.0.0',
      category: 'developer-tools' as const,
      keywords: [
        'gitlab', 'git', 'repository', 'repo', 'source code', 'version control',
        'issues', 'projects', 'open source', 'code search', 'merge requests',
        'ci/cd', 'devops', 'code hosting', 'scm',
      ],
      toolNames: ['search_projects', 'get_project', 'search_issues'],
      description: 'GitLab Public API: search public GitLab projects by keyword, retrieve full project details by ID or path, and search issues across all public projects — no authentication required.',
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
        name: 'search_projects',
        description:
          'Search public GitLab projects by keyword, ordered by star count. Returns project ID, name, description, stars, forks, open issues count, and web URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default 10, max 100)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_project',
        description:
          'Get a public GitLab project by numeric ID or URL-encoded path (e.g., "gitlab-org%2Fgitlab"). Returns full project details including name, description, stars, forks, default branch, topics, and activity dates.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Project numeric ID or URL-encoded path (e.g., "gitlab-org%2Fgitlab")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_issues',
        description:
          'Search issues across all public GitLab projects. Returns issue title, state, author, labels, project ID, and URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query for issue titles and descriptions',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (default 10, max 100)',
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
        case 'search_projects':
          return this.searchProjects(args.query as string, (args.limit as number) ?? 10);
        case 'get_project':
          return this.getProject(args.id as string);
        case 'search_issues':
          return this.searchIssues(args.query as string, (args.limit as number) ?? 10);
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

  private async gitlabGet(path: string, params?: Record<string, string>): Promise<Response> {
    const qs = params ? `?${new URLSearchParams(params).toString()}` : '';
    const url = `${BASE_URL}${path}${qs}`;
    return this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
  }

  private async searchProjects(query: string, limit: number): Promise<ToolResult> {
    const perPage = Math.min(100, Math.max(1, limit));
    const response = await this.gitlabGet('/projects', {
      search: query,
      per_page: String(perPage),
      order_by: 'stars_count',
      sort: 'desc',
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `GitLab API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      id: number;
      name: string;
      path_with_namespace: string;
      description: string | null;
      star_count: number;
      forks_count: number;
      open_issues_count: number;
      web_url: string;
      default_branch: string;
      visibility: string;
      last_activity_at: string;
    }[];

    const result = {
      projects: data.map((p) => ({
        id: p.id,
        name: p.name,
        full_path: p.path_with_namespace,
        description: p.description ?? null,
        stars: p.star_count,
        forks: p.forks_count,
        open_issues: p.open_issues_count,
        url: p.web_url,
        default_branch: p.default_branch,
        visibility: p.visibility,
        last_activity: p.last_activity_at,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getProject(id: string): Promise<ToolResult> {
    const response = await this.gitlabGet(`/projects/${encodeURIComponent(id)}`);
    if (!response.ok) {
      if (response.status === 404) {
        return { content: [{ type: 'text', text: `Not found: project "${id}"` }], isError: true };
      }
      if (response.status === 401 || response.status === 403) {
        return { content: [{ type: 'text', text: 'Project is private or requires authentication.' }], isError: true };
      }
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `GitLab API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      id: number;
      name: string;
      path_with_namespace: string;
      description: string | null;
      web_url: string;
      star_count: number;
      forks_count: number;
      open_issues_count: number;
      default_branch: string;
      visibility: string;
      archived: boolean;
      topics: string[];
      namespace: { full_path: string };
      created_at: string;
      last_activity_at: string;
    };

    const result = {
      id: data.id,
      name: data.name,
      full_path: data.path_with_namespace,
      description: data.description ?? null,
      url: data.web_url,
      stars: data.star_count,
      forks: data.forks_count,
      open_issues: data.open_issues_count,
      default_branch: data.default_branch,
      visibility: data.visibility,
      archived: data.archived,
      topics: data.topics ?? [],
      namespace: data.namespace?.full_path ?? null,
      created_at: data.created_at,
      last_activity: data.last_activity_at,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchIssues(query: string, limit: number): Promise<ToolResult> {
    const perPage = Math.min(100, Math.max(1, limit));
    const response = await this.gitlabGet('/issues', {
      search: query,
      scope: 'all',
      per_page: String(perPage),
      order_by: 'updated_at',
      sort: 'desc',
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `GitLab API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      iid: number;
      id: number;
      title: string;
      state: string;
      labels: string[];
      author: { username: string } | null;
      assignee: { username: string } | null;
      project_id: number;
      web_url: string;
      created_at: string;
      updated_at: string;
    }[];

    const result = {
      issues: data.map((i) => ({
        id: i.id,
        iid: i.iid,
        title: i.title,
        state: i.state,
        labels: i.labels,
        author: i.author?.username ?? null,
        assignee: i.assignee?.username ?? null,
        project_id: i.project_id,
        url: i.web_url,
        created_at: i.created_at,
        updated_at: i.updated_at,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
