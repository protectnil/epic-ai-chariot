/**
 * Maven Central MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://search.maven.org/solrsearch/select
// Auth: none (public Solr endpoint)
// API docs: https://central.sonatype.org/search/rest-api-guide/
// Category: developer-tools

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://search.maven.org/solrsearch/select';

export class MavenCentralMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'maven-central',
      displayName: 'Maven Central',
      version: '1.0.0',
      category: 'developer-tools',
      keywords: [
        'maven', 'maven central', 'java', 'jvm', 'artifact', 'dependency',
        'groupId', 'artifactId', 'jar', 'pom', 'gradle', 'sonatype',
        'package registry', 'library', 'open source', 'jvm ecosystem',
      ],
      toolNames: ['search', 'search_by_coords', 'list_versions', 'latest_version'],
      description: 'Maven Central: full-text and coordinate-based search of the Java/JVM artifact registry — find artifacts, browse versions, and resolve latest releases.',
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
        name: 'search',
        description: 'Full-text search across groupId, artifactId, version, and tags in Maven Central.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text query (e.g. "spring-core" or "log4j")',
            },
            rows: {
              type: 'number',
              description: 'Max results to return, 1–200 (default 20)',
            },
            start: {
              type: 'number',
              description: '0-based offset for pagination (default 0)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_by_coords',
        description: 'Structured lookup by Maven coordinates. Provide any combination of groupId / artifactId / version.',
        inputSchema: {
          type: 'object',
          properties: {
            group_id: {
              type: 'string',
              description: 'groupId — e.g. "org.springframework"',
            },
            artifact_id: {
              type: 'string',
              description: 'artifactId — e.g. "spring-core"',
            },
            version: {
              type: 'string',
              description: 'version — e.g. "6.1.0"',
            },
            rows: {
              type: 'number',
              description: '1–200 (default 20)',
            },
            start: {
              type: 'number',
              description: '0-based offset (default 0)',
            },
          },
        },
      },
      {
        name: 'list_versions',
        description: 'List all published versions for a given (groupId, artifactId) pair.',
        inputSchema: {
          type: 'object',
          properties: {
            group_id: {
              type: 'string',
              description: 'groupId — e.g. "org.springframework"',
            },
            artifact_id: {
              type: 'string',
              description: 'artifactId — e.g. "spring-core"',
            },
            rows: {
              type: 'number',
              description: '1–200 (default 200)',
            },
          },
          required: ['group_id', 'artifact_id'],
        },
      },
      {
        name: 'latest_version',
        description: 'Resolve the most recent release version for a given (groupId, artifactId) pair.',
        inputSchema: {
          type: 'object',
          properties: {
            group_id: {
              type: 'string',
              description: 'groupId — e.g. "org.springframework"',
            },
            artifact_id: {
              type: 'string',
              description: 'artifactId — e.g. "spring-core"',
            },
          },
          required: ['group_id', 'artifact_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':          return this.search(args);
        case 'search_by_coords': return this.searchByCoords(args);
        case 'list_versions':   return this.listVersions(args);
        case 'latest_version':  return this.latestVersion(args);
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

  private async solrFetch(params: URLSearchParams): Promise<ToolResult> {
    const url = `${BASE_URL}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epic-ai-chariot/1.0',
      },
    });
    if (response.status === 429) {
      return { content: [{ type: 'text', text: 'Maven Central: rate-limit (HTTP 429). Retry after a moment.' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Maven Central error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "query" is missing or empty.' }], isError: true };
    }
    const rows = Math.min(200, Math.max(1, typeof args.rows === 'number' ? args.rows : 20));
    const start = Math.max(0, typeof args.start === 'number' ? args.start : 0);
    const params = new URLSearchParams({
      q: query,
      rows: String(rows),
      start: String(start),
      wt: 'json',
    });
    return this.solrFetch(params);
  }

  private async searchByCoords(args: Record<string, unknown>): Promise<ToolResult> {
    const parts: string[] = [];
    if (typeof args.group_id === 'string' && args.group_id.trim()) {
      parts.push(`g:${this.quoteCoord(args.group_id)}`);
    }
    if (typeof args.artifact_id === 'string' && args.artifact_id.trim()) {
      parts.push(`a:${this.quoteCoord(args.artifact_id)}`);
    }
    if (typeof args.version === 'string' && args.version.trim()) {
      parts.push(`v:${this.quoteCoord(args.version)}`);
    }
    if (parts.length === 0) {
      return {
        content: [{ type: 'text', text: 'Provide at least one of group_id / artifact_id / version.' }],
        isError: true,
      };
    }
    const rows = Math.min(200, Math.max(1, typeof args.rows === 'number' ? args.rows : 20));
    const start = Math.max(0, typeof args.start === 'number' ? args.start : 0);
    const params = new URLSearchParams({
      q: parts.join(' AND '),
      rows: String(rows),
      start: String(start),
      wt: 'json',
    });
    return this.solrFetch(params);
  }

  private async listVersions(args: Record<string, unknown>): Promise<ToolResult> {
    const g = this.requireString(args, 'group_id');
    if (g === null) return { content: [{ type: 'text', text: 'Required argument "group_id" is missing.' }], isError: true };
    const a = this.requireString(args, 'artifact_id');
    if (a === null) return { content: [{ type: 'text', text: 'Required argument "artifact_id" is missing.' }], isError: true };

    const rows = Math.min(200, Math.max(1, typeof args.rows === 'number' ? args.rows : 200));
    const params = new URLSearchParams({
      q: `g:${this.quoteCoord(g)} AND a:${this.quoteCoord(a)}`,
      core: 'gav',
      rows: String(rows),
      wt: 'json',
    });
    const response = await this.fetchWithRetry(`${BASE_URL}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Maven Central error: ${response.status} ${errText.slice(0, 200)}` }], isError: true };
    }
    const raw = await response.json() as {
      response?: { docs?: { v?: string; timestamp?: number }[] };
    };
    const docs = raw.response?.docs ?? [];
    const result = {
      group_id: g,
      artifact_id: a,
      count: docs.length,
      versions: docs.map((d) => ({
        version: d.v,
        released: d.timestamp ? new Date(d.timestamp).toISOString() : null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async latestVersion(args: Record<string, unknown>): Promise<ToolResult> {
    const g = this.requireString(args, 'group_id');
    if (g === null) return { content: [{ type: 'text', text: 'Required argument "group_id" is missing.' }], isError: true };
    const a = this.requireString(args, 'artifact_id');
    if (a === null) return { content: [{ type: 'text', text: 'Required argument "artifact_id" is missing.' }], isError: true };

    const params = new URLSearchParams({
      q: `g:${this.quoteCoord(g)} AND a:${this.quoteCoord(a)}`,
      rows: '1',
      wt: 'json',
    });
    const response = await this.fetchWithRetry(`${BASE_URL}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `Maven Central error: ${response.status} ${errText.slice(0, 200)}` }], isError: true };
    }
    const raw = await response.json() as {
      response?: { docs?: { g?: string; a?: string; latestVersion?: string; v?: string }[] };
    };
    const doc = raw.response?.docs?.[0];
    if (!doc) {
      return { content: [{ type: 'text', text: `Maven Central: no artifact found for ${g}:${a}` }], isError: true };
    }
    const result = {
      group_id: g,
      artifact_id: a,
      latest_version: doc.latestVersion ?? doc.v,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  /** Quote a Maven coordinate value for Solr: wrap in quotes if it contains special chars. */
  private quoteCoord(s: string): string {
    return /^[a-zA-Z0-9._-]+$/.test(s) ? s : `"${s.replace(/"/g, '\\"')}"`;
  }

  /** Return the string value for a required key, or null if absent/empty. */
  private requireString(args: Record<string, unknown>, key: string): string | null {
    const v = args[key];
    if (typeof v === 'string' && v.trim()) return v;
    return null;
  }
}
