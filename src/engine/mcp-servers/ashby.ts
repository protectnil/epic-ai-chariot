/**
 * Ashby ATS MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.ashbyhq.com
// Auth: HTTP Basic — apiKey as username, empty password (Base64-encoded "apiKey:")
// All endpoints: POST with JSON body
// Docs: https://developers.ashbyhq.com/reference/introduction
// Category: crm

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AshbyConfig {
  apiKey: string;
  baseUrl?: string;
}

export class AshbyMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AshbyConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Ashby ATS: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Ashby ATS: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.ashbyhq.com';
  }

  static catalog() {
    return {
      name: 'ashby',
      displayName: 'Ashby ATS',
      version: '1.0.0',
      category: 'crm' as const,
      keywords: [
        'ashby', 'ats', 'applicant tracking', 'recruiting', 'hiring', 'candidates',
        'jobs', 'applications', 'hr', 'talent acquisition', 'recruitment',
        'job postings', 'pipeline', 'interview',
      ],
      toolNames: [
        'list_candidates',
        'get_candidate',
        'list_jobs',
        'get_job',
        'list_applications',
      ],
      description: 'Ashby ATS: list and retrieve candidates, jobs, and applications from your Ashby applicant tracking system.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'list_candidates',
        description: 'List candidates from Ashby. Returns candidate names, emails, and metadata. Supports pagination via cursor.',
        inputSchema: {
          type: 'object',
          properties: {
            cursor: {
              type: 'string',
              description: 'Pagination cursor from a previous response',
            },
            per_page: {
              type: 'number',
              description: 'Number of candidates per page (default 50)',
            },
          },
        },
      },
      {
        name: 'get_candidate',
        description: 'Get details for a specific candidate by their ID. Returns full candidate profile.',
        inputSchema: {
          type: 'object',
          properties: {
            candidateId: {
              type: 'string',
              description: 'Ashby candidate ID',
            },
          },
          required: ['candidateId'],
        },
      },
      {
        name: 'list_jobs',
        description: 'List jobs from Ashby. Optionally filter by status: Open, Closed, Draft, or Archived.',
        inputSchema: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              description: 'Filter by job status: Open, Closed, Draft, Archived',
            },
          },
        },
      },
      {
        name: 'get_job',
        description: 'Get details for a specific job by its ID. Returns full job posting information.',
        inputSchema: {
          type: 'object',
          properties: {
            jobId: {
              type: 'string',
              description: 'Ashby job ID',
            },
          },
          required: ['jobId'],
        },
      },
      {
        name: 'list_applications',
        description: 'List job applications from Ashby. Returns application details including candidate and job info. Supports pagination via cursor.',
        inputSchema: {
          type: 'object',
          properties: {
            cursor: {
              type: 'string',
              description: 'Pagination cursor from a previous response',
            },
            per_page: {
              type: 'number',
              description: 'Number of applications per page (default 50)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_candidates':   return this.listCandidates(args);
        case 'get_candidate':     return this.getCandidate(args);
        case 'list_jobs':         return this.listJobs(args);
        case 'get_job':           return this.getJob(args);
        case 'list_applications': return this.listApplications(args);
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

  private authHeaders(): Record<string, string> {
    const encoded = Buffer.from(`${this.apiKey}:`).toString('base64');
    return {
      Authorization: `Basic ${encoded}`,
      'Content-Type': 'application/json',
    };
  }

  private async post(path: string, body: Record<string, unknown>): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: this.authHeaders(),
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

  private async listCandidates(args: Record<string, unknown>): Promise<ToolResult> {
    const body: Record<string, unknown> = {};
    if (args.cursor)   body.cursor  = args.cursor;
    if (args.per_page) body.perPage = args.per_page;
    return this.post('/candidate.list', body);
  }

  private async getCandidate(args: Record<string, unknown>): Promise<ToolResult> {
    return this.post('/candidate.info', { candidateId: args.candidateId as string });
  }

  private async listJobs(args: Record<string, unknown>): Promise<ToolResult> {
    const body: Record<string, unknown> = {};
    if (args.status) body.status = args.status;
    return this.post('/job.list', body);
  }

  private async getJob(args: Record<string, unknown>): Promise<ToolResult> {
    return this.post('/job.info', { jobId: args.jobId as string });
  }

  private async listApplications(args: Record<string, unknown>): Promise<ToolResult> {
    const body: Record<string, unknown> = {};
    if (args.cursor)   body.cursor  = args.cursor;
    if (args.per_page) body.perPage = args.per_page;
    return this.post('/application.list', body);
  }
}
