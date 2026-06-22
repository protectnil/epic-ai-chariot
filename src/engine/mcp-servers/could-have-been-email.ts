/**
 * Could Have Been Email MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: StupidAPIs — https://api.stupidapis.com/could-have-been-email/analyze
// Auth: X-API-Key header (required)
// Category: productivity
// Docs: https://stupidapis.com

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface CouldHaveBeenEmailConfig {
  apiKey: string;
  baseUrl?: string;
}

export class CouldHaveBeenEmailMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: CouldHaveBeenEmailConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Could Have Been Email: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Could Have Been Email: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com';
  }

  static catalog() {
    return {
      name: 'could-have-been-email',
      displayName: 'Could Have Been Email',
      version: '1.0.0',
      category: 'productivity',
      keywords: [
        'meeting', 'email', 'productivity', 'transcript', 'analysis',
        'filler words', 'action items', 'decisions', 'meeting analysis',
        'could have been email', 'meeting efficiency',
      ],
      toolNames: ['could_have_been_email_analyze'],
      description: 'Could Have Been Email: analyze a meeting transcript to determine if it could have been an email, counting filler words, decisions, and action items, and generating the email that should have been sent instead.',
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
        name: 'could_have_been_email_analyze',
        description: 'Analyze a meeting transcript to determine if it could have been an email. Counts filler words, decisions, action items, and generates the email that should have been sent instead.',
        inputSchema: {
          type: 'object',
          properties: {
            transcript: {
              type: 'string',
              description: 'Meeting transcript or summary',
            },
            duration: {
              type: 'number',
              description: 'Meeting duration in minutes',
            },
            attendee_count: {
              type: 'number',
              description: 'Number of attendees',
            },
            recurring: {
              type: 'boolean',
              description: 'Is this a recurring meeting',
            },
          },
          required: ['transcript'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'could_have_been_email_analyze':
          return this.analyzeTranscript(args);
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

  private async analyzeTranscript(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const path = '/could-have-been-email/analyze';
    const qs = params.toString();
    const url = `${this.baseUrl}${path}${qs ? '?' + qs : ''}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'X-API-Key': this.apiKey,
        Accept: 'application/json',
      },
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
}
