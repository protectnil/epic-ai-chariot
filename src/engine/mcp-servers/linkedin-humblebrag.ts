/**
 * LinkedIn Humblebrag MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: StupidAPIs LinkedIn Humblebrag
// Base URL: https://api.stupidapis.com/linkedin-humblebrag
// Auth: X-API-Key header
// Docs: https://stupidapis.com
// Category: social
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface LinkedInHumlebragConfig {
  apiKey: string;
  baseUrl?: string;
}

export class LinkedInHumlebragMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: LinkedInHumlebragConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('LinkedIn Humblebrag: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('LinkedIn Humblebrag: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/linkedin-humblebrag';
  }

  static catalog() {
    return {
      name: 'linkedin-humblebrag',
      displayName: 'LinkedIn Humblebrag',
      version: '1.0.0',
      category: 'social' as const,
      keywords: [
        'linkedin', 'humblebrag', 'post', 'achievement', 'social media',
        'content generation', 'professional', 'networking', 'ai writing',
        'inspiration', 'vulnerability', 'grateful',
      ],
      toolNames: ['linkedin_humblebrag_generate'],
      description: 'LinkedIn Humblebrag: transform any achievement into a LinkedIn post with gratitude, vulnerability, or inspirational spin.',
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
        name: 'linkedin_humblebrag_generate',
        description: 'Transform any achievement into a LinkedIn post. Vulnerability included. Dave will be mentioned.',
        inputSchema: {
          type: 'object',
          properties: {
            achievement: {
              type: 'string',
              description: 'Your achievement',
            },
            spin: {
              type: 'string',
              enum: ['grateful', 'vulnerable', 'inspirational', 'all_three'],
              description: 'The emotional spin to apply to the post',
            },
            include_lesson: {
              type: 'boolean',
              description: 'Add a universal lesson for strangers',
            },
          },
          required: ['achievement'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'linkedin_humblebrag_generate': return this.generate(args);
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

  private async generate(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const query = params.toString();
    const url = `${this.baseUrl}/generate${query ? '?' + query : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-API-Key': this.apiKey,
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
