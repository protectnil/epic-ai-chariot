/**
 * Performance Review MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://api.stupidapis.com/performance-review
// Base URL: https://api.stupidapis.com
// Auth: X-API-Key header (api-key)
// Docs: https://stupidapis.com
// Category: productivity
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface PerformanceReviewConfig {
  apiKey: string;
  baseUrl?: string;
}

export class PerformanceReviewMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: PerformanceReviewConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Performance Review: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Performance Review: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com';
  }

  static catalog() {
    return {
      name: 'performance-review',
      displayName: 'Performance Review Generator',
      version: '1.0.0',
      category: 'productivity' as const,
      keywords: [
        'performance review', 'hr', 'human resources', 'employee', 'review',
        'feedback', 'evaluation', 'rating', 'workplace', 'manager',
        'corporate', 'annual review', 'performance',
      ],
      toolNames: ['performance_review_generate'],
      description: 'Performance Review Generator: generate HR-approved performance reviews for employees — API key required.',
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
        name: 'performance_review_generate',
        description: 'Generate a performance review that communicates nothing clearly. HR approved.',
        inputSchema: {
          type: 'object',
          properties: {
            employee_name: {
              type: 'string',
              description: 'The name of the employee being reviewed.',
            },
            role: {
              type: 'string',
              description: 'The role or job title of the employee.',
            },
            rating: {
              type: 'string',
              enum: ['rockstar', 'solid', 'developing', 'not_a_culture_fit'],
              description: 'Performance rating for the employee.',
            },
            actual_performance: {
              type: 'string',
              description: 'Description of the employee\'s actual performance.',
            },
            what_manager_wants_to_say: {
              type: 'string',
              description: 'What the manager actually wants to communicate (will be obscured in HR-speak).',
            },
          },
          required: ['employee_name'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'performance_review_generate':
          return this.generateReview(args);
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

  private async generateReview(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const qs = params.toString();
    const url = `${this.baseUrl}/performance-review/generate${qs ? '?' + qs : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
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
