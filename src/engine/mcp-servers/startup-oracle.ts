/**
 * Startup Oracle MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/startup-oracle
// Auth: X-API-Key header (api-key)
// Docs: https://stupidapis.com
// Category: business
// Rate limits: depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface StartupOracleConfig {
  apiKey: string;
  baseUrl?: string;
}

export class StartupOracleMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: StartupOracleConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Startup Oracle: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Startup Oracle: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/startup-oracle';
  }

  static catalog() {
    return {
      name: 'startup-oracle',
      displayName: 'Startup Oracle',
      version: '1.0.0',
      category: 'business',
      keywords: [
        'startup', 'startup idea', 'evaluate', 'startup evaluation',
        'pivot', 'yc', 'y combinator', 'rejection', 'tam', 'venture capital',
        'pitch', 'founder', 'entrepreneurship', 'idea validation',
      ],
      toolNames: ['startup_oracle_evaluate'],
      description: 'Startup Oracle: evaluate a startup idea and receive a brutal verdict, pivot count, funny comparable, realistic YC rejection reason, and TAM estimate.',
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
        name: 'startup_oracle_evaluate',
        description: 'Evaluate a startup idea. Returns a brutal verdict, number of pivots required, a funny comparable, a realistic YC rejection reason, and the actual TAM.',
        inputSchema: {
          type: 'object',
          properties: {
            idea: {
              type: 'string',
              description: 'Your startup idea',
            },
            have_you_talked_to_users: {
              type: 'boolean',
              description: 'Have you actually talked to users?',
            },
            is_it_uber_for: {
              type: 'boolean',
              description: 'Is this an "Uber for X" idea?',
            },
            vc_buzzword_count: {
              type: 'number',
              description: 'Number of VC buzzwords in your pitch',
            },
          },
          required: ['idea'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'startup_oracle_evaluate': return this.evaluate(args);
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

  private async evaluate(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const qs = params.toString();
    const url = `${this.baseUrl}/evaluate${qs ? '?' + qs : ''}`;
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
