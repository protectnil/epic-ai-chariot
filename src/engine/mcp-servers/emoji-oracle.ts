/**
 * Emoji Oracle MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: StupidAPIs Emoji Oracle
// Base URL: https://api.stupidapis.com/emoji-oracle
// Auth: X-API-Key header (api-key)
// Docs: https://stupidapis.com
// Category: entertainment

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface EmojiOracleConfig {
  apiKey: string;
  baseUrl?: string;
}

export class EmojiOracleMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: EmojiOracleConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Emoji Oracle: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Emoji Oracle: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/emoji-oracle';
  }

  static catalog() {
    return {
      name: 'emoji-oracle',
      displayName: 'Emoji Oracle',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'emoji', 'oracle', 'prophecy', 'fortune', 'fun',
        'mystical', 'interpretation', 'vibe', 'divination',
        'humor', 'novelty', 'question', 'answer',
      ],
      toolNames: ['emoji_oracle_consult'],
      description: 'Emoji Oracle: ask any question and receive a cryptic emoji prophecy with a vibe check, optionally with a mystical interpretation.',
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
        name: 'emoji_oracle_consult',
        description: 'Consult the Emoji Oracle. Ask any question and receive a cryptic emoji prophecy with a vibe check. Optionally request an interpretation.',
        inputSchema: {
          type: 'object',
          properties: {
            question: {
              type: 'string',
              description: 'Your question for the Emoji Oracle',
            },
            interpret: {
              type: 'boolean',
              description: 'If true, the Oracle provides a mystical interpretation',
            },
            emoji_count: {
              type: 'number',
              description: 'Number of emojis (1-5, default 3)',
            },
          },
          required: ['question'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'emoji_oracle_consult': return this.consult(args);
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

  private async consult(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const qs = params.toString();
    const url = `${this.baseUrl}/consult${qs ? '?' + qs : ''}`;
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
