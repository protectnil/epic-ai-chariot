/**
 * Jargon Translator MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/jargon-translator
// Auth: API key header (X-API-Key)
// Docs: https://stupidapis.com
// Category: entertainment
// Rate limits: Depends on plan

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface JargonTranslatorConfig {
  apiKey: string;
  baseUrl?: string;
}

export class JargonTranslatorMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: JargonTranslatorConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Jargon Translator: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Jargon Translator: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com/jargon-translator';
  }

  static catalog() {
    return {
      name: 'jargon-translator',
      displayName: 'Jargon Translator',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'jargon', 'corporate', 'translate', 'translator', 'plain english',
        'business speak', 'buzzwords', 'office jargon', 'corporate speak',
        'formality', 'passive aggressive', 'enthusiastic', 'defeated',
      ],
      toolNames: ['jargon_translator_translate'],
      description: 'Jargon Translator: translate between corporate jargon and plain English, with support for bidirectional translation and formality modes.',
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
        name: 'jargon_translator_translate',
        description: 'Translate between corporate jargon and plain English. Supports bidirectional translation with formality modes: passive_aggressive, enthusiastic, or defeated.',
        inputSchema: {
          type: 'object',
          properties: {
            content: {
              type: 'string',
              description: 'Text to translate',
            },
            direction: {
              type: 'string',
              description: 'Translation direction',
              enum: ['corporate_to_english', 'english_to_corporate'],
            },
            formality: {
              type: 'string',
              description: 'Tone of the translation',
              enum: ['passive_aggressive', 'enthusiastic', 'defeated'],
            },
          },
          required: ['content', 'direction'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'jargon_translator_translate': return this.translate(args);
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

  private async translate(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const url = `${this.baseUrl}/translate?${params.toString()}`;
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
