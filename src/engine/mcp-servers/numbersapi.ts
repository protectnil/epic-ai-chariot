/**
 * Numbers API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: http://numbersapi.com
// Auth: none (public, no key required)
// Docs: http://numbersapi.com
// Category: education
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'http://numbersapi.com';

interface NumbersApiResponse {
  text: string;
  number: number | string;
  found: boolean;
  type: string;
}

export class NumbersAPIMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NumbersAPIMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'numbersapi',
      displayName: 'Numbers API',
      version: '1.0.0',
      category: 'education',
      keywords: [
        'numbers', 'trivia', 'math', 'facts', 'date', 'calendar',
        'number facts', 'math facts', 'random number', 'fun facts', 'education',
      ],
      toolNames: ['number_fact', 'date_fact', 'math_fact', 'random_fact'],
      description: 'Numbers API: retrieve trivia, math, and date facts about numbers — free and unauthenticated.',
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
        name: 'number_fact',
        description: 'Get an interesting trivia fact about a specific number.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'number',
              description: 'The number to get a fact about (e.g., 42)',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'date_fact',
        description: 'Get an interesting fact about a specific calendar date.',
        inputSchema: {
          type: 'object',
          properties: {
            month: {
              type: 'number',
              description: 'Month number (1-12)',
            },
            day: {
              type: 'number',
              description: 'Day number (1-31)',
            },
          },
          required: ['month', 'day'],
        },
      },
      {
        name: 'math_fact',
        description: 'Get a mathematical fact about a specific number.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'number',
              description: 'The number to get a mathematical fact about (e.g., 1729)',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'random_fact',
        description: 'Get a trivia fact about a randomly chosen number.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'number_fact': return this.numberFact(args.number as number);
        case 'date_fact':   return this.dateFact(args.month as number, args.day as number);
        case 'math_fact':   return this.mathFact(args.number as number);
        case 'random_fact': return this.randomFact();
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

  private async numberFact(number: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/${encodeURIComponent(String(number))}?json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as NumbersApiResponse;
    return {
      content: [{ type: 'text', text: this.truncate({ number: data.number, fact: data.text, type: data.type, found: data.found }) }],
      isError: false,
    };
  }

  private async dateFact(month: number, day: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/${encodeURIComponent(String(month))}/${encodeURIComponent(String(day))}/date?json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as NumbersApiResponse;
    return {
      content: [{ type: 'text', text: this.truncate({ date: `${month}/${day}`, fact: data.text, type: data.type, found: data.found }) }],
      isError: false,
    };
  }

  private async mathFact(number: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/${encodeURIComponent(String(number))}/math?json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as NumbersApiResponse;
    return {
      content: [{ type: 'text', text: this.truncate({ number: data.number, fact: data.text, type: data.type, found: data.found }) }],
      isError: false,
    };
  }

  private async randomFact(): Promise<ToolResult> {
    const url = `${this.baseUrl}/random?json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as NumbersApiResponse;
    return {
      content: [{ type: 'text', text: this.truncate({ number: data.number, fact: data.text, type: data.type, found: data.found }) }],
      isError: false,
    };
  }
}
