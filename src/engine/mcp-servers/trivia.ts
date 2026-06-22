/**
 * Open Trivia Database MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://opentdb.com
// Auth: none (public, unauthenticated)
// Docs: https://opentdb.com/api_config.php
// Category: entertainment
// Rate limits: soft limit — wait 5 seconds between bursts; response_code 5 signals throttle

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://opentdb.com';

// HTML entity map for decoding encoded question text returned by the API
const HTML_ENTITIES: Record<string, string> = {
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&#039;': "'",
  '&apos;': "'",
  '&ndash;': '–',
  '&mdash;': '—',
  '&laquo;': '«',
  '&raquo;': '»',
  '&ldquo;': '“',
  '&rdquo;': '”',
  '&lsquo;': '‘',
  '&rsquo;': '’',
  '&hellip;': '…',
  '&deg;': '°',
  '&eacute;': 'é',
  '&egrave;': 'è',
  '&ecirc;': 'ê',
  '&agrave;': 'à',
  '&aacute;': 'á',
  '&ocirc;': 'ô',
  '&ouml;': 'ö',
  '&uuml;': 'ü',
  '&ccedil;': 'ç',
  '&ntilde;': 'ñ',
};

function decodeHtml(text: string): string {
  return text.replace(/&[a-zA-Z0-9#]+;/g, (entity) => {
    if (entity in HTML_ENTITIES) return HTML_ENTITIES[entity]!;
    const numMatch = entity.match(/^&#(\d+);$/);
    if (numMatch) return String.fromCharCode(parseInt(numMatch[1]!, 10));
    const hexMatch = entity.match(/^&#x([0-9a-fA-F]+);$/);
    if (hexMatch) return String.fromCharCode(parseInt(hexMatch[1]!, 16));
    return entity;
  });
}

const RESPONSE_CODE_MESSAGES: Record<number, string> = {
  1: 'No results: not enough questions for the requested parameters',
  2: 'Invalid parameter in request',
  3: 'Session token not found',
  4: 'Session token empty: all questions for this token have been used',
  5: 'Rate limit exceeded: too many requests, please wait 5 seconds',
};

export class TriviaMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('TriviaMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'trivia',
      displayName: 'Open Trivia Database',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'trivia', 'quiz', 'questions', 'categories', 'multiple choice',
        'true false', 'difficulty', 'open trivia', 'opentdb', 'general knowledge',
      ],
      toolNames: ['get_questions', 'list_categories', 'get_category_stats'],
      description: 'Open Trivia Database: fetch trivia questions with optional filters, list all categories, and get per-difficulty question counts for any category — free and unauthenticated.',
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
        name: 'get_questions',
        description:
          'Get trivia questions from the Open Trivia Database. Optionally filter by category, difficulty, and question type.',
        inputSchema: {
          type: 'object',
          properties: {
            amount: {
              type: 'number',
              description: 'Number of questions to return. Defaults to 10. Max 50.',
            },
            category: {
              type: 'number',
              description:
                'Category ID to filter by. Use list_categories to get available IDs.',
            },
            difficulty: {
              type: 'string',
              description: 'Difficulty level. One of: easy, medium, hard.',
            },
            type: {
              type: 'string',
              description:
                'Question type. One of: multiple (multiple choice), boolean (true/false).',
            },
          },
        },
      },
      {
        name: 'list_categories',
        description: 'List all available trivia categories and their IDs.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_category_stats',
        description:
          'Get the total and per-difficulty question counts for a specific category.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'number',
              description: 'Category ID. Use list_categories to get available IDs.',
            },
          },
          required: ['category'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_questions':   return this.getQuestions(args);
        case 'list_categories': return this.listCategories();
        case 'get_category_stats': return this.getCategoryStats(args);
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

  private async getQuestions(args: Record<string, unknown>): Promise<ToolResult> {
    const amount = (args.amount as number | undefined) ?? 10;
    const params = new URLSearchParams({ amount: String(amount) });
    if (args.category !== undefined) params.set('category', String(args.category as number));
    if (args.difficulty) params.set('difficulty', args.difficulty as string);
    if (args.type) params.set('type', args.type as string);

    const url = `${this.baseUrl}/api.php?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Trivia DB error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      response_code: number;
      results: Array<{
        category: string;
        type: string;
        difficulty: string;
        question: string;
        correct_answer: string;
        incorrect_answers: string[];
      }>;
    };

    if (data.response_code !== 0) {
      const msg = RESPONSE_CODE_MESSAGES[data.response_code] ?? `Response code ${data.response_code}`;
      return {
        content: [{ type: 'text', text: `Open Trivia DB error: ${msg}` }],
        isError: true,
      };
    }

    const result = {
      count: data.results.length,
      questions: data.results.map((q) => ({
        category: decodeHtml(q.category),
        difficulty: q.difficulty,
        type: q.type,
        question: decodeHtml(q.question),
        correct_answer: decodeHtml(q.correct_answer),
        incorrect_answers: q.incorrect_answers.map(decodeHtml),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listCategories(): Promise<ToolResult> {
    const url = `${this.baseUrl}/api_category.php`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Trivia DB error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      trivia_categories: Array<{ id: number; name: string }>;
    };

    const result = {
      count: data.trivia_categories.length,
      categories: data.trivia_categories.map((c) => ({ id: c.id, name: c.name })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCategoryStats(args: Record<string, unknown>): Promise<ToolResult> {
    const category = args.category as number;
    const url = `${this.baseUrl}/api_count.php?category=${encodeURIComponent(String(category))}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Trivia DB error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      category_id: number;
      category_question_count: {
        total_question_count: number;
        total_easy_question_count: number;
        total_medium_question_count: number;
        total_hard_question_count: number;
      };
    };

    const counts = data.category_question_count;
    const result = {
      category_id: data.category_id,
      total: counts.total_question_count,
      easy: counts.total_easy_question_count,
      medium: counts.total_medium_question_count,
      hard: counts.total_hard_question_count,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
