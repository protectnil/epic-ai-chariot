/**
 * Tinder Bio Generator MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.stupidapis.com/tinder-bio
// Auth: API key header (X-API-Key)
// Category: entertainment
// Upstream: StupidAPIs — dating profile bio generator

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface TinderBioConfig {
  apiKey: string;
  baseUrl?: string;
}

export class TinderBioMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: TinderBioConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Tinder Bio Generator: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Tinder Bio Generator: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.stupidapis.com';
  }

  static catalog() {
    return {
      name: 'tinder-bio',
      displayName: 'Tinder Bio Generator',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'tinder', 'bio', 'dating', 'profile', 'dating profile',
        'bio generator', 'dating app', 'relationship', 'matchmaking',
        'online dating', 'humor', 'creative writing',
      ],
      toolNames: ['tinder_bio_generate'],
      description: 'Tinder Bio Generator: generate a dating profile bio with configurable personality traits, energy, and situational context.',
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
        name: 'tinder_bio_generate',
        description: 'Generate a dating profile bio. Customize with age, profession, personality traits, situation, gender, dealbreakers, what you are looking for, and energy level.',
        inputSchema: {
          type: 'object',
          properties: {
            age: {
              type: 'number',
              description: 'Age of the person.',
            },
            profession: {
              type: 'string',
              description: 'Profession or job title.',
            },
            personality: {
              type: 'string',
              description: 'Comma-separated personality traits: adventurous, homebody, foodie, gym_rat, intellectual, creative, outdoorsy, gamer, spiritual, workaholic, recently_divorced, dog_person, cat_person, doesnt_know_how_to_describe_self.',
            },
            situation: {
              type: 'string',
              description: 'Current dating app situation.',
              enum: [
                'new_to_app',
                'returned_after_break',
                'just_got_out_of_something',
                'never_done_this_before',
                'doing_this_for_a_friend',
              ],
            },
            gender: {
              type: 'string',
              description: 'Gender of the person.',
            },
            dealbreaker: {
              type: 'string',
              description: 'A dealbreaker to embed in the bio.',
            },
            looking_for: {
              type: 'string',
              description: 'What the person is looking for.',
              enum: ['friendship', 'relationship', 'not_sure', 'lying_about_this'],
            },
            energy: {
              type: 'string',
              description: 'The energy/tone of the bio.',
              enum: ['low_effort', 'trying_too_hard', 'unhinged_honesty', 'corporate', 'post_breakup'],
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'tinder_bio_generate': return this.generateBio(args);
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

  private async generateBio(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(args)) {
      if (v !== undefined && v !== null && v !== '') {
        params.set(k, String(v));
      }
    }
    const path = params.toString()
      ? `/tinder-bio/generate?${params.toString()}`
      : '/tinder-bio/generate';
    const url = `${this.baseUrl}${path}`;
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
