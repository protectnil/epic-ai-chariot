/**
 * Imgflip MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.imgflip.com
// Auth: None required for template listing
// Docs: https://imgflip.com/api
// Category: entertainment

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class ImgflipMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('ImgflipMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || 'https://api.imgflip.com';
  }

  static catalog() {
    return {
      name: 'imgflip',
      displayName: 'Imgflip',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'imgflip', 'meme', 'memes', 'meme templates', 'image macros',
        'humor', 'funny', 'viral', 'internet culture', 'meme generator',
      ],
      toolNames: ['get_memes'],
      description: 'Imgflip API: retrieve the top 100 most popular meme templates including name, image URL, dimensions, and text box count.',
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
        name: 'get_memes',
        description:
          'Get the top 100 most popular meme templates from Imgflip, including name, image URL, dimensions, and text box count.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, _args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_memes':
          return this.getMemes();
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

  private async getMemes(): Promise<ToolResult> {
    const url = `${this.baseUrl}/get_memes`;
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

    const data = (await response.json()) as {
      success: boolean;
      error_message?: string;
      data: {
        memes: Array<{
          id: string;
          name: string;
          url: string;
          width: number;
          height: number;
          box_count: number;
        }>;
      };
    };

    if (!data.success) {
      return {
        content: [{ type: 'text', text: `Imgflip API error: ${data.error_message ?? 'unknown error'}` }],
        isError: true,
      };
    }

    const result = {
      count: data.data.memes.length,
      memes: data.data.memes.map((m) => ({
        id: m.id,
        name: m.name,
        url: m.url,
        width: m.width,
        height: m.height,
        box_count: m.box_count,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
