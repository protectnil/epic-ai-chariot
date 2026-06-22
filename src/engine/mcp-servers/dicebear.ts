/**
 * DiceBear Avatar API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: DiceBear Avatar API v7 (https://api.dicebear.com/7.x)
// Auth: none — public, unauthenticated API
// Docs: https://www.dicebear.com/how-to-use/http-api/
// Category: media

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.dicebear.com/7.x';

const STYLES = [
  'adventurer',
  'avataaars',
  'bottts',
  'fun-emoji',
  'identicon',
  'initials',
  'lorelei',
  'micah',
  'miniavs',
  'notionists',
  'open-peeps',
  'personas',
  'pixel-art',
  'thumbs',
] as const;

type Style = (typeof STYLES)[number];

export class DiceBearMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DiceBearMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'dicebear',
      displayName: 'DiceBear Avatar API',
      version: '1.0.0',
      category: 'media',
      keywords: [
        'dicebear', 'avatar', 'avatar generator', 'profile picture',
        'identicon', 'svg', 'pixel art', 'fun emoji', 'bottts',
        'avataaars', 'lorelei', 'micah', 'open peeps', 'personas',
        'notionists', 'miniavs', 'initials', 'thumbs', 'image',
        'illustration', 'user icon', 'generative art',
      ],
      toolNames: ['generate_avatar', 'list_styles'],
      description: 'DiceBear Avatar API v7: generate deterministic SVG avatar URLs from a style + seed, or list all available avatar styles. Free, public, no authentication required.',
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
        name: 'generate_avatar',
        description:
          'Generate a DiceBear avatar SVG URL for a given style and seed string. Returns the URL that renders the avatar inline. Same style + seed always produces the same avatar.',
        inputSchema: {
          type: 'object',
          properties: {
            style: {
              type: 'string',
              description:
                'The avatar style to use. Available styles: adventurer, avataaars, bottts, fun-emoji, identicon, initials, lorelei, micah, miniavs, notionists, open-peeps, personas, pixel-art, thumbs.',
            },
            seed: {
              type: 'string',
              description:
                'A seed string that determines the avatar appearance. Same seed + style always produces the same avatar.',
            },
          },
          required: ['style', 'seed'],
        },
      },
      {
        name: 'list_styles',
        description: 'List all available DiceBear avatar styles.',
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
        case 'generate_avatar': return this.generateAvatar(args);
        case 'list_styles':     return this.listStyles();
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

  private async generateAvatar(args: Record<string, unknown>): Promise<ToolResult> {
    const style = args.style as string;
    const seed  = args.seed  as string;

    if (!style || typeof style !== 'string') {
      return { content: [{ type: 'text', text: 'generate_avatar: "style" is required' }], isError: true };
    }
    if (!seed || typeof seed !== 'string') {
      return { content: [{ type: 'text', text: 'generate_avatar: "seed" is required' }], isError: true };
    }
    if (!STYLES.includes(style as Style)) {
      return {
        content: [{
          type: 'text',
          text: `Unknown style: "${style}". Available styles: ${STYLES.join(', ')}`,
        }],
        isError: true,
      };
    }

    // DiceBear SVG URLs are fully deterministic: no upstream fetch needed.
    // Construct the URL directly so the call has zero latency and zero
    // upstream dependency; a GET on this URL renders the avatar.
    const url = `${this.baseUrl}/${encodeURIComponent(style)}/svg?seed=${encodeURIComponent(seed)}`;

    // Verify the URL is reachable (HEAD request) so callers get early
    // feedback on upstream availability, then return the URL + metadata.
    const response = await this.fetchWithRetry(url, { method: 'HEAD', headers: { Accept: 'image/svg+xml' } });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `DiceBear API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    return {
      content: [{
        type: 'text',
        text: this.truncate({ style, seed, url, format: 'svg' }),
      }],
      isError: false,
    };
  }

  private listStyles(): ToolResult {
    return {
      content: [{
        type: 'text',
        text: this.truncate({ count: STYLES.length, styles: [...STYLES] }),
      }],
      isError: false,
    };
  }
}
