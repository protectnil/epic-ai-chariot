/**
 * Dog CEO REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream API: https://dog.ceo/api (Dog CEO's Dog API — public, no auth)
// Docs: https://dog.ceo/dog-api/documentation
// Category: entertainment
// Rate limits: None documented; public free API

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://dog.ceo/api';

export class DogCeoMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'dogceo',
      displayName: 'Dog CEO Dog API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'dog', 'dogs', 'breeds', 'puppy', 'pet', 'animal', 'image',
        'random', 'dog image', 'dog breed', 'sub-breed',
      ],
      toolNames: ['random_image', 'list_breeds', 'breed_images', 'random_breed_image'],
      description: 'Dog CEO Dog API: fetch random dog images, list all breeds and sub-breeds, and retrieve single or multiple random images for a specific breed.',
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
        name: 'random_image',
        description: 'Get a random dog image URL from any breed.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_breeds',
        description: 'List all dog breeds and their sub-breeds.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'breed_images',
        description: 'Get multiple random dog images for a specific breed.',
        inputSchema: {
          type: 'object',
          properties: {
            breed: {
              type: 'string',
              description: 'The breed name (e.g. "hound", "labrador"). Use list_breeds to see valid values.',
            },
            count: {
              type: 'number',
              description: 'Number of images to return. Defaults to 3.',
            },
          },
          required: ['breed'],
        },
      },
      {
        name: 'random_breed_image',
        description: 'Get a single random dog image for a specific breed.',
        inputSchema: {
          type: 'object',
          properties: {
            breed: {
              type: 'string',
              description: 'The breed name (e.g. "hound", "labrador"). Use list_breeds to see valid values.',
            },
          },
          required: ['breed'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'random_image':      return this.randomImage();
        case 'list_breeds':       return this.listBreeds();
        case 'breed_images':      return this.breedImages(args.breed as string, (args.count as number | undefined) ?? 3);
        case 'random_breed_image': return this.randomBreedImage(args.breed as string);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
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
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async randomImage(): Promise<ToolResult> {
    return this.get('/breeds/image/random');
  }

  private async listBreeds(): Promise<ToolResult> {
    return this.get('/breeds/list/all');
  }

  private async breedImages(breed: string, count: number): Promise<ToolResult> {
    return this.get(`/breed/${encodeURIComponent(breed)}/images/random/${count}`);
  }

  private async randomBreedImage(breed: string): Promise<ToolResult> {
    return this.get(`/breed/${encodeURIComponent(breed)}/images/random`);
  }
}
