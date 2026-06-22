/**
 * Monster Hunter World MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream API: https://mhw-db.com (free, no auth required)
// Docs: https://docs.mhw-db.com
// Category: gaming
// Auth: none — public API, no key required

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://mhw-db.com';

const WEAPON_TYPES = [
  'great-sword',
  'sword-and-shield',
  'dual-blades',
  'long-sword',
  'hammer',
  'hunting-horn',
  'lance',
  'gunlance',
  'switch-axe',
  'charge-blade',
  'insect-glaive',
  'light-bowgun',
  'heavy-bowgun',
  'bow',
] as const;

type WeaponType = (typeof WEAPON_TYPES)[number];

export class MHWMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'mhw',
      displayName: 'Monster Hunter World',
      version: '1.0.0',
      category: 'gaming',
      keywords: [
        'mhw', 'monster hunter', 'monster hunter world', 'monsters', 'weapons',
        'armor', 'skills', 'gaming', 'rpg', 'capcom', 'great sword', 'bow',
        'lance', 'hammer', 'insect glaive', 'charge blade', 'switch axe',
      ],
      toolNames: ['get_monsters', 'get_weapons', 'get_armor', 'get_skills'],
      description: 'Monster Hunter World API: list monsters, weapons, armor, and skills from the mhw-db.com public database — free, no authentication required.',
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
        name: 'get_monsters',
        description: 'List monsters from Monster Hunter World, including their type, species, elements, ailments, and weaknesses.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Maximum number of monsters to return. Defaults to 20.',
            },
          },
        },
      },
      {
        name: 'get_weapons',
        description: 'List weapons from Monster Hunter World. Optionally filter by weapon type to narrow results.',
        inputSchema: {
          type: 'object',
          properties: {
            type: {
              type: 'string',
              description: 'Filter by weapon type. One of: great-sword, sword-and-shield, dual-blades, long-sword, hammer, hunting-horn, lance, gunlance, switch-axe, charge-blade, insect-glaive, light-bowgun, heavy-bowgun, bow. Omit to return all types.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of weapons to return. Defaults to 20.',
            },
          },
        },
      },
      {
        name: 'get_armor',
        description: 'List armor pieces from Monster Hunter World, including their type, rank, defense, resistances, and slots.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Maximum number of armor pieces to return. Defaults to 20.',
            },
          },
        },
      },
      {
        name: 'get_skills',
        description: 'List skills from Monster Hunter World, including their descriptions and rank-level details.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Maximum number of skills to return. Defaults to 20.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_monsters': return this.getMonsters((args.limit as number | undefined) ?? 20);
        case 'get_weapons':  return this.getWeapons(args.type as WeaponType | undefined, (args.limit as number | undefined) ?? 20);
        case 'get_armor':    return this.getArmor((args.limit as number | undefined) ?? 20);
        case 'get_skills':   return this.getSkills((args.limit as number | undefined) ?? 20);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async request(path: string): Promise<ToolResult> {
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

  private getMonsters(limit: number): Promise<ToolResult> {
    return this.request(`/monsters?limit=${encodeURIComponent(String(limit))}`);
  }

  private getWeapons(type: WeaponType | undefined, limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (type) params.set('type', type);
    return this.request(`/weapons?${params.toString()}`);
  }

  private getArmor(limit: number): Promise<ToolResult> {
    return this.request(`/armor?limit=${encodeURIComponent(String(limit))}`);
  }

  private getSkills(limit: number): Promise<ToolResult> {
    return this.request(`/skills?limit=${encodeURIComponent(String(limit))}`);
  }
}
