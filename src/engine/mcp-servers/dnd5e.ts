/**
 * D&D 5e MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://www.dnd5eapi.co/api/2014  (free, no auth)
 * Docs: https://5e-bits.github.io/docs/
 * Category: entertainment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.dnd5eapi.co/api/2014';

export class Dnd5eMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'dnd5e',
      displayName: 'D&D 5e API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'dnd', 'd&d', 'dungeons and dragons', '5e', 'fifth edition',
        'tabletop', 'rpg', 'spells', 'monsters', 'classes',
        'fantasy', 'fireball', 'goblin', 'wizard', 'character',
      ],
      toolNames: ['get_spell', 'get_monster', 'get_class', 'list_spells'],
      description: 'D&D 5e API: look up spells, monsters, and character classes from the 5th Edition ruleset — free and unauthenticated.',
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
        name: 'get_spell',
        description:
          'Get full details for a D&D 5e spell by its index name (e.g. "fireball", "magic-missile", "cure-wounds").',
        inputSchema: {
          type: 'object',
          properties: {
            index: {
              type: 'string',
              description: 'Spell index name in kebab-case (e.g. "fireball", "magic-missile").',
            },
          },
          required: ['index'],
        },
      },
      {
        name: 'get_monster',
        description:
          'Get full details for a D&D 5e monster by its index name (e.g. "aboleth", "dragon-red-adult", "goblin").',
        inputSchema: {
          type: 'object',
          properties: {
            index: {
              type: 'string',
              description: 'Monster index name in kebab-case (e.g. "goblin", "dragon-red-adult").',
            },
          },
          required: ['index'],
        },
      },
      {
        name: 'get_class',
        description:
          'Get details for a D&D 5e character class by its index name (e.g. "barbarian", "wizard", "rogue").',
        inputSchema: {
          type: 'object',
          properties: {
            index: {
              type: 'string',
              description: 'Class index name in lowercase (e.g. "wizard", "fighter", "cleric").',
            },
          },
          required: ['index'],
        },
      },
      {
        name: 'list_spells',
        description: 'List all available D&D 5e spells with their index names.',
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
        case 'get_spell':   return this.getSpell(args.index as string);
        case 'get_monster': return this.getMonster(args.index as string);
        case 'get_class':   return this.getClass(args.index as string);
        case 'list_spells': return this.listSpells();
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
        content: [{ type: 'text', text: `D&D 5e API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getSpell(index: string): Promise<ToolResult> {
    if (!index || typeof index !== 'string') {
      return { content: [{ type: 'text', text: 'get_spell: index is required' }], isError: true };
    }
    const url = `${BASE_URL}/spells/${encodeURIComponent(index)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `D&D 5e API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      index: string;
      name: string;
      level: number;
      school: { name: string };
      casting_time: string;
      range: string;
      duration: string;
      concentration: boolean;
      ritual: boolean;
      components: string[];
      material?: string;
      desc: string[];
      higher_level?: string[];
      classes: Array<{ name: string }>;
    };
    const result = {
      index: data.index,
      name: data.name,
      level: data.level,
      school: data.school.name,
      casting_time: data.casting_time,
      range: data.range,
      duration: data.duration,
      concentration: data.concentration,
      ritual: data.ritual,
      components: data.components,
      material: data.material,
      description: data.desc,
      higher_level: data.higher_level,
      classes: data.classes.map((c) => c.name),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getMonster(index: string): Promise<ToolResult> {
    if (!index || typeof index !== 'string') {
      return { content: [{ type: 'text', text: 'get_monster: index is required' }], isError: true };
    }
    const url = `${BASE_URL}/monsters/${encodeURIComponent(index)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `D&D 5e API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      index: string;
      name: string;
      size: string;
      type: string;
      alignment: string;
      armor_class: Array<{ value: number; type: string }>;
      hit_points: number;
      hit_dice: string;
      speed: Record<string, string>;
      strength: number;
      dexterity: number;
      constitution: number;
      intelligence: number;
      wisdom: number;
      charisma: number;
      challenge_rating: number;
      xp: number;
    };
    const result = {
      index: data.index,
      name: data.name,
      size: data.size,
      type: data.type,
      alignment: data.alignment,
      armor_class: data.armor_class,
      hit_points: data.hit_points,
      hit_dice: data.hit_dice,
      speed: data.speed,
      ability_scores: {
        str: data.strength,
        dex: data.dexterity,
        con: data.constitution,
        int: data.intelligence,
        wis: data.wisdom,
        cha: data.charisma,
      },
      challenge_rating: data.challenge_rating,
      xp: data.xp,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getClass(index: string): Promise<ToolResult> {
    if (!index || typeof index !== 'string') {
      return { content: [{ type: 'text', text: 'get_class: index is required' }], isError: true };
    }
    const url = `${BASE_URL}/classes/${encodeURIComponent(index)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `D&D 5e API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      index: string;
      name: string;
      hit_die: number;
      saving_throws: Array<{ name: string }>;
      proficiencies: Array<{ name: string }>;
      subclasses: Array<{ name: string }>;
    };
    const result = {
      index: data.index,
      name: data.name,
      hit_die: data.hit_die,
      saving_throws: data.saving_throws.map((s) => s.name),
      proficiencies: data.proficiencies.map((p) => p.name),
      subclasses: data.subclasses.map((s) => s.name),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listSpells(): Promise<ToolResult> {
    return this.request('/spells');
  }
}
