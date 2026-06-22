/**
 * Pokemon MCP Adapter — wraps PokeAPI (free, no auth required)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://pokeapi.co/api/v2
 * Auth: none (public, no credentials required)
 * Docs: https://pokeapi.co/docs/v2
 * Category: gaming
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://pokeapi.co/api/v2';

export class PokemonMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'pokemon',
      displayName: 'Pokemon (PokeAPI)',
      version: '1.0.0',
      category: 'gaming',
      keywords: [
        'pokemon', 'pokeapi', 'pokedex', 'pikachu', 'evolution', 'ability',
        'type', 'fire', 'water', 'electric', 'stats', 'sprites', 'game',
        'nintendo', 'creatures',
      ],
      toolNames: ['get_pokemon', 'get_type', 'get_ability', 'get_evolution_chain'],
      description: 'Pokemon (PokeAPI): look up Pokemon details, type effectiveness, ability descriptions, and full evolution chains — free public API, no authentication required.',
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
        name: 'get_pokemon',
        description:
          'Get Pokemon details by name or ID. Returns name, ID, types, base stats (HP, attack, defense, etc.), abilities, height, weight, and sprites.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Pokemon name (e.g., "pikachu") or numeric ID (e.g., "25")',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'get_type',
        description:
          'Get type effectiveness information and Pokemon list for a given type. Returns damage relations (double/half/no damage to and from) and the first 20 Pokemon of that type.',
        inputSchema: {
          type: 'object',
          properties: {
            type: {
              type: 'string',
              description: 'Type name (e.g., "fire", "water", "electric")',
            },
          },
          required: ['type'],
        },
      },
      {
        name: 'get_ability',
        description:
          'Get ability details including effect description and the list of Pokemon that can have this ability.',
        inputSchema: {
          type: 'object',
          properties: {
            ability: {
              type: 'string',
              description: 'Ability name (e.g., "overgrow", "blaze", "static")',
            },
          },
          required: ['ability'],
        },
      },
      {
        name: 'get_evolution_chain',
        description:
          'Get the full evolution chain by chain ID. Returns each species in the chain with its evolution trigger, minimum level, and evolution item.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Evolution chain ID (e.g., 1 for Bulbasaur line, 10 for Caterpie line)',
            },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_pokemon':        return this.getPokemon(args.name as string);
        case 'get_type':           return this.getType(args.type as string);
        case 'get_ability':        return this.getAbility(args.ability as string);
        case 'get_evolution_chain': return this.getEvolutionChain(args.id as number);
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

  private async getPokemon(name: string): Promise<ToolResult> {
    const url = `${BASE_URL}/pokemon/${encodeURIComponent(name.toLowerCase())}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `PokeAPI error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      id: number;
      name: string;
      height: number;
      weight: number;
      types: { type: { name: string } }[];
      stats: { base_stat: number; stat: { name: string } }[];
      abilities: { ability: { name: string }; is_hidden: boolean }[];
      sprites: { front_default: string | null; front_shiny: string | null };
    };
    const stats: Record<string, number> = {};
    for (const s of data.stats) {
      stats[s.stat.name] = s.base_stat;
    }
    const result = {
      id: data.id,
      name: data.name,
      height: data.height,
      weight: data.weight,
      types: data.types.map((t) => t.type.name),
      stats,
      abilities: data.abilities.map((a) => ({
        name: a.ability.name,
        is_hidden: a.is_hidden,
      })),
      sprites: {
        front_default: data.sprites.front_default,
        front_shiny: data.sprites.front_shiny,
      },
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getType(type: string): Promise<ToolResult> {
    const url = `${BASE_URL}/type/${encodeURIComponent(type.toLowerCase())}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `PokeAPI error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      name: string;
      damage_relations: {
        double_damage_to: { name: string }[];
        double_damage_from: { name: string }[];
        half_damage_to: { name: string }[];
        half_damage_from: { name: string }[];
        no_damage_to: { name: string }[];
        no_damage_from: { name: string }[];
      };
      pokemon: { pokemon: { name: string; url: string } }[];
    };
    const dr = data.damage_relations;
    const result = {
      name: data.name,
      damage_relations: {
        double_damage_to:   dr.double_damage_to.map((t) => t.name),
        double_damage_from: dr.double_damage_from.map((t) => t.name),
        half_damage_to:     dr.half_damage_to.map((t) => t.name),
        half_damage_from:   dr.half_damage_from.map((t) => t.name),
        no_damage_to:       dr.no_damage_to.map((t) => t.name),
        no_damage_from:     dr.no_damage_from.map((t) => t.name),
      },
      pokemon: data.pokemon.slice(0, 20).map((p) => p.pokemon.name),
      total_pokemon: data.pokemon.length,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAbility(ability: string): Promise<ToolResult> {
    const url = `${BASE_URL}/ability/${encodeURIComponent(ability.toLowerCase())}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `PokeAPI error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      name: string;
      effect_entries: { effect: string; short_effect: string; language: { name: string } }[];
      pokemon: { pokemon: { name: string; url: string }; is_hidden: boolean }[];
    };
    const englishEntry = data.effect_entries.find((e) => e.language.name === 'en');
    const result = {
      name: data.name,
      effect: englishEntry?.effect ?? null,
      short_effect: englishEntry?.short_effect ?? null,
      pokemon: data.pokemon.map((p) => ({
        name: p.pokemon.name,
        is_hidden: p.is_hidden,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getEvolutionChain(id: number): Promise<ToolResult> {
    const url = `${BASE_URL}/evolution-chain/${id}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `PokeAPI error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      id: number;
      chain: ChainLink;
    };
    const result = {
      id: data.id,
      chain: flattenChain(data.chain),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

// ── Private types & helpers ────────────────────────────────────────────────

interface ChainLink {
  species: { name: string };
  evolution_details: {
    min_level: number | null;
    trigger: { name: string } | null;
    item: { name: string } | null;
  }[];
  evolves_to: ChainLink[];
}

function flattenChain(link: ChainLink): object[] {
  const detail = link.evolution_details[0] ?? null;
  const entry = {
    species: link.species.name,
    evolution_trigger: detail?.trigger?.name ?? null,
    min_level: detail?.min_level ?? null,
    item: detail?.item?.name ?? null,
  };
  const rest = link.evolves_to.flatMap((next) => flattenChain(next));
  return [entry, ...rest];
}
