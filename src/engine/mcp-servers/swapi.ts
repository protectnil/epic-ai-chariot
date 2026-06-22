/**
 * Star Wars API (SWAPI) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://swapi.dev/api
// Auth: none (public, no key required)
// Docs: https://swapi.dev/documentation
// Category: entertainment
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://swapi.dev/api';

// ── Upstream response shapes ──────────────────────────────────────────────────

interface SwapiList<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

interface SwapiPerson {
  name: string;
  height: string;
  mass: string;
  hair_color: string;
  skin_color: string;
  eye_color: string;
  birth_year: string;
  gender: string;
  homeworld: string;
  url: string;
}

interface SwapiPlanet {
  name: string;
  rotation_period: string;
  orbital_period: string;
  diameter: string;
  climate: string;
  gravity: string;
  terrain: string;
  surface_water: string;
  population: string;
  url: string;
}

interface SwapiStarship {
  name: string;
  model: string;
  manufacturer: string;
  cost_in_credits: string;
  length: string;
  max_atmosphering_speed: string;
  crew: string;
  passengers: string;
  cargo_capacity: string;
  starship_class: string;
  hyperdrive_rating: string;
  MGLT: string;
  url: string;
}

interface SwapiFilm {
  title: string;
  episode_id: number;
  opening_crawl: string;
  director: string;
  producer: string;
  release_date: string;
  url: string;
}

// ── Adapter ───────────────────────────────────────────────────────────────────

export class SwapiMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('SwapiMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'swapi',
      displayName: 'Star Wars API (SWAPI)',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'star wars', 'swapi', 'characters', 'people', 'planets', 'starships',
        'films', 'movies', 'sci-fi', 'luke skywalker', 'tatooine', 'death star',
        'jedi', 'force', 'galactic', 'space opera',
      ],
      toolNames: ['search_people', 'get_planet', 'get_starship', 'get_film'],
      description: 'Star Wars API (SWAPI): search characters, look up planets, starships, and films from the Star Wars universe — free and unauthenticated.',
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
        name: 'search_people',
        description: 'Search Star Wars characters by name. Returns name, physical attributes, birth year, gender, and homeworld URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Character name to search for (e.g., "Luke")',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_planet',
        description: 'Get a Star Wars planet by its numeric ID. Returns name, climate, terrain, population, and orbital data.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Planet ID (e.g., 1 for Tatooine)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_starship',
        description: 'Get a Star Wars starship by its numeric ID. Returns name, model, manufacturer, crew capacity, and hyperdrive rating.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Starship ID (e.g., 9 for the Death Star)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_film',
        description: 'Get a Star Wars film by its numeric ID. Returns title, episode number, director, producer, release date, and opening crawl.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Film ID (e.g., 1 for A New Hope)',
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
        case 'search_people': return this.searchPeople(args.query as string);
        case 'get_planet':    return this.getPlanet(args.id as number);
        case 'get_starship':  return this.getStarship(args.id as number);
        case 'get_film':      return this.getFilm(args.id as number);
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

  private async searchPeople(query: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/people/?search=${encodeURIComponent(query)}`;
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
    const data = (await response.json()) as SwapiList<SwapiPerson>;
    const result = {
      count: data.count,
      results: data.results.map((p) => ({
        name: p.name,
        height: p.height,
        mass: p.mass,
        hair_color: p.hair_color,
        skin_color: p.skin_color,
        eye_color: p.eye_color,
        birth_year: p.birth_year,
        gender: p.gender,
        homeworld: p.homeworld,
        url: p.url,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPlanet(id: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/planets/${encodeURIComponent(String(id))}/`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: `Planet not found: ID ${id}` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const p = (await response.json()) as SwapiPlanet;
    const result = {
      name: p.name,
      rotation_period: p.rotation_period,
      orbital_period: p.orbital_period,
      diameter: p.diameter,
      climate: p.climate,
      gravity: p.gravity,
      terrain: p.terrain,
      surface_water: p.surface_water,
      population: p.population,
      url: p.url,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getStarship(id: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/starships/${encodeURIComponent(String(id))}/`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: `Starship not found: ID ${id}` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const s = (await response.json()) as SwapiStarship;
    const result = {
      name: s.name,
      model: s.model,
      manufacturer: s.manufacturer,
      cost_in_credits: s.cost_in_credits,
      length: s.length,
      max_atmosphering_speed: s.max_atmosphering_speed,
      crew: s.crew,
      passengers: s.passengers,
      cargo_capacity: s.cargo_capacity,
      starship_class: s.starship_class,
      hyperdrive_rating: s.hyperdrive_rating,
      MGLT: s.MGLT,
      url: s.url,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getFilm(id: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/films/${encodeURIComponent(String(id))}/`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: `Film not found: ID ${id}` }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const f = (await response.json()) as SwapiFilm;
    const result = {
      title: f.title,
      episode_id: f.episode_id,
      director: f.director,
      producer: f.producer,
      release_date: f.release_date,
      opening_crawl: f.opening_crawl,
      url: f.url,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
