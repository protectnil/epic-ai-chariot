/**
 * TheCocktailDB MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://www.thecocktaildb.com/api/json/v1/1
// Auth: none — free public API, no key required
// Docs: https://www.thecocktaildb.com/api.php
// Category: food
// Rate limits: none documented for free tier

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.thecocktaildb.com/api/json/v1/1';

interface CocktailsConfig {
  baseUrl?: string;
}

// Raw cocktail shape returned by TheCocktailDB
interface RawCocktail {
  idDrink: string;
  strDrink: string;
  strCategory: string | null;
  strAlcoholic: string | null;
  strGlass: string | null;
  strInstructions: string | null;
  strDrinkThumb: string | null;
  [key: string]: string | null | undefined;
}

interface RawSummary {
  idDrink: string;
  strDrink: string;
  strDrinkThumb: string;
}

function formatIngredients(raw: RawCocktail): { ingredient: string; measure: string }[] {
  const ingredients: { ingredient: string; measure: string }[] = [];
  for (let i = 1; i <= 15; i++) {
    const ingredient = raw[`strIngredient${i}`] as string | null;
    const measure = raw[`strMeasure${i}`] as string | null;
    if (ingredient && ingredient.trim()) {
      ingredients.push({
        ingredient: ingredient.trim(),
        measure: measure?.trim() ?? '',
      });
    }
  }
  return ingredients;
}

function formatFullCocktail(raw: RawCocktail) {
  return {
    id: raw.idDrink,
    name: raw.strDrink,
    category: raw.strCategory ?? '',
    alcoholic: raw.strAlcoholic ?? '',
    glass: raw.strGlass ?? '',
    instructions: raw.strInstructions ?? '',
    thumbnail: raw.strDrinkThumb ?? '',
    ingredients: formatIngredients(raw),
  };
}

function formatSummaryCocktail(raw: RawCocktail) {
  return {
    id: raw.idDrink,
    name: raw.strDrink,
    category: raw.strCategory ?? '',
    alcoholic: raw.strAlcoholic ?? '',
    glass: raw.strGlass ?? '',
    thumbnail: raw.strDrinkThumb ?? '',
    ingredients: formatIngredients(raw),
  };
}

export class CocktailsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: CocktailsConfig) {
    super();
    if (config === null) { throw new Error('CocktailsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'cocktails',
      displayName: 'TheCocktailDB',
      version: '1.0.0',
      category: 'food',
      keywords: [
        'cocktails', 'drinks', 'recipes', 'bartender', 'mixology',
        'ingredients', 'alcohol', 'beverages', 'bar', 'cocktail db',
        'random cocktail', 'search drinks',
      ],
      toolNames: [
        'search_cocktails',
        'get_cocktail',
        'random_cocktail',
        'cocktails_by_ingredient',
      ],
      description: 'TheCocktailDB: search cocktails by name, look up full drink details by ID, retrieve a random cocktail, or filter drinks by ingredient — free and unauthenticated.',
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
        name: 'search_cocktails',
        description: 'Search for cocktails by name. Returns a list of matching cocktails with key details.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Cocktail name or partial name to search for',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_cocktail',
        description: 'Get full details for a cocktail by its TheCocktailDB ID, including all ingredients and instructions.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'TheCocktailDB cocktail ID (e.g., "11007")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'random_cocktail',
        description: 'Get a random cocktail with full details including ingredients and instructions.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'cocktails_by_ingredient',
        description: 'Find cocktails that use a specific ingredient (e.g., "vodka", "lime juice", "gin").',
        inputSchema: {
          type: 'object',
          properties: {
            ingredient: {
              type: 'string',
              description: 'Ingredient name to filter by (e.g., "vodka", "gin")',
            },
          },
          required: ['ingredient'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_cocktails':      return this.searchCocktails(args);
        case 'get_cocktail':          return this.getCocktail(args);
        case 'random_cocktail':       return this.randomCocktail();
        case 'cocktails_by_ingredient': return this.cocktailsByIngredient(args);
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

  private async searchCocktails(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/search.php?s=${encodeURIComponent(query)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as { drinks: RawCocktail[] | null };
    if (!data.drinks) {
      return { content: [{ type: 'text', text: this.truncate({ cocktails: [] }) }], isError: false };
    }
    return {
      content: [{
        type: 'text',
        text: this.truncate({ count: data.drinks.length, cocktails: data.drinks.map(formatSummaryCocktail) }),
      }],
      isError: false,
    };
  }

  private async getCocktail(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id as string;
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/lookup.php?i=${encodeURIComponent(id)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as { drinks: RawCocktail[] | null };
    if (!data.drinks || data.drinks.length === 0) {
      return { content: [{ type: 'text', text: `Cocktail not found: ${id}` }], isError: true };
    }
    return {
      content: [{ type: 'text', text: this.truncate(formatFullCocktail(data.drinks[0])) }],
      isError: false,
    };
  }

  private async randomCocktail(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/random.php`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as { drinks: RawCocktail[] | null };
    if (!data.drinks || data.drinks.length === 0) {
      return { content: [{ type: 'text', text: 'Failed to retrieve a random cocktail' }], isError: true };
    }
    return {
      content: [{ type: 'text', text: this.truncate(formatFullCocktail(data.drinks[0])) }],
      isError: false,
    };
  }

  private async cocktailsByIngredient(args: Record<string, unknown>): Promise<ToolResult> {
    const ingredient = args.ingredient as string;
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/filter.php?i=${encodeURIComponent(ingredient)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as { drinks: RawSummary[] | null };
    if (!data.drinks) {
      return {
        content: [{ type: 'text', text: this.truncate({ ingredient, cocktails: [] }) }],
        isError: false,
      };
    }
    return {
      content: [{
        type: 'text',
        text: this.truncate({
          ingredient,
          count: data.drinks.length,
          cocktails: data.drinks.map((d) => ({
            id: d.idDrink,
            name: d.strDrink,
            thumbnail: d.strDrinkThumb,
          })),
        }),
      }],
      isError: false,
    };
  }
}
