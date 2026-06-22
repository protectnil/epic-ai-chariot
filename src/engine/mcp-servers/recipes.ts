/**
 * TheMealDB Recipes API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://www.themealdb.com/api.php
// Auth: none (free tier uses the test API key "1" in the URL path; no header required)
// Docs: https://www.themealdb.com/api.php
// Category: food
// Rate limits: none documented for the free tier

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.themealdb.com/api/json/v1/1';

interface RawMeal {
  idMeal: string;
  strMeal: string;
  strCategory?: string;
  strArea?: string;
  strInstructions?: string;
  strMealThumb?: string;
  strYoutube?: string;
  strSource?: string;
  strTags?: string;
  [key: string]: string | undefined;
}

interface SlimMeal {
  idMeal: string;
  strMeal: string;
  strMealThumb?: string;
}

export class RecipesMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('RecipesMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'recipes',
      displayName: 'Recipes (TheMealDB)',
      version: '1.0.0',
      category: 'food',
      keywords: [
        'recipes', 'meals', 'cooking', 'food', 'ingredients', 'meal search',
        'random meal', 'mealdb', 'dinner', 'cuisine', 'kitchen', 'dish',
      ],
      toolNames: ['search_meals', 'get_meal', 'random_meal', 'meals_by_ingredient'],
      description: 'TheMealDB Recipes API: search recipes by name or ingredient, look up full meal details by ID, and fetch a random recipe — free and unauthenticated.',
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
        name: 'search_meals',
        description: 'Search for recipes by meal name. Returns a list of matching meals with full details.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Meal name or partial name to search for (e.g., "chicken", "pasta arrabiata")',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_meal',
        description: 'Get the full recipe for a meal by its TheMealDB ID, including ingredients, measures, and instructions.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'TheMealDB meal ID (e.g., "52772")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'random_meal',
        description: 'Get a single random meal recipe with full ingredients and instructions.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'meals_by_ingredient',
        description: 'Find meals that use a specific ingredient (e.g., "chicken", "garlic", "pasta"). Returns a slim list with meal names and thumbnail URLs.',
        inputSchema: {
          type: 'object',
          properties: {
            ingredient: {
              type: 'string',
              description: 'Ingredient name to filter by (e.g., "chicken", "garlic")',
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
        case 'search_meals':       return this.searchMeals(args.query as string);
        case 'get_meal':           return this.getMeal(args.id as string);
        case 'random_meal':        return this.randomMeal();
        case 'meals_by_ingredient': return this.mealsByIngredient(args.ingredient as string);
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

  private extractIngredients(meal: RawMeal): { ingredient: string; measure: string }[] {
    const ingredients: { ingredient: string; measure: string }[] = [];
    for (let i = 1; i <= 20; i++) {
      const ingredient = meal[`strIngredient${i}`]?.trim();
      const measure = meal[`strMeasure${i}`]?.trim();
      if (ingredient) {
        ingredients.push({ ingredient, measure: measure ?? '' });
      }
    }
    return ingredients;
  }

  private formatFullMeal(meal: RawMeal): Record<string, unknown> {
    return {
      id: meal.idMeal,
      name: meal.strMeal,
      category: meal.strCategory ?? null,
      area: meal.strArea ?? null,
      instructions: meal.strInstructions ?? null,
      thumbnail_url: meal.strMealThumb ?? null,
      youtube_url: meal.strYoutube ?? null,
      source_url: meal.strSource ?? null,
      tags: meal.strTags ? meal.strTags.split(',').map((t) => t.trim()).filter(Boolean) : [],
      ingredients: this.extractIngredients(meal),
    };
  }

  private formatSlimMeal(meal: SlimMeal): Record<string, unknown> {
    return {
      id: meal.idMeal,
      name: meal.strMeal,
      thumbnail_url: meal.strMealThumb ?? null,
    };
  }

  private async searchMeals(query: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/search.php?s=${encodeURIComponent(query)}`;
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
    const data = (await response.json()) as { meals: RawMeal[] | null };
    if (!data.meals) {
      return {
        content: [{ type: 'text', text: this.truncate({ meals: [], total: 0 }) }],
        isError: false,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate({ total: data.meals.length, meals: data.meals.map((m) => this.formatFullMeal(m)) }) }],
      isError: false,
    };
  }

  private async getMeal(id: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/lookup.php?i=${encodeURIComponent(id)}`;
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
    const data = (await response.json()) as { meals: RawMeal[] | null };
    if (!data.meals || data.meals.length === 0) {
      return {
        content: [{ type: 'text', text: `Meal not found for ID: "${id}"` }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate(this.formatFullMeal(data.meals[0])) }],
      isError: false,
    };
  }

  private async randomMeal(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/random.php`, {
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
    const data = (await response.json()) as { meals: RawMeal[] | null };
    if (!data.meals || data.meals.length === 0) {
      return {
        content: [{ type: 'text', text: 'Failed to retrieve a random meal' }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate(this.formatFullMeal(data.meals[0])) }],
      isError: false,
    };
  }

  private async mealsByIngredient(ingredient: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/filter.php?i=${encodeURIComponent(ingredient)}`;
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
    const data = (await response.json()) as { meals: SlimMeal[] | null };
    if (!data.meals) {
      return {
        content: [{ type: 'text', text: this.truncate({ ingredient, meals: [], total: 0 }) }],
        isError: false,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate({ ingredient, total: data.meals.length, meals: data.meals.map((m) => this.formatSlimMeal(m)) }) }],
      isError: false,
    };
  }
}
