/**
 * USDA Food Data Central MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.nal.usda.gov/fdc/v1
// Auth: ?api_key= query parameter (free registration at https://api.data.gov/signup/)
// Docs: https://fdc.nal.usda.gov/api-guide
// Category: food-nutrition
// Rate limits: 1,000 requests/hour (default); higher tiers available

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const DATA_TYPES = 'Branded | Foundation | Survey (FNDDS) | SR Legacy | Experimental';

interface UsdaFdcConfig {
  apiKey: string;
  baseUrl?: string;
}

export class UsdaFdcMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: UsdaFdcConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('USDA FDC: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('USDA FDC: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.nal.usda.gov/fdc/v1';
  }

  static catalog() {
    return {
      name: 'usda-fdc',
      displayName: 'USDA Food Data Central',
      version: '1.0.0',
      category: 'food-nutrition',
      keywords: [
        'usda', 'fdc', 'food', 'nutrition', 'nutrients', 'calories',
        'food database', 'branded food', 'food search', 'nutrient values',
        'dietary', 'fdc id', 'food data central', 'food composition',
        'sr legacy', 'foundation foods', 'survey', 'ingredients',
      ],
      toolNames: [
        'search_foods',
        'get_food',
        'list_foods',
        'list_food_groups',
        'nutrients_for_food',
      ],
      description: 'USDA Food Data Central: search foods, fetch full nutrient records, browse food lists, and retrieve nutrient values — free API key required (api.data.gov).',
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
        name: 'search_foods',
        description: 'Search USDA FDC food items by name, brand, or ingredient.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search — name / brand / ingredient',
            },
            data_type: {
              type: 'string',
              description: `Filter to data type(s). Comma-separated. Options: ${DATA_TYPES}`,
            },
            brand_owner: {
              type: 'string',
              description: 'Restrict results to a specific brand owner',
            },
            page_size: {
              type: 'number',
              description: '1–200 results per page (default 50)',
            },
            page_number: {
              type: 'number',
              description: '1-based page number (default 1)',
            },
            sort_by: {
              type: 'string',
              description: 'dataType.keyword | lowercaseDescription.keyword | fdcId | publishedDate (default relevance)',
            },
            sort_order: {
              type: 'string',
              description: 'asc | desc',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_food',
        description: 'Retrieve the full nutrient record for a food item by its FDC id.',
        inputSchema: {
          type: 'object',
          properties: {
            fdc_id: {
              type: 'number',
              description: 'FDC id (e.g. 1102704)',
            },
            format: {
              type: 'string',
              description: 'abridged | full (default full)',
            },
            nutrients: {
              type: 'string',
              description: 'Comma-separated nutrient numbers to restrict the response (e.g. "208,205")',
            },
          },
          required: ['fdc_id'],
        },
      },
      {
        name: 'list_foods',
        description: 'Paginated browse of all FDC foods, optionally filtered by data type.',
        inputSchema: {
          type: 'object',
          properties: {
            data_type: {
              type: 'string',
              description: `Filter to data type(s). Options: ${DATA_TYPES}`,
            },
            page_size: {
              type: 'number',
              description: '1–200 results per page (default 50)',
            },
            page_number: {
              type: 'number',
              description: '1-based page number (default 1)',
            },
            sort_by: {
              type: 'string',
              description: 'Sort field',
            },
            sort_order: {
              type: 'string',
              description: 'asc | desc',
            },
          },
        },
      },
      {
        name: 'list_food_groups',
        description: 'Return USDA WWEIA food group reference categories.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'nutrients_for_food',
        description: 'Convenience: retrieve nutrient values only for a food by FDC id.',
        inputSchema: {
          type: 'object',
          properties: {
            fdc_id: {
              type: 'number',
              description: 'FDC id (e.g. 1102704)',
            },
            nutrient_numbers: {
              type: 'string',
              description: 'Comma-separated nutrient numbers to restrict results (e.g. "208,205")',
            },
          },
          required: ['fdc_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_foods':     return this.searchFoods(args);
        case 'get_food':         return this.getFood(args);
        case 'list_foods':       return this.listFoods(args);
        case 'list_food_groups': return this.listFoodGroups();
        case 'nutrients_for_food': return this.nutrientsForFood(args);
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

  private async fdcGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'USDA FDC: unauthorized — check your API key' }],
        isError: true,
      };
    }
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'USDA FDC: not found' }],
        isError: true,
      };
    }
    if (response.status === 429) {
      return {
        content: [{ type: 'text', text: 'USDA FDC: rate-limit exceeded (HTTP 429)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USDA FDC error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchFoods(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      return {
        content: [{ type: 'text', text: 'search_foods: required argument "query" is missing or empty' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({
      api_key: this.apiKey,
      query: query,
      pageSize: String(Math.min(200, Math.max(1, (args.page_size as number) ?? 50))),
      pageNumber: String(Math.max(1, (args.page_number as number) ?? 1)),
    });
    if (args.data_type)   params.set('dataType',   String(args.data_type));
    if (args.brand_owner) params.set('brandOwner', String(args.brand_owner));
    if (args.sort_by)     params.set('sortBy',     String(args.sort_by));
    if (args.sort_order)  params.set('sortOrder',  String(args.sort_order));
    return this.fdcGet(`/foods/search?${params}`);
  }

  private async getFood(args: Record<string, unknown>): Promise<ToolResult> {
    const fdcId = args.fdc_id;
    if (typeof fdcId !== 'number' || !Number.isFinite(fdcId)) {
      return {
        content: [{ type: 'text', text: 'get_food: required argument "fdc_id" must be a number (e.g. 1102704)' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({
      api_key: this.apiKey,
      format: String(args.format ?? 'full'),
    });
    if (args.nutrients) params.set('nutrients', String(args.nutrients));
    return this.fdcGet(`/food/${fdcId}?${params}`);
  }

  private async listFoods(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      api_key: this.apiKey,
      pageSize: String(Math.min(200, Math.max(1, (args.page_size as number) ?? 50))),
      pageNumber: String(Math.max(1, (args.page_number as number) ?? 1)),
    });
    if (args.data_type)  params.set('dataType',  String(args.data_type));
    if (args.sort_by)    params.set('sortBy',    String(args.sort_by));
    if (args.sort_order) params.set('sortOrder', String(args.sort_order));
    return this.fdcGet(`/foods/list?${params}`);
  }

  private async listFoodGroups(): Promise<ToolResult> {
    // The FDC API does not expose a dedicated /food-groups endpoint.
    // The canonical reference is the WWEIA category list published at
    // https://fdc.nal.usda.gov/portal-data/wweia
    const data = {
      note: 'Food groups come from the WWEIA category list. See https://fdc.nal.usda.gov/portal-data/wweia for the full reference.',
      wweia_categories_url: 'https://fdc.nal.usda.gov/portal-data/wweia',
    };
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async nutrientsForFood(args: Record<string, unknown>): Promise<ToolResult> {
    const fdcId = args.fdc_id;
    if (typeof fdcId !== 'number' || !Number.isFinite(fdcId)) {
      return {
        content: [{ type: 'text', text: 'nutrients_for_food: required argument "fdc_id" must be a number (e.g. 1102704)' }],
        isError: true,
      };
    }
    const params = new URLSearchParams({
      api_key: this.apiKey,
      format: 'full',
    });
    if (args.nutrient_numbers) params.set('nutrients', String(args.nutrient_numbers));
    const raw = await this.fetchWithRetry(`${this.baseUrl}/food/${fdcId}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!raw.ok) {
      const errText = await raw.text().catch(() => raw.statusText);
      return {
        content: [{ type: 'text', text: `USDA FDC error: ${raw.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const full = (await raw.json()) as {
      fdcId?: number;
      description?: string;
      foodNutrients?: {
        nutrient?: { name?: string; number?: string; unitName?: string };
        amount?: number;
      }[];
    };
    const result = {
      fdc_id: full.fdcId,
      description: full.description,
      nutrients: (full.foodNutrients ?? [])
        .filter((n) => n.amount !== undefined)
        .map((n) => ({
          name: n.nutrient?.name,
          number: n.nutrient?.number,
          amount: n.amount,
          unit: n.nutrient?.unitName,
        })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
