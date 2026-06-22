/**
 * Open Food Facts Nutrition MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://world.openfoodfacts.org
// Auth: None — free public API
// Docs: https://openfoodfacts.github.io/openfoodfacts-server/api/
// Category: health
// Rate limits: No hard limit published; reasonable use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://world.openfoodfacts.org';

export class NutritionMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'nutrition',
      displayName: 'Open Food Facts Nutrition',
      version: '1.0.0',
      category: 'health' as const,
      keywords: [
        'nutrition', 'food', 'diet', 'calories', 'macros', 'protein',
        'carbohydrates', 'fat', 'fiber', 'nutriscore', 'nova', 'barcode',
        'ingredients', 'allergens', 'open food facts', 'food database',
        'health', 'wellness', 'eating', 'product', 'brand',
      ],
      toolNames: ['search_products', 'get_product'],
      description: 'Open Food Facts Nutrition: search food products by name or brand and retrieve full nutrition details by barcode — free public API, no authentication required.',
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
        name: 'search_products',
        description:
          'Search for food products by name, brand, or keyword. Returns product name, brand, Nutri-Score, and key nutrition facts.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (product name, brand, or ingredient)',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1-20, default 5)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_product',
        description:
          'Get full nutrition details for a food product by its barcode (EAN/UPC).',
        inputSchema: {
          type: 'object',
          properties: {
            barcode: {
              type: 'string',
              description: 'Product barcode (EAN-13 or UPC-A)',
            },
          },
          required: ['barcode'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_products':
          return this.searchProducts(
            args.query as string,
            typeof args.limit === 'number' ? args.limit : 5,
          );
        case 'get_product':
          return this.getProduct(args.barcode as string);
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

  private formatNutriments(n: Record<string, number | undefined> | undefined): Record<string, number | null> | null {
    if (!n) return null;
    return {
      calories_per_100g: (n['energy-kcal_100g'] as number | undefined) ?? null,
      fat_g: (n['fat_100g'] as number | undefined) ?? null,
      saturated_fat_g: (n['saturated-fat_100g'] as number | undefined) ?? null,
      carbohydrates_g: (n['carbohydrates_100g'] as number | undefined) ?? null,
      sugars_g: (n['sugars_100g'] as number | undefined) ?? null,
      fiber_g: (n['fiber_100g'] as number | undefined) ?? null,
      protein_g: (n['proteins_100g'] as number | undefined) ?? null,
      salt_g: (n['salt_100g'] as number | undefined) ?? null,
      sodium_g: (n['sodium_100g'] as number | undefined) ?? null,
    };
  }

  private async searchProducts(query: string, limit: number): Promise<ToolResult> {
    const count = Math.min(20, Math.max(1, limit));
    const params = new URLSearchParams({
      search_terms: query,
      json: '1',
      page_size: String(count),
    });
    const url = `${BASE_URL}/cgi/search.pl?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      return {
        content: [{ type: 'text', text: `Open Food Facts search error: ${response.status} ${response.statusText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { count: number; products: Array<Record<string, unknown>> };
    const products = (data.products ?? []).map((p) => ({
      barcode: (p['code'] ?? p['id']) as string | null ?? null,
      name: (p['product_name'] as string | undefined) ?? null,
      brand: (p['brands'] as string | undefined) ?? null,
      quantity: (p['quantity'] as string | undefined) ?? null,
      nutriscore: typeof p['nutriscore_grade'] === 'string'
        ? (p['nutriscore_grade'] as string).toUpperCase()
        : null,
      nova_group: (p['nova_group'] as number | undefined) ?? null,
      image_url: (p['image_url'] as string | undefined) ?? null,
      nutrition: this.formatNutriments(p['nutriments'] as Record<string, number | undefined> | undefined),
    }));
    return {
      content: [{ type: 'text', text: this.truncate({ total_found: data.count, products }) }],
      isError: false,
    };
  }

  private async getProduct(barcode: string): Promise<ToolResult> {
    const cleanBarcode = barcode.replace(/\D/g, '');
    const url = `${BASE_URL}/api/v2/product/${encodeURIComponent(cleanBarcode)}.json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      return {
        content: [{ type: 'text', text: `Open Food Facts error: ${response.status} ${response.statusText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { status: number; product: Record<string, unknown> };
    if (data.status === 0) {
      return {
        content: [{ type: 'text', text: `Product not found for barcode: "${barcode}"` }],
        isError: true,
      };
    }
    const p = data.product;
    const result = {
      barcode: cleanBarcode,
      name: (p['product_name'] as string | undefined) ?? null,
      brand: (p['brands'] as string | undefined) ?? null,
      quantity: (p['quantity'] as string | undefined) ?? null,
      serving_size: (p['serving_size'] as string | undefined) ?? null,
      categories: (p['categories'] as string | undefined) ?? null,
      ingredients: (p['ingredients_text'] as string | undefined) ?? null,
      allergens: (p['allergens'] as string | undefined) ?? null,
      nutriscore: typeof p['nutriscore_grade'] === 'string'
        ? (p['nutriscore_grade'] as string).toUpperCase()
        : null,
      nova_group: (p['nova_group'] as number | undefined) ?? null,
      image_url: (p['image_url'] as string | undefined) ?? null,
      nutrition_per_100g: this.formatNutriments(p['nutriments'] as Record<string, number | undefined> | undefined),
    };
    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }
}
