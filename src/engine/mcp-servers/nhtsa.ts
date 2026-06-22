/**
 * NHTSA vPIC MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://vpic.nhtsa.dot.gov/api (NHTSA Vehicle Product Information Catalog)
// Auth: none (public, no-auth-verified)
// Docs: https://vpic.nhtsa.dot.gov/api/
// Category: automotive
// Rate limits: None documented; public government API

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://vpic.nhtsa.dot.gov/api';

export class NhtsaMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NhtsaMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'nhtsa',
      displayName: 'NHTSA vPIC',
      version: '1.0.0',
      category: 'automotive',
      keywords: [
        'nhtsa', 'vin', 'vehicle', 'decode vin', 'vehicle identification number',
        'make', 'model', 'year', 'automotive', 'car', 'truck', 'vehicle lookup',
        'vehicle data', 'vpic', 'dot', 'government', 'recall', 'safety',
      ],
      toolNames: ['decode_vin', 'get_makes', 'get_models'],
      description: 'NHTSA vPIC: decode a Vehicle Identification Number (VIN) into make, model, year, and detailed attributes; retrieve all registered vehicle makes; and list models for a given make and model year. Free public API, no authentication required.',
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
        name: 'decode_vin',
        description:
          'Decode a 17-character Vehicle Identification Number (VIN) to get make, model, year, body style, engine, and other attributes.',
        inputSchema: {
          type: 'object',
          properties: {
            vin: {
              type: 'string',
              description: '17-character VIN (e.g., "1HGBH41JXMN109186")',
            },
          },
          required: ['vin'],
        },
      },
      {
        name: 'get_makes',
        description: 'Retrieve all vehicle makes (brands) registered with NHTSA.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_models',
        description: 'Get all vehicle models available for a specific make and model year.',
        inputSchema: {
          type: 'object',
          properties: {
            make: {
              type: 'string',
              description: 'Vehicle make name (e.g., "Toyota", "Ford", "BMW")',
            },
            year: {
              type: 'number',
              description: 'Model year (e.g., 2022)',
            },
          },
          required: ['make', 'year'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'decode_vin':  return this.decodeVin(args.vin as string);
        case 'get_makes':   return this.getMakes();
        case 'get_models':  return this.getModels(args.make as string, args.year as number);
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

  private async decodeVin(vin: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/vehicles/DecodeVin/${encodeURIComponent(vin)}?format=json`;
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
    const data = (await response.json()) as {
      Results?: Array<{ Variable?: string; Value?: string | null; ValueId?: string | null }>;
      Message?: string;
    };

    if (!data.Results || data.Results.length === 0) {
      return {
        content: [{ type: 'text', text: 'No results returned for VIN' }],
        isError: true,
      };
    }

    const attributes: Record<string, string> = {};
    for (const r of data.Results) {
      if (r.Variable && r.Value && r.Value.trim() !== '' && r.Value !== 'Not Applicable') {
        attributes[r.Variable] = r.Value;
      }
    }

    const result = {
      vin: vin.toUpperCase(),
      make: attributes['Make'] ?? null,
      model: attributes['Model'] ?? null,
      model_year: attributes['Model Year'] ?? null,
      trim: attributes['Trim'] ?? null,
      vehicle_type: attributes['Vehicle Type'] ?? null,
      body_class: attributes['Body Class'] ?? null,
      doors: attributes['Doors'] ?? null,
      drive_type: attributes['Drive Type'] ?? null,
      fuel_type_primary: attributes['Fuel Type - Primary'] ?? null,
      engine_cylinders: attributes['Engine Number of Cylinders'] ?? null,
      engine_displacement_l: attributes['Displacement (L)'] ?? null,
      transmission: attributes['Transmission Style'] ?? null,
      plant_country: attributes['Plant Country'] ?? null,
      manufacturer: attributes['Manufacturer Name'] ?? null,
      all_attributes: attributes,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getMakes(): Promise<ToolResult> {
    const url = `${this.baseUrl}/vehicles/GetAllMakes?format=json`;
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
    const data = (await response.json()) as {
      Results?: Array<{ Make_ID?: number; Make_Name?: string }>;
      Count?: number;
    };

    const result = {
      count: data.Count ?? (data.Results?.length ?? 0),
      makes: (data.Results ?? []).map((m) => ({
        id: m.Make_ID ?? null,
        name: m.Make_Name ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getModels(make: string, year: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/vehicles/GetModelsForMakeYear/make/${encodeURIComponent(make)}/modelyear/${year}?format=json`;
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
    const data = (await response.json()) as {
      Results?: Array<{
        Make_ID?: number;
        Make_Name?: string;
        Model_ID?: number;
        Model_Name?: string;
      }>;
      Count?: number;
    };

    const result = {
      make,
      year,
      count: data.Count ?? (data.Results?.length ?? 0),
      models: (data.Results ?? []).map((m) => ({
        make_id: m.Make_ID ?? null,
        make_name: m.Make_Name ?? null,
        model_id: m.Model_ID ?? null,
        model_name: m.Model_Name ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
