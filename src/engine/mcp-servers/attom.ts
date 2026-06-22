/**
 * ATTOM Data Solutions MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

//
// Base URL: https://api.gateway.attomdata.com/propertyapi/v1.0.0
// Auth: Required — ATTOM API key passed via `apikey` request header.
//       Obtain a key at https://api.gateway.attomdata.com
// Docs: https://api.developer.attomdata.com/docs
// Category: real-estate
// Rate limits: Depends on subscription plan.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface AttomConfig {
  apiKey: string;
  baseUrl?: string;
}

export class AttomMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: AttomConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('ATTOM: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('ATTOM: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.gateway.attomdata.com/propertyapi/v1.0.0';
  }

  static catalog() {
    return {
      name: 'attom',
      displayName: 'ATTOM Data Solutions',
      version: '1.0.0',
      category: 'real-estate',
      keywords: [
        'attom', 'real estate', 'property', 'avm', 'automated valuation',
        'property detail', 'property search', 'sales history', 'assessment',
        'tax assessment', 'sales trend', 'rental avm', 'rental valuation',
        'school search', 'mortgage', 'home value', 'market data',
        'residential', 'commercial', 'address lookup', 'zip code',
      ],
      toolNames: [
        'attom_property_detail',
        'attom_property_search',
        'attom_sales_history',
        'attom_avm',
        'attom_assessment',
        'attom_sales_trend',
        'attom_rental_avm',
        'attom_school_search',
      ],
      description: 'ATTOM Data Solutions: property detail, address-based search, sales history, automated valuations (AVM), tax assessments, market sales trends, rental AVMs, and school search — directly via the ATTOM REST API.',
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
        name: 'attom_property_detail',
        description:
          'Get full property characteristics by address — lot size, square footage, bedrooms, bathrooms, year built, construction type, heating/cooling, and more.',
        inputSchema: {
          type: 'object',
          properties: {
            address1: { type: 'string', description: 'Street address (e.g., "123 Main St")' },
            address2: { type: 'string', description: 'City, state ZIP (e.g., "Denver, CO 80202")' },
          },
          required: ['address1', 'address2'],
        },
      },
      {
        name: 'attom_property_search',
        description:
          'Search properties by location with optional filters. Search by postal code or by latitude/longitude with a radius.',
        inputSchema: {
          type: 'object',
          properties: {
            postalCode: { type: 'string', description: 'ZIP/postal code to search in' },
            latitude: { type: 'string', description: 'Latitude for radius search (use with longitude and radius)' },
            longitude: { type: 'string', description: 'Longitude for radius search (use with latitude and radius)' },
            radius: { type: 'string', description: 'Search radius in miles (use with latitude/longitude)' },
            propertyType: { type: 'string', description: 'Property type filter (e.g., "SFR", "CONDO", "APARTMENT")' },
            minBeds: { type: 'string', description: 'Minimum number of bedrooms' },
            maxBeds: { type: 'string', description: 'Maximum number of bedrooms' },
            minBathsTotal: { type: 'string', description: 'Minimum total bathrooms' },
            maxBathsTotal: { type: 'string', description: 'Maximum total bathrooms' },
            minYearBuilt: { type: 'string', description: 'Minimum year built' },
            maxYearBuilt: { type: 'string', description: 'Maximum year built' },
          },
        },
      },
      {
        name: 'attom_sales_history',
        description:
          'Get complete sales history for a property (up to 10 years) — sale dates, prices, deed types, seller/buyer info.',
        inputSchema: {
          type: 'object',
          properties: {
            address1: { type: 'string', description: 'Street address (e.g., "123 Main St")' },
            address2: { type: 'string', description: 'City, state ZIP (e.g., "Denver, CO 80202")' },
          },
          required: ['address1', 'address2'],
        },
      },
      {
        name: 'attom_avm',
        description:
          'Get automated valuation (AVM) for a property — estimated market value, confidence score, value range (low/high).',
        inputSchema: {
          type: 'object',
          properties: {
            address1: { type: 'string', description: 'Street address (e.g., "123 Main St")' },
            address2: { type: 'string', description: 'City, state ZIP (e.g., "Denver, CO 80202")' },
          },
          required: ['address1', 'address2'],
        },
      },
      {
        name: 'attom_assessment',
        description:
          'Get property tax assessment details — assessed value, market value, tax amount, tax year, and assessment history.',
        inputSchema: {
          type: 'object',
          properties: {
            address1: { type: 'string', description: 'Street address (e.g., "123 Main St")' },
            address2: { type: 'string', description: 'City, state ZIP (e.g., "Denver, CO 80202")' },
          },
          required: ['address1', 'address2'],
        },
      },
      {
        name: 'attom_sales_trend',
        description:
          'Get market sales trends by ZIP code — average/median sale price, volume, and price changes over time.',
        inputSchema: {
          type: 'object',
          properties: {
            geoid: { type: 'string', description: 'ZIP code prefixed with "ZI" (e.g., "ZI80202")' },
            interval: { type: 'string', description: 'Time interval: monthly, quarterly, or yearly' },
            startYear: { type: 'string', description: 'Start year (e.g., "2020")' },
            endYear: { type: 'string', description: 'End year (e.g., "2024")' },
          },
          required: ['geoid', 'interval', 'startYear', 'endYear'],
        },
      },
      {
        name: 'attom_rental_avm',
        description:
          'Get rental property AVM — estimated monthly rent, rental yield, and rental value range.',
        inputSchema: {
          type: 'object',
          properties: {
            address1: { type: 'string', description: 'Street address (e.g., "123 Main St")' },
            address2: { type: 'string', description: 'City, state ZIP (e.g., "Denver, CO 80202")' },
          },
          required: ['address1', 'address2'],
        },
      },
      {
        name: 'attom_school_search',
        description:
          'Search schools near a location — name, type (public/private), grades, distance, and rankings.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'string', description: 'Latitude of the search center' },
            longitude: { type: 'string', description: 'Longitude of the search center' },
            radius: { type: 'string', description: 'Search radius in miles (default 5, max 20)' },
          },
          required: ['latitude', 'longitude'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'attom_property_detail':
          return this.propertyDetail(args);
        case 'attom_property_search':
          return this.propertySearch(args);
        case 'attom_sales_history':
          return this.salesHistory(args);
        case 'attom_avm':
          return this.avm(args);
        case 'attom_assessment':
          return this.assessment(args);
        case 'attom_sales_trend':
          return this.salesTrend(args);
        case 'attom_rental_avm':
          return this.rentalAvm(args);
        case 'attom_school_search':
          return this.schoolSearch(args);
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

  private async attomGet(path: string, params: Record<string, string> = {}): Promise<ToolResult> {
    const url = new URL(`${this.baseUrl}${path}`);
    for (const [k, v] of Object.entries(params)) {
      if (v) url.searchParams.set(k, v);
    }
    const response = await this.fetchWithRetry(url.toString(), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        apikey: this.apiKey,
      },
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

  private async propertyDetail(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/property/detail', {
      address1: args.address1 as string,
      address2: args.address2 as string,
    });
  }

  private async propertySearch(args: Record<string, unknown>): Promise<ToolResult> {
    const params: Record<string, string> = {};
    if (args.postalCode) params.postalCode = args.postalCode as string;
    if (args.latitude) params.latitude = args.latitude as string;
    if (args.longitude) params.longitude = args.longitude as string;
    if (args.radius) params.radius = args.radius as string;
    if (args.propertyType) params.propertytype = args.propertyType as string;
    if (args.minBeds) params.minBeds = args.minBeds as string;
    if (args.maxBeds) params.maxBeds = args.maxBeds as string;
    if (args.minBathsTotal) params.minBathsTotal = args.minBathsTotal as string;
    if (args.maxBathsTotal) params.maxBathsTotal = args.maxBathsTotal as string;
    if (args.minYearBuilt) params.minYearBuilt = args.minYearBuilt as string;
    if (args.maxYearBuilt) params.maxYearBuilt = args.maxYearBuilt as string;
    if (!params.postalCode && !params.latitude) {
      return {
        content: [{ type: 'text', text: 'Either postalCode or latitude+longitude is required for property search.' }],
        isError: true,
      };
    }
    return this.attomGet('/property/snapshot', params);
  }

  private async salesHistory(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/saleshistory/expandedhistory', {
      address1: args.address1 as string,
      address2: args.address2 as string,
    });
  }

  private async avm(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/attomavm/detail', {
      address1: args.address1 as string,
      address2: args.address2 as string,
    });
  }

  private async assessment(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/assessment/detail', {
      address1: args.address1 as string,
      address2: args.address2 as string,
    });
  }

  private async salesTrend(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/salestrend/snapshot', {
      geoid: args.geoid as string,
      interval: args.interval as string,
      startyear: args.startYear as string,
      endyear: args.endYear as string,
    });
  }

  private async rentalAvm(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/valuation/rentalavm', {
      address1: args.address1 as string,
      address2: args.address2 as string,
    });
  }

  private async schoolSearch(args: Record<string, unknown>): Promise<ToolResult> {
    return this.attomGet('/school/search', {
      latitude: args.latitude as string,
      longitude: args.longitude as string,
      radius: (args.radius as string) ?? '5',
    });
  }
}
