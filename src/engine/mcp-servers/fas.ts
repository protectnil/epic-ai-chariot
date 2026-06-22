/**
 * USDA Foreign Agricultural Service (FAS) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://apps.fas.usda.gov/OpenData/api
// Auth: none (public, no key required)
// Docs: https://apps.fas.usda.gov/OpenData
// Category: agriculture
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const PSD_BASE_URL  = 'https://apps.fas.usda.gov/OpenData/api/psd';
const GATS_BASE_URL = 'https://apps.fas.usda.gov/OpenData/api/gats';

// ── Commodity reference table ────────────────────────────────────────────────

interface CommodityInfo {
  code: string;
  name: string;
  category: string;
}

const COMMODITY_CODES: CommodityInfo[] = [
  { code: '0440000', name: 'Corn',                          category: 'Grains'   },
  { code: '0410000', name: 'Wheat',                         category: 'Grains'   },
  { code: '0450000', name: 'Rice, Milled',                  category: 'Grains'   },
  { code: '0451000', name: 'Rice, Rough',                   category: 'Grains'   },
  { code: '0460000', name: 'Barley',                        category: 'Grains'   },
  { code: '0459000', name: 'Sorghum',                       category: 'Grains'   },
  { code: '0430000', name: 'Oats',                          category: 'Grains'   },
  { code: '2222000', name: 'Soybeans',                      category: 'Oilseeds' },
  { code: '2232000', name: 'Soybean Meal',                  category: 'Oilseeds' },
  { code: '2234000', name: 'Soybean Oil',                   category: 'Oilseeds' },
  { code: '2226000', name: 'Rapeseed (Canola)',              category: 'Oilseeds' },
  { code: '2224000', name: 'Sunflowerseed',                 category: 'Oilseeds' },
  { code: '2223000', name: 'Peanuts',                       category: 'Oilseeds' },
  { code: '2631000', name: 'Palm Oil',                      category: 'Oilseeds' },
  { code: '0574000', name: 'Cotton',                        category: 'Fiber'    },
  { code: '0114000', name: 'Beef and Veal',                 category: 'Meat'     },
  { code: '0112000', name: 'Pork',                          category: 'Meat'     },
  { code: '0113000', name: 'Poultry, Broiler',              category: 'Meat'     },
  { code: '0401000', name: 'Dairy, Butter',                 category: 'Dairy'    },
  { code: '0402000', name: 'Dairy, Cheese',                 category: 'Dairy'    },
  { code: '0404000', name: 'Dairy, Dry Whole Milk Powder',  category: 'Dairy'    },
  { code: '0405000', name: 'Dairy, Nonfat Dry Milk',        category: 'Dairy'    },
  { code: '0612000', name: 'Sugar, Centrifugal',            category: 'Sugar'    },
  { code: '0711000', name: 'Coffee, Green',                 category: 'Tropical' },
  { code: '0721000', name: 'Cocoa Beans',                   category: 'Tropical' },
];

const COUNTRY_CODES: Record<string, string> = {
  US: 'United States', BR: 'Brazil',      CN: 'China',
  AR: 'Argentina',     IN: 'India',        AU: 'Australia',
  CA: 'Canada',        EU: 'European Union', RU: 'Russia',
  UA: 'Ukraine',       ID: 'Indonesia',    TH: 'Thailand',
  MX: 'Mexico',        JP: 'Japan',        KR: 'South Korea',
  EG: 'Egypt',         NG: 'Nigeria',      PK: 'Pakistan',
  VN: 'Vietnam',       MY: 'Malaysia',
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function findCommodityCode(name: string): string | null {
  const lower = name.toLowerCase();
  const match = COMMODITY_CODES.find(
    (c) => c.name.toLowerCase() === lower || c.name.toLowerCase().includes(lower),
  );
  return match?.code ?? null;
}

function normalizeTradeRecord(r: Record<string, unknown>) {
  return {
    year:         r.year         ?? r.Year         ?? null,
    month:        r.month        ?? r.Month        ?? null,
    partner:      r.partnerDesc  ?? r.PartnerDesc  ?? r.partner ?? null,
    partner_code: r.partnerCode  ?? r.PartnerCode  ?? null,
    value:        r.value        ?? r.Value        ?? null,
    quantity:     r.quantity     ?? r.Quantity     ?? null,
    unit:         r.unit         ?? r.Unit         ?? null,
  };
}

function normalizePsdRecord(r: Record<string, unknown>) {
  return {
    country:      r.countryDesc   ?? r.CountryDesc   ?? r.country   ?? null,
    country_code: r.countryCode   ?? r.CountryCode   ?? null,
    market_year:  r.marketYear    ?? r.MarketYear    ?? null,
    attribute:    r.attributeDesc ?? r.AttributeDesc ?? r.attribute ?? null,
    value:        r.value         ?? r.Value         ?? null,
    unit:         r.unitDesc      ?? r.UnitDesc      ?? r.unit      ?? null,
  };
}

// ── Adapter ──────────────────────────────────────────────────────────────────

export class FasMCPServer extends MCPAdapterBase {
  private readonly psdBaseUrl:  string;
  private readonly gatsBaseUrl: string;

  constructor(config?: { psdBaseUrl?: string; gatsBaseUrl?: string }) {
    super();
    if (config === null) { throw new Error('FasMCPServer: configuration object is required when provided'); }
    this.psdBaseUrl  = config?.psdBaseUrl  ?? PSD_BASE_URL;
    this.gatsBaseUrl = config?.gatsBaseUrl ?? GATS_BASE_URL;
  }

  static catalog() {
    return {
      name:        'fas',
      displayName: 'USDA Foreign Agricultural Service',
      version:     '1.0.0',
      category:    'agriculture',
      keywords: [
        'usda', 'fas', 'agriculture', 'agricultural', 'trade', 'exports', 'imports',
        'production', 'supply', 'distribution', 'psd', 'gats', 'commodity',
        'corn', 'wheat', 'soybeans', 'cotton', 'beef', 'pork', 'dairy',
        'global markets', 'food security', 'crop', 'livestock',
      ],
      toolNames: ['fas_exports', 'fas_imports', 'fas_production', 'fas_commodity_codes'],
      description:
        'USDA Foreign Agricultural Service OpenData: US agricultural export/import trade data ' +
        'via GATS and world production/supply/distribution estimates via the PSD database. ' +
        'No authentication required.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none'             as const,
        probeState:    'no-auth-verified' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'fas_exports',
        description:
          'Get US agricultural export data by commodity and destination country. ' +
          'Uses USDA FAS GATS (Global Agricultural Trade System) data. ' +
          'Shows export volumes and values.',
        inputSchema: {
          type: 'object',
          properties: {
            commodity: {
              type: 'string',
              description:
                'Commodity name (e.g. "corn", "soybeans", "wheat", "beef", "pork", "cotton") or commodity code.',
            },
            country: {
              type: 'string',
              description:
                'Destination country code (e.g. "CN" for China, "MX" for Mexico, "JP" for Japan). ' +
                'Optional — omit for all destinations.',
            },
            start_year: {
              type: 'string',
              description: 'Start year (e.g. "2020"). Optional.',
            },
            end_year: {
              type: 'string',
              description: 'End year (e.g. "2024"). Optional.',
            },
          },
          required: ['commodity'],
        },
      },
      {
        name: 'fas_imports',
        description:
          'Get US agricultural import data by commodity and origin country. ' +
          'Shows import volumes and values from USDA FAS GATS trade data.',
        inputSchema: {
          type: 'object',
          properties: {
            commodity: {
              type: 'string',
              description:
                'Commodity name (e.g. "coffee", "cocoa", "sugar", "beef") or commodity code.',
            },
            country: {
              type: 'string',
              description:
                'Origin country code (e.g. "BR" for Brazil, "CO" for Colombia). ' +
                'Optional — omit for all origins.',
            },
            start_year: {
              type: 'string',
              description: 'Start year. Optional.',
            },
            end_year: {
              type: 'string',
              description: 'End year. Optional.',
            },
          },
          required: ['commodity'],
        },
      },
      {
        name: 'fas_production',
        description:
          'Get world production, supply, and distribution estimates for agricultural commodities ' +
          'from the USDA FAS PSD (Production, Supply & Distribution) database. ' +
          'Covers global production, consumption, stocks, and trade flows.',
        inputSchema: {
          type: 'object',
          properties: {
            commodity: {
              type: 'string',
              description:
                'Commodity name (e.g. "corn", "soybeans", "wheat") or PSD commodity code (e.g. "0440000").',
            },
            country: {
              type: 'string',
              description:
                'Country code (e.g. "US", "BR", "CN"). Optional — omit for world totals.',
            },
            market_year: {
              type: 'string',
              description: 'Market year (e.g. "2024"). Optional.',
            },
          },
          required: ['commodity'],
        },
      },
      {
        name: 'fas_commodity_codes',
        description:
          'List available USDA FAS PSD commodity codes with names and categories. ' +
          'Use these codes with fas_production, fas_exports, and fas_imports. ' +
          'Supports filtering by category or keyword.',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description:
                'Filter by category: "Grains", "Oilseeds", "Meat", "Dairy", "Fiber", "Sugar", "Tropical". Optional.',
            },
            search: {
              type: 'string',
              description: 'Search keyword (e.g. "soy", "wheat"). Optional.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'fas_exports':         return this.getExports(args);
        case 'fas_imports':         return this.getImports(args);
        case 'fas_production':      return this.getProduction(args);
        case 'fas_commodity_codes': return this.getCommodityCodes(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  // ── Private: shared fetch ────────────────────────────────────────────────

  private async fasGet(
    baseUrl: string,
    path: string,
    params?: Record<string, string>,
  ): Promise<unknown> {
    const url = new URL(`${baseUrl}${path}`);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v) url.searchParams.set(k, v);
      }
    }
    const response = await this.fetchWithRetry(url.toString(), {
      method:  'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      if (response.status === 404) {
        throw new Error(
          `FAS API endpoint not found (${response.status}). ` +
          `The USDA FAS API may have changed. ` +
          `Alternative: https://apps.fas.usda.gov/psdonline for manual PSD access. ` +
          `Detail: ${text}`,
        );
      }
      throw new Error(`FAS API error (${response.status}): ${text}`);
    }
    return response.json();
  }

  // ── Private: tool implementations ────────────────────────────────────────

  private async getExports(args: Record<string, unknown>): Promise<ToolResult> {
    const commodity     = args.commodity as string;
    const commodityCode = findCommodityCode(commodity) ?? commodity;

    const params: Record<string, string> = {};
    if (args.country)    params.partnerCode = args.country    as string;
    if (args.start_year) params.startYear   = args.start_year as string;
    if (args.end_year)   params.endYear     = args.end_year   as string;

    try {
      const data    = await this.fasGet(this.gatsBaseUrl, `/exports/commodity/${commodityCode}`, params);
      const records = Array.isArray(data) ? data : [];
      const result  = {
        commodity,
        commodity_code: commodityCode,
        direction:      'exports',
        count:          records.length,
        data:           records.slice(0, 100).map((r: Record<string, unknown>) => normalizeTradeRecord(r)),
        truncated:      records.length > 100,
      };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    } catch (primaryErr) {
      // Fallback: query param form
      try {
        const altData  = await this.fasGet(this.gatsBaseUrl, '/exports', { ...params, commodityCode });
        const records  = Array.isArray(altData) ? altData : [];
        const result   = {
          commodity,
          commodity_code: commodityCode,
          direction:      'exports',
          count:          records.length,
          data:           records.slice(0, 100),
          truncated:      records.length > 100,
        };
        return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
      } catch {
        const msg =
          `Could not retrieve FAS export data for "${commodity}". ` +
          `The FAS API may have changed or be temporarily unavailable. ` +
          `Alternatives: (1) https://apps.fas.usda.gov/gats, ` +
          `(2) fas_commodity_codes to verify the commodity code. ` +
          `Original error: ${primaryErr instanceof Error ? primaryErr.message : String(primaryErr)}`;
        return { content: [{ type: 'text', text: msg }], isError: true };
      }
    }
  }

  private async getImports(args: Record<string, unknown>): Promise<ToolResult> {
    const commodity     = args.commodity as string;
    const commodityCode = findCommodityCode(commodity) ?? commodity;

    const params: Record<string, string> = {};
    if (args.country)    params.partnerCode = args.country    as string;
    if (args.start_year) params.startYear   = args.start_year as string;
    if (args.end_year)   params.endYear     = args.end_year   as string;

    try {
      const data    = await this.fasGet(this.gatsBaseUrl, `/imports/commodity/${commodityCode}`, params);
      const records = Array.isArray(data) ? data : [];
      const result  = {
        commodity,
        commodity_code: commodityCode,
        direction:      'imports',
        count:          records.length,
        data:           records.slice(0, 100).map((r: Record<string, unknown>) => normalizeTradeRecord(r)),
        truncated:      records.length > 100,
      };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    } catch (primaryErr) {
      try {
        const altData  = await this.fasGet(this.gatsBaseUrl, '/imports', { ...params, commodityCode });
        const records  = Array.isArray(altData) ? altData : [];
        const result   = {
          commodity,
          commodity_code: commodityCode,
          direction:      'imports',
          count:          records.length,
          data:           records.slice(0, 100),
          truncated:      records.length > 100,
        };
        return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
      } catch {
        const msg =
          `Could not retrieve FAS import data for "${commodity}". ` +
          `The FAS API may have changed or be temporarily unavailable. ` +
          `Alternatives: (1) https://apps.fas.usda.gov/gats, ` +
          `(2) fas_commodity_codes to verify the commodity code. ` +
          `Original error: ${primaryErr instanceof Error ? primaryErr.message : String(primaryErr)}`;
        return { content: [{ type: 'text', text: msg }], isError: true };
      }
    }
  }

  private async getProduction(args: Record<string, unknown>): Promise<ToolResult> {
    const commodity     = args.commodity as string;
    const commodityCode = findCommodityCode(commodity) ?? commodity;

    const params: Record<string, string> = {};
    if (args.country)     params.countryCode = args.country     as string;
    if (args.market_year) params.marketYear  = args.market_year as string;

    try {
      const data    = await this.fasGet(this.psdBaseUrl, `/commodity/${commodityCode}`, params);
      const records = Array.isArray(data) ? data : [];
      const result  = {
        commodity,
        commodity_code: commodityCode,
        type:           'production_supply_distribution',
        count:          records.length,
        data:           records.slice(0, 100).map((r: Record<string, unknown>) => normalizePsdRecord(r)),
        truncated:      records.length > 100,
      };
      return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
    } catch (primaryErr) {
      try {
        const altData  = await this.fasGet(this.psdBaseUrl, '', { ...params, commodityCode });
        const records  = Array.isArray(altData) ? altData : [];
        const result   = {
          commodity,
          commodity_code: commodityCode,
          type:           'production_supply_distribution',
          count:          records.length,
          data:           records.slice(0, 100),
          truncated:      records.length > 100,
        };
        return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
      } catch {
        const msg =
          `Could not retrieve FAS PSD data for "${commodity}" (code: ${commodityCode}). ` +
          `The FAS PSD API may have changed or be temporarily unavailable. ` +
          `Alternatives: (1) https://apps.fas.usda.gov/psdonline for manual PSD data, ` +
          `(2) fas_commodity_codes to verify the commodity code. ` +
          `Original error: ${primaryErr instanceof Error ? primaryErr.message : String(primaryErr)}`;
        return { content: [{ type: 'text', text: msg }], isError: true };
      }
    }
  }

  private getCommodityCodes(args: Record<string, unknown>): ToolResult {
    let filtered = COMMODITY_CODES;

    if (args.category) {
      const cat = (args.category as string).toLowerCase();
      filtered  = filtered.filter((c) => c.category.toLowerCase() === cat);
    }
    if (args.search) {
      const term = (args.search as string).toLowerCase();
      filtered   = filtered.filter(
        (c) =>
          c.name.toLowerCase().includes(term) ||
          c.category.toLowerCase().includes(term) ||
          c.code.includes(term),
      );
    }

    const grouped: Record<string, { code: string; name: string }[]> = {};
    for (const c of filtered) {
      if (!grouped[c.category]) grouped[c.category] = [];
      grouped[c.category].push({ code: c.code, name: c.name });
    }

    const result = {
      total:         filtered.length,
      categories:    grouped,
      country_codes: COUNTRY_CODES,
      note:
        'Use commodity codes with fas_production, fas_exports, and fas_imports. ' +
        'Country codes are ISO 2-letter codes.',
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
