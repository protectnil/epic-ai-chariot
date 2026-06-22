/**
 * HUD (U.S. Department of Housing and Urban Development) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://www.huduser.gov/hudapi/public
// Auth: Bearer token (API key) — get one at https://www.huduser.gov/portal/dataset/fmr-api.html
// Docs: https://www.huduser.gov/portal/dataset/fmr-api.html
// Category: government
// Rate limits: Determined by HUD user account tier

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface HudConfig {
  apiKey: string;
  baseUrl?: string;
}

export class HudMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: HudConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('HUD: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('HUD: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://www.huduser.gov/hudapi/public';
  }

  static catalog() {
    return {
      name: 'hud',
      displayName: 'HUD (U.S. Dept. of Housing and Urban Development)',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'hud', 'housing', 'fair market rents', 'fmr', 'income limits',
        'section 8', 'housing voucher', 'chas', 'housing affordability',
        'zip crosswalk', 'usps crosswalk', 'cbsa', 'census tract', 'county',
        'affordable housing', 'hud api', 'federal housing', 'rental assistance',
        'low income', 'housing programs', 'urban development',
      ],
      toolNames: [
        'hud_fair_market_rents',
        'hud_income_limits',
        'hud_crosswalk',
        'hud_chas',
        'hud_list_states',
      ],
      description: 'HUD public APIs: fetch Fair Market Rents, income limits, USPS ZIP geographic crosswalks, Comprehensive Housing Affordability Strategy (CHAS) data, and state code lookups from the U.S. Department of Housing and Urban Development.',
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
        name: 'hud_fair_market_rents',
        description:
          'Get Fair Market Rents (FMR) from HUD. FMRs are used to determine payment standards for the Housing Choice Voucher program, initial rents for Section 8 project-based assistance, and rent ceilings for HOME-assisted rental units. Returns rent estimates by bedroom count.',
        inputSchema: {
          type: 'object',
          properties: {
            state_code: {
              type: 'string',
              description: 'Two-letter state code (e.g., "CA", "NY", "TX"). Required to get state-level summary.',
            },
            entity_id: {
              type: 'string',
              description: 'FIPS code or ZIP code to get FMR for a specific area. Omit to get all areas in the state.',
            },
            year: {
              type: 'number',
              description: 'Fiscal year (e.g., 2024). Omit for the most recent year.',
            },
          },
          required: ['state_code'],
        },
      },
      {
        name: 'hud_income_limits',
        description:
          'Get HUD income limits for housing programs by area. Income limits determine eligibility for HUD-assisted housing programs. Returns thresholds for extremely low, very low, and low income categories by family size.',
        inputSchema: {
          type: 'object',
          properties: {
            state_code: {
              type: 'string',
              description: 'Two-letter state code (e.g., "CA", "NY").',
            },
            entity_id: {
              type: 'string',
              description: 'FIPS code or metro area code for a specific area. Omit to get all areas in the state.',
            },
            year: {
              type: 'number',
              description: 'Fiscal year (e.g., 2024). Omit for the most recent year.',
            },
          },
          required: ['state_code'],
        },
      },
      {
        name: 'hud_crosswalk',
        description:
          'HUD USPS ZIP code crosswalk. Maps between ZIP codes, census tracts, counties, CBSAs (metro areas), and congressional districts. Essential for geographic analysis when joining data from different sources.',
        inputSchema: {
          type: 'object',
          properties: {
            type: {
              type: 'number',
              description: 'Crosswalk type: 1=ZIP-to-tract, 2=ZIP-to-county, 3=ZIP-to-CBSA, 4=ZIP-to-congressional-district, 7=county-to-ZIP.',
            },
            query: {
              type: 'string',
              description: 'Input value: ZIP code (for types 1-4), or FIPS county code (for type 7). Example: "90210" or "06037".',
            },
          },
          required: ['type', 'query'],
        },
      },
      {
        name: 'hud_chas',
        description:
          'Get Comprehensive Housing Affordability Strategy (CHAS) data from HUD. CHAS data demonstrates the extent of housing problems and housing needs, particularly for low-income households. Used by communities to plan affordable housing.',
        inputSchema: {
          type: 'object',
          properties: {
            state_code: {
              type: 'string',
              description: 'Two-letter state code (e.g., "CA", "NY").',
            },
            entity_id: {
              type: 'string',
              description: 'FIPS code for a specific county or place. Omit to get state-level data.',
            },
            year: {
              type: 'number',
              description: 'Data year (e.g., 2020). Omit for the most recent available.',
            },
          },
          required: ['state_code'],
        },
      },
      {
        name: 'hud_list_states',
        description:
          'List all U.S. state codes and names recognized by the HUD API. Useful for discovering valid state codes to use with other HUD tools.',
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
        case 'hud_fair_market_rents': return this.hudFairMarketRents(args);
        case 'hud_income_limits':     return this.hudIncomeLimits(args);
        case 'hud_crosswalk':         return this.hudCrosswalk(args);
        case 'hud_chas':              return this.hudChas(args);
        case 'hud_list_states':       return this.hudListStates();
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

  private async hudRequest(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        Accept: 'application/json',
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `HUD API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async hudFairMarketRents(args: Record<string, unknown>): Promise<ToolResult> {
    const stateCode = args.state_code as string;
    const entityId = args.entity_id as string | undefined;
    const year = args.year as number | undefined;

    let path: string;
    if (entityId) {
      const params = new URLSearchParams();
      if (year) params.set('year', String(year));
      const qs = params.toString();
      path = `/fmr/data/${encodeURIComponent(entityId)}${qs ? `?${qs}` : ''}`;
    } else {
      path = `/fmr/statedata/${encodeURIComponent(stateCode)}`;
      if (year) path += `?year=${year}`;
    }

    return this.hudRequest(path);
  }

  private async hudIncomeLimits(args: Record<string, unknown>): Promise<ToolResult> {
    const stateCode = args.state_code as string;
    const entityId = args.entity_id as string | undefined;
    const year = args.year as number | undefined;

    let path: string;
    if (entityId) {
      const params = new URLSearchParams();
      if (year) params.set('year', String(year));
      const qs = params.toString();
      path = `/il/data/${encodeURIComponent(entityId)}${qs ? `?${qs}` : ''}`;
    } else {
      path = `/il/statedata/${encodeURIComponent(stateCode)}`;
      if (year) path += `?year=${year}`;
    }

    return this.hudRequest(path);
  }

  private async hudCrosswalk(args: Record<string, unknown>): Promise<ToolResult> {
    const type = args.type as number;
    const query = args.query as string;
    return this.hudRequest(`/usps?type=${type}&query=${encodeURIComponent(query)}`);
  }

  private async hudChas(args: Record<string, unknown>): Promise<ToolResult> {
    const stateCode = args.state_code as string;
    const entityId = args.entity_id as string | undefined;
    const year = args.year as number | undefined;

    let path: string;
    if (entityId) {
      const params = new URLSearchParams();
      if (year) params.set('year', String(year));
      const qs = params.toString();
      path = `/chas/data/${encodeURIComponent(entityId)}${qs ? `?${qs}` : ''}`;
    } else {
      path = `/chas/statedata/${encodeURIComponent(stateCode)}`;
      if (year) path += `?year=${year}`;
    }

    return this.hudRequest(path);
  }

  private async hudListStates(): Promise<ToolResult> {
    return this.hudRequest('/fmr/listStates');
  }
}
