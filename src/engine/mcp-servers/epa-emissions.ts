/**
 * EPA Emissions MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: EPA Envirofacts DMAP REST API (free, no auth required)
 * Combines GHGRP (greenhouse gas) and TRI (toxic releases) data.
 * API pattern: GET https://data.epa.gov/dmapservice/[schema].[table]/[col]/[op]/[val]/[first]:[last]/[format]
 *
 * Base URL: https://data.epa.gov/dmapservice
 * Auth: none (public government API)
 * Docs: https://www.epa.gov/enviro/envirofacts-data-service-api
 * Category: environment
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://data.epa.gov/dmapservice';

export class EpaEmissionsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('EpaEmissionsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'epa-emissions',
      displayName: 'EPA Emissions (GHGRP + TRI)',
      version: '1.0.0',
      category: 'environment',
      keywords: [
        'epa', 'emissions', 'greenhouse gas', 'ghg', 'ghgrp', 'tri',
        'toxic release', 'toxic release inventory', 'co2', 'carbon',
        'pollution', 'air quality', 'envirofacts', 'facility emissions',
        'chemical releases', 'environment', 'climate',
      ],
      toolNames: [
        'ghg_facility_emissions',
        'ghg_emissions_by_sector',
        'tri_facility_releases',
        'tri_chemical_releases',
        'tri_trends',
      ],
      description: 'EPA Emissions adapter: search greenhouse gas (GHGRP) and toxic chemical release (TRI) data from the EPA Envirofacts DMAP API — free, no authentication required.',
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
        name: 'ghg_facility_emissions',
        description:
          'Search greenhouse gas emissions by state and optionally by facility name. Returns facility details and total GHG emissions in metric tons CO2 equivalent.',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Full state name (e.g., "Texas", "California").',
            },
            facility_name: {
              type: 'string',
              description: 'Facility name to search for (partial match).',
            },
            year: {
              type: 'number',
              description: 'Reporting year (default: 2022).',
            },
            limit: { type: 'number', description: 'Max results (default 20, max 100).' },
          },
          required: ['state'],
        },
      },
      {
        name: 'ghg_emissions_by_sector',
        description:
          'Get greenhouse gas emissions by industry sector for a state. Optionally filter by sector type (e.g., "Power Plants", "Chemicals").',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Full state name (e.g., "Texas").',
            },
            sector: {
              type: 'string',
              description: 'Industry type filter (partial match, e.g., "Power Plants", "Petroleum", "Chemicals").',
            },
            year: {
              type: 'number',
              description: 'Reporting year (default: 2022).',
            },
            limit: { type: 'number', description: 'Max results (default 20, max 100).' },
          },
          required: ['state'],
        },
      },
      {
        name: 'tri_facility_releases',
        description:
          'Search Toxic Release Inventory (TRI) facilities by state. Returns facility details.',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Two-letter state abbreviation (e.g., "TX", "CA").',
            },
            facility_name: {
              type: 'string',
              description: 'Facility name to search for (partial match).',
            },
            limit: { type: 'number', description: 'Max results (default 20, max 100).' },
          },
          required: ['state'],
        },
      },
      {
        name: 'tri_chemical_releases',
        description:
          'Search toxic chemical releases across all facilities. Filter by chemical name and optionally by state and year. Returns quantities released by media (air, water, land).',
        inputSchema: {
          type: 'object',
          properties: {
            chemical: {
              type: 'string',
              description: 'Chemical name (partial match, e.g., "Lead", "Mercury", "Benzene", "Toluene").',
            },
            state: {
              type: 'string',
              description: 'Two-letter state abbreviation to filter by (optional).',
            },
            year: {
              type: 'number',
              description: 'Reporting year (default: 2022).',
            },
            limit: { type: 'number', description: 'Max results (default 20, max 100).' },
          },
          required: ['chemical'],
        },
      },
      {
        name: 'tri_trends',
        description:
          'Get toxic release trends over time for a state or chemical across reporting years. Queries multiple years and summarizes totals. At least one of state or chemical must be provided.',
        inputSchema: {
          type: 'object',
          properties: {
            state: {
              type: 'string',
              description: 'Two-letter state abbreviation (e.g., "OH"). At least one of state or chemical is required.',
            },
            chemical: {
              type: 'string',
              description: 'Chemical name partial match (e.g., "Lead"). At least one of state or chemical is required.',
            },
            start_year: {
              type: 'number',
              description: 'Start year for the trend range (default: 5 years ago).',
            },
            end_year: {
              type: 'number',
              description: 'End year for the trend range (default: most recent available year).',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'ghg_facility_emissions':   return this.ghgFacilityEmissions(args);
        case 'ghg_emissions_by_sector':  return this.ghgEmissionsBySector(args);
        case 'tri_facility_releases':    return this.triFacilityReleases(args);
        case 'tri_chemical_releases':    return this.triChemicalReleases(args);
        case 'tri_trends':               return this.triTrends(args);
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

  // ── Private helpers ───────────────────────────────────────────────────────

  /**
   * Fetch from the EPA dmapservice API.
   * URL format: BASE/schema.table/col/op/val/.../first:last/json
   * Row range is 1-based: first=1, last=limit.
   */
  private async dmapFetch(table: string, filters: string, limit: number): Promise<unknown[]> {
    const last = Math.min(100, Math.max(1, limit));
    const url = `${this.baseUrl}/${table}/${filters}/1:${last}/json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`EPA DMAP API error: ${response.status} ${errText}`);
    }
    const data = await response.json();
    if (!Array.isArray(data)) {
      // API returns an error object on bad table/filter combos
      const errMsg = (data as Record<string, unknown>)['error'];
      if (errMsg) throw new Error(`EPA DMAP API error: ${errMsg}`);
      return [];
    }
    return data as unknown[];
  }

  private cleanGhgFacility(f: Record<string, unknown>) {
    return {
      facility_id: f['facility_id'] ?? null,
      name: f['facility_name'] ?? null,
      city: f['city'] ?? null,
      state: f['state_name'] ?? null,
      zip: f['zip'] ?? null,
      latitude: f['latitude'] ?? null,
      longitude: f['longitude'] ?? null,
      industry_type: f['reported_industry_types'] ?? null,
      total_ghg_emissions_mt_co2e: f['co2e_emission'] ?? null,
      year: f['year'] ?? null,
    };
  }

  private cleanTriFacility(f: Record<string, unknown>) {
    return {
      tri_facility_id: f['tri_facility_id'] ?? null,
      name: f['facility_name'] ?? null,
      city: f['city_name'] ?? null,
      county: f['county_name'] ?? null,
      state: f['state_abbr'] ?? null,
      zip: f['zip_code'] ?? null,
      latitude: f['fac_latitude'] ?? null,
      longitude: f['fac_longitude'] ?? null,
    };
  }

  private cleanTriRelease(r: Record<string, unknown>) {
    return {
      tri_facility_id: r['tri_facility_id'] ?? null,
      facility_name: r['facility_name'] ?? null,
      chemical: r['cas_chem_name'] ?? null,
      reporting_year: r['reporting_year'] ?? null,
      state: r['state_abbr'] ?? null,
      air_fugitive: r['fugitive_tot_rel'] ?? null,
      air_stack: r['stack_tot_rel'] ?? null,
      air_total: r['air_total_release'] ?? null,
      water_total: r['water_total_release'] ?? null,
      land_total: r['land_total_release'] ?? null,
      underground_injection: r['uninj_total_release'] ?? null,
    };
  }

  private async ghgFacilityEmissions(args: Record<string, unknown>): Promise<ToolResult> {
    const state = String(args['state']);
    const limit = Number(args['limit']) || 20;
    const year = Number(args['year']) || 2022;

    // Join pub_facts_sector_ghg_emission (has co2e_emission) with pub_dim_facility (has state/name)
    // Filter by year + state, join on facility_id
    let filters = `year/equals/${year}/left/ghg.pub_dim_facility/facility_id/equals/facility_id/state_name/equals/${encodeURIComponent(state)}`;
    if (args['facility_name']) {
      filters += `/facility_name/contains/${encodeURIComponent(String(args['facility_name']))}`;
    }

    const table = 'ghg.pub_facts_sector_ghg_emission';
    const rows = (await this.dmapFetch(table, filters, limit)) as Record<string, unknown>[];

    // Deduplicate by facility_id (multiple sector rows per facility)
    const seen = new Set<unknown>();
    const unique = rows.filter(r => {
      if (seen.has(r['facility_id'])) return false;
      seen.add(r['facility_id']);
      return true;
    });

    const result = {
      count: unique.length,
      state,
      year,
      facilities: unique.map(f => this.cleanGhgFacility(f)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async ghgEmissionsBySector(args: Record<string, unknown>): Promise<ToolResult> {
    const state = String(args['state']);
    const limit = Number(args['limit']) || 50;
    const year = Number(args['year']) || 2022;

    let filters = `year/equals/${year}/left/ghg.pub_dim_facility/facility_id/equals/facility_id/state_name/equals/${encodeURIComponent(state)}`;
    if (args['sector']) {
      filters += `/reported_industry_types/contains/${encodeURIComponent(String(args['sector']))}`;
    }

    const table = 'ghg.pub_facts_sector_ghg_emission';
    const rows = (await this.dmapFetch(table, filters, limit)) as Record<string, unknown>[];

    // Group emissions by industry type
    const sectorMap = new Map<string, { count: number; total_emissions: number }>();
    for (const row of rows) {
      const sector = (row['reported_industry_types'] as string) ?? 'Unknown';
      const entry = sectorMap.get(sector) ?? { count: 0, total_emissions: 0 };
      entry.count += 1;
      entry.total_emissions += Number(row['co2e_emission']) || 0;
      sectorMap.set(sector, entry);
    }

    const result = {
      state,
      year,
      record_count: rows.length,
      sectors: Array.from(sectorMap.entries()).map(([name, data]) => ({
        sector: name,
        record_count: data.count,
        total_emissions_mt_co2e: Math.round(data.total_emissions * 100) / 100,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async triFacilityReleases(args: Record<string, unknown>): Promise<ToolResult> {
    const state = String(args['state']).toUpperCase();
    const limit = Number(args['limit']) || 20;

    let filters = `state_abbr/equals/${encodeURIComponent(state)}`;
    if (args['facility_name']) {
      filters += `/facility_name/contains/${encodeURIComponent(String(args['facility_name']))}`;
    }

    const table = 'tri.tri_facility';
    const rows = (await this.dmapFetch(table, filters, limit)) as Record<string, unknown>[];

    const result = {
      count: rows.length,
      state,
      facilities: rows.map(f => this.cleanTriFacility(f)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async triChemicalReleases(args: Record<string, unknown>): Promise<ToolResult> {
    const chemical = String(args['chemical']);
    const limit = Number(args['limit']) || 20;
    const year = Number(args['year']) || 2022;

    // tri_reporting_form has chemical name + reporting_year + doc_ctrl_num + tri_facility_id
    // Join tri_facility for state/facility_name, join tri_form_r for release quantities
    let filters = `reporting_year/equals/${year}/and/cas_chem_name/contains/${encodeURIComponent(chemical)}`;
    if (args['state']) {
      filters += `/left/tri.tri_facility/tri_facility_id/equals/tri_facility_id/state_abbr/equals/${encodeURIComponent(String(args['state']).toUpperCase())}`;
    } else {
      filters += `/left/tri.tri_facility/tri_facility_id/equals/tri_facility_id`;
    }
    filters += `/left/tri.tri_form_r/doc_ctrl_num/equals/doc_ctrl_num`;

    const table = 'tri.tri_reporting_form';
    const rows = (await this.dmapFetch(table, filters, limit)) as Record<string, unknown>[];

    const result = {
      chemical,
      year,
      count: rows.length,
      releases: rows.map(r => this.cleanTriRelease(r)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async triTrends(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args['state'] && !args['chemical']) {
      return {
        content: [{ type: 'text', text: 'At least one of "state" or "chemical" is required for trend queries.' }],
        isError: true,
      };
    }

    const currentYear = new Date().getFullYear();
    const startYear = Number(args['start_year']) || currentYear - 5;
    const endYear = Number(args['end_year']) || currentYear - 1;

    if (endYear - startYear > 10) {
      return {
        content: [{ type: 'text', text: 'Year range cannot exceed 10 years to stay within API limits.' }],
        isError: true,
      };
    }

    const yearlyTotals: { year: number; total_air: number; total_water: number; total_land: number; facility_count: number }[] = [];

    for (let year = startYear; year <= endYear; year++) {
      let filters = `reporting_year/equals/${year}`;
      if (args['chemical']) {
        filters += `/and/cas_chem_name/contains/${encodeURIComponent(String(args['chemical']))}`;
      }
      if (args['state']) {
        filters += `/left/tri.tri_facility/tri_facility_id/equals/tri_facility_id/state_abbr/equals/${encodeURIComponent(String(args['state']).toUpperCase())}`;
      } else {
        filters += `/left/tri.tri_facility/tri_facility_id/equals/tri_facility_id`;
      }
      filters += `/left/tri.tri_form_r/doc_ctrl_num/equals/doc_ctrl_num`;

      const table = 'tri.tri_reporting_form';
      const rows = (await this.dmapFetch(table, filters, 100)) as Record<string, unknown>[];

      let totalAir = 0;
      let totalWater = 0;
      let totalLand = 0;
      for (const r of rows) {
        totalAir += Number(r['air_total_release']) || 0;
        totalWater += Number(r['water_total_release']) || 0;
        totalLand += Number(r['land_total_release']) || 0;
      }

      yearlyTotals.push({
        year,
        total_air: Math.round(totalAir * 100) / 100,
        total_water: Math.round(totalWater * 100) / 100,
        total_land: Math.round(totalLand * 100) / 100,
        facility_count: rows.length,
      });
    }

    const result = {
      state: args['state'] ? String(args['state']).toUpperCase() : null,
      chemical: args['chemical'] ? String(args['chemical']) : null,
      start_year: startYear,
      end_year: endYear,
      trends: yearlyTotals,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
