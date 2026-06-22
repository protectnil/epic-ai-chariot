/**
 * Meteors MCP Adapter — NASA fireball, near-Earth asteroid, and close approach data
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Sources:
 *   - NASA/JPL Fireball API:        https://ssd-api.jpl.nasa.gov/fireball.api
 *   - NASA/JPL Close Approach Data: https://ssd-api.jpl.nasa.gov/cad.api
 *   - NASA NeoWs (Near Earth Object Web Service): https://api.nasa.gov/neo/rest/v1/feed
 *
 * Auth: none required (JPL APIs are public; NeoWs uses DEMO_KEY)
 * Category: science
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const JPL_BASE = 'https://ssd-api.jpl.nasa.gov';
const NEO_BASE = 'https://api.nasa.gov/neo/rest/v1';

export class MeteorsMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'meteors',
      displayName: 'NASA Meteors & Near-Earth Objects',
      version: '1.0.0',
      category: 'science' as const,
      keywords: [
        'meteors', 'fireballs', 'bolide', 'asteroid', 'near-earth object', 'NEO',
        'close approach', 'NASA', 'JPL', 'NeoWs', 'impact energy', 'space',
        'astronomy', 'planetary defense', 'potentially hazardous asteroid',
      ],
      toolNames: ['get_fireballs', 'get_close_approaches', 'get_neo_feed'],
      description: 'NASA/JPL fireball events, near-Earth asteroid close approaches, and NeoWs NEO feed — no authentication required.',
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
        name: 'get_fireballs',
        description:
          'Get recent bolide and fireball events recorded by US government sensors. Returns impact energy, radiated energy, velocity, altitude, and geographic location for each event.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Maximum number of fireball events to return (default 10, max 100).',
            },
          },
        },
      },
      {
        name: 'get_close_approaches',
        description:
          'Get near-Earth asteroid close approach events within 0.05 AU of Earth. Returns object name, approach date, miss distance, relative velocity, and diameter estimates.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Maximum number of close approach records to return (default 10, max 50).',
            },
          },
        },
      },
      {
        name: 'get_neo_feed',
        description:
          'Get Near-Earth Objects (NEOs) passing by Earth for a given date range using the NASA NeoWs API. Returns asteroid names, sizes, velocities, miss distances, and hazard status.',
        inputSchema: {
          type: 'object',
          properties: {
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format (e.g. "2025-01-01").',
            },
            end_date: {
              type: 'string',
              description:
                'End date in YYYY-MM-DD format. Maximum 7-day range from start_date (e.g. "2025-01-07").',
            },
          },
          required: ['start_date', 'end_date'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_fireballs':
          return this.getFireballs((args.limit as number | undefined) ?? 10);
        case 'get_close_approaches':
          return this.getCloseApproaches((args.limit as number | undefined) ?? 10);
        case 'get_neo_feed':
          return this.getNeoFeed(args.start_date as string, args.end_date as string);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async getFireballs(limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: String(Math.min(limit, 100)) });
    const url = `${JPL_BASE}/fireball.api?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `JPL Fireball API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const raw = (await response.json()) as {
      signature: { source: string; version: string };
      count: string;
      fields: string[];
      data: (string | null)[][];
    };
    const fields = raw.fields;
    const result = {
      count: parseInt(raw.count, 10),
      fireballs: raw.data.map((row) => {
        const obj: Record<string, string | null> = {};
        fields.forEach((f, i) => { obj[f] = row[i]; });
        return {
          date: obj['date'],
          energy_GJ: obj['energy'] ? parseFloat(obj['energy']) : null,
          radiated_energy_J: obj['impact-e'] ? parseFloat(obj['impact-e']) : null,
          latitude: obj['lat'] ? parseFloat(obj['lat']) : null,
          latitude_dir: obj['lat-dir'],
          longitude: obj['lon'] ? parseFloat(obj['lon']) : null,
          longitude_dir: obj['lon-dir'],
          altitude_km: obj['alt'] ? parseFloat(obj['alt']) : null,
          velocity_km_s: obj['vel'] ? parseFloat(obj['vel']) : null,
        };
      }),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCloseApproaches(limit: number): Promise<ToolResult> {
    const params = new URLSearchParams({
      limit: String(Math.min(limit, 50)),
      'dist-max': '0.05',
    });
    const url = `${JPL_BASE}/cad.api?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `JPL CAD API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const raw = (await response.json()) as {
      signature: { source: string; version: string };
      count: string;
      fields: string[];
      data: string[][];
    };
    const fields = raw.fields;
    const result = {
      count: parseInt(raw.count, 10),
      close_approaches: raw.data.map((row) => {
        const obj: Record<string, string> = {};
        fields.forEach((f, i) => { obj[f] = row[i]; });
        return {
          designation: obj['des'],
          orbit_id: obj['orbit_id'],
          jd_time: obj['jd'],
          date: obj['cd'],
          distance_au: obj['dist'] ? parseFloat(obj['dist']) : null,
          distance_min_au: obj['dist_min'] ? parseFloat(obj['dist_min']) : null,
          velocity_rel_km_s: obj['v_rel'] ? parseFloat(obj['v_rel']) : null,
          velocity_inf_km_s: obj['v_inf'] ? parseFloat(obj['v_inf']) : null,
          h_magnitude: obj['h'] ? parseFloat(obj['h']) : null,
        };
      }),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getNeoFeed(startDate: string, endDate: string): Promise<ToolResult> {
    const params = new URLSearchParams({
      start_date: startDate,
      end_date: endDate,
      api_key: 'DEMO_KEY',
    });
    const url = `${NEO_BASE}/feed?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NASA NeoWs API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const raw = (await response.json()) as {
      element_count: number;
      near_earth_objects: Record<
        string,
        Array<{
          id: string;
          name: string;
          nasa_jpl_url: string;
          estimated_diameter: {
            kilometers: { estimated_diameter_min: number; estimated_diameter_max: number };
          };
          is_potentially_hazardous_asteroid: boolean;
          close_approach_data: Array<{
            close_approach_date: string;
            relative_velocity: { kilometers_per_hour: string };
            miss_distance: { astronomical: string; kilometers: string };
            orbiting_body: string;
          }>;
        }>
      >;
    };
    const objects = Object.entries(raw.near_earth_objects).flatMap(([date, neos]) =>
      neos.map((neo) => ({
        date,
        id: neo.id,
        name: neo.name,
        potentially_hazardous: neo.is_potentially_hazardous_asteroid,
        diameter_km_min: neo.estimated_diameter.kilometers.estimated_diameter_min,
        diameter_km_max: neo.estimated_diameter.kilometers.estimated_diameter_max,
        close_approaches: neo.close_approach_data.map((ca) => ({
          date: ca.close_approach_date,
          velocity_km_h: parseFloat(ca.relative_velocity.kilometers_per_hour),
          miss_distance_au: parseFloat(ca.miss_distance.astronomical),
          miss_distance_km: parseFloat(ca.miss_distance.kilometers),
          orbiting_body: ca.orbiting_body,
        })),
      })),
    );
    const result = {
      element_count: raw.element_count,
      near_earth_objects: objects,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
