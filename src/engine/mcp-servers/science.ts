/**
 * Science MCP Adapter — free public science data APIs
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream APIs (all public, no auth required):
 *   ISS location  — http://api.open-notify.org/iss-now.json
 *   Earthquakes   — https://earthquake.usgs.gov/fdsnws/event/1/query
 *   Air quality   — https://api.openaq.org/v2/latest
 *   NASA APOD     — https://api.nasa.gov/planetary/apod  (DEMO_KEY)
 *
 * Category: science
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class ScienceMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'science',
      displayName: 'Science Data APIs',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'science', 'iss', 'space station', 'earthquake', 'usgs', 'seismic',
        'air quality', 'openaq', 'pollution', 'nasa', 'apod', 'astronomy',
        'picture of the day', 'nature', 'earth', 'space', 'environment',
      ],
      toolNames: ['get_iss_location', 'get_earthquakes', 'get_air_quality', 'get_apod'],
      description: 'Science Data APIs: real-time ISS position, recent earthquakes (USGS), air quality measurements (OpenAQ), and NASA Astronomy Picture of the Day — all public, no API key required.',
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
        name: 'get_iss_location',
        description: 'Get the current location of the International Space Station',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_earthquakes',
        description: 'Get recent earthquakes from USGS',
        inputSchema: {
          type: 'object',
          properties: {
            days: {
              type: 'number',
              description: 'Look back N days (1-30, default 1)',
            },
            min_magnitude: {
              type: 'number',
              description: 'Minimum magnitude (default 4.0)',
            },
          },
        },
      },
      {
        name: 'get_air_quality',
        description: 'Get air quality measurements near a location from OpenAQ',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: {
              type: 'number',
              description: 'Latitude',
            },
            longitude: {
              type: 'number',
              description: 'Longitude',
            },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'get_apod',
        description: 'Get NASA Astronomy Picture of the Day',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'Date in YYYY-MM-DD format (default: today)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_iss_location':  return this.getIssLocation();
        case 'get_earthquakes':   return this.getEarthquakes(args);
        case 'get_air_quality':   return this.getAirQuality(args);
        case 'get_apod':          return this.getApod(args);
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

  private async getIssLocation(): Promise<ToolResult> {
    const response = await this.fetchWithRetry('http://api.open-notify.org/iss-now.json', {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Open Notify API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      iss_position: { latitude: string; longitude: string };
      timestamp: number;
    };
    const result = {
      latitude: parseFloat(data.iss_position.latitude),
      longitude: parseFloat(data.iss_position.longitude),
      timestamp: data.timestamp,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getEarthquakes(args: Record<string, unknown>): Promise<ToolResult> {
    const days = Math.min(30, Math.max(1, (args.days as number) ?? 1));
    const minMag = (args.min_magnitude as number) ?? 4.0;
    const now = new Date();
    const start = new Date(now.getTime() - days * 86400000);
    const params = new URLSearchParams({
      format: 'geojson',
      starttime: start.toISOString().slice(0, 10),
      endtime: now.toISOString().slice(0, 10),
      minmagnitude: String(minMag),
      orderby: 'magnitude',
      limit: '20',
    });
    const url = `https://earthquake.usgs.gov/fdsnws/event/1/query?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USGS API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      metadata: { count: number };
      features: {
        properties: {
          mag: number;
          place: string;
          time: number;
          url: string;
          tsunami: number;
        };
        geometry: { coordinates: number[] };
      }[];
    };
    const result = {
      count: data.metadata.count,
      earthquakes: data.features.map((f) => ({
        magnitude: f.properties.mag,
        location: f.properties.place,
        time: new Date(f.properties.time).toISOString(),
        latitude: f.geometry.coordinates[1],
        longitude: f.geometry.coordinates[0],
        depth_km: f.geometry.coordinates[2],
        tsunami_warning: f.properties.tsunami === 1,
        details_url: f.properties.url,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAirQuality(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude as number;
    const lon = args.longitude as number;
    const params = new URLSearchParams({
      coordinates: `${lat},${lon}`,
      radius: '25000',
      limit: '5',
      order_by: 'distance',
    });
    const url = `https://api.openaq.org/v2/latest?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAQ API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      results: {
        location: string;
        city?: string;
        country: string;
        measurements: {
          parameter: string;
          value: number;
          unit: string;
          lastUpdated: string;
        }[];
      }[];
    };
    const result = {
      stations: data.results.map((r) => ({
        location: r.location,
        city: r.city ?? '',
        country: r.country,
        measurements: r.measurements.map((m) => ({
          parameter: m.parameter,
          value: m.value,
          unit: m.unit,
          last_updated: m.lastUpdated,
        })),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getApod(args: Record<string, unknown>): Promise<ToolResult> {
    const date = args.date as string | undefined;
    const params = new URLSearchParams({ api_key: 'DEMO_KEY' });
    if (date) params.set('date', date);
    const url = `https://api.nasa.gov/planetary/apod?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NASA APOD API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      title: string;
      explanation: string;
      date: string;
      url: string;
      hdurl?: string;
      media_type: string;
      copyright?: string;
    };
    const result = {
      title: data.title,
      date: data.date,
      explanation: data.explanation,
      image_url: data.url,
      hd_url: data.hdurl ?? null,
      media_type: data.media_type,
      copyright: data.copyright ?? null,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
