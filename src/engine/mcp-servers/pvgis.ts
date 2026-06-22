/**
 * PVGIS MCP Adapter — EU Joint Research Centre PV system modeler
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream API: https://re.jrc.ec.europa.eu/api/v5_3/
 * Auth: none (public JRC service)
 * Docs: https://joint-research-centre.ec.europa.eu/photovoltaic-geographical-information-system-pvgis_en
 * Category: energy
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://re.jrc.ec.europa.eu/api/v5_3';

export class PvgisMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('PvgisMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'pvgis',
      displayName: 'PVGIS — EU JRC PV System Modeler',
      version: '1.0.0',
      category: 'energy' as const,
      keywords: [
        'pvgis', 'photovoltaic', 'solar', 'pv', 'solar energy',
        'renewable energy', 'irradiation', 'solar radiation', 'tmy',
        'typical meteorological year', 'solar power', 'kWh', 'solar output',
        'EU JRC', 'joint research centre', 'energy modeling', 'solar forecast',
      ],
      toolNames: ['pv_performance', 'monthly_radiation', 'tmy'],
      description: 'PVGIS: model annual and monthly PV system output, retrieve long-term monthly irradiation, and generate Typical Meteorological Year data from the EU Joint Research Centre.',
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
        name: 'pv_performance',
        description:
          'Model annual + monthly PV system output. Returns kWh/year estimates and monthly breakdowns.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:     { type: 'number', description: 'Latitude in degrees' },
            longitude:    { type: 'number', description: 'Longitude in degrees' },
            peakpower:    { type: 'number', description: 'Nominal peak power (kWp). Default 1.' },
            loss:         { type: 'number', description: 'System losses (%) — default 14.' },
            mountingplace:{ type: 'string', description: 'free | building (BIPV). Default free.' },
            angle:        { type: 'number', description: 'Tilt angle in degrees from horizontal. Default 35.' },
            aspect:       { type: 'number', description: 'Azimuth: 0=south, 90=west, -90=east, 180=north. Default 0.' },
            pvtechchoice: { type: 'string', description: 'crystSi | CIS | CdTe | Unknown. Default crystSi.' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'monthly_radiation',
        description: 'Long-term monthly average global / diffuse / direct irradiation on horizontal / inclined plane.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:  { type: 'number', description: 'Latitude in degrees' },
            longitude: { type: 'number', description: 'Longitude in degrees' },
            horirrad:  { type: 'boolean', description: 'Include horizontal irradiation (default true).' },
            optrad:    { type: 'boolean', description: 'Include optimum-angle irradiation (default true).' },
            startyear: { type: 'number', description: 'Earliest year, defaults to climate database start.' },
            endyear:   { type: 'number', description: 'Latest year.' },
            angle:     { type: 'number', description: 'Specific tilt angle (default optimum).' },
          },
          required: ['latitude', 'longitude'],
        },
      },
      {
        name: 'tmy',
        description: 'Typical Meteorological Year — hourly synthetic year representative of the climate at a location.',
        inputSchema: {
          type: 'object',
          properties: {
            latitude:  { type: 'number', description: 'Latitude in degrees' },
            longitude: { type: 'number', description: 'Longitude in degrees' },
            startyear: { type: 'number', description: 'Start year for TMY calculation.' },
            endyear:   { type: 'number', description: 'End year for TMY calculation.' },
          },
          required: ['latitude', 'longitude'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'pv_performance':    return this.pvPerformance(args);
        case 'monthly_radiation': return this.monthlyRadiation(args);
        case 'tmy':               return this.tmyCall(args);
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

  private requireNum(args: Record<string, unknown>, key: string, example: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a finite number. Example: ${example}.`);
    }
    return v;
  }

  private async pvgisGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 300)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async pvPerformance(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      lat:          String(this.requireNum(args, 'latitude', '52.5')),
      lon:          String(this.requireNum(args, 'longitude', '13.4')),
      peakpower:    String((args.peakpower as number) ?? 1),
      loss:         String((args.loss as number) ?? 14),
      mountingplace:String(args.mountingplace ?? 'free'),
      angle:        String((args.angle as number) ?? 35),
      aspect:       String((args.aspect as number) ?? 0),
      pvtechchoice: String(args.pvtechchoice ?? 'crystSi'),
      outputformat: 'json',
    });
    return this.pvgisGet(`/PVcalc?${params}`);
  }

  private async monthlyRadiation(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      lat:      String(this.requireNum(args, 'latitude', '52.5')),
      lon:      String(this.requireNum(args, 'longitude', '13.4')),
      horirrad: args.horirrad === false ? '0' : '1',
      optrad:   args.optrad === false ? '0' : '1',
      outputformat: 'json',
    });
    if (args.startyear !== undefined) params.set('startyear', String(args.startyear));
    if (args.endyear   !== undefined) params.set('endyear',   String(args.endyear));
    if (args.angle     !== undefined) params.set('angle',     String(args.angle));
    return this.pvgisGet(`/MRcalc?${params}`);
  }

  private async tmyCall(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      lat:         String(this.requireNum(args, 'latitude', '52.5')),
      lon:         String(this.requireNum(args, 'longitude', '13.4')),
      outputformat: 'json',
    });
    if (args.startyear !== undefined) params.set('startyear', String(args.startyear));
    if (args.endyear   !== undefined) params.set('endyear',   String(args.endyear));
    return this.pvgisGet(`/tmy?${params}`);
  }
}
