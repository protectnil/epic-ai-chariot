/**
 * UK Police Data API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://data.police.uk/api
// Auth: none (free public API, no key required)
// Docs: https://data.police.uk/docs/
// Category: government
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://data.police.uk/api';

export class UKPoliceMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'ukpolice',
      displayName: 'UK Police Data',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'uk police', 'police', 'crime', 'street crime', 'england', 'wales',
        'northern ireland', 'police forces', 'crime outcomes', 'law enforcement',
        'crime statistics', 'public safety', 'data.police.uk',
      ],
      toolNames: ['get_crimes', 'get_forces', 'get_outcomes'],
      description: 'UK Police Data: retrieve street-level crimes near a location, list all police forces in England/Wales/Northern Ireland, and look up crime outcomes at a location — free public API, no authentication required.',
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
        name: 'get_crimes',
        description:
          'Get street-level crimes near a latitude/longitude for a given month. Returns crime category, location, and outcome status.',
        inputSchema: {
          type: 'object',
          properties: {
            lat: { type: 'number', description: 'Latitude of the location' },
            lng: { type: 'number', description: 'Longitude of the location' },
            date: {
              type: 'string',
              description: 'Month to query in YYYY-MM format (e.g. "2024-01"). Defaults to latest available.',
            },
          },
          required: ['lat', 'lng'],
        },
      },
      {
        name: 'get_forces',
        description:
          'List all police forces in England, Wales, and Northern Ireland. Returns force ID and name.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_outcomes',
        description:
          'Get outcomes for crimes at a location for a given month. Returns outcome category and date for each crime.',
        inputSchema: {
          type: 'object',
          properties: {
            lat: { type: 'number', description: 'Latitude of the location' },
            lng: { type: 'number', description: 'Longitude of the location' },
            date: {
              type: 'string',
              description: 'Month to query in YYYY-MM format (e.g. "2024-01"). Defaults to latest available.',
            },
          },
          required: ['lat', 'lng'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_crimes':  return this.getCrimes(args);
        case 'get_forces':  return this.getForces();
        case 'get_outcomes': return this.getOutcomes(args);
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

  private async request(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
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
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getCrimes(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.lat as number;
    const lng = args.lng as number;
    const date = args.date as string | undefined;
    const params = new URLSearchParams({ lat: String(lat), lng: String(lng) });
    if (date) params.set('date', date);
    return this.request(`/crimes-street/all-crime?${params}`);
  }

  private async getForces(): Promise<ToolResult> {
    return this.request('/forces');
  }

  private async getOutcomes(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.lat as number;
    const lng = args.lng as number;
    const date = args.date as string | undefined;
    const params = new URLSearchParams({ lat: String(lat), lng: String(lng) });
    if (date) params.set('date', date);
    return this.request(`/outcomes-at-location?${params}`);
  }
}
