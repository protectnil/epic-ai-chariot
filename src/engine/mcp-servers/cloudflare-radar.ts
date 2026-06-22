/**
 * Cloudflare Radar MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.cloudflare.com/client/v4/radar
// Auth: Bearer token (Cloudflare API Token — no special scope required for Radar)
// Docs: https://developers.cloudflare.com/radar/
// Category: network
// Rate limits: Varies by plan — standard Cloudflare API rate limits apply

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface CloudflareRadarConfig {
  apiToken: string;
  baseUrl?: string;
}

export class CloudflareRadarMCPServer extends MCPAdapterBase {
  private readonly apiToken: string;
  private readonly baseUrl: string;

  constructor(config: CloudflareRadarConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Cloudflare Radar: configuration object is required');
    }
    if (!config.apiToken) {
      throw new Error('Cloudflare Radar: apiToken is required');
    }
    this.apiToken = config.apiToken;
    this.baseUrl = config.baseUrl || 'https://api.cloudflare.com/client/v4/radar';
  }

  static catalog() {
    return {
      name: 'cloudflare-radar',
      displayName: 'Cloudflare Radar — Internet Observatory',
      version: '1.0.0',
      category: 'network',
      keywords: [
        'cloudflare', 'radar', 'internet', 'traffic', 'ddos', 'attack',
        'bgp', 'route leak', 'internet quality', 'iqi', 'latency', 'bandwidth',
        'jitter', 'packet loss', 'http traffic', 'dns', 'top locations',
        'network', 'security', 'l7', 'layer7', 'autonomous system',
      ],
      toolNames: [
        'internet_quality',
        'attack_summary',
        'top_locations',
        'bgp_leaks',
      ],
      description: 'Cloudflare Radar: internet observatory surfacing HTTP traffic trends, Layer-7 DDoS attack patterns, BGP route-leak events, and Internet Quality Index (bandwidth/latency/jitter/loss) by location — directly via the Cloudflare Radar REST API.',
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
        name: 'internet_quality',
        description:
          'Internet Quality Index (IQI) summary — bandwidth, latency, jitter, packet loss — current value + change vs prior period. Optionally filtered to a 2-letter location code.',
        inputSchema: {
          type: 'object',
          properties: {
            location: {
              type: 'string',
              description: '2-letter location code (e.g., "US", "DE", "JP"). Omit for global.',
            },
            date_range: {
              type: 'string',
              description: 'Lookback window: 1d | 7d | 14d | 28d | 12w | 24w | 52w (default 28d)',
            },
          },
        },
      },
      {
        name: 'attack_summary',
        description:
          'Layer-7 DDoS attack mix over a time window. Returns the percentage breakdown of attacks by mitigation product or attack vector. Filter by location to scope to a region/country.',
        inputSchema: {
          type: 'object',
          properties: {
            dimension: {
              type: 'string',
              description:
                'Summary dimension: mitigation_product | http_method | http_version | ip_version | bot_class (default mitigation_product)',
            },
            location: {
              type: 'string',
              description: '2-letter location code (optional)',
            },
            date_range: {
              type: 'string',
              description: 'Lookback window (default 28d)',
            },
          },
        },
      },
      {
        name: 'top_locations',
        description:
          'Top locations by a metric. metric=http_requests returns countries by share of HTTP traffic; metric=dns_queries by DNS; metric=attacks by attack origin. Returns ranked list with share percentages.',
        inputSchema: {
          type: 'object',
          properties: {
            metric: {
              type: 'string',
              description: 'http_requests | dns_queries | attacks (default http_requests)',
            },
            date_range: {
              type: 'string',
              description: 'Lookback window (default 28d)',
            },
            limit: {
              type: 'number',
              description: '1-100 (default 10)',
            },
          },
        },
      },
      {
        name: 'bgp_leaks',
        description:
          'Recent BGP route-leak events detected by Cloudflare. Returns leaker AS, victim AS, originated prefixes, start/end times.',
        inputSchema: {
          type: 'object',
          properties: {
            date_range: {
              type: 'string',
              description: 'Lookback window (default 28d)',
            },
            limit: {
              type: 'number',
              description: '1-500 (default 50)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'internet_quality': return this.internetQuality(args);
        case 'attack_summary':   return this.attackSummary(args);
        case 'top_locations':    return this.topLocations(args);
        case 'bgp_leaks':        return this.bgpLeaks(args);
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

  private async radarFetch(path: string, params: URLSearchParams): Promise<ToolResult> {
    const qs = params.toString();
    const url = `${this.baseUrl}${path}${qs ? `?${qs}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        Accept: 'application/json',
      },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'Cloudflare Radar: unauthorized — check the API token' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Cloudflare Radar API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private commonParams(args: Record<string, unknown>): URLSearchParams {
    const params = new URLSearchParams();
    if (args.date_range) params.set('dateRange', String(args.date_range));
    if (args.location) params.set('location', String(args.location).toUpperCase());
    return params;
  }

  private async internetQuality(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.commonParams(args);
    return this.radarFetch('/quality/iqi/summary', params);
  }

  private async attackSummary(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.commonParams(args);
    const dimension = (args.dimension as string) ?? 'mitigation_product';
    return this.radarFetch(`/attacks/layer7/summary/${encodeURIComponent(dimension)}`, params);
  }

  private async topLocations(args: Record<string, unknown>): Promise<ToolResult> {
    const metric = (args.metric as string) ?? 'http_requests';
    const params = new URLSearchParams();
    if (args.date_range) params.set('dateRange', String(args.date_range));
    const limit = Math.min(100, Math.max(1, (args.limit as number) ?? 10));
    params.set('limit', String(limit));

    const path =
      metric === 'dns_queries'
        ? '/dns/top/locations'
        : metric === 'attacks'
          ? '/attacks/layer7/top/locations/origin'
          : '/http/top/locations';

    return this.radarFetch(path, params);
  }

  private async bgpLeaks(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.commonParams(args);
    const limit = Math.min(500, Math.max(1, (args.limit as number) ?? 50));
    params.set('limit', String(limit));
    return this.radarFetch('/bgp/leaks/events', params);
  }
}
