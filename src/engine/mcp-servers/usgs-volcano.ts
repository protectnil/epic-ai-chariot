/**
 * USGS Volcano Hazards Program REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Source API: USGS HANS-public (Hazards Notification System) — public, no auth
// Base URL: https://volcanoes.usgs.gov/hans-public/api
// Docs: https://volcanoes.usgs.gov/hans-public/
// Category: weather
// Rate limits: None documented; public government feed

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://volcanoes.usgs.gov/hans-public/api';

export class UsgsVolcanoMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'usgs-volcano',
      displayName: 'USGS Volcano Hazards',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'usgs', 'volcano', 'eruption', 'volcanic', 'hazards', 'alert',
        'aviation color code', 'VONA', 'VAN', 'alaska', 'hawaii', 'yellowstone',
        'kilauea', 'shishaldin', 'cascades', 'observatory', 'lava', 'ash',
        'hans', 'hans-public', 'notice', 'advisory', 'watch', 'warning',
      ],
      toolNames: ['list_volcanoes', 'list_elevated', 'list_notices'],
      description: 'USGS Volcano Hazards Program: monitor ~170 US volcanoes with current alert levels and aviation color codes, surface elevated unrest, and retrieve recent VAN/VONA notices — no authentication required.',
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
        name: 'list_volcanoes',
        description:
          'List every US volcano monitored by USGS with current alert level (Normal/Advisory/Watch/Warning) and aviation color code (Green/Yellow/Orange/Red). Filter optionally by observatory short code.',
        inputSchema: {
          type: 'object',
          properties: {
            observatory: {
              type: 'string',
              description:
                'Observatory short code (AVO=Alaska, CVO=Cascades, YVO=Yellowstone, HVO=Hawaiian, CalVO=California). Optional.',
            },
          },
        },
      },
      {
        name: 'list_elevated',
        description:
          "List only the volcanoes currently above Normal/Green status (i.e., elevated unrest or eruption). Smallest practical fingerprint of \"what's happening right now.\"",
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_notices',
        description:
          'Recent USGS volcano notices and reports — observatory updates, VAN (Volcano Activity Notice) and VONA (Volcano Observatory Notice for Aviation) text. Filter by volcano slug.',
        inputSchema: {
          type: 'object',
          properties: {
            volcano_slug: {
              type: 'string',
              description:
                'USGS volcano slug (e.g., "kilauea", "shishaldin"). Optional — omit for all recent.',
            },
            limit: {
              type: 'number',
              description: 'Cap notices returned (default 50).',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_volcanoes':
          return this.listVolcanoes(args.observatory as string | undefined);
        case 'list_elevated':
          return this.listElevated();
        case 'list_notices':
          return this.listNotices(
            args.volcano_slug as string | undefined,
            typeof args.limit === 'number' ? args.limit : 50,
          );
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  /**
   * Fetch a HANS API path and return the parsed JSON data.
   * Does NOT truncate — callers operate on the full data and truncate
   * only the final tool output. (PATTERN-A fix: truncating here caused
   * JSON.parse on the truncated string to throw in listVolcanoes / listElevated
   * / listNotices.)
   */
  private async hansFetch(path: string): Promise<{ data: unknown } | ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USGS HANS API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { data };
  }

  private async listVolcanoes(observatory: string | undefined): Promise<ToolResult> {
    // /volcano/getMonitoredVolcanoes — returns one record per monitored US volcano
    // with its most-recent alert level and color code.
    const result = await this.hansFetch('/volcano/getMonitoredVolcanoes');
    if ('isError' in result) return result;

    const raw = (result.data as Array<Record<string, unknown>>) ?? [];
    const all = raw.map(normalizeVolcano);
    const filtered = observatory
      ? all.filter(
          (v) =>
            typeof v.observatory === 'string' &&
            v.observatory.toLowerCase() === observatory.toLowerCase(),
        )
      : all;

    return {
      content: [
        {
          type: 'text',
          text: this.truncate({ total: all.length, returned: filtered.length, volcanoes: filtered }),
        },
      ],
      isError: false,
    };
  }

  private async listElevated(): Promise<ToolResult> {
    // /volcano/getElevatedVolcanoes — returns only volcanoes currently above
    // Normal/Green (advisory, watch, or warning).
    const result = await this.hansFetch('/volcano/getElevatedVolcanoes');
    if ('isError' in result) return result;

    const raw = (result.data as Array<Record<string, unknown>>) ?? [];
    const list = raw.map(normalizeVolcano);

    return {
      content: [
        {
          type: 'text',
          text: this.truncate({
            count: list.length,
            note: 'All volcanoes currently above Normal/Green status (advisories, watches, or warnings).',
            volcanoes: list,
          }),
        },
      ],
      isError: false,
    };
  }

  private async listNotices(volcanoSlug: string | undefined, limit: number): Promise<ToolResult> {
    // /notice/getRecentNotices — returns all notices sent in approximately the
    // last month. There is no per-volcano-slug server-side filter; when a slug
    // is given we filter client-side on the `volcanoes` field (comma-separated
    // volcano names) using a case-insensitive substring match.
    const result = await this.hansFetch('/notice/getRecentNotices');
    if ('isError' in result) return result;

    const raw = (result.data as Array<Record<string, unknown>>) ?? [];
    const filtered = volcanoSlug
      ? raw.filter((n) => {
          const names = (n['volcanoes'] as string | undefined) ?? '';
          return names.toLowerCase().includes(volcanoSlug.toLowerCase());
        })
      : raw;
    const list = filtered.slice(0, Math.max(1, limit)).map(normalizeNotice);

    return {
      content: [
        {
          type: 'text',
          text: this.truncate({
            volcano_slug: volcanoSlug ?? null,
            count: list.length,
            notices: list,
          }),
        },
      ],
      isError: false,
    };
  }
}

// ── Normalizers ────────────────────────────────────────────────────────────────
// Field names verified against live USGS HANS API responses (2026-06-09).

function normalizeVolcano(v: Record<string, unknown>) {
  return {
    name: (v['volcano_name'] as string | undefined) ?? null,
    volcano_cd: (v['volcano_cd'] as string | undefined) ?? null,
    observatory: (v['obs_abbr'] as string | undefined) ?? null,
    observatory_full: (v['obs_fullname'] as string | undefined) ?? null,
    alert_level: (v['alert_level'] as string | undefined) ?? null,
    color_code: (v['color_code'] as string | undefined) ?? null,
    vnum: (v['vnum'] as string | undefined) ?? null,
    notice_type: (v['notice_type_cd'] as string | undefined) ?? null,
    sent_utc: (v['sent_utc'] as string | undefined) ?? null,
    notice_url: (v['notice_url'] as string | undefined) ?? null,
  };
}

function normalizeNotice(n: Record<string, unknown>) {
  return {
    id: (n['notice_identifier'] as string | undefined) ?? null,
    volcanoes: (n['volcanoes'] as string | undefined) ?? null,
    observatory: (n['obs_abbr'] as string | undefined) ?? null,
    observatory_full: (n['obs_fullname'] as string | undefined) ?? null,
    type: (n['notice_type_title'] as string | undefined) ?? (n['notice_type_cd'] as string | undefined) ?? null,
    category: (n['notice_category'] as string | undefined) ?? null,
    sent_utc: (n['sent_utc'] as string | undefined) ?? null,
    notice_url: (n['notice_url'] as string | undefined) ?? null,
    notice_data: (n['notice_data'] as string | undefined) ?? null,
  };
}
