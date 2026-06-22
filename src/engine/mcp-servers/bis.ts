/**
 * BIS (Bank for International Settlements) Statistics MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://stats.bis.org/api/v2 (SDMX 2.1 REST, public, no auth)
 * Docs: https://stats.bis.org/api-doc/v2/
 * Category: finance
 *
 * Covers: cross-border banking, FX, debt securities, monetary policy rates,
 * payment systems, credit-to-GDP gaps, commercial and residential property
 * prices, effective exchange rates, OTC derivatives.
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://stats.bis.org/api/v2';

interface CuratedFlow {
  flow_ref: string;
  topic: string;
  title: string;
}

const CURATED: CuratedFlow[] = [
  { flow_ref: 'BIS,WS_CBPOL_D,1.0',       topic: 'rates',       title: 'Central bank policy rates (daily)' },
  { flow_ref: 'BIS,WS_CBPOL,1.0',          topic: 'rates',       title: 'Central bank policy rates (monthly)' },
  { flow_ref: 'BIS,WS_TC,1.0',             topic: 'fx',          title: 'Triennial Central Bank Survey — FX/derivatives' },
  { flow_ref: 'BIS,WS_FAS,1.0',            topic: 'finance',     title: 'Financial accounts (FAS)' },
  { flow_ref: 'BIS,WS_LBS_D_PUB,1.0',      topic: 'banking',     title: 'Locational banking statistics (LBS)' },
  { flow_ref: 'BIS,WS_CBS_PUB,1.0',        topic: 'banking',     title: 'Consolidated banking statistics (CBS)' },
  { flow_ref: 'BIS,WS_DEBT_SEC2_PUB,1.0',  topic: 'debt',        title: 'Debt securities — international + domestic' },
  { flow_ref: 'BIS,WS_GLI,1.0',            topic: 'credit',      title: 'Global liquidity indicators' },
  { flow_ref: 'BIS,WS_OTC_DERIV2,1.0',     topic: 'derivatives', title: 'OTC derivatives semi-annual' },
  { flow_ref: 'BIS,WS_CREDIT_GAP,1.0',     topic: 'credit',      title: 'Credit-to-GDP gaps' },
  { flow_ref: 'BIS,WS_CPP,1.0',            topic: 'property',    title: 'Commercial property prices' },
  { flow_ref: 'BIS,WS_LONG_PP,1.0',         topic: 'property',    title: 'Long property prices (residential)' },
  { flow_ref: 'BIS,WS_EER_D,1.0',          topic: 'fx',          title: 'Effective exchange rates (daily)' },
  { flow_ref: 'BIS,WS_XRU_D,1.0',          topic: 'fx',          title: 'US-dollar exchange rates (daily)' },
];

export class BISMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'bis',
      displayName: 'BIS — Bank for International Settlements Statistics',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'bis', 'bank for international settlements', 'central bank', 'policy rates',
        'cross-border banking', 'forex', 'fx', 'exchange rates', 'debt securities',
        'credit gap', 'property prices', 'otc derivatives', 'sdmx', 'statistics',
        'monetary policy', 'global liquidity', 'locational banking', 'consolidated banking',
        'financial accounts', 'effective exchange rate',
      ],
      toolNames: ['list_curated_flows', 'search_dataflows', 'fetch_dataset'],
      description: 'BIS Statistics SDMX 2.1 REST API: query central bank policy rates, cross-border banking, FX, debt securities, credit-to-GDP gaps, property prices, and OTC derivatives — all free and unauthenticated.',
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
        name: 'list_curated_flows',
        description:
          'List BIS dataflow refs pre-vetted by topic (rates, fx, banking, debt, credit, property, derivatives, finance). Use the returned flow_ref with fetch_dataset. For the full catalog use search_dataflows.',
        inputSchema: {
          type: 'object',
          properties: {
            topic: {
              type: 'string',
              description: 'Optional topic filter (rates, fx, banking, debt, credit, property, derivatives, finance)',
            },
          },
        },
      },
      {
        name: 'search_dataflows',
        description:
          'Search the BIS SDMX dataflow registry by keyword. Returns flow_refs ready to pass to fetch_dataset.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Keyword to match against dataflow name or ID (e.g. "policy rates")',
            },
            limit: {
              type: 'number',
              description: 'Maximum results to return (default 25, max 100)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'fetch_dataset',
        description:
          'Fetch tidy rows from a BIS dataflow. flow_ref format: "BIS,WS_CBPOL_D,1.0". The key is a dot-separated dimension filter (e.g. "D.US" for frequency.country; omit for all). Use start_period / end_period like "2020", "2020-Q1", or "2020-01".',
        inputSchema: {
          type: 'object',
          properties: {
            flow_ref: {
              type: 'string',
              description: 'SDMX dataflow reference, e.g. "BIS,WS_CBPOL_D,1.0"',
            },
            key: {
              type: 'string',
              description: 'Dot-separated dimension filter (empty or omit for all series)',
            },
            start_period: {
              type: 'string',
              description: 'Inclusive start period (e.g. "2020", "2020-Q1", "2020-01")',
            },
            end_period: {
              type: 'string',
              description: 'Inclusive end period',
            },
            limit: {
              type: 'number',
              description: 'Maximum data rows to return (default 5000)',
            },
          },
          required: ['flow_ref'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_curated_flows':
          return this.listCuratedFlows(args.topic as string | undefined);
        case 'search_dataflows':
          return this.searchDataflows(
            this.requireString(args, 'query', '"policy rates"'),
            typeof args.limit === 'number' ? args.limit : 25,
          );
        case 'fetch_dataset':
          return this.fetchDataset(
            this.requireString(args, 'flow_ref', '"BIS,WS_CBPOL_D,1.0"'),
            typeof args.key === 'string' ? args.key : '',
            args.start_period as string | undefined,
            args.end_period as string | undefined,
            typeof args.limit === 'number' ? args.limit : 5000,
          );
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

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private listCuratedFlows(topic?: string): ToolResult {
    const filtered = topic ? CURATED.filter((f) => f.topic === topic) : CURATED;
    const data = {
      count: filtered.length,
      topics: Array.from(new Set(CURATED.map((f) => f.topic))).sort(),
      flows: filtered,
      note: 'For the full catalog use search_dataflows or browse https://stats.bis.org.',
    };
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchDataflows(query: string, limit: number): Promise<ToolResult> {
    const url = `${BASE_URL}/structure/dataflow/BIS/all/latest?detail=allstubs`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/vnd.sdmx.structure+json;version=1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `BIS dataflow registry error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as {
      data?: {
        dataflows?: {
          id?: string;
          agencyID?: string;
          version?: string;
          name?: string;
          names?: Record<string, string>;
        }[];
      };
    };
    const flows = data.data?.dataflows ?? [];
    const q = query.toLowerCase();
    const matched = flows.filter((f) => {
      const n = (f.name ?? f.names?.en ?? '').toLowerCase();
      return n.includes(q) || (f.id ?? '').toLowerCase().includes(q);
    });
    const cap = Math.min(100, Math.max(1, limit));
    const capped = matched.slice(0, cap);
    const result = {
      total_matched: matched.length,
      returned: capped.length,
      dataflows: capped.map((f) => ({
        flow_ref: `${f.agencyID ?? 'BIS'},${f.id ?? ''},${f.version ?? '1.0'}`,
        id: f.id ?? null,
        version: f.version ?? null,
        name: f.name ?? f.names?.en ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async fetchDataset(
    flowRef: string,
    key: string,
    start?: string,
    end?: string,
    limit = 5000,
  ): Promise<ToolResult> {
    const encodedRef = encodeURIComponent(flowRef);
    const keySegment = key ? encodeURIComponent(key) : '';
    const urlStr = `${BASE_URL}/data/dataflow/${encodedRef}/${keySegment}`;
    const url = new URL(urlStr);
    url.searchParams.set('format', 'csvfilewithlabels');
    if (start) url.searchParams.set('startPeriod', start);
    if (end) url.searchParams.set('endPeriod', end);

    const response = await this.fetchWithRetry(url.toString(), { method: 'GET' });
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `BIS data error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    const csv = await response.text();
    const rows = this.parseCsv(csv);
    if (rows.length === 0) {
      const empty = { flow_ref: flowRef, columns: [], count: 0, rows: [] };
      return { content: [{ type: 'text', text: this.truncate(empty) }], isError: false };
    }
    const header = rows[0];
    const out: Record<string, string>[] = [];
    for (let i = 1; i < rows.length && out.length < limit; i++) {
      const r = rows[i];
      if (r.length === 1 && r[0] === '') continue;
      const obj: Record<string, string> = {};
      for (let c = 0; c < header.length; c++) obj[header[c]] = r[c] ?? '';
      out.push(obj);
    }
    const flowId = flowRef.split(',')[1] ?? '';
    const result = {
      flow_ref: flowRef,
      source_url: `https://stats.bis.org/statx/srs/data/${encodeURIComponent(flowId)}`,
      columns: header,
      truncated: rows.length - 1 > limit,
      count: out.length,
      rows: out,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private parseCsv(text: string): string[][] {
    const rows: string[][] = [];
    let row: string[] = [];
    let cell = '';
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inQuotes) {
        if (ch === '"' && text[i + 1] === '"') {
          cell += '"';
          i++;
        } else if (ch === '"') {
          inQuotes = false;
        } else {
          cell += ch;
        }
      } else {
        if (ch === '"') {
          inQuotes = true;
        } else if (ch === ',') {
          row.push(cell);
          cell = '';
        } else if (ch === '\n') {
          row.push(cell);
          rows.push(row);
          row = [];
          cell = '';
        } else if (ch === '\r') {
          // skip
        } else {
          cell += ch;
        }
      }
    }
    if (cell.length > 0 || row.length > 0) {
      row.push(cell);
      rows.push(row);
    }
    return rows;
  }
}
