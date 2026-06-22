/**
 * UK Office for National Statistics (ONS) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// REST API: https://api.beta.ons.gov.uk/v1
// Auth: none — public open-data API
// Docs: https://developer.ons.gov.uk/
// Category: government
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.beta.ons.gov.uk/v1';

export class UkOnsMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'uk-ons',
      displayName: 'UK Office for National Statistics',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'uk', 'ons', 'statistics', 'economy', 'population', 'labour market',
        'public finances', 'trade', 'inflation', 'cpih', 'gdp', 'open data',
        'official statistics', 'national statistics', 'datasets',
      ],
      toolNames: [
        'list_datasets',
        'get_dataset',
        'list_editions',
        'get_version',
        'get_observations',
      ],
      description:
        'UK Office for National Statistics open-data API: browse and query official datasets covering economy, population, labour market, public finances, and trade.',
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
        name: 'list_datasets',
        description:
          'Paginated catalog of ONS datasets. Returns id, title, description, contacts, release frequency, last release, theme.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'number', description: '1–100 (default 20)' },
            offset: { type: 'number', description: '0-based offset (default 0)' },
          },
          required: [],
        },
      },
      {
        name: 'get_dataset',
        description:
          'Single dataset metadata: title, description, methodology, contacts, release frequency, latest version, related links.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id: {
              type: 'string',
              description: 'ONS dataset ID (e.g., "cpih01", "ashe-table-1")',
            },
          },
          required: ['dataset_id'],
        },
      },
      {
        name: 'list_editions',
        description:
          'Editions of a dataset (e.g., quarterly editions, annual editions). Returns edition labels + latest versions.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id: { type: 'string', description: 'ONS dataset ID' },
          },
          required: ['dataset_id'],
        },
      },
      {
        name: 'get_version',
        description:
          'Specific edition + version metadata. Returns dimension definitions (with codelists), download links, release date.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id: { type: 'string', description: 'ONS dataset ID' },
            edition: { type: 'string', description: 'Edition label' },
            version: { type: 'string', description: 'Version number (e.g., "1", "2")' },
          },
          required: ['dataset_id', 'edition', 'version'],
        },
      },
      {
        name: 'get_observations',
        description:
          'Fetch observation rows from a dataset/edition/version. Pass dimension filters as a `dimensions` map ' +
          '(e.g. {"geography":"K02000001","time":"2023"}). Use "*" for all values within a dimension.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id: { type: 'string', description: 'ONS dataset ID' },
            edition: { type: 'string', description: 'Edition label' },
            version: { type: 'string', description: 'Version number' },
            dimensions: {
              type: 'object',
              description:
                'Dimension code → value (or "*" for all). Example: {"geography":"K02000001","time":"2023"}.',
            },
          },
          required: ['dataset_id', 'edition', 'version', 'dimensions'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_datasets':
          return this.listDatasets(
            typeof args.limit === 'number' ? args.limit : 20,
            typeof args.offset === 'number' ? args.offset : 0,
          );
        case 'get_dataset':
          return this.getDataset(this.requireString(args, 'dataset_id', '"cpih01"'));
        case 'list_editions':
          return this.listEditions(this.requireString(args, 'dataset_id', '"cpih01"'));
        case 'get_version':
          return this.getVersion(
            this.requireString(args, 'dataset_id', '"cpih01"'),
            this.requireString(args, 'edition', '"time-series"'),
            this.requireString(args, 'version', '"1"'),
          );
        case 'get_observations':
          return this.getObservations(
            this.requireString(args, 'dataset_id', '"cpih01"'),
            this.requireString(args, 'edition', '"time-series"'),
            this.requireString(args, 'version', '"1"'),
            (args.dimensions as Record<string, string>) ?? {},
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

  private requireString(
    args: Record<string, unknown>,
    key: string,
    example: string,
  ): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(
        `Required argument "${key}" is missing or empty. Pass a string like ${example}.`,
      );
    }
    return v;
  }

  private async onsFetch(path: string, params?: URLSearchParams): Promise<ToolResult> {
    const qs = params?.toString() ? `?${params.toString()}` : '';
    const url = `${BASE_URL}${path}${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'UK ONS: resource not found (HTTP 404)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `UK ONS API error: ${response.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async listDatasets(limit: number, offset: number): Promise<ToolResult> {
    const params = new URLSearchParams({
      limit: String(Math.min(100, Math.max(1, limit))),
      offset: String(Math.max(0, offset)),
    });
    const raw = await this.fetchWithRetry(
      `${BASE_URL}/datasets?${params.toString()}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!raw.ok) {
      const body = await raw.text().catch(() => raw.statusText);
      return {
        content: [{ type: 'text', text: `UK ONS API error: ${raw.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    interface OnsDataset {
      id?: string; title?: string; description?: string; theme?: string; state?: string;
      type?: string; national_statistic?: boolean; release_frequency?: string;
      next_release?: string; license?: string;
      publisher?: { name?: string };
      contacts?: { name?: string; email?: string }[];
      links?: { latest_version?: { id?: string } };
    }
    const data = await raw.json() as {
      count?: number; items?: OnsDataset[]; total_count?: number; total?: number;
    };
    const result = {
      total: data.total_count ?? data.total ?? null,
      returned: data.items?.length ?? 0,
      datasets: (data.items ?? []).map((d: OnsDataset) => ({
        id: d.id ?? null,
        title: d.title ?? null,
        description: d.description ?? null,
        theme: d.theme ?? null,
        state: d.state ?? null,
        type: d.type ?? null,
        national_statistic: d.national_statistic ?? null,
        release_frequency: d.release_frequency ?? null,
        next_release: d.next_release ?? null,
        license: d.license ?? null,
        publisher: d.publisher?.name ?? null,
        contacts: (d.contacts ?? []).map((c) => ({ name: c.name ?? null, email: c.email ?? null })),
        latest_version_id: d.links?.latest_version?.id ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getDataset(datasetId: string): Promise<ToolResult> {
    return this.onsFetch(`/datasets/${encodeURIComponent(datasetId)}`);
  }

  private async listEditions(datasetId: string): Promise<ToolResult> {
    const raw = await this.fetchWithRetry(
      `${BASE_URL}/datasets/${encodeURIComponent(datasetId)}/editions`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!raw.ok) {
      const body = await raw.text().catch(() => raw.statusText);
      return {
        content: [{ type: 'text', text: `UK ONS API error: ${raw.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    interface OnsEdition {
      edition?: string; release_date?: string; state?: string;
      links?: { latest_version?: { id?: string } };
    }
    const data = await raw.json() as {
      count?: number; items?: OnsEdition[]; total_count?: number;
    };
    const result = {
      dataset_id: datasetId,
      total: data.total_count ?? data.count ?? 0,
      editions: (data.items ?? []).map((e: OnsEdition) => ({
        edition: e.edition ?? null,
        release_date: e.release_date ?? null,
        state: e.state ?? null,
        latest_version_id: e.links?.latest_version?.id ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getVersion(
    datasetId: string,
    edition: string,
    version: string,
  ): Promise<ToolResult> {
    const raw = await this.fetchWithRetry(
      `${BASE_URL}/datasets/${encodeURIComponent(datasetId)}/editions/${encodeURIComponent(edition)}/versions/${encodeURIComponent(version)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!raw.ok) {
      const body = await raw.text().catch(() => raw.statusText);
      return {
        content: [{ type: 'text', text: `UK ONS API error: ${raw.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    interface OnsVersion {
      version?: number; release_date?: string; state?: string;
      dimensions?: { name?: string; id?: string; label?: string }[];
      downloads?: {
        csv?: { href?: string }; csvw?: { href?: string };
        xls?: { href?: string }; xlsx?: { href?: string };
      };
    }
    const data = await raw.json() as OnsVersion;
    const result = {
      dataset_id: datasetId,
      edition,
      version: data.version ?? Number(version),
      state: data.state ?? null,
      release_date: data.release_date ?? null,
      dimensions: (data.dimensions ?? []).map((d) => ({
        name: d.name ?? null,
        id: d.id ?? null,
        label: d.label ?? null,
      })),
      downloads: {
        csv: data.downloads?.csv?.href ?? null,
        csvw: data.downloads?.csvw?.href ?? null,
        xls: data.downloads?.xls?.href ?? null,
        xlsx: data.downloads?.xlsx?.href ?? null,
      },
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getObservations(
    datasetId: string,
    edition: string,
    version: string,
    dimensions: Record<string, string>,
  ): Promise<ToolResult> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(dimensions)) {
      params.set(k, v);
    }
    const qs = params.toString() ? `?${params.toString()}` : '';
    const raw = await this.fetchWithRetry(
      `${BASE_URL}/datasets/${encodeURIComponent(datasetId)}/editions/${encodeURIComponent(edition)}/versions/${encodeURIComponent(version)}/observations${qs}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!raw.ok) {
      const body = await raw.text().catch(() => raw.statusText);
      return {
        content: [{ type: 'text', text: `UK ONS API error: ${raw.status} ${body.slice(0, 200)}` }],
        isError: true,
      };
    }
    interface OnsObs {
      observation?: string;
      dimensions?: Record<string, { id?: string; label?: string }>;
    }
    interface OnsObsResp {
      total_observations?: number;
      unit_of_measure?: string;
      usage_notes?: { title?: string; note?: string }[];
      observations?: OnsObs[];
    }
    const data = await raw.json() as OnsObsResp;
    const result = {
      dataset_id: datasetId,
      edition,
      version,
      total_observations: data.total_observations ?? null,
      unit_of_measure: data.unit_of_measure ?? null,
      notes: (data.usage_notes ?? []).map((n) => n.note).filter(Boolean),
      observations: (data.observations ?? []).map((o: OnsObs) => ({
        value: o.observation ?? null,
        dimensions: Object.fromEntries(
          Object.entries(o.dimensions ?? {}).map(([k, v]) => [
            k,
            { id: v.id ?? null, label: v.label ?? null },
          ]),
        ),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
