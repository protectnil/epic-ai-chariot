/**
 * PyPI MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://pypi.org (Python Package Index JSON API, free, no auth)
// Base URL: https://pypi.org
// Stats URL: https://pypistats.org
// Auth: none (public, no-auth-verified)
// Docs: https://warehouse.pypa.io/api-reference/json.html
// Category: developer-tools
// Rate limits: None documented; be respectful of the public server

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://pypi.org';
const STATS_BASE_URL = 'https://pypistats.org';

export class PypiMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;
  private readonly statsBaseUrl: string;

  constructor(config?: { baseUrl?: string; statsBaseUrl?: string }) {
    super();
    if (config === null) { throw new Error('PypiMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
    this.statsBaseUrl = config?.statsBaseUrl ?? STATS_BASE_URL;
  }

  static catalog() {
    return {
      name: 'pypi',
      displayName: 'PyPI (Python Package Index)',
      version: '1.0.0',
      category: 'developer-tools',
      keywords: [
        'pypi', 'python', 'pip', 'package', 'packages', 'dependencies',
        'package index', 'release', 'versions', 'python package',
        'open source', 'library', 'module', 'download stats', 'pypistats',
      ],
      toolNames: ['get_package', 'get_package_version', 'list_releases', 'get_download_stats'],
      description: 'PyPI (Python Package Index): look up Python package metadata, inspect specific versions and their dependencies, list release history, and fetch download statistics — free public API, no authentication required.',
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
        name: 'get_package',
        description:
          'Get metadata for a Python package on PyPI (the Python Package Index). Returns the latest version, summary, author, license, project URLs, required Python version, keywords, classifiers, and the release artifact files that `pip install` would download. Pass the exact pip package name (e.g. "requests", "numpy").',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Exact PyPI package name, e.g. "requests".',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'get_package_version',
        description:
          'Get metadata for a specific version of a Python package on PyPI. Returns the summary, required Python version, the full dependency list (requires_dist, i.e. what pip would resolve), and the downloadable files for that version. Use to inspect a pinned release like requests 2.31.0.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Exact PyPI package name, e.g. "requests".',
            },
            version: {
              type: 'string',
              description: 'Version string, e.g. "2.31.0".',
            },
          },
          required: ['name', 'version'],
        },
      },
      {
        name: 'list_releases',
        description:
          "List all published version strings for a Python package on PyPI, sorted, plus the latest version. Useful to see a package's release history or check which versions are available to pip install.",
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Exact PyPI package name, e.g. "requests".',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'get_download_stats',
        description:
          'Get recent download counts for a Python package (last day, last week, last month) from pypistats.org. Gauges how popular a pip package is.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Exact PyPI package name, e.g. "requests".',
            },
          },
          required: ['name'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_package':        return this.getPackage(args);
        case 'get_package_version': return this.getPackageVersion(args);
        case 'list_releases':      return this.listReleases(args);
        case 'get_download_stats': return this.getDownloadStats(args);
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

  private reqStr(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string, e.g. "requests".`);
    }
    return v.trim();
  }

  private mapFiles(urls: PypiUrl[] | undefined): MappedFile[] {
    return (urls ?? []).map((u) => ({
      filename: u.filename,
      size: u.size,
      packagetype: u.packagetype,
      upload_time: u.upload_time_iso_8601,
    }));
  }

  private async getPackage(args: Record<string, unknown>): Promise<ToolResult> {
    const pkg = this.reqStr(args, 'name');
    const url = `${this.baseUrl}/pypi/${encodeURIComponent(pkg)}/json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as PypiResponse;
    const { info, urls } = data;
    const result = {
      name: info.name,
      summary: info.summary,
      version: info.version,
      author: info.author,
      license: info.license,
      home_page: info.home_page,
      project_urls: info.project_urls,
      requires_python: info.requires_python,
      keywords: info.keywords,
      classifiers: (info.classifiers ?? []).slice(0, 15),
      latest_release_files: this.mapFiles(urls),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPackageVersion(args: Record<string, unknown>): Promise<ToolResult> {
    const pkg = this.reqStr(args, 'name');
    const version = this.reqStr(args, 'version');
    const url = `${this.baseUrl}/pypi/${encodeURIComponent(pkg)}/${encodeURIComponent(version)}/json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as PypiResponse;
    const { info, urls } = data;
    const result = {
      name: info.name,
      version: info.version,
      summary: info.summary,
      requires_python: info.requires_python,
      requires_dist: info.requires_dist,
      files: this.mapFiles(urls),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listReleases(args: Record<string, unknown>): Promise<ToolResult> {
    const pkg = this.reqStr(args, 'name');
    const url = `${this.baseUrl}/pypi/${encodeURIComponent(pkg)}/json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as PypiResponse;
    let versions = Object.keys(data.releases).sort();
    if (versions.length > 100) versions = versions.slice(-100);
    const result = { name: data.info.name, latest: data.info.version, releases: versions };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getDownloadStats(args: Record<string, unknown>): Promise<ToolResult> {
    const pkg = this.reqStr(args, 'name');
    const url = `${this.statsBaseUrl}/api/packages/${encodeURIComponent(pkg)}/recent`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': 'epic-ai-chariot/1.0' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as PypiStatsResponse;
    const result = {
      name: pkg,
      last_day: data.data.last_day,
      last_week: data.data.last_week,
      last_month: data.data.last_month,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

// ── Upstream type shapes ────────────────────────────────────────────────────

interface PypiUrl {
  filename: string;
  size: number;
  packagetype: string;
  upload_time_iso_8601: string;
}

interface PypiInfo {
  name: string;
  summary: string | null;
  version: string;
  author: string | null;
  license: string | null;
  home_page: string | null;
  project_urls: Record<string, string> | null;
  requires_python: string | null;
  requires_dist: string[] | null;
  keywords: string | null;
  classifiers: string[] | null;
}

interface PypiResponse {
  info: PypiInfo;
  urls?: PypiUrl[];
  releases: Record<string, unknown[]>;
}

interface PypiStatsResponse {
  data: {
    last_day: number;
    last_week: number;
    last_month: number;
  };
}

interface MappedFile {
  filename: string;
  size: number;
  packagetype: string;
  upload_time: string;
}
