/**
 * Go Module Proxy (proxy.golang.org) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://proxy.golang.org
// Auth: none (public Go module proxy — no credentials required)
// Docs: https://proxy.golang.org/ + https://go.dev/ref/mod#goproxy-protocol
// Category: developer-tools
// Rate limits: None documented; best-effort public service

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://proxy.golang.org';

export class PkgGoDevMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('PkgGoDevMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'pkg-go-dev',
      displayName: 'Go Module Proxy',
      version: '1.0.0',
      category: 'developer-tools',
      keywords: [
        'go', 'golang', 'modules', 'packages', 'go.mod', 'dependencies',
        'module proxy', 'pkg.go.dev', 'versions', 'semver', 'import path',
        'open source', 'go modules', 'goproxy',
      ],
      toolNames: ['list_versions', 'latest_version', 'get_module_info', 'get_go_mod'],
      description: 'Go module proxy (proxy.golang.org): list published versions, fetch the latest release, retrieve version metadata, and download raw go.mod contents for any Go module by import path.',
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
        name: 'list_versions',
        description: 'List all published versions of a Go module.',
        inputSchema: {
          type: 'object',
          properties: {
            module_path: {
              type: 'string',
              description: 'Module import path (e.g. "github.com/gin-gonic/gin", "golang.org/x/net")',
            },
          },
          required: ['module_path'],
        },
      },
      {
        name: 'latest_version',
        description: 'Most recent released version of a Go module — with the resolved time.',
        inputSchema: {
          type: 'object',
          properties: {
            module_path: {
              type: 'string',
              description: 'Module import path',
            },
          },
          required: ['module_path'],
        },
      },
      {
        name: 'get_module_info',
        description: 'Metadata for a specific version (resolved version, commit time, origin).',
        inputSchema: {
          type: 'object',
          properties: {
            module_path: {
              type: 'string',
              description: 'Module import path',
            },
            version: {
              type: 'string',
              description: 'Semver-ish version (e.g. "v1.9.1")',
            },
          },
          required: ['module_path', 'version'],
        },
      },
      {
        name: 'get_go_mod',
        description: 'Raw go.mod contents for a specific version. Useful for dependency analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            module_path: {
              type: 'string',
              description: 'Module import path',
            },
            version: {
              type: 'string',
              description: 'Version',
            },
          },
          required: ['module_path', 'version'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_versions':    return this.listVersions(args);
        case 'latest_version':   return this.latestVersion(args);
        case 'get_module_info':  return this.getModuleInfo(args);
        case 'get_go_mod':       return this.getGoMod(args);
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

  /**
   * Go module proxy spec: uppercase letters in module paths must be lowercased
   * and preceded by '!'. e.g. github.com/Masterminds/semver →
   * github.com/!masterminds/!semver
   */
  private escapeModulePath(path: string): string {
    return path.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async fetchText(url: string): Promise<string> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'text/plain' },
    });
    if (response.status === 404 || response.status === 410) {
      throw new Error('go module proxy: module or version not found');
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`go module proxy error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.text();
  }

  private async fetchJson(url: string): Promise<unknown> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404 || response.status === 410) {
      throw new Error('go module proxy: module or version not found');
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`go module proxy error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.json();
  }

  private async listVersions(args: Record<string, unknown>): Promise<ToolResult> {
    const modulePath = this.requireString(args, 'module_path', '"github.com/gin-gonic/gin"');
    const escaped = this.escapeModulePath(modulePath);
    const text = await this.fetchText(`${this.baseUrl}/${escaped}/@v/list`);
    const versions = text.split('\n').map((s) => s.trim()).filter(Boolean).sort();
    const data = { module_path: modulePath, count: versions.length, versions };
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async latestVersion(args: Record<string, unknown>): Promise<ToolResult> {
    const modulePath = this.requireString(args, 'module_path', '"github.com/gin-gonic/gin"');
    const escaped = this.escapeModulePath(modulePath);
    const data = await this.fetchJson(`${this.baseUrl}/${escaped}/@latest`);
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getModuleInfo(args: Record<string, unknown>): Promise<ToolResult> {
    const modulePath = this.requireString(args, 'module_path', '"github.com/gin-gonic/gin"');
    const version = this.requireString(args, 'version', '"v1.9.1"');
    const escaped = this.escapeModulePath(modulePath);
    const data = await this.fetchJson(`${this.baseUrl}/${escaped}/@v/${encodeURIComponent(version)}.info`);
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getGoMod(args: Record<string, unknown>): Promise<ToolResult> {
    const modulePath = this.requireString(args, 'module_path', '"github.com/gin-gonic/gin"');
    const version = this.requireString(args, 'version', '"v1.9.1"');
    const escaped = this.escapeModulePath(modulePath);
    const text = await this.fetchText(`${this.baseUrl}/${escaped}/@v/${encodeURIComponent(version)}.mod`);
    const data = { module_path: modulePath, version, go_mod: text };
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}
