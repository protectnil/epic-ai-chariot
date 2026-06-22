/**
 * Dropbox MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.dropboxapi.com/2  (file metadata / search / folder ops)
// Content URL: https://content.dropboxapi.com/2  (file download)
// Auth: OAuth 2.0 Bearer access token
// Docs: https://www.dropbox.com/developers/documentation/http/documentation
// Category: collaboration
// Tools: list folder, search, get metadata, download, create folder

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface DropboxConfig {
  accessToken: string;
  baseUrl?: string;
  contentBaseUrl?: string;
}

export class DropboxMCPServer extends MCPAdapterBase {
  private readonly accessToken: string;
  private readonly baseUrl: string;
  private readonly contentBaseUrl: string;

  constructor(config: DropboxConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Dropbox: configuration object is required');
    }
    if (!config.accessToken) {
      throw new Error('Dropbox: accessToken is required');
    }
    this.accessToken = config.accessToken;
    this.baseUrl = config.baseUrl || 'https://api.dropboxapi.com/2';
    this.contentBaseUrl = config.contentBaseUrl || 'https://content.dropboxapi.com/2';
  }

  static catalog() {
    return {
      name: 'dropbox',
      displayName: 'Dropbox',
      version: '1.0.0',
      category: 'collaboration' as const,
      keywords: [
        'dropbox', 'file storage', 'cloud storage', 'file sharing',
        'folder', 'documents', 'sync', 'download', 'upload',
        'file management', 'search files', 'metadata',
      ],
      toolNames: [
        'dropbox_list_folder',
        'dropbox_search',
        'dropbox_get_metadata',
        'dropbox_download',
        'dropbox_create_folder',
      ],
      description: 'Dropbox API v2: list folder contents, search files and folders, retrieve file/folder metadata, download file content, and create new folders.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'oauth2' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil' as const,
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'dropbox_list_folder',
        description: 'List files and folders in a Dropbox directory.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Folder path (e.g., "" for root, "/Documents")',
            },
            limit: {
              type: 'number',
              description: 'Max entries to return (default 100)',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'dropbox_search',
        description: 'Search for files and folders in Dropbox by name or content.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string',
            },
            max_results: {
              type: 'number',
              description: 'Maximum results to return (default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'dropbox_get_metadata',
        description: 'Get metadata for a file or folder in Dropbox.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'File or folder path',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'dropbox_download',
        description: 'Download a file from Dropbox. Returns the file content as text and its metadata.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'File path to download',
            },
          },
          required: ['path'],
        },
      },
      {
        name: 'dropbox_create_folder',
        description: 'Create a new folder in Dropbox.',
        inputSchema: {
          type: 'object',
          properties: {
            path: {
              type: 'string',
              description: 'Path of the folder to create (e.g., "/New Folder")',
            },
            autorename: {
              type: 'boolean',
              description: 'Auto-rename if a folder with the same name exists (default false)',
            },
          },
          required: ['path'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'dropbox_list_folder':   return this.listFolder(args);
        case 'dropbox_search':        return this.search(args);
        case 'dropbox_get_metadata':  return this.getMetadata(args);
        case 'dropbox_download':      return this.download(args);
        case 'dropbox_create_folder': return this.createFolder(args);
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

  private authHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.accessToken}`,
      'Content-Type': 'application/json',
    };
  }

  private async postJson(path: string, body: unknown): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: this.authHeaders(),
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Dropbox API error (${response.status}): ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async listFolder(args: Record<string, unknown>): Promise<ToolResult> {
    return this.postJson('/files/list_folder', {
      path: args.path as string,
      limit: (args.limit as number) ?? 100,
    });
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    return this.postJson('/files/search_v2', {
      query: args.query as string,
      options: {
        max_results: (args.max_results as number) ?? 20,
      },
    });
  }

  private async getMetadata(args: Record<string, unknown>): Promise<ToolResult> {
    return this.postJson('/files/get_metadata', {
      path: args.path as string,
      include_media_info: true,
    });
  }

  private async download(args: Record<string, unknown>): Promise<ToolResult> {
    const filePath = args.path as string;
    const apiArg = JSON.stringify({ path: filePath });
    const url = `${this.contentBaseUrl}/files/download`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Dropbox-API-Arg': apiArg,
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Dropbox API error (${response.status}): ${errText}` }],
        isError: true,
      };
    }
    const metadataHeader = response.headers.get('dropbox-api-result');
    const content = await response.text();
    const result = {
      metadata: metadataHeader ? JSON.parse(metadataHeader) : null,
      content,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async createFolder(args: Record<string, unknown>): Promise<ToolResult> {
    return this.postJson('/files/create_folder_v2', {
      path: args.path as string,
      autorename: (args.autorename as boolean) ?? false,
    });
  }
}
