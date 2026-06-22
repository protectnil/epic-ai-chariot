/**
 * android-mcp MCP Adapter (Phase R.6a auto-generated)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import { MCPAdapterBase } from './base.js';

interface AndroidMcpMCPServerConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class AndroidMcpMCPServer extends MCPAdapterBase {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: AndroidMcpMCPServerConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('android-mcp: configuration object is required');
    }
    this.apiKey = config.apiKey ?? '';
    this.baseUrl = config.baseUrl ?? "https://researchtwin.net/api";
  }

  static catalog() {
    return {
      name: "android-mcp",
      displayName: "android-mcp",
      version: '1.0.0',
      category: 'misc',
      keywords: [],
      toolNames: ["get_researcher_profile","get_researcher_papers","get_researcher_datasets","get_researcher_repos","discover_research"],
      description: "Retrieves a researcher's profile with HATEOAS links.",
      author: 'protectnil',
    };
  }

  get tools() {
    return [
      {
        name: "get_researcher_profile",
        description: "Retrieves a researcher's profile with HATEOAS links.",
        inputSchema: {
          type: 'object',
          properties: {
                  "slug": {
                            "type": "string",
                            "description": "Researcher slug identifier."
                  }
        },
          required: ["slug"]
        }
      },
      {
        name: "get_researcher_papers",
        description: "Fetches a researcher's papers with citations.",
        inputSchema: {
          type: 'object',
          properties: {
                  "slug": {
                            "type": "string",
                            "description": "Researcher slug identifier."
                  }
        },
          required: ["slug"]
        }
      },
      {
        name: "get_researcher_datasets",
        description: "Fetches a researcher's datasets with QIC scores.",
        inputSchema: {
          type: 'object',
          properties: {
                  "slug": {
                            "type": "string",
                            "description": "Researcher slug identifier."
                  }
        },
          required: ["slug"]
        }
      },
      {
        name: "get_researcher_repos",
        description: "Fetches a researcher's code repositories with QIC scores.",
        inputSchema: {
          type: 'object',
          properties: {
                  "slug": {
                            "type": "string",
                            "description": "Researcher slug identifier."
                  }
        },
          required: ["slug"]
        }
      },
      {
        name: "discover_research",
        description: "Searches across researchers for papers, datasets, or repos by keyword.",
        inputSchema: {
          type: 'object',
          properties: {
                  "q": {
                            "type": "string",
                            "description": "Search keyword."
                  },
                  "type": {
                            "type": "string",
                            "description": "Search type: paper/dataset/repo."
                  }
        },
          required: ["q","type"]
        }
      }
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    try {
      switch (name) {
      case "get_researcher_profile": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/researcher/${encodeURIComponent(String(args["slug"]))}/profile` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
        
        const response = await this.fetchWithRetry(url, {
          method: "GET",
          headers,
          
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "get_researcher_papers": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/researcher/${encodeURIComponent(String(args["slug"]))}/papers` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
        
        const response = await this.fetchWithRetry(url, {
          method: "GET",
          headers,
          
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "get_researcher_datasets": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/researcher/${encodeURIComponent(String(args["slug"]))}/datasets` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
        
        const response = await this.fetchWithRetry(url, {
          method: "GET",
          headers,
          
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "get_researcher_repos": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/researcher/${encodeURIComponent(String(args["slug"]))}/repos` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
        
        const response = await this.fetchWithRetry(url, {
          method: "GET",
          headers,
          
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "discover_research": {
        const params: Array<[string,string]> = [];
        
        for (const q of ["q","type"]) {
          if (args[q] !== undefined && args[q] !== null) params.push([q, String(args[q])]);
        }
        const qs = params.length ? '?' + params.map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&') : '';
        const body = undefined;
        const url = `${this.baseUrl}/discover` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
        
        const response = await this.fetchWithRetry(url, {
          method: "GET",
          headers,
          
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
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
}

export default AndroidMcpMCPServer;
