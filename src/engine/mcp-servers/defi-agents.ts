/**
 * defi-agents MCP Adapter (Phase R.6a auto-generated)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import { MCPAdapterBase } from './base.js';

interface DefiAgentsMCPServerConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class DefiAgentsMCPServer extends MCPAdapterBase {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: DefiAgentsMCPServerConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('defi-agents: configuration object is required');
    }
    this.apiKey = config.apiKey ?? '';
    this.baseUrl = config.baseUrl ?? "https://lyra-registry.vercel.app/api";
  }

  static catalog() {
    return {
      name: "defi-agents",
      displayName: "defi-agents",
      version: '1.0.0',
      category: 'misc',
      keywords: [],
      toolNames: ["list_tools","get_tool_by_id","register_tool","update_tool","delete_tool","search_tools","get_trending_tools","submit_tool_for_review","get_health_stats","list_categories"],
      description: "Retrieve paginated list of tools with optional filters",
      author: 'protectnil',
    };
  }

  get tools() {
    return [
      {
        name: "list_tools",
        description: "Retrieve paginated list of tools with optional filters",
        inputSchema: {
          type: 'object',
          properties: {
                  "q": {
                            "type": "string",
                            "description": "Search query string"
                  },
                  "category": {
                            "type": "string",
                            "description": "Filter by category slug"
                  },
                  "chain": {
                            "type": "string",
                            "description": "Filter by blockchain (e.g., bsc, ethereum)"
                  },
                  "protocol": {
                            "type": "string",
                            "description": "Filter by protocol (e.g., pancakeswap, aave)"
                  },
                  "grade": {
                            "type": "string",
                            "description": "Filter by trust grade (a|b|f)"
                  },
                  "requiresApiKey": {
                            "type": "string",
                            "description": "Filter by API key requirement (true|false)"
                  },
                  "tags": {
                            "type": "string",
                            "description": "Comma-separated tags"
                  },
                  "page": {
                            "type": "string",
                            "description": "Page number (default: 1)"
                  },
                  "limit": {
                            "type": "string",
                            "description": "Items per page (default: 20, max: 100)"
                  },
                  "sortBy": {
                            "type": "string",
                            "description": "Sort field (name, createdAt, totalScore, downloadCount)"
                  },
                  "sortOrder": {
                            "type": "string",
                            "description": "Sort direction (asc|desc, default: desc)"
                  }
        },
          required: []
        }
      },
      {
        name: "get_tool_by_id",
        description: "Retrieve a specific tool by ID",
        inputSchema: {
          type: 'object',
          properties: {
                  "id": {
                            "type": "string",
                            "description": "Tool ID"
                  }
        },
          required: ["id"]
        }
      },
      {
        name: "register_tool",
        description: "Register a new tool with metadata",
        inputSchema: {
          type: 'object',
          properties: {
                  "body": {
                            "type": "string",
                            "description": "Tool metadata including name, description, category, inputSchema, chains, tags"
                  }
        },
          required: ["body"]
        }
      },
      {
        name: "update_tool",
        description: "Update an existing tool",
        inputSchema: {
          type: 'object',
          properties: {
                  "id": {
                            "type": "string",
                            "description": "Tool ID"
                  },
                  "body": {
                            "type": "string",
                            "description": "Partial tool metadata to update"
                  }
        },
          required: ["id","body"]
        }
      },
      {
        name: "delete_tool",
        description: "Delete a tool by ID",
        inputSchema: {
          type: 'object',
          properties: {
                  "id": {
                            "type": "string",
                            "description": "Tool ID"
                  }
        },
          required: ["id"]
        }
      },
      {
        name: "search_tools",
        description: "Full-text search for tools with filters",
        inputSchema: {
          type: 'object',
          properties: {
                  "q": {
                            "type": "string",
                            "description": "Search query string"
                  },
                  "category": {
                            "type": "string",
                            "description": "Filter by category slug"
                  },
                  "chain": {
                            "type": "string",
                            "description": "Filter by blockchain"
                  },
                  "protocol": {
                            "type": "string",
                            "description": "Filter by protocol"
                  },
                  "grade": {
                            "type": "string",
                            "description": "Filter by trust grade (a|b|f)"
                  },
                  "tags": {
                            "type": "string",
                            "description": "Comma-separated tags"
                  },
                  "page": {
                            "type": "string",
                            "description": "Page number (default: 1)"
                  },
                  "limit": {
                            "type": "string",
                            "description": "Items per page (default: 20, max: 100)"
                  }
        },
          required: ["q"]
        }
      },
      {
        name: "get_trending_tools",
        description: "Retrieve trending tools by time period",
        inputSchema: {
          type: 'object',
          properties: {
                  "period": {
                            "type": "string",
                            "description": "Time period (day|week|month, default: week)"
                  },
                  "limit": {
                            "type": "string",
                            "description": "Number of results (default: 10, max: 50)"
                  },
                  "category": {
                            "type": "string",
                            "description": "Filter by category"
                  }
        },
          required: []
        }
      },
      {
        name: "submit_tool_for_review",
        description: "Submit a tool for review in the discovery pipeline",
        inputSchema: {
          type: 'object',
          properties: {
                  "body": {
                            "type": "string",
                            "description": "Tool metadata for review"
                  }
        },
          required: ["body"]
        }
      },
      {
        name: "get_health_stats",
        description: "Health check and registry statistics",
        inputSchema: {
          type: 'object',
          properties: {},
          required: []
        }
      },
      {
        name: "list_categories",
        description: "List all available tool categories",
        inputSchema: {
          type: 'object',
          properties: {},
          required: []
        }
      }
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    try {
      switch (name) {
      case "list_tools": {
        const params: Array<[string,string]> = [];
        
        for (const q of ["q","category","chain","protocol","grade","requiresApiKey","tags","page","limit","sortBy","sortOrder"]) {
          if (args[q] !== undefined && args[q] !== null) params.push([q, String(args[q])]);
        }
        const qs = params.length ? '?' + params.map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&') : '';
        const body = undefined;
        const url = `${this.baseUrl}/tools` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
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
      case "get_tool_by_id": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/tools/${encodeURIComponent(String(args["id"]))}` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
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
      case "register_tool": {
        const qs = '';
        const body: Record<string, unknown> = {};
        for (const b of ["body"]) {
          if (args[b] !== undefined) body[b] = args[b];
        }
        const url = `${this.baseUrl}/tools` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        headers['Content-Type'] = 'application/json';
        const response = await this.fetchWithRetry(url, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "update_tool": {
        const qs = '';
        const body: Record<string, unknown> = {};
        for (const b of ["body"]) {
          if (args[b] !== undefined) body[b] = args[b];
        }
        const url = `${this.baseUrl}/tools/${encodeURIComponent(String(args["id"]))}` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        headers['Content-Type'] = 'application/json';
        const response = await this.fetchWithRetry(url, {
          method: "PATCH",
          headers,
          body: JSON.stringify(body),
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "delete_tool": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/tools/${encodeURIComponent(String(args["id"]))}` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
        const response = await this.fetchWithRetry(url, {
          method: "DELETE",
          headers,
          
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "search_tools": {
        const params: Array<[string,string]> = [];
        
        for (const q of ["q","category","chain","protocol","grade","tags","page","limit"]) {
          if (args[q] !== undefined && args[q] !== null) params.push([q, String(args[q])]);
        }
        const qs = params.length ? '?' + params.map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&') : '';
        const body = undefined;
        const url = `${this.baseUrl}/search` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
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
      case "get_trending_tools": {
        const params: Array<[string,string]> = [];
        
        for (const q of ["period","limit","category"]) {
          if (args[q] !== undefined && args[q] !== null) params.push([q, String(args[q])]);
        }
        const qs = params.length ? '?' + params.map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&') : '';
        const body = undefined;
        const url = `${this.baseUrl}/trending` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
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
      case "submit_tool_for_review": {
        const qs = '';
        const body: Record<string, unknown> = {};
        for (const b of ["body"]) {
          if (args[b] !== undefined) body[b] = args[b];
        }
        const url = `${this.baseUrl}/discovery` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        headers['Content-Type'] = 'application/json';
        const response = await this.fetchWithRetry(url, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        });
        if (!response.ok) {
          const errText = await response.text().catch(() => response.statusText);
          return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
        }
        const data = await response.json();
        return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
      }
      case "get_health_stats": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/health` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
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
      case "list_categories": {
        const qs = '';
        const body = undefined;
        const url = `${this.baseUrl}/categories` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["Authorization"] = this.apiKey;
        
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

export default DefiAgentsMCPServer;
