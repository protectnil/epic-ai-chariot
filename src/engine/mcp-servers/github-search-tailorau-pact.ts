/**
 * github-search-tailorau-pact MCP Adapter (Phase R.6a auto-generated)
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import { MCPAdapterBase } from './base.js';

interface GithubSearchTailorauPactMCPServerConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class GithubSearchTailorauPactMCPServer extends MCPAdapterBase {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: GithubSearchTailorauPactMCPServerConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('github-search-tailorau-pact: configuration object is required');
    }
    this.apiKey = config.apiKey ?? '';
    this.baseUrl = config.baseUrl ?? "https://your-server.com/api/pact";
  }

  static catalog() {
    return {
      name: "github-search-tailorau-pact",
      displayName: "github-search-tailorau-pact",
      version: '1.0.0',
      category: 'misc',
      keywords: [],
      toolNames: ["join_document","declare_constraint","object_proposal","poll_events"],
      description: "Register an agent to a document via invite token.",
      author: 'protectnil',
    };
  }

  get tools() {
    return [
      {
        name: "join_document",
        description: "Register an agent to a document via invite token.",
        inputSchema: {
          type: 'object',
          properties: {
                  "docId": {
                            "type": "string",
                            "description": "The document ID to join."
                  },
                  "agentName": {
                            "type": "string",
                            "description": "Name of the agent joining."
                  },
                  "token": {
                            "type": "string",
                            "description": "Invite token for the document."
                  }
        },
          required: ["docId","agentName","token"]
        }
      },
      {
        name: "declare_constraint",
        description: "Set a constraint on a document section.",
        inputSchema: {
          type: 'object',
          properties: {
                  "docId": {
                            "type": "string",
                            "description": "The document ID."
                  },
                  "sectionId": {
                            "type": "string",
                            "description": "Section ID to constrain (e.g., 'sec:budget')."
                  },
                  "boundary": {
                            "type": "string",
                            "description": "Constraint boundary (e.g., 'Total must not exceed $2M')."
                  }
        },
          required: ["docId","sectionId","boundary"]
        }
      },
      {
        name: "object_proposal",
        description: "Raise an objection to a proposal violating constraints.",
        inputSchema: {
          type: 'object',
          properties: {
                  "docId": {
                            "type": "string",
                            "description": "The document ID."
                  },
                  "proposalId": {
                            "type": "string",
                            "description": "The proposal ID to object to."
                  },
                  "reason": {
                            "type": "string",
                            "description": "Reason for objection (e.g., 'Exceeds $2M budget cap')."
                  }
        },
          required: ["docId","proposalId","reason"]
        }
      },
      {
        name: "poll_events",
        description: "Fetch document events since a given timestamp.",
        inputSchema: {
          type: 'object',
          properties: {
                  "docId": {
                            "type": "string",
                            "description": "The document ID."
                  },
                  "since": {
                            "type": "string",
                            "description": "Event timestamp to poll from (e.g., 'evt_0')."
                  }
        },
          required: ["docId","since"]
        }
      }
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    try {
      switch (name) {
      case "join_document": {
        const qs = '';
        const body: Record<string, unknown> = {};
        for (const b of ["agentName","token"]) {
          if (args[b] !== undefined) body[b] = args[b];
        }
        const url = `${this.baseUrl}/${encodeURIComponent(String(args["docId"]))}/join-token` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["X-Api-Key"] = this.apiKey;
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
      case "declare_constraint": {
        const qs = '';
        const body: Record<string, unknown> = {};
        for (const b of ["sectionId","boundary"]) {
          if (args[b] !== undefined) body[b] = args[b];
        }
        const url = `${this.baseUrl}/${encodeURIComponent(String(args["docId"]))}/constraints` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["X-Api-Key"] = this.apiKey;
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
      case "object_proposal": {
        const qs = '';
        const body: Record<string, unknown> = {};
        for (const b of ["reason"]) {
          if (args[b] !== undefined) body[b] = args[b];
        }
        const url = `${this.baseUrl}/${encodeURIComponent(String(args["docId"]))}/proposals/${encodeURIComponent(String(args["proposalId"]))}/object` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["X-Api-Key"] = this.apiKey;
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
      case "poll_events": {
        const params: Array<[string,string]> = [];
        
        for (const q of ["since"]) {
          if (args[q] !== undefined && args[q] !== null) params.push([q, String(args[q])]);
        }
        const qs = params.length ? '?' + params.map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&') : '';
        const body = undefined;
        const url = `${this.baseUrl}/${encodeURIComponent(String(args["docId"]))}/poll` + qs;
        const headers: Record<string, string> = { 'Accept': 'application/json' };
        if (this.apiKey) headers["X-Api-Key"] = this.apiKey;
        
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

export default GithubSearchTailorauPactMCPServer;
