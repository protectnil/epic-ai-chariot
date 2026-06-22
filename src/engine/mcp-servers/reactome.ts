/**
 * Reactome MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://reactome.org/ContentService
 * Auth: none — Reactome ContentService is a public, unauthenticated API.
 * Docs: https://reactome.org/ContentService/
 * Category: science
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://reactome.org/ContentService';

export class ReactomeMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('ReactomeMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'reactome',
      displayName: 'Reactome Pathway Database',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'reactome', 'pathway', 'biology', 'bioinformatics', 'signaling',
        'gene', 'protein', 'reaction', 'complex', 'orthology',
        'UniProt', 'ChEBI', 'Ensembl', 'NCBI', 'species', 'human',
        'biological pathway', 'molecular interaction', 'content service',
      ],
      toolNames: [
        'search',
        'pathway',
        'participants',
        'pathways_for_entity',
        'orthologous_events',
      ],
      description: 'Reactome ContentService: search biological pathways, retrieve pathway records, list entity participants, map external identifiers to pathways, and fetch orthologous events across species.',
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
        name: 'search',
        description: 'Search across all Reactome objects (pathways, reactions, proteins, complexes, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search term, e.g. "signaling by EGFR".',
            },
            types: {
              type: 'string',
              description: 'Comma-separated list of object types to restrict results: Pathway, Reaction, Protein, Complex, etc.',
            },
            cluster: {
              type: 'boolean',
              description: 'Group results by type (default true).',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'pathway',
        description: 'Retrieve the full contained-events record for a pathway by its stable Reactome id (e.g. R-HSA-68886).',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Reactome stable identifier, e.g. "R-HSA-68886".',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'participants',
        description: 'List all entity participants of a pathway by its stable Reactome id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Reactome stable identifier, e.g. "R-HSA-68886".',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'pathways_for_entity',
        description: 'Return all pathways that contain an entity looked up by external resource identifier (e.g. UniProt accession P04637 for TP53).',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'External resource name: UniProt, ChEBI, Ensembl, NCBI, GeneCards, etc. Defaults to "UniProt".',
            },
            entity_id: {
              type: 'string',
              description: 'Identifier within the resource, e.g. "P04637" for TP53 in UniProt.',
            },
            species: {
              type: 'string',
              description: 'NCBI taxonomy id as a string. Defaults to "9606" (Homo sapiens).',
            },
          },
          required: ['entity_id'],
        },
      },
      {
        name: 'orthologous_events',
        description: 'Retrieve orthologous pathways or reactions for a given Reactome event in another target species.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Source Reactome event stable id, e.g. "R-HSA-68886".',
            },
            species: {
              type: 'string',
              description: 'Target species name, e.g. "Mus musculus".',
            },
          },
          required: ['id', 'species'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':           return this.search(args);
        case 'pathway':          return this.getPathway(args);
        case 'participants':     return this.getParticipants(args);
        case 'pathways_for_entity': return this.getPathwaysForEntity(args);
        case 'orthologous_events':  return this.getOrthologousEvents(args);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Reactome: resource not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Reactome API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"signaling by EGFR"');
    const params = new URLSearchParams({
      query,
      cluster: args.cluster === false ? 'false' : 'true',
    });
    if (typeof args.types === 'string' && args.types.trim()) {
      params.set('types', args.types.trim());
    }
    return this.get(`/search/query?${params.toString()}`);
  }

  private async getPathway(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"R-HSA-68886"');
    return this.get(`/data/pathway/${encodeURIComponent(id)}/containedEvents`);
  }

  private async getParticipants(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"R-HSA-68886"');
    return this.get(`/data/pathway/${encodeURIComponent(id)}/participants`);
  }

  private async getPathwaysForEntity(args: Record<string, unknown>): Promise<ToolResult> {
    const entityId = this.requireString(args, 'entity_id', '"P04637"');
    const resource = typeof args.resource === 'string' && args.resource.trim() ? args.resource.trim() : 'UniProt';
    const species = typeof args.species === 'string' && args.species.trim() ? args.species.trim() : '9606';
    return this.get(
      `/data/mapping/${encodeURIComponent(resource)}/${encodeURIComponent(entityId)}/pathways?species=${encodeURIComponent(species)}`,
    );
  }

  private async getOrthologousEvents(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"R-HSA-68886"');
    const species = this.requireString(args, 'species', '"Mus musculus"');
    return this.get(`/data/orthologies/${encodeURIComponent(id)}/species/${encodeURIComponent(species)}`);
  }
}
