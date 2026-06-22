/**
 * EBI OLS4 (Ontology Lookup Service) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://www.ebi.ac.uk/ols4/api
// Auth: none (public API)
// Docs: https://www.ebi.ac.uk/ols4/help
// Category: science
// Rate limits: Fair-use; no published hard cap

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.ebi.ac.uk/ols4/api';

export class EbiOlsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('EbiOlsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'ebi-ols',
      displayName: 'EBI Ontology Lookup Service (OLS4)',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'ontology', 'ols', 'ebi', 'embl', 'obo', 'term', 'class', 'iri',
        'biomedical', 'bioinformatics', 'go', 'efo', 'mondo', 'hp', 'chebi',
        'taxonomy', 'ancestors', 'hierarchy', 'search', 'life science',
      ],
      toolNames: [
        'list_ontologies',
        'get_ontology',
        'search',
        'get_term',
        'term_ancestors',
        'term_children',
      ],
      description: 'EBI OLS4: browse and search biomedical ontologies (GO, EFO, MONDO, HP, ChEBI, and 200+ more), retrieve term metadata, ancestors, and children. Free and unauthenticated.',
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
        name: 'list_ontologies',
        description: 'List loaded ontologies (paginated).',
        inputSchema: {
          type: 'object',
          properties: {
            size: { type: 'number', description: '1–500 (default 20).' },
            page: { type: 'number', description: '0-based page (default 0).' },
          },
        },
      },
      {
        name: 'get_ontology',
        description: 'Ontology metadata by id (e.g. "efo", "mondo", "go").',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Ontology identifier, e.g. "efo".' },
          },
          required: ['id'],
        },
      },
      {
        name: 'search',
        description: 'Full-text search across all ontologies (or restrict to one).',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query string.' },
            ontology: { type: 'string', description: 'Restrict to one ontology id (optional).' },
            type: { type: 'string', description: 'Filter by term type: class | property | individual.' },
            exact: { type: 'boolean', description: 'Exact-match mode (default false).' },
            rows: { type: 'number', description: '1–1000 results (default 20).' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_term',
        description: 'Term details by ontology + iri, short_form, or obo_id (iri preferred).',
        inputSchema: {
          type: 'object',
          properties: {
            ontology: { type: 'string', description: 'Ontology id, e.g. "efo".' },
            iri: { type: 'string', description: 'Full term IRI (preferred), e.g. "http://www.ebi.ac.uk/efo/EFO_0000408".' },
            short_form: { type: 'string', description: 'Short form identifier, e.g. "EFO_0000408".' },
            obo_id: { type: 'string', description: 'OBO id, e.g. "EFO:0000408".' },
          },
          required: ['ontology'],
        },
      },
      {
        name: 'term_ancestors',
        description: 'Transitive ancestors of a term.',
        inputSchema: {
          type: 'object',
          properties: {
            ontology: { type: 'string', description: 'Ontology id, e.g. "efo".' },
            iri: { type: 'string', description: 'Full term IRI.' },
          },
          required: ['ontology', 'iri'],
        },
      },
      {
        name: 'term_children',
        description: 'Direct children of a term.',
        inputSchema: {
          type: 'object',
          properties: {
            ontology: { type: 'string', description: 'Ontology id, e.g. "efo".' },
            iri: { type: 'string', description: 'Full term IRI.' },
          },
          required: ['ontology', 'iri'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_ontologies':  return this.listOntologies(args);
        case 'get_ontology':     return this.getOntology(args);
        case 'search':           return this.search(args);
        case 'get_term':         return this.getTerm(args);
        case 'term_ancestors':   return this.termAncestors(args);
        case 'term_children':    return this.termChildren(args);
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

  private async olsGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'EBI OLS: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `EBI OLS API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async listOntologies(args: Record<string, unknown>): Promise<ToolResult> {
    const size = Math.min(500, Math.max(1, (args.size as number) ?? 20));
    const page = Math.max(0, (args.page as number) ?? 0);
    const params = new URLSearchParams({ size: String(size), page: String(page) });
    return this.olsGet(`/ontologies?${params}`);
  }

  private async getOntology(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"efo"').toLowerCase();
    return this.olsGet(`/ontologies/${encodeURIComponent(id)}`);
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"diabetes"');
    const rows = Math.min(1000, Math.max(1, (args.rows as number) ?? 20));
    const params = new URLSearchParams({ q: query, rows: String(rows) });
    if (args.ontology) params.set('ontology', String(args.ontology).toLowerCase());
    if (args.type) params.set('type', String(args.type));
    if (args.exact === true) params.set('exact', 'true');
    return this.olsGet(`/search?${params}`);
  }

  private async getTerm(args: Record<string, unknown>): Promise<ToolResult> {
    const ont = this.requireString(args, 'ontology', '"efo"').toLowerCase();
    if (args.iri) {
      const params = new URLSearchParams({ iri: String(args.iri) });
      return this.olsGet(`/ontologies/${ont}/terms?${params}`);
    }
    if (args.short_form) {
      return this.olsGet(`/ontologies/${ont}/terms/short_form/${encodeURIComponent(String(args.short_form))}`);
    }
    if (args.obo_id) {
      return this.olsGet(`/ontologies/${ont}/terms/obo_id/${encodeURIComponent(String(args.obo_id))}`);
    }
    throw new Error('get_term: provide at least one of iri, short_form, or obo_id.');
  }

  private async termAncestors(args: Record<string, unknown>): Promise<ToolResult> {
    const ont = this.requireString(args, 'ontology', '"efo"').toLowerCase();
    const iri = this.requireString(args, 'iri', '"http://www.ebi.ac.uk/efo/EFO_0000408"');
    const params = new URLSearchParams({ iri });
    return this.olsGet(`/ontologies/${ont}/ancestors?${params}`);
  }

  private async termChildren(args: Record<string, unknown>): Promise<ToolResult> {
    const ont = this.requireString(args, 'ontology', '"efo"').toLowerCase();
    const iri = this.requireString(args, 'iri', '"http://www.ebi.ac.uk/efo/EFO_0000408"');
    const params = new URLSearchParams({ iri });
    return this.olsGet(`/ontologies/${ont}/children?${params}`);
  }
}
