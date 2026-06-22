/**
 * RxNorm (NLM RxNav) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://rxnav.nlm.nih.gov/REST
// Auth: None — free public API provided by the U.S. National Library of Medicine
// Docs: https://lhncbc.nlm.nih.gov/RxNav/APIs/RxNormAPIs.html
// Category: medical
// Rate limits: None documented; reasonable use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://rxnav.nlm.nih.gov/REST';

export class RxNormMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'rxnorm',
      displayName: 'RxNorm (NLM RxNav)',
      version: '1.0.0',
      category: 'medical',
      keywords: [
        'rxnorm', 'rxcui', 'drug', 'medication', 'pharmaceutical',
        'ndc', 'national drug code', 'drug interaction', 'brand name',
        'generic', 'ingredient', 'dose form', 'nlm', 'rxnav', 'drug name',
        'semaglutide', 'metformin', 'drug lookup',
      ],
      toolNames: [
        'rxnorm_search',
        'rxnorm_get_properties',
        'rxnorm_related',
        'rxnorm_interactions',
        'rxnorm_ndc',
      ],
      description: 'RxNorm (NLM RxNav): search and retrieve drug concepts, properties, brand/generic mappings, NDC codes, and drug-drug interaction data from the U.S. National Library of Medicine standard drug nomenclature system.',
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
        name: 'rxnorm_search',
        description: 'Search for drugs by name (brand or generic). Returns concept groups with RxCUI identifiers, names, synonyms, and term types (BN=brand, IN=ingredient, SBD=branded dose form, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Drug name to search for — brand or generic (e.g., "Ozempic", "semaglutide", "metformin")',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'rxnorm_get_properties',
        description: 'Get properties for a drug by its RxCUI (RxNorm concept ID). Returns name, synonym, term type, language, and suppress flag.',
        inputSchema: {
          type: 'object',
          properties: {
            rxcui: {
              type: 'string',
              description: 'RxNorm concept ID (e.g., "7052" for metformin)',
            },
          },
          required: ['rxcui'],
        },
      },
      {
        name: 'rxnorm_related',
        description: 'Get related concepts for a drug — brand names, generics, ingredients, and dose forms. Useful for mapping between brand and generic names.',
        inputSchema: {
          type: 'object',
          properties: {
            rxcui: {
              type: 'string',
              description: 'RxNorm concept ID',
            },
            tty: {
              type: 'string',
              description: 'Optional term type filter: BN (brand name), IN (ingredient), SBD (semantic branded drug), SCD (semantic clinical drug), GPCK (generic pack), BPCK (branded pack). Comma-separated for multiple.',
            },
          },
          required: ['rxcui'],
        },
      },
      {
        name: 'rxnorm_interactions',
        description: 'Check drug-drug interactions for a given RxCUI. NOTE: The NIH retired this API in January 2024 — this tool may return errors. Use PubMed or drug label lookups for interaction data instead.',
        inputSchema: {
          type: 'object',
          properties: {
            rxcui: {
              type: 'string',
              description: 'RxNorm concept ID of the drug to check interactions for',
            },
            sources: {
              type: 'string',
              description: 'Optional interaction source filter: "DrugBank", "ONCHigh", or omit for all sources',
            },
          },
          required: ['rxcui'],
        },
      },
      {
        name: 'rxnorm_ndc',
        description: 'Get NDC (National Drug Code) identifiers for a drug by its RxCUI. NDC codes uniquely identify drug products in the US market.',
        inputSchema: {
          type: 'object',
          properties: {
            rxcui: {
              type: 'string',
              description: 'RxNorm concept ID',
            },
          },
          required: ['rxcui'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'rxnorm_search':          return this.searchDrugs(args.name as string);
        case 'rxnorm_get_properties':  return this.getProperties(args.rxcui as string);
        case 'rxnorm_related':         return this.getRelated(args.rxcui as string, args.tty as string | undefined);
        case 'rxnorm_interactions':    return this.getInteractions(args.rxcui as string, args.sources as string | undefined);
        case 'rxnorm_ndc':             return this.getNdcCodes(args.rxcui as string);
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

  private async request(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchDrugs(name: string): Promise<ToolResult> {
    if (!name) {
      return { content: [{ type: 'text', text: 'rxnorm_search: name is required' }], isError: true };
    }
    const response = await this.fetchWithRetry(
      `${BASE_URL}/drugs.json?name=${encodeURIComponent(name)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as { drugGroup: { name: string; conceptGroup?: Array<{ tty: string; conceptProperties?: Array<{ rxcui: string; name: string; synonym: string; tty: string; language: string }> }> } };
    const drugGroup = data.drugGroup;
    const result = {
      name: drugGroup?.name ?? name,
      concept_groups: (drugGroup?.conceptGroup ?? [])
        .filter((g) => g.conceptProperties && g.conceptProperties.length > 0)
        .map((g) => ({
          term_type: g.tty,
          concepts: (g.conceptProperties ?? []).map((c) => ({
            rxcui: c.rxcui,
            name: c.name,
            synonym: c.synonym || null,
            tty: c.tty,
            language: c.language,
          })),
        })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getProperties(rxcui: string): Promise<ToolResult> {
    if (!rxcui) {
      return { content: [{ type: 'text', text: 'rxnorm_get_properties: rxcui is required' }], isError: true };
    }
    const response = await this.fetchWithRetry(
      `${BASE_URL}/rxcui/${encodeURIComponent(rxcui)}/properties.json`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as { properties: { rxcui: string; name: string; synonym: string; tty: string; language: string; suppress: string } | null };
    if (!data.properties) {
      return { content: [{ type: 'text', text: `No properties found for RxCUI: ${rxcui}` }], isError: true };
    }
    const p = data.properties;
    const result = {
      rxcui: p.rxcui,
      name: p.name,
      synonym: p.synonym || null,
      tty: p.tty,
      language: p.language,
      suppress: p.suppress,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getRelated(rxcui: string, tty?: string): Promise<ToolResult> {
    if (!rxcui) {
      return { content: [{ type: 'text', text: 'rxnorm_related: rxcui is required' }], isError: true };
    }
    const ttyParam = tty || 'IN+BN+SBD+SCD+GPCK+BPCK';
    const response = await this.fetchWithRetry(
      `${BASE_URL}/rxcui/${encodeURIComponent(rxcui)}/related.json?tty=${encodeURIComponent(ttyParam)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as { relatedGroup: { conceptGroup?: Array<{ tty: string; conceptProperties?: Array<{ rxcui: string; name: string; tty: string }> }> } };
    const groups = data.relatedGroup?.conceptGroup;
    const result = {
      rxcui,
      related_groups: (groups ?? [])
        .filter((g) => g.conceptProperties && g.conceptProperties.length > 0)
        .map((g) => ({
          term_type: g.tty,
          concepts: (g.conceptProperties ?? []).map((c) => ({
            rxcui: c.rxcui,
            name: c.name,
            tty: c.tty,
          })),
        })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getInteractions(rxcui: string, sources?: string): Promise<ToolResult> {
    if (!rxcui) {
      return { content: [{ type: 'text', text: 'rxnorm_interactions: rxcui is required' }], isError: true };
    }
    let path = `/interaction/interaction.json?rxcui=${encodeURIComponent(rxcui)}`;
    if (sources) path += `&sources=${encodeURIComponent(sources)}`;
    const response = await this.fetchWithRetry(
      `${BASE_URL}${path}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as {
      interactionTypeGroup?: Array<{
        sourceName: string;
        sourceDisclaimer: string;
        fullInteractionType?: Array<{
          comment: string;
          minConcept: Array<{ rxcui: string; name: string; tty: string }>;
          interactionPair: Array<{
            interactionConcept: unknown[];
            severity: string;
            description: string;
          }>;
        }>;
      }>;
    };
    const result = {
      rxcui,
      interactions: (data.interactionTypeGroup ?? []).map((group) => ({
        source: group.sourceName,
        disclaimer: group.sourceDisclaimer,
        pairs: (group.fullInteractionType ?? []).flatMap((fit) =>
          fit.interactionPair.map((pair) => ({
            drugs: fit.minConcept.map((c) => ({ rxcui: c.rxcui, name: c.name })),
            severity: pair.severity,
            description: pair.description,
          })),
        ),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getNdcCodes(rxcui: string): Promise<ToolResult> {
    if (!rxcui) {
      return { content: [{ type: 'text', text: 'rxnorm_ndc: rxcui is required' }], isError: true };
    }
    const response = await this.fetchWithRetry(
      `${BASE_URL}/rxcui/${encodeURIComponent(rxcui)}/ndcs.json`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as { ndcGroup: { ndcList?: { ndc: string[] } } };
    const ndcs = data.ndcGroup?.ndcList?.ndc ?? [];
    const result = {
      rxcui,
      ndc_count: ndcs.length,
      ndcs,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
