/**
 * MedlinePlus MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official upstream: NIH MedlinePlus — two keyless public services:
//   Connect API:  https://connect.medlineplus.gov/service
//   NLM Web Search: https://wsearch.nlm.nih.gov/ws/query
// Docs: https://medlineplus.gov/about/developers/medlineplusconnectapi/
//       https://wsearch.nlm.nih.gov/ws/query
// Category: health
// Auth: none — public, keyless APIs

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const CONNECT_BASE = 'https://connect.medlineplus.gov/service';
const WSEARCH_BASE = 'https://wsearch.nlm.nih.gov/ws/query';

// Common code system short names → official OIDs
const CODE_SYSTEM_OIDS: Record<string, string> = {
  'ICD-9-CM':   '2.16.840.1.113883.6.103',
  ICD9:         '2.16.840.1.113883.6.103',
  'ICD-10-CM':  '2.16.840.1.113883.6.90',
  ICD10:        '2.16.840.1.113883.6.90',
  'ICD-10-PCS': '2.16.840.1.113883.6.4',
  SNOMED:       '2.16.840.1.113883.6.96',
  'SNOMED CT':  '2.16.840.1.113883.6.96',
  RXNORM:       '2.16.840.1.113883.6.88',
  RxNorm:       '2.16.840.1.113883.6.88',
  LOINC:        '2.16.840.1.113883.6.1',
  NDC:          '2.16.840.1.113883.6.69',
  MESH:         '2.16.840.1.113883.6.177',
  MeSH:         '2.16.840.1.113883.6.177',
  HGNC:         '2.16.840.1.113883.6.282',
  GENE:         '2.16.840.1.113883.6.282',
};

interface SearchResult {
  rank?: number;
  url?: string;
  title?: string;
  snippet?: string;
  organization?: string;
}

export class MedlinePlusMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'medlineplus',
      displayName: 'MedlinePlus',
      version: '1.0.0',
      category: 'health',
      keywords: [
        'medlineplus', 'nih', 'health', 'medical', 'consumer health',
        'icd-10', 'snomed', 'rxnorm', 'loinc', 'clinical codes',
        'drug information', 'disease', 'health topics', 'nlm',
        'national library of medicine', 'connect api', 'health search',
      ],
      toolNames: ['connect', 'search'],
      description: 'MedlinePlus: map clinical codes (ICD-10-CM, SNOMED CT, RxNorm, LOINC, NDC, MeSH, HGNC) to NIH consumer-health topics, and free-text search across MedlinePlus health topics and NLM databases.',
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
        name: 'connect',
        description:
          'Map a clinical code (ICD-10-CM, SNOMED CT, RxCUI, LOINC, NDC, MeSH, HGNC) to MedlinePlus consumer-health topic pages via the NIH MedlinePlus Connect API.',
        inputSchema: {
          type: 'object',
          properties: {
            code: {
              type: 'string',
              description: 'Code value (e.g. "J00" for ICD-10-CM acute nasopharyngitis)',
            },
            code_system: {
              type: 'string',
              description: 'Short name or OID — ICD-10-CM | SNOMED | RxNorm | LOINC | NDC | MeSH | HGNC | ICD-9-CM, or pass the OID directly',
            },
            lang: {
              type: 'string',
              description: 'Response language: en (default) | es',
            },
          },
          required: ['code', 'code_system'],
        },
      },
      {
        name: 'search',
        description:
          'Free-text search across MedlinePlus health topics (and related NLM databases) via the NLM Web Search API.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search terms (e.g. "diabetes symptoms")',
            },
            db: {
              type: 'string',
              description: 'Database to search: healthTopics (default) | healthTopicsSpanish | drug | herb | meshhd | genetic',
            },
            limit: {
              type: 'number',
              description: 'Maximum results to return: 1–100 (default 10)',
            },
            retstart: {
              type: 'number',
              description: '0-based offset for pagination (default 0)',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'connect': return this.connect(args);
        case 'search':  return this.search(args);
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

  private async connect(args: Record<string, unknown>): Promise<ToolResult> {
    const code = this.requireString(args, 'code', '"J00"');
    const sysIn = this.requireString(args, 'code_system', '"ICD-10-CM"');
    const oid = /^[0-9.]+$/.test(sysIn)
      ? sysIn
      : CODE_SYSTEM_OIDS[sysIn] ?? CODE_SYSTEM_OIDS[sysIn.toUpperCase()];
    if (!oid) {
      return {
        content: [{
          type: 'text',
          text: `Unknown code_system "${sysIn}". Supported: ${Object.keys(CODE_SYSTEM_OIDS).slice(0, 8).join(', ')}, or pass the OID directly.`,
        }],
        isError: true,
      };
    }
    const params = new URLSearchParams({
      'mainSearchCriteria.v.cs': oid,
      'mainSearchCriteria.v.c': code,
      'informationRecipient.languageCode.c': String(args.lang ?? 'en'),
      knowledgeResponseType: 'application/json',
    });
    const url = `${CONNECT_BASE}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `MedlinePlus Connect error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query', '"diabetes"');
    const limit = Math.min(100, Math.max(1, typeof args.limit === 'number' ? args.limit : 10));
    const retstart = Math.max(0, typeof args.retstart === 'number' ? args.retstart : 0);
    const params = new URLSearchParams({
      db:       String(args.db ?? 'healthTopics'),
      term:     query,
      rettype:  'brief',
      retmax:   String(limit),
      retstart: String(retstart),
    });
    const url = `${WSEARCH_BASE}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/xml' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `MedlinePlus search error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const xml = await response.text();
    const parsed = this.parseWsearchXml(xml);
    return { content: [{ type: 'text', text: this.truncate(parsed) }], isError: false };
  }

  /**
   * Parse NLM wsearch XML response into a structured result object.
   */
  private parseWsearchXml(xml: string): { total: number; returned: number; results: SearchResult[] } {
    const count = Number(/count=["'](\d+)["']/.exec(xml)?.[1] ?? '0');
    const total = Number(/<count>(\d+)<\/count>/.exec(xml)?.[1] ?? count);
    const docs: SearchResult[] = [];
    const docRe = /<document(?:\s+rank=["'](\d+)["'])?[^>]*?(?:\s+url=["']([^"']+)["'])?[^>]*>([\s\S]*?)<\/document>/g;
    for (const m of xml.matchAll(docRe)) {
      const rank = m[1] ? Number(m[1]) : undefined;
      const url  = m[2];
      const inner = m[3];
      const fields: Record<string, string> = {};
      const fieldRe = /<content name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/content>/g;
      for (const f of inner.matchAll(fieldRe)) {
        fields[f[1]] = this.stripTags(f[2]);
      }
      docs.push({
        rank,
        url,
        title:        fields['title'],
        snippet:      fields['snippet'] ?? fields['FullSummary'],
        organization: fields['organizationName'],
      });
    }
    return { total, returned: docs.length, results: docs };
  }

  private stripTags(s: string): string {
    return s
      .replace(/<[^>]+>/g, '')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .trim();
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }
}
