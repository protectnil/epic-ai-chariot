/**
 * DailyMed MCP Adapter — FDA Structured Product Labels via NLM
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://dailymed.nlm.nih.gov/dailymed/services/v2
 * Auth: None — public NLM/FDA API
 * Docs: https://dailymed.nlm.nih.gov/dailymed/app-support-web-services.cfm
 * Category: health
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://dailymed.nlm.nih.gov/dailymed/services/v2';

export class DailyMedMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DailyMedMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'dailymed',
      displayName: 'DailyMed',
      version: '1.0.0',
      category: 'health',
      keywords: [
        'dailymed', 'fda', 'drug', 'drugs', 'medication', 'medications',
        'spl', 'structured product label', 'nlm', 'pharmacology',
        'ndc', 'rxcui', 'rxnorm', 'drug class', 'dosage', 'warnings',
        'prescription', 'anda', 'nda', 'pharmaceutical',
      ],
      toolNames: [
        'search_drugs',
        'get_drug',
        'list_labels_for_drug_name',
        'recent_updates',
        'list_classes',
      ],
      description: 'DailyMed: search and retrieve FDA Structured Product Labels (SPLs) — drug names, dosage, warnings, NDC codes, RxCUI, pharmacologic classes. Free public NLM API.',
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
        name: 'search_drugs',
        description: 'Search Structured Product Labels by any combination of name, ANDA/NDA, NDC, RxCUI.',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Drug name (brand or generic)' },
            application_number: { type: 'string', description: 'ANDA/NDA number (e.g. "NDA021436")' },
            ndc: { type: 'string', description: 'NDC code (11-digit)' },
            rxcui: { type: 'string', description: 'RxNorm RxCUI' },
            manufacturer: { type: 'string', description: 'Manufacturer name' },
            page: { type: 'number', description: '1-based page (default 1)' },
            pagesize: { type: 'number', description: '1-100 (default 25)' },
          },
        },
      },
      {
        name: 'get_drug',
        description: 'Full SPL metadata + sections (e.g. dosage, warnings) by set_id.',
        inputSchema: {
          type: 'object',
          properties: {
            set_id: { type: 'string', description: 'DailyMed setId UUID' },
          },
          required: ['set_id'],
        },
      },
      {
        name: 'list_labels_for_drug_name',
        description: 'All labels mentioning a drug name.',
        inputSchema: {
          type: 'object',
          properties: {
            drug_name: { type: 'string', description: 'Drug name to search for' },
            page: { type: 'number', description: '1-based page (default 1)' },
            pagesize: { type: 'number', description: '1-100 (default 25)' },
          },
          required: ['drug_name'],
        },
      },
      {
        name: 'recent_updates',
        description: 'Recently updated labels.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'number', description: '1-100 (default 25)' },
          },
        },
      },
      {
        name: 'list_classes',
        description: 'Pharmacologic / drug-class reference (EPC, MoA, PE, CS).',
        inputSchema: {
          type: 'object',
          properties: {
            class_code: { type: 'string', description: 'Restrict to a specific class code' },
            type: { type: 'string', description: 'EPC | MoA | PE | CS' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_drugs':              return this.searchDrugs(args);
        case 'get_drug':                  return this.getDrug(args);
        case 'list_labels_for_drug_name': return this.listLabelsForDrugName(args);
        case 'recent_updates':            return this.recentUpdates(args);
        case 'list_classes':              return this.listClasses(args);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'DailyMed: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `DailyMed API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchDrugs(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.name)               params.set('drug_name', String(args.name));
    if (args.application_number) params.set('application_number', String(args.application_number));
    if (args.ndc)                params.set('ndc', String(args.ndc));
    if (args.rxcui)              params.set('rxcui', String(args.rxcui));
    if (args.manufacturer)       params.set('manufacturer', String(args.manufacturer));
    params.set('page',     String(Math.max(1, (args.page as number) ?? 1)));
    params.set('pagesize', String(Math.min(100, Math.max(1, (args.pagesize as number) ?? 25))));
    return this.get(`/spls.json?${params}`);
  }

  private async getDrug(args: Record<string, unknown>): Promise<ToolResult> {
    const setId = this.requireString(args, 'set_id', '"abc123-..."');
    return this.get(`/spls/${encodeURIComponent(setId)}.json`);
  }

  private async listLabelsForDrugName(args: Record<string, unknown>): Promise<ToolResult> {
    const drugName = this.requireString(args, 'drug_name', '"ibuprofen"');
    const params = new URLSearchParams({
      drug_name: drugName,
      page:     String(Math.max(1, (args.page as number) ?? 1)),
      pagesize: String(Math.min(100, Math.max(1, (args.pagesize as number) ?? 25))),
    });
    return this.get(`/spls.json?${params}`);
  }

  private async recentUpdates(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      pagesize: String(Math.min(100, Math.max(1, (args.limit as number) ?? 25))),
    });
    return this.get(`/spls.json?${params}`);
  }

  private async listClasses(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.class_code) params.set('class_code', String(args.class_code));
    if (args.type)       params.set('type', String(args.type));
    const qs = params.toString();
    return this.get(`/drugclasses.json${qs ? `?${qs}` : ''}`);
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }
}
