/**
 * Pharma Intel MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrappers (MIT) for the real government APIs.
// This file calls the real upstreams directly. No proxy or gateway is involved.
//
// Primary Base URL: https://api.fda.gov  (OpenFDA — free, no auth)
// Secondary URLs:
//   https://clinicaltrials.gov/api/v2/studies  (ClinicalTrials.gov v2 — free, no auth)
//   https://rxnav.nlm.nih.gov/REST             (RxNorm/NLM — free, no auth)
// Auth: None required — all three upstreams are public government APIs.
// Docs:
//   https://open.fda.gov/apis/
//   https://clinicaltrials.gov/data-api/api
//   https://lhncbc.nlm.nih.gov/RxNav/APIs/RxNormAPIs.html
// Category: health
// Rate limits: OpenFDA ~1,000 req/day unauthenticated; ClinicalTrials.gov unmetered; RxNorm unmetered.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface PharmaIntelConfig {
  /** Optional base URL override for OpenFDA (default: https://api.fda.gov) */
  baseUrl?: string;
}

export class PharmaIntelMCPServer extends MCPAdapterBase {
  private readonly fdaBase: string;
  private readonly ctBase: string;
  private readonly rxBase: string;

  constructor(config: PharmaIntelConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Pharma Intel: configuration object is required');
    }
    this.fdaBase = config.baseUrl ?? 'https://api.fda.gov';
    this.ctBase = 'https://clinicaltrials.gov/api/v2/studies';
    this.rxBase = 'https://rxnav.nlm.nih.gov/REST';
  }

  static catalog() {
    return {
      name: 'pharma-intel',
      displayName: 'Pharma Intel',
      version: '1.0.0',
      category: 'health',
      keywords: [
        'pharma', 'pharmaceutical', 'drug', 'fda', 'openfda', 'clinical trials',
        'rxnorm', 'adverse events', 'faers', 'drug approvals', 'drug labels',
        'drug recalls', 'drug interactions', 'pipeline', 'oncology', 'biotech',
        'clinical research', 'regulatory', 'safety', 'pharmacovigilance',
        'nda', 'biologics', 'bla', 'anda', 'nct', 'clinicaltrials.gov',
      ],
      toolNames: [
        'pharma_drug_profile',
        'pharma_pipeline_scan',
        'pharma_safety_report',
      ],
      description:
        'Pharma Intel: compound tools that chain FDA approvals, drug labels, adverse events, RxNorm data, interactions, and active clinical trials — answering pharma research questions in single calls across ClinicalTrials.gov, OpenFDA, and RxNorm/NLM.',
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
        name: 'pharma_drug_profile',
        description:
          'Pull a complete pharma dossier for a given drug. Chains OpenFDA approvals, structured product labeling, adverse event counts, RxNorm concept data, drug interactions, and active ClinicalTrials.gov studies — all in a single call.',
        inputSchema: {
          type: 'object',
          properties: {
            drug_name: {
              type: 'string',
              description:
                'Brand or generic drug name (e.g., "ozempic", "semaglutide", "keytruda", "pembrolizumab"). Case-insensitive.',
            },
          },
          required: ['drug_name'],
        },
      },
      {
        name: 'pharma_pipeline_scan',
        description:
          'Analyze the clinical trial pipeline for a condition or sponsor. Returns phase breakdowns and a list of recruiting studies from ClinicalTrials.gov, with optional FDA approval cross-reference.',
        inputSchema: {
          type: 'object',
          properties: {
            condition: {
              type: 'string',
              description:
                'Disease or condition to scan (e.g., "breast cancer", "type 2 diabetes", "Alzheimer disease"). Mutually exclusive with sponsor — supply one.',
            },
            sponsor: {
              type: 'string',
              description:
                'Sponsor or pharmaceutical company to scan (e.g., "Pfizer", "Novo Nordisk", "Moderna"). Mutually exclusive with condition — supply one.',
            },
            status: {
              type: 'string',
              description:
                'Optional trial status filter. One of: RECRUITING, ACTIVE_NOT_RECRUITING, COMPLETED, NOT_YET_RECRUITING, TERMINATED, SUSPENDED, WITHDRAWN.',
            },
            limit: {
              type: 'number',
              description: 'Max studies to return (1-100, default 20).',
            },
          },
        },
      },
      {
        name: 'pharma_safety_report',
        description:
          'Aggregate adverse event signals, drug recalls, and interaction data for a drug. Chains OpenFDA FAERS adverse event counts, enforcement/recall records, and RxNorm interaction lookup.',
        inputSchema: {
          type: 'object',
          properties: {
            drug_name: {
              type: 'string',
              description:
                'Brand or generic drug name to report on (e.g., "valsartan", "ozempic", "atorvastatin"). Case-insensitive.',
            },
            limit: {
              type: 'number',
              description: 'Max adverse event results to return per category (1-100, default 10).',
            },
          },
          required: ['drug_name'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'pharma_drug_profile':  return this.pharmaDrugProfile(args);
        case 'pharma_pipeline_scan': return this.pharmaPipelineScan(args);
        case 'pharma_safety_report': return this.pharmaSafetyReport(args);
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

  /** Encode a query string for OpenFDA — preserves +, :, [], quotes; encodes spaces. */
  private encodeOfdaQuery(query: string): string {
    return query.replace(/ /g, '+');
  }

  private async fdaFetch(endpoint: string, params: string): Promise<unknown> {
    const url = `${this.fdaBase}${endpoint}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      if (response.status === 404) return { results: [], meta: { results: { total: 0 } } };
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`OpenFDA API error: ${response.status} ${errText}`);
    }
    return response.json();
  }

  private async ctFetch(params: string[]): Promise<unknown> {
    const url = `${this.ctBase}?${params.join('&')}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`ClinicalTrials.gov API error: ${response.status} ${errText}`);
    }
    return response.json();
  }

  private async rxNormGetRxcui(drugName: string): Promise<string | null> {
    const url = `${this.rxBase}/rxcui.json?name=${encodeURIComponent(drugName)}&search=1`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return null;
    const data = await response.json() as { idGroup?: { rxnormId?: string[] } };
    const ids = data?.idGroup?.rxnormId;
    return (ids && ids.length > 0) ? ids[0] : null;
  }

  private async rxNormGetInteractions(rxcui: string): Promise<unknown> {
    const url = `${this.rxBase}/interaction/interaction.json?rxcui=${encodeURIComponent(rxcui)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return null;
    return response.json();
  }

  private async rxNormGetDrugInfo(rxcui: string): Promise<unknown> {
    const url = `${this.rxBase}/rxcui/${encodeURIComponent(rxcui)}/allrelated.json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return null;
    return response.json();
  }

  // ── Tool implementations ───────────────────────────────────────────────────

  private async pharmaDrugProfile(args: Record<string, unknown>): Promise<ToolResult> {
    const drugName = (args.drug_name as string).trim();
    const drugQ = `openfda.brand_name:"${drugName}"+openfda.generic_name:"${drugName}"`;

    // Run OpenFDA and ClinicalTrials calls in parallel; RxNorm is sequential after rxcui lookup
    const [approvals, labels, adverseEventCounts, activeTrials, rxcui] = await Promise.all([
      this.fdaFetch('/drug/drugsfda.json',  `search=${this.encodeOfdaQuery(`openfda.brand_name:"${drugName}"`)}&limit=5`).catch(() => null),
      this.fdaFetch('/drug/label.json',     `search=${this.encodeOfdaQuery(`openfda.brand_name:"${drugName}"`)}&limit=3`).catch(() => null),
      this.fdaFetch('/drug/event.json',     `search=${this.encodeOfdaQuery(`patient.drug.openfda.brand_name:"${drugName}"`)}&count=patient.reaction.reactionmeddrapt.exact`).catch(() => null),
      this.ctFetch([
        `query.term=${encodeURIComponent(drugName)}`,
        `filter.overallStatus=RECRUITING`,
        `countTotal=true`,
        `pageSize=10`,
      ]).catch(() => null),
      this.rxNormGetRxcui(drugName).catch(() => null),
    ]);

    const [rxInfo, rxInteractions] = rxcui
      ? await Promise.all([
          this.rxNormGetDrugInfo(rxcui).catch(() => null),
          this.rxNormGetInteractions(rxcui).catch(() => null),
        ])
      : [null, null];

    const profile = {
      drug_name: drugName,
      fda_approvals: approvals,
      fda_labels: labels,
      adverse_event_top_reactions: adverseEventCounts,
      active_clinical_trials: activeTrials,
      rxnorm: {
        rxcui,
        drug_info: rxInfo,
        interactions: rxInteractions,
      },
    };

    return { content: [{ type: 'text', text: this.truncate(profile) }], isError: false };
  }

  private async pharmaPipelineScan(args: Record<string, unknown>): Promise<ToolResult> {
    const condition = args.condition as string | undefined;
    const sponsor   = args.sponsor   as string | undefined;
    const status    = args.status    as string | undefined;
    const limit     = Math.min(100, Math.max(1, Number(args.limit ?? 20)));

    if (!condition && !sponsor) {
      return {
        content: [{ type: 'text', text: 'pharma_pipeline_scan: supply at least one of condition or sponsor' }],
        isError: true,
      };
    }

    const params: string[] = [`countTotal=true`, `pageSize=${limit}`];
    if (condition) params.push(`query.cond=${encodeURIComponent(condition)}`);
    if (sponsor)   params.push(`query.spons=${encodeURIComponent(sponsor)}`);
    if (status)    params.push(`filter.overallStatus=${encodeURIComponent(status)}`);

    // Phase breakdown: run four phase-filtered count queries in parallel with the main search
    const phaseFilters = ['PHASE1', 'PHASE2', 'PHASE3', 'PHASE4'];
    const phaseParams = phaseFilters.map((ph) => {
      const p = [...params.filter((x) => !x.startsWith('pageSize')), `pageSize=0`, `filter.advanced=AREA[Phase]${encodeURIComponent(ph)}`];
      return this.ctFetch(p).catch(() => null);
    });

    const [mainResults, ...phaseResults] = await Promise.all([
      this.ctFetch(params).catch(() => null),
      ...phaseParams,
    ]);

    type CTResponse = { totalCount?: number; studies?: unknown[] };
    const phaseCounts: Record<string, number> = {};
    phaseFilters.forEach((ph, i) => {
      phaseCounts[ph] = (phaseResults[i] as CTResponse)?.totalCount ?? 0;
    });

    const result = {
      condition: condition ?? null,
      sponsor:   sponsor   ?? null,
      status_filter: status ?? 'all',
      total_matching_trials: (mainResults as CTResponse)?.totalCount ?? 0,
      phase_breakdown: phaseCounts,
      studies: (mainResults as CTResponse)?.studies ?? [],
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async pharmaSafetyReport(args: Record<string, unknown>): Promise<ToolResult> {
    const drugName = (args.drug_name as string).trim();
    const limit    = Math.min(100, Math.max(1, Number(args.limit ?? 10)));

    const [adverseEvents, adverseEventCounts, recalls, rxcui] = await Promise.all([
      this.fdaFetch('/drug/event.json',
        `search=${this.encodeOfdaQuery(`patient.drug.openfda.brand_name:"${drugName}"`)}&limit=${limit}`
      ).catch(() => null),
      this.fdaFetch('/drug/event.json',
        `search=${this.encodeOfdaQuery(`patient.drug.openfda.brand_name:"${drugName}"`)}&count=patient.reaction.reactionmeddrapt.exact`
      ).catch(() => null),
      this.fdaFetch('/drug/enforcement.json',
        `search=${this.encodeOfdaQuery(`openfda.brand_name:"${drugName}"`)}&limit=${limit}`
      ).catch(() => null),
      this.rxNormGetRxcui(drugName).catch(() => null),
    ]);

    const interactions = rxcui
      ? await this.rxNormGetInteractions(rxcui).catch(() => null)
      : null;

    const report = {
      drug_name: drugName,
      adverse_events: adverseEvents,
      top_adverse_reactions: adverseEventCounts,
      recalls_and_enforcement: recalls,
      rxnorm: {
        rxcui,
        interactions,
      },
    };

    return { content: [{ type: 'text', text: this.truncate(report) }], isError: false };
  }
}
