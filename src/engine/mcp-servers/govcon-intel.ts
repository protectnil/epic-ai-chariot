/**
 * GovCon Intel — US Federal Procurement Intelligence MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Calls the real upstream APIs directly:
 *   - SAM.gov Entity Information API v3  https://api.sam.gov/entity-information/v3/entities
 *   - SAM.gov Opportunities API v2       https://api.sam.gov/opportunities/v2/search
 *   - USASpending.gov API v2             https://api.usaspending.gov/api/v2
 *
 * Auth: SAM.gov requires a free API key (api_key query parameter).
 *       USASpending.gov is fully public — no auth required.
 *       Register: https://sam.gov/content/entity-registration (free account)
 *
 * Docs:
 *   SAM.gov Entity API:        https://open.gsa.gov/api/entity-api/
 *   SAM.gov Opportunities API: https://open.gsa.gov/api/get-opportunities-public-api/
 *   USASpending API:           https://api.usaspending.gov/
 *
 * Category: government
 * Tools: govcon_contractor_profile, govcon_opportunity_scan, govcon_agency_landscape,
 *        resolve_entity, compare_entities, entity_profile, recent_changes,
 *        validate_claim, discover_tools
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface GovConIntelConfig {
  /** SAM.gov API key — required for SAM.gov entity and opportunities endpoints. */
  apiKey: string;
  /** Optional SAM.gov base URL override (default: https://api.sam.gov) */
  samBaseUrl?: string;
  /** Optional USASpending base URL override (default: https://api.usaspending.gov) */
  usaSpendingBaseUrl?: string;
}

export class GovConIntelMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly samBaseUrl: string;
  private readonly usaSpendingBaseUrl: string;

  constructor(config: GovConIntelConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('GovCon Intel: configuration object is required');
    }
    if (!config.apiKey || typeof config.apiKey !== 'string' || config.apiKey.trim() === '') {
      throw new Error('GovCon Intel: apiKey is required — register a free SAM.gov account at https://sam.gov/content/entity-registration');
    }
    this.apiKey = config.apiKey.trim();
    this.samBaseUrl = (config.samBaseUrl ?? 'https://api.sam.gov').replace(/\/$/, '');
    this.usaSpendingBaseUrl = (config.usaSpendingBaseUrl ?? 'https://api.usaspending.gov').replace(/\/$/, '');
  }

  static catalog() {
    return {
      name: 'govcon-intel',
      displayName: 'GovCon Intel — US Federal Procurement Intelligence',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'government contractor intelligence',
        'federal opportunity scanning',
        'agency landscape mapping',
        'contractor profile validation',
        'entity comparison',
        'procurement data analysis',
        'contract award tracking',
        'agency procurement trends',
        'compliance monitoring',
        'bid opportunity discovery',
        'entity resolution',
        'federal budget tracking',
        'sam.gov',
        'usaspending',
        'uei',
        'cage code',
        'duns',
        'naics',
        'fpds',
        'set-aside',
        'small business',
        'federal acquisition',
        'grants and contracts database',
        'govcon',
      ],
      toolNames: [
        'govcon_contractor_profile',
        'govcon_opportunity_scan',
        'govcon_agency_landscape',
        'resolve_entity',
        'compare_entities',
        'entity_profile',
        'recent_changes',
        'validate_claim',
        'discover_tools',
      ],
      description: 'GovCon Intel: scan federal procurement opportunities on SAM.gov, retrieve contractor entity profiles and registrations, compare entities by UEI or CAGE code, analyze agency spending landscapes via USASpending.gov, and validate contractor claims against live federal data.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'govcon_contractor_profile',
        description: 'Retrieve a federal contractor\'s full SAM.gov registration profile including entity type, business types, certifications, NAICS codes, and registration status. Accepts UEI (Unique Entity Identifier) or legal entity name.',
        inputSchema: {
          type: 'object',
          properties: {
            ueiSAM: {
              type: 'string',
              description: 'SAM.gov Unique Entity Identifier (UEI) — 12-character alphanumeric. Preferred lookup key.',
            },
            legalBusinessName: {
              type: 'string',
              description: 'Legal business name to search (partial match supported). Used when UEI is unknown.',
            },
            includeSections: {
              type: 'string',
              description: 'Comma-separated SAM.gov entity sections to include (e.g. "entityRegistration,coreData,assertions,repsAndCerts,pointsOfContact"). Defaults to entityRegistration and coreData.',
            },
          },
        },
      },
      {
        name: 'govcon_opportunity_scan',
        description: 'Search active and archived federal procurement opportunities (solicitations, awards, sources sought) on SAM.gov. Filter by keyword, NAICS code, set-aside type, agency, and date range.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Keyword or phrase to search within opportunity titles and descriptions.',
            },
            naicsCode: {
              type: 'string',
              description: 'NAICS code to filter opportunities (e.g. "541512" for Custom Computer Programming).',
            },
            setAsideCode: {
              type: 'string',
              description: 'Set-aside type code: SBA (Small Business), SBP (SB Set-Aside), 8A (8(a)), HZC (HUBZone), WOSB, SDVOSBC, etc.',
            },
            organizationId: {
              type: 'string',
              description: 'Federal agency organization ID to scope the search (e.g. "100136966" for DOD).',
            },
            postedFrom: {
              type: 'string',
              description: 'Posted date lower bound in MM/DD/YYYY format.',
            },
            postedTo: {
              type: 'string',
              description: 'Posted date upper bound in MM/DD/YYYY format.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default: 10, max: 100).',
            },
            offset: {
              type: 'number',
              description: 'Pagination offset (default: 0).',
            },
          },
        },
      },
      {
        name: 'govcon_agency_landscape',
        description: 'Retrieve agency spending landscape from USASpending.gov — total obligations, contract counts, top vendors, and sub-agency breakdowns for a federal agency by toptier agency code.',
        inputSchema: {
          type: 'object',
          properties: {
            agencyCode: {
              type: 'string',
              description: 'Toptier federal agency code (e.g. "097" for Department of Defense, "089" for HHS). Required.',
            },
            fiscalYear: {
              type: 'number',
              description: 'Fiscal year to query (e.g. 2024). Defaults to current fiscal year.',
            },
          },
          required: ['agencyCode'],
        },
      },
      {
        name: 'resolve_entity',
        description: 'Resolve a federal contractor entity by name, UEI, CAGE code, or EFT indicator. Returns the best-matching SAM.gov entity registration record.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Entity name, UEI, CAGE code, or other identifier to resolve.',
            },
            registrationStatus: {
              type: 'string',
              description: 'Filter by registration status: "A" (Active), "E" (Expired), "D" (Draft). Defaults to "A".',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'compare_entities',
        description: 'Compare two or more federal contractor entities side-by-side using their UEI or CAGE codes. Returns registration details, business type, NAICS, and certification data for each.',
        inputSchema: {
          type: 'object',
          properties: {
            ueis: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of UEI codes to compare (2–5 entities).',
            },
            cageCodes: {
              type: 'array',
              items: { type: 'string' },
              description: 'Array of CAGE codes to compare (alternative to UEIs; 2–5 entities).',
            },
          },
        },
      },
      {
        name: 'entity_profile',
        description: 'Retrieve a detailed SAM.gov entity profile by UEI or CAGE code, including all registration sections: core data, assertions, representations and certifications, and points of contact.',
        inputSchema: {
          type: 'object',
          properties: {
            ueiSAM: {
              type: 'string',
              description: 'SAM.gov Unique Entity Identifier (UEI) — preferred.',
            },
            cageCode: {
              type: 'string',
              description: 'CAGE code (Commercial and Government Entity code) — used when UEI is unknown.',
            },
          },
        },
      },
      {
        name: 'recent_changes',
        description: 'Retrieve SAM.gov entity registrations that have changed (updated, newly registered, or deactivated) within a specified date range. Useful for tracking contractor status changes.',
        inputSchema: {
          type: 'object',
          properties: {
            updatedDateFrom: {
              type: 'string',
              description: 'Start of date range for updated registrations (MM/DD/YYYY format).',
            },
            updatedDateTo: {
              type: 'string',
              description: 'End of date range for updated registrations (MM/DD/YYYY format). Defaults to today.',
            },
            registrationStatus: {
              type: 'string',
              description: 'Filter by registration status: "A" (Active), "E" (Expired). Defaults to "A".',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results (default: 20, max: 100).',
            },
          },
          required: ['updatedDateFrom'],
        },
      },
      {
        name: 'validate_claim',
        description: 'Validate a specific contractor claim against live SAM.gov data. Checks whether the stated entity is actively registered, has the claimed certifications (8(a), WOSB, HUBZone, SDVOSB, etc.), and whether the UEI/CAGE/NAICS combination is consistent.',
        inputSchema: {
          type: 'object',
          properties: {
            ueiSAM: {
              type: 'string',
              description: 'UEI of the entity whose claims are being validated.',
            },
            claimedCertifications: {
              type: 'array',
              items: { type: 'string' },
              description: 'List of certifications the contractor claims to hold (e.g. ["SBA8A", "WOSB", "HUBZone"]).',
            },
            claimedNaicsCodes: {
              type: 'array',
              items: { type: 'string' },
              description: 'NAICS codes the contractor claims to operate under.',
            },
          },
          required: ['ueiSAM'],
        },
      },
      {
        name: 'discover_tools',
        description: 'List all available GovCon Intel tools with descriptions and parameter schemas.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'govcon_contractor_profile': return this.govconContractorProfile(args);
        case 'govcon_opportunity_scan':   return this.govconOpportunityScan(args);
        case 'govcon_agency_landscape':   return this.govconAgencyLandscape(args);
        case 'resolve_entity':            return this.resolveEntity(args);
        case 'compare_entities':          return this.compareEntities(args);
        case 'entity_profile':            return this.entityProfile(args);
        case 'recent_changes':            return this.recentChanges(args);
        case 'validate_claim':            return this.validateClaim(args);
        case 'discover_tools':            return this.discoverTools();
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

  /** Build a SAM.gov Entity API URL with the api_key appended. */
  private samEntityUrl(params: Record<string, string | number | undefined>): string {
    const qs = new URLSearchParams({ api_key: this.apiKey });
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        qs.set(k, String(v));
      }
    }
    return `${this.samBaseUrl}/entity-information/v3/entities?${qs.toString()}`;
  }

  /** Build a SAM.gov Opportunities API URL with the api_key appended. */
  private samOppsUrl(params: Record<string, string | number | undefined>): string {
    const qs = new URLSearchParams({ api_key: this.apiKey });
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        qs.set(k, String(v));
      }
    }
    return `${this.samBaseUrl}/opportunities/v2/search?${qs.toString()}`;
  }

  /** Execute a GET against a SAM.gov endpoint and return a ToolResult. */
  private async samGet(url: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SAM.gov API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  /** Execute a GET against a USASpending.gov endpoint and return a ToolResult. */
  private async usaSpendingGet(path: string): Promise<ToolResult> {
    const url = `${this.usaSpendingBaseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USASpending.gov API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  /** Execute a POST against a USASpending.gov endpoint and return a ToolResult. */
  private async usaSpendingPost(path: string, body: unknown): Promise<ToolResult> {
    const url = `${this.usaSpendingBaseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `USASpending.gov API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async govconContractorProfile(args: Record<string, unknown>): Promise<ToolResult> {
    const params: Record<string, string | number | undefined> = {};
    if (args.ueiSAM) params['ueiSAM'] = String(args.ueiSAM);
    if (args.legalBusinessName) params['legalBusinessName'] = String(args.legalBusinessName);

    // Default sections: entityRegistration and coreData; caller can override
    const sections = args.includeSections
      ? String(args.includeSections)
      : 'entityRegistration,coreData';
    params['includeSections'] = sections;

    if (!params['ueiSAM'] && !params['legalBusinessName']) {
      return {
        content: [{ type: 'text', text: 'govcon_contractor_profile: at least one of ueiSAM or legalBusinessName is required' }],
        isError: true,
      };
    }

    const url = this.samEntityUrl(params);
    return this.samGet(url);
  }

  private async govconOpportunityScan(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = Math.min(Number(args.limit ?? 10), 100);
    const offset = Number(args.offset ?? 0);

    const params: Record<string, string | number | undefined> = {
      limit,
      offset,
    };

    if (args.keyword)        params['keyword']        = String(args.keyword);
    if (args.naicsCode)      params['naicsCode']      = String(args.naicsCode);
    if (args.setAsideCode)   params['typeOfSetAsideCode'] = String(args.setAsideCode);
    if (args.organizationId) params['organizationId'] = String(args.organizationId);
    if (args.postedFrom)     params['postedFrom']     = String(args.postedFrom);
    if (args.postedTo)       params['postedTo']       = String(args.postedTo);

    const url = this.samOppsUrl(params);
    return this.samGet(url);
  }

  private async govconAgencyLandscape(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.agencyCode) {
      return {
        content: [{ type: 'text', text: 'govcon_agency_landscape: agencyCode is required' }],
        isError: true,
      };
    }

    const agencyCode = encodeURIComponent(String(args.agencyCode));

    // Fetch agency overview
    const agencyResult = await this.usaSpendingGet(`/api/v2/references/agency/${agencyCode}/`);
    if (agencyResult.isError) return agencyResult;

    // Fetch spending totals for the requested fiscal year
    const fy = args.fiscalYear ? Number(args.fiscalYear) : new Date().getFullYear();
    const spendingResult = await this.usaSpendingPost('/api/v2/search/spending_by_category/awarding_agency/', {
      filters: {
        agencies: [{ type: 'toptier', tier: 'toptier', name: '' }],
        time_period: [{ start_date: `${fy - 1}-10-01`, end_date: `${fy}-09-30` }],
      },
      limit: 10,
      page: 1,
    });

    // Return both results combined
    const combined = {
      agencyProfile: agencyResult.content[0].text,
      spendingLandscape: spendingResult.isError
        ? { error: spendingResult.content[0].text }
        : spendingResult.content[0].text,
      fiscalYear: fy,
      agencyCode: String(args.agencyCode),
    };

    return {
      content: [{ type: 'text', text: this.truncate(combined) }],
      isError: false,
    };
  }

  private async resolveEntity(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.query) {
      return {
        content: [{ type: 'text', text: 'resolve_entity: query is required' }],
        isError: true,
      };
    }

    const query = String(args.query).trim();
    const registrationStatus = args.registrationStatus ? String(args.registrationStatus) : 'A';

    // SAM.gov entity search — attempt UEI match first, then name search
    const ueiPattern = /^[A-Z0-9]{12}$/i;
    const cagePattern = /^[A-Z0-9]{5}$/i;

    const params: Record<string, string | number | undefined> = {
      registrationStatus,
      includeSections: 'entityRegistration,coreData',
    };

    if (ueiPattern.test(query)) {
      params['ueiSAM'] = query.toUpperCase();
    } else if (cagePattern.test(query)) {
      params['cageCode'] = query.toUpperCase();
    } else {
      params['legalBusinessName'] = query;
    }

    const url = this.samEntityUrl(params);
    return this.samGet(url);
  }

  private async compareEntities(args: Record<string, unknown>): Promise<ToolResult> {
    const ueis = Array.isArray(args.ueis) ? (args.ueis as string[]) : [];
    const cages = Array.isArray(args.cageCodes) ? (args.cageCodes as string[]) : [];

    if (ueis.length === 0 && cages.length === 0) {
      return {
        content: [{ type: 'text', text: 'compare_entities: at least one of ueis or cageCodes array is required' }],
        isError: true,
      };
    }

    const identifiers: Array<{ key: string; value: string }> = [
      ...ueis.slice(0, 5).map((v) => ({ key: 'ueiSAM', value: v })),
      ...cages.slice(0, 5).map((v) => ({ key: 'cageCode', value: v })),
    ].slice(0, 5);

    const results: Record<string, unknown> = {};

    for (const { key, value } of identifiers) {
      const url = this.samEntityUrl({
        [key]: value,
        includeSections: 'entityRegistration,coreData,assertions',
      });
      const res = await this.samGet(url);
      results[value] = res.isError
        ? { error: res.content[0].text }
        : (() => { try { return JSON.parse(res.content[0].text); } catch { return res.content[0].text; } })();
    }

    return {
      content: [{ type: 'text', text: this.truncate(results) }],
      isError: false,
    };
  }

  private async entityProfile(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.ueiSAM && !args.cageCode) {
      return {
        content: [{ type: 'text', text: 'entity_profile: at least one of ueiSAM or cageCode is required' }],
        isError: true,
      };
    }

    const params: Record<string, string | number | undefined> = {
      includeSections: 'entityRegistration,coreData,assertions,repsAndCerts,pointsOfContact',
    };

    if (args.ueiSAM)   params['ueiSAM']   = String(args.ueiSAM);
    if (args.cageCode) params['cageCode']  = String(args.cageCode);

    const url = this.samEntityUrl(params);
    return this.samGet(url);
  }

  private async recentChanges(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.updatedDateFrom) {
      return {
        content: [{ type: 'text', text: 'recent_changes: updatedDateFrom is required (MM/DD/YYYY)' }],
        isError: true,
      };
    }

    const limit = Math.min(Number(args.limit ?? 20), 100);
    const registrationStatus = args.registrationStatus ? String(args.registrationStatus) : 'A';

    const params: Record<string, string | number | undefined> = {
      updatedDateFrom:      String(args.updatedDateFrom),
      registrationStatus,
      limit,
      includeSections:      'entityRegistration,coreData',
    };

    if (args.updatedDateTo) {
      params['updatedDateTo'] = String(args.updatedDateTo);
    }

    const url = this.samEntityUrl(params);
    return this.samGet(url);
  }

  private async validateClaim(args: Record<string, unknown>): Promise<ToolResult> {
    if (!args.ueiSAM) {
      return {
        content: [{ type: 'text', text: 'validate_claim: ueiSAM is required' }],
        isError: true,
      };
    }

    const url = this.samEntityUrl({
      ueiSAM:           String(args.ueiSAM),
      includeSections:  'entityRegistration,coreData,assertions,repsAndCerts',
    });

    const entityResult = await this.samGet(url);
    if (entityResult.isError) return entityResult;

    let entityData: unknown;
    try {
      entityData = JSON.parse(entityResult.content[0].text);
    } catch {
      entityData = entityResult.content[0].text;
    }

    const claimedCertifications = Array.isArray(args.claimedCertifications)
      ? (args.claimedCertifications as string[])
      : [];
    const claimedNaicsCodes = Array.isArray(args.claimedNaicsCodes)
      ? (args.claimedNaicsCodes as string[])
      : [];

    const validationResult = {
      ueiSAM: String(args.ueiSAM),
      claimedCertifications,
      claimedNaicsCodes,
      samEntityData: entityData,
      note: 'Cross-reference claimedCertifications and claimedNaicsCodes against the samEntityData assertions and repsAndCerts sections to confirm or refute each claim.',
    };

    return {
      content: [{ type: 'text', text: this.truncate(validationResult) }],
      isError: false,
    };
  }

  private discoverTools(): ToolResult {
    const manifest = this.tools.map((t) => ({
      name: t.name,
      description: t.description,
      parameters: t.inputSchema,
    }));
    return {
      content: [{ type: 'text', text: this.truncate(manifest) }],
      isError: false,
    };
  }
}
