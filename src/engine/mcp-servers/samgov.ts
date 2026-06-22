/**
 * SAM.gov MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URLs: https://api.sam.gov/opportunities/v2/search (contract opportunities)
//            https://api.sam.gov/entity-information/v3/entities (entity/vendor registry)
// Auth: api_key query parameter — free key from https://sam.gov/content/entity-information
// Docs: https://open.gsa.gov/api/opportunities-api/
//       https://open.gsa.gov/api/entity-api/
// Category: government

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const OPPS_BASE = 'https://api.sam.gov/opportunities/v2/search';
const ENTITY_BASE = 'https://api.sam.gov/entity-information/v3/entities';

interface SamGovConfig {
  apiKey: string;
}

export class SamGovMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;

  constructor(config: SamGovConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('SAM.gov: configuration object is required');
    }
    if (!config.apiKey) {
      throw new Error('SAM.gov: apiKey is required — get a free key at https://sam.gov/content/entity-information');
    }
    this.apiKey = config.apiKey;
  }

  static catalog() {
    return {
      name: 'samgov',
      displayName: 'SAM.gov — Federal Contracts & Entity Registry',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'sam.gov', 'federal contracts', 'government procurement', 'contract opportunities',
        'solicitation', 'rfp', 'rfq', 'naics', 'set-aside', 'small business',
        'sdvosb', 'hubzone', '8a', 'wosb', 'edwosb', 'entity registration',
        'uei', 'cage code', 'vendor registration', 'federal acquisition',
        'government contracting', 'presolicitation', 'award notice',
      ],
      toolNames: [
        'sam_search_opportunities',
        'sam_get_opportunity',
        'sam_entity_search',
        'sam_set_aside_opportunities',
      ],
      description:
        'SAM.gov: search active federal contract opportunities, look up full opportunity details by solicitation number, search registered vendors/entities in the SAM database, and filter opportunities by small business set-aside type.',
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
        name: 'sam_search_opportunities',
        description:
          'Search active federal contract opportunities on SAM.gov. Filter by keyword, NAICS code, set-aside type, posting date range, and procurement type.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Search term for opportunity title or description',
            },
            naics: {
              type: 'string',
              description: 'NAICS code to filter by (e.g. "541512" for computer systems design)',
            },
            set_aside: {
              type: 'string',
              description:
                'Small business set-aside type: SBA (Small Business), SDVOSB (Service-Disabled Veteran), HUBZone, 8AN (8(a)), WOSB (Women-Owned), EDWOSB (Economically Disadvantaged Women-Owned)',
            },
            posted_from: {
              type: 'string',
              description: 'Start of posting date range in MM/dd/yyyy format',
            },
            posted_to: {
              type: 'string',
              description: 'End of posting date range in MM/dd/yyyy format',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–100, default 10)',
            },
            offset: {
              type: 'number',
              description: 'Result offset for pagination (default 0)',
            },
            ptype: {
              type: 'string',
              description:
                'Procurement type: p (presolicitation), o (solicitation), k (combined synopsis/solicitation), a (award notice)',
            },
          },
          required: ['keyword'],
        },
      },
      {
        name: 'sam_get_opportunity',
        description:
          'Get full details for a specific federal contract opportunity by its solicitation number. Returns point of contact, attachments, classification, and full description.',
        inputSchema: {
          type: 'object',
          properties: {
            solicitation_number: {
              type: 'string',
              description: 'The solicitation number to look up (e.g. "W912DY-24-R-0001")',
            },
          },
          required: ['solicitation_number'],
        },
      },
      {
        name: 'sam_entity_search',
        description:
          'Search for registered entities (vendors/contractors) in the SAM.gov entity database. Returns UEI, CAGE code, business name, address, NAICS codes, small business status, and certifications.',
        inputSchema: {
          type: 'object',
          properties: {
            business_name: {
              type: 'string',
              description: 'Legal business name to search for',
            },
            naics: {
              type: 'string',
              description: 'Filter by primary NAICS code (optional)',
            },
            state: {
              type: 'string',
              description: 'Filter by 2-letter US state code (e.g. "VA", "CA")',
            },
            small_business: {
              type: 'boolean',
              description: 'Filter to only small business entities (optional)',
            },
          },
          required: ['business_name'],
        },
      },
      {
        name: 'sam_set_aside_opportunities',
        description:
          'Search federal contract opportunities filtered by small business set-aside type. Useful for finding opportunities reserved for specific small business categories.',
        inputSchema: {
          type: 'object',
          properties: {
            set_aside: {
              type: 'string',
              description:
                'Set-aside type (required): SBA, SDVOSB, HUBZone, 8AN, WOSB, EDWOSB',
            },
            keyword: {
              type: 'string',
              description: 'Optional keyword to narrow results',
            },
            naics: {
              type: 'string',
              description: 'Optional NAICS code filter',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–100, default 10)',
            },
          },
          required: ['set_aside'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'sam_search_opportunities':
          return this.searchOpportunities(args);
        case 'sam_get_opportunity':
          return this.getOpportunity(args.solicitation_number as string);
        case 'sam_entity_search':
          return this.entitySearch(args);
        case 'sam_set_aside_opportunities':
          return this.setAsideOpportunities(args);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async samRequest(url: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SAM.gov API error (${response.status}): ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private formatOpportunity(opp: Record<string, unknown>) {
    return {
      title: opp['title'] ?? null,
      solicitation_number: opp['solicitationNumber'] ?? null,
      department: opp['department'] ?? null,
      sub_tier: opp['subTier'] ?? null,
      office: opp['office'] ?? null,
      posted_date: opp['postedDate'] ?? null,
      response_deadline: opp['responseDeadLine'] ?? null,
      type: opp['type'] ?? null,
      set_aside:
        (opp['setAsideDescription'] as string | null) ??
        (opp['setAside'] as string | null) ??
        null,
      naics_code: opp['naicsCode'] ?? null,
      classification_code: opp['classificationCode'] ?? null,
      active: opp['active'] ?? null,
      ui_link: opp['uiLink'] ?? null,
    };
  }

  private async searchOpportunities(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ api_key: this.apiKey });
    if (args['keyword']) params.set('keyword', args['keyword'] as string);
    if (args['naics']) params.set('ncode', args['naics'] as string);
    if (args['set_aside']) params.set('typeOfSetAside', args['set_aside'] as string);
    if (args['posted_from']) params.set('postedFrom', args['posted_from'] as string);
    if (args['posted_to']) params.set('postedTo', args['posted_to'] as string);
    if (args['ptype']) params.set('ptype', args['ptype'] as string);

    const limit = Math.min(100, Math.max(1, (args['limit'] as number) ?? 10));
    params.set('limit', String(limit));
    const offset = (args['offset'] as number) ?? 0;
    params.set('offset', String(offset));

    const result = await this.samRequest(`${OPPS_BASE}?${params}`);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text);
      const opps: Record<string, unknown>[] = raw.opportunitiesData ?? [];
      const out = {
        total_records: raw.totalRecords ?? 0,
        limit,
        offset,
        opportunities: opps.map((o) => this.formatOpportunity(o)),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getOpportunity(solicitationNumber: string): Promise<ToolResult> {
    if (!solicitationNumber) {
      return {
        content: [{ type: 'text', text: 'sam_get_opportunity: solicitation_number is required' }],
        isError: true,
      };
    }

    const params = new URLSearchParams({
      api_key: this.apiKey,
      solnum: solicitationNumber,
      limit: '1',
    });

    const result = await this.samRequest(`${OPPS_BASE}?${params}`);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text);
      const opps: Record<string, unknown>[] = raw.opportunitiesData ?? [];
      if (opps.length === 0) {
        return {
          content: [
            {
              type: 'text',
              text: `No opportunity found for solicitation number: ${solicitationNumber}`,
            },
          ],
          isError: true,
        };
      }

      const opp = opps[0];
      const pocs: Record<string, unknown>[] = (opp['pointOfContact'] as Record<string, unknown>[] | undefined) ?? [];
      const out = {
        ...this.formatOpportunity(opp),
        description: opp['description'] ?? null,
        point_of_contact: pocs.map((poc) => ({
          name: poc['fullName'] ?? null,
          title: poc['title'] ?? null,
          email: poc['email'] ?? null,
          phone: poc['phone'] ?? null,
          type: poc['type'] ?? null,
        })),
        resource_links: (opp['resourceLinks'] as string[] | undefined) ?? [],
        archive_type: opp['archiveType'] ?? null,
        archive_date: opp['archiveDate'] ?? null,
        organization_type: opp['organizationType'] ?? null,
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async entitySearch(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      api_key: this.apiKey,
      legalBusinessName: args['business_name'] as string,
      samRegistered: 'Yes',
      purposeOfRegistrationCode: 'Z2~Z5',
    });
    if (args['naics']) params.set('naicsCode', args['naics'] as string);
    if (args['state']) params.set('physicalAddressStateCode', args['state'] as string);
    if (args['small_business'] === true) params.set('businessTypeCode', 'SB');

    const result = await this.samRequest(`${ENTITY_BASE}?${params}`);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text);
      const entities: Record<string, unknown>[] = raw.entityData ?? [];
      const out = {
        total_records: raw.totalRecords ?? 0,
        entities: entities.map((e) => {
          const reg = (e['entityRegistration'] as Record<string, unknown> | undefined) ?? {};
          const addr = (reg['physicalAddress'] as Record<string, unknown> | undefined) ?? {};
          const assertions = (e['assertions'] as Record<string, unknown> | undefined) ?? {};
          const sbaTypes: Record<string, unknown>[] =
            (assertions['sbaBusinessTypes'] as Record<string, unknown>[] | undefined) ?? [];
          const coreData = (e['coreData'] as Record<string, unknown> | undefined) ?? {};
          const entityInfo = (coreData['entityInformation'] as Record<string, unknown> | undefined) ?? {};

          return {
            uei: reg['ueiSAM'] ?? null,
            cage_code: reg['cageCode'] ?? null,
            legal_business_name: reg['legalBusinessName'] ?? null,
            dba_name: reg['dbaName'] ?? null,
            registration_status: reg['registrationStatus'] ?? null,
            registration_date: reg['registrationDate'] ?? null,
            expiration_date: reg['expirationDate'] ?? null,
            address: {
              line1: addr['addressLine1'] ?? null,
              city: addr['city'] ?? null,
              state: addr['stateOrProvinceCode'] ?? null,
              zip: addr['zipCode'] ?? null,
              country: addr['countryCode'] ?? null,
            },
            primary_naics: reg['primaryNaics'] ?? null,
            business_types: (reg['businessTypes'] as string[] | undefined) ?? [],
            sba_certifications: sbaTypes
              .map((t) => (t['sbaBusinessTypeDesc'] as string | null) ?? null)
              .filter(Boolean),
            entity_url: entityInfo['entityURL'] ?? null,
          };
        }),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }

  private async setAsideOpportunities(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      api_key: this.apiKey,
      typeOfSetAside: args['set_aside'] as string,
    });
    if (args['keyword']) params.set('keyword', args['keyword'] as string);
    if (args['naics']) params.set('ncode', args['naics'] as string);

    const limit = Math.min(100, Math.max(1, (args['limit'] as number) ?? 10));
    params.set('limit', String(limit));

    const result = await this.samRequest(`${OPPS_BASE}?${params}`);
    if (result.isError) return result;

    try {
      const raw = JSON.parse(result.content[0].text);
      const opps: Record<string, unknown>[] = raw.opportunitiesData ?? [];
      const out = {
        set_aside_type: args['set_aside'],
        total_records: raw.totalRecords ?? 0,
        limit,
        opportunities: opps.map((o) => this.formatOpportunity(o)),
      };
      return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
    } catch {
      return result;
    }
  }
}
