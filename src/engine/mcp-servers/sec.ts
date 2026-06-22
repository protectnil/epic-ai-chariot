/**
 * SEC EDGAR MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL (search): https://efts.sec.gov/LATEST
// Base URL (data):   https://data.sec.gov
// Auth: None — SEC EDGAR public APIs are free and unauthenticated.
//       SEC requires a descriptive User-Agent header per their usage guidelines.
// Docs: https://www.sec.gov/developer
// Category: finance

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const EFTS_BASE = 'https://efts.sec.gov/LATEST';
const DATA_BASE = 'https://data.sec.gov';

const SEC_USER_AGENT = 'Epic AI / protectNIL contact@protectnil.com';

export class SECMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'sec',
      displayName: 'SEC EDGAR',
      version: '1.0.0',
      category: 'finance' as const,
      keywords: [
        'sec', 'edgar', 'securities', 'filing', '10-k', '10-q', '8-k',
        'annual report', 'quarterly report', 'cik', 'xbrl', 'financial facts',
        'revenue', 'net income', 'assets', 'company search', 'ticker',
        'public company', 'stock', 'equity', 'disclosure', 'regulatory',
        'us-gaap', 'financial statements',
      ],
      toolNames: [
        'search_companies',
        'get_company_filings',
        'get_company_facts',
      ],
      description: 'SEC EDGAR: search public companies by name or ticker, retrieve recent SEC filings (10-K, 10-Q, 8-K, etc.), and fetch XBRL financial facts — free and unauthenticated.',
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
        name: 'search_companies',
        description:
          'Search SEC EDGAR for companies by name or ticker symbol. Returns matching company names and their CIK numbers, which are needed for other SEC tools.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Company name or ticker to search for (e.g., "Apple", "TSLA", "Microsoft")',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_company_filings',
        description:
          'Get recent SEC filings for a company using its CIK number. Returns filing dates, form types, accession numbers, and direct document URLs. Optionally filter by form type (e.g., "10-K", "10-Q", "8-K").',
        inputSchema: {
          type: 'object',
          properties: {
            cik: {
              type: 'string',
              description: 'Company CIK number (digits only, e.g., "320193" for Apple)',
            },
            form_type: {
              type: 'string',
              description: 'Filter by SEC form type (e.g., "10-K", "10-Q", "8-K", "DEF 14A"). Omit to return all recent filings.',
            },
          },
          required: ['cik'],
        },
      },
      {
        name: 'get_company_facts',
        description:
          'Get XBRL financial facts for a company using its CIK number. Returns structured financial data including revenue, net income, total assets, and other reported metrics over time.',
        inputSchema: {
          type: 'object',
          properties: {
            cik: {
              type: 'string',
              description: 'Company CIK number (digits only, e.g., "320193" for Apple)',
            },
          },
          required: ['cik'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_companies':
          return this.searchCompanies(args.query as string);
        case 'get_company_filings':
          return this.getCompanyFilings(args.cik as string, args.form_type as string | undefined);
        case 'get_company_facts':
          return this.getCompanyFacts(args.cik as string);
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

  private padCik(cik: string): string {
    return cik.replace(/\D/g, '').padStart(10, '0');
  }

  private async searchCompanies(query: string): Promise<ToolResult> {
    const params = new URLSearchParams({ q: query });
    const url = `${EFTS_BASE}/search-index?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'User-Agent': SEC_USER_AGENT,
        Accept: 'application/json',
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SEC EDGAR search error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      hits: {
        hits: {
          _source: {
            entity_name: string;
            entity_id: string;
            category: string;
            form_type: string;
            file_date: string;
          };
        }[];
        total: { value: number };
      };
    };

    const seen = new Set<string>();
    const companies: { cik: string; name: string; category: string }[] = [];

    for (const hit of (data?.hits?.hits ?? [])) {
      const src = hit._source;
      const cik = src.entity_id;
      if (!seen.has(cik)) {
        seen.add(cik);
        companies.push({
          cik,
          name: src.entity_name,
          category: src.category ?? '',
        });
      }
    }

    const result = {
      query,
      total_hits: data.hits?.total?.value ?? 0,
      companies,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCompanyFilings(cik: string, formType?: string): Promise<ToolResult> {
    const paddedCik = this.padCik(cik);
    const url = `${DATA_BASE}/submissions/CIK${paddedCik}.json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'User-Agent': SEC_USER_AGENT,
        Accept: 'application/json',
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SEC EDGAR submissions error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      cik: string;
      name: string;
      sic: string;
      sicDescription: string;
      stateOfIncorporation: string;
      fiscalYearEnd: string;
      filings: {
        recent: {
          accessionNumber: string[];
          filingDate: string[];
          form: string[];
          primaryDocument: string[];
          items: string[];
          size: number[];
        };
      };
    };

    const recent = data.filings.recent;
    const filings: {
      accession_number: string;
      filing_date: string;
      form: string;
      primary_document: string;
      document_url: string;
    }[] = [];

    for (let i = 0; i < recent.accessionNumber.length; i++) {
      const form = recent.form[i];
      if (formType && form !== formType) continue;

      const accession = recent.accessionNumber[i];
      const accessionPath = accession.replace(/-/g, '');
      filings.push({
        accession_number: accession,
        filing_date: recent.filingDate[i],
        form,
        primary_document: recent.primaryDocument[i],
        document_url: `https://www.sec.gov/Archives/edgar/data/${data.cik}/${accessionPath}/${recent.primaryDocument[i]}`,
      });

      if (filings.length >= 20) break;
    }

    const result = {
      cik: data.cik,
      company_name: data.name,
      sic_description: data.sicDescription,
      state_of_incorporation: data.stateOfIncorporation,
      fiscal_year_end: data.fiscalYearEnd,
      filter_form_type: formType ?? 'all',
      filings,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getCompanyFacts(cik: string): Promise<ToolResult> {
    const paddedCik = this.padCik(cik);
    const url = `${DATA_BASE}/api/xbrl/companyfacts/CIK${paddedCik}.json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'User-Agent': SEC_USER_AGENT,
        Accept: 'application/json',
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `SEC EDGAR company facts error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      cik: number;
      entityName: string;
      facts: {
        'us-gaap'?: Record<
          string,
          {
            label: string;
            description: string;
            units: Record<
              string,
              {
                end: string;
                val: number;
                accn: string;
                fy: number;
                fp: string;
                form: string;
                filed: string;
                frame?: string;
              }[]
            >;
          }
        >;
      };
    };

    const usGaap = data.facts?.['us-gaap'] ?? {};
    const KEY_METRICS = [
      'Revenues',
      'RevenueFromContractWithCustomerExcludingAssessedTax',
      'NetIncomeLoss',
      'Assets',
      'Liabilities',
      'StockholdersEquity',
      'CashAndCashEquivalentsAtCarryingValue',
      'EarningsPerShareBasic',
      'EarningsPerShareDiluted',
      'CommonStockSharesOutstanding',
      'OperatingIncomeLoss',
      'GrossProfit',
      'ResearchAndDevelopmentExpense',
    ];

    const metrics: Record<
      string,
      { label: string; most_recent_annual: { year: number; value: number; filed: string } | null }
    > = {};

    for (const key of KEY_METRICS) {
      const fact = usGaap[key];
      if (!fact) continue;

      const usdEntries = fact.units['USD'] ?? fact.units['shares'] ?? [];
      const annual = usdEntries
        .filter((e) => e.form === '10-K' && e.frame !== undefined)
        .sort((a, b) => (b.fy ?? 0) - (a.fy ?? 0));

      metrics[key] = {
        label: fact.label,
        most_recent_annual: annual[0]
          ? { year: annual[0].fy, value: annual[0].val, filed: annual[0].filed }
          : null,
      };
    }

    const result = {
      cik: String(data.cik),
      company_name: data.entityName,
      key_financials: metrics,
      available_concepts: Object.keys(usGaap).length,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
