/**
 * SEC EDGAR MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URLs:
//   Full-text search:  https://efts.sec.gov/LATEST
//   Submissions/facts: https://data.sec.gov
//   Ticker lookup:     https://www.sec.gov/files/company_tickers.json
// Auth: None — SEC EDGAR public APIs, no key required
// Docs: https://www.sec.gov/developer
// Category: finance

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const EFTS_BASE = 'https://efts.sec.gov/LATEST';
const DATA_BASE = 'https://data.sec.gov';
const TICKERS_URL = 'https://www.sec.gov/files/company_tickers.json';

const SEC_HEADERS: Record<string, string> = {
  'User-Agent': 'EpicAI/1.0 (support@protectnil.com)',
  Accept: 'application/json',
};

export class EdgarMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'edgar',
      displayName: 'SEC EDGAR',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'sec', 'edgar', 'filings', 'securities', 'annual report', '10-K', '10-Q', '8-K',
        'xbrl', 'financial data', 'company facts', 'cik', 'ticker', 'public company',
        'revenue', 'net income', 'assets', 'gaap', 'quarterly', 'investor relations',
      ],
      toolNames: [
        'edgar_search_filings',
        'edgar_company_filings',
        'edgar_company_facts',
        'edgar_company_concept',
        'edgar_ticker_to_cik',
      ],
      description: 'SEC EDGAR public APIs: full-text filing search, company filings, XBRL financial facts, financial concepts over time, and ticker-to-CIK lookup — all free, no authentication required.',
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
        name: 'edgar_search_filings',
        description:
          'Full-text search across all SEC EDGAR filings. Search by keyword, company name, or topic. Optionally filter by form type and date range.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (e.g., "artificial intelligence", "Tesla revenue")',
            },
            form_type: {
              type: 'string',
              description: 'Filter by SEC form type (e.g., "10-K", "10-Q", "8-K", "DEF 14A"). Omit for all types.',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format (e.g., "2024-01-01")',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format (e.g., "2024-12-31")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1-40, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'edgar_company_filings',
        description:
          'Get recent SEC filings for a specific company. Accepts a ticker symbol or CIK number. Optionally filter by form type.',
        inputSchema: {
          type: 'object',
          properties: {
            ticker_or_cik: {
              type: 'string',
              description: 'Ticker symbol (e.g., "AAPL") or CIK number (e.g., "320193")',
            },
            form_type: {
              type: 'string',
              description: 'Filter by SEC form type (e.g., "10-K", "10-Q", "8-K"). Omit for all types.',
            },
            limit: {
              type: 'number',
              description: 'Max filings to return (1-40, default 20)',
            },
          },
          required: ['ticker_or_cik'],
        },
      },
      {
        name: 'edgar_company_facts',
        description:
          'Get structured XBRL financial data for a company by CIK. Returns key financial metrics like revenue, net income, assets, and more with their most recent annual values.',
        inputSchema: {
          type: 'object',
          properties: {
            cik: {
              type: 'string',
              description: 'Company CIK number (e.g., "320193" for Apple). Use edgar_ticker_to_cik to look up if needed.',
            },
          },
          required: ['cik'],
        },
      },
      {
        name: 'edgar_company_concept',
        description:
          'Get a specific financial metric over time for a company. Returns all reported annual values across filings for a given US-GAAP concept.',
        inputSchema: {
          type: 'object',
          properties: {
            cik: {
              type: 'string',
              description: 'Company CIK number (e.g., "320193" for Apple)',
            },
            concept: {
              type: 'string',
              description:
                'US-GAAP concept name (e.g., "Revenue", "NetIncomeLoss", "Assets", "Liabilities", "StockholdersEquity", "EarningsPerShareDiluted")',
            },
          },
          required: ['cik', 'concept'],
        },
      },
      {
        name: 'edgar_ticker_to_cik',
        description:
          'Look up a company CIK number from its ticker symbol. The CIK is needed for other EDGAR tools.',
        inputSchema: {
          type: 'object',
          properties: {
            ticker: {
              type: 'string',
              description: 'Stock ticker symbol (e.g., "AAPL", "MSFT", "TSLA")',
            },
          },
          required: ['ticker'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'edgar_search_filings':
          return this.searchFilings(
            args.query as string,
            args.form_type as string | undefined,
            args.start_date as string | undefined,
            args.end_date as string | undefined,
            args.limit as number | undefined,
          );
        case 'edgar_company_filings':
          return this.companyFilings(
            args.ticker_or_cik as string,
            args.form_type as string | undefined,
            args.limit as number | undefined,
          );
        case 'edgar_company_facts':
          return this.companyFacts(args.cik as string);
        case 'edgar_company_concept':
          return this.companyConcept(args.cik as string, args.concept as string);
        case 'edgar_ticker_to_cik':
          return this.tickerToCik(args.ticker as string);
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

  private isNumericCik(value: string): boolean {
    return /^\d+$/.test(value.trim());
  }

  private async secFetch(url: string): Promise<Response> {
    return this.fetchWithRetry(url, {
      method: 'GET',
      headers: SEC_HEADERS,
    });
  }

  private async searchFilings(
    query: string,
    formType?: string,
    startDate?: string,
    endDate?: string,
    limit?: number,
  ): Promise<ToolResult> {
    const count = Math.min(40, Math.max(1, limit ?? 10));
    const params = new URLSearchParams({ q: query, from: '0', size: String(count) });

    if (formType) params.set('forms', formType);
    if (startDate || endDate) {
      params.set('dateRange', 'custom');
      if (startDate) params.set('startdt', startDate);
      if (endDate) params.set('enddt', endDate);
    }

    const response = await this.secFetch(`${EFTS_BASE}/search-index?${params}`);
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `SEC EDGAR search error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as {
      hits: {
        hits: {
          _source: {
            entity_name: string;
            entity_id: string;
            form_type: string;
            file_date: string;
            period_of_report: string;
            biz_location: string;
          };
          _id: string;
        }[];
        total: { value: number };
      };
    };

    const results = (data.hits?.hits ?? []).map((hit) => {
      const s = hit._source;
      return {
        entity_name: s.entity_name,
        cik: s.entity_id,
        form_type: s.form_type,
        filing_date: s.file_date,
        period_of_report: s.period_of_report,
        location: s.biz_location,
        filing_id: hit._id,
      };
    });

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          query,
          form_type_filter: formType ?? 'all',
          date_range: { start: startDate ?? null, end: endDate ?? null },
          total_hits: data.hits?.total?.value ?? 0,
          results,
        }),
      }],
      isError: false,
    };
  }

  private async tickerToCikInternal(ticker: string): Promise<{
    ticker: string;
    cik: string;
    cik_padded: string;
    company_name: string;
  }> {
    const response = await this.secFetch(TICKERS_URL);
    if (!response.ok) throw new Error(`SEC ticker lookup error: ${response.status}`);

    const data = (await response.json()) as Record<
      string,
      { cik_str: number; ticker: string; title: string }
    >;

    const upperTicker = ticker.toUpperCase().trim();
    for (const entry of Object.values(data)) {
      if (entry.ticker === upperTicker) {
        return {
          ticker: entry.ticker,
          cik: String(entry.cik_str),
          cik_padded: String(entry.cik_str).padStart(10, '0'),
          company_name: entry.title,
        };
      }
    }

    throw new Error(`Ticker "${ticker}" not found in SEC company tickers`);
  }

  private async tickerToCik(ticker: string): Promise<ToolResult> {
    const result = await this.tickerToCikInternal(ticker);
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async resolveCik(tickerOrCik: string): Promise<string> {
    if (this.isNumericCik(tickerOrCik)) return tickerOrCik.trim();
    const result = await this.tickerToCikInternal(tickerOrCik);
    return result.cik;
  }

  private async companyFilings(
    tickerOrCik: string,
    formType?: string,
    limit?: number,
  ): Promise<ToolResult> {
    const cik = await this.resolveCik(tickerOrCik);
    const paddedCik = this.padCik(cik);
    const count = Math.min(40, Math.max(1, limit ?? 20));

    const response = await this.secFetch(`${DATA_BASE}/submissions/CIK${paddedCik}.json`);
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `SEC EDGAR submissions error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as {
      cik: string;
      name: string;
      sic: string;
      sicDescription: string;
      stateOfIncorporation: string;
      fiscalYearEnd: string;
      tickers: string[];
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

    for (let i = 0; i < recent.accessionNumber.length && filings.length < count; i++) {
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
    }

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          cik: data.cik,
          company_name: data.name,
          tickers: data.tickers ?? [],
          sic_description: data.sicDescription,
          state_of_incorporation: data.stateOfIncorporation,
          fiscal_year_end: data.fiscalYearEnd,
          filter_form_type: formType ?? 'all',
          filings,
        }),
      }],
      isError: false,
    };
  }

  private async companyFacts(cik: string): Promise<ToolResult> {
    const paddedCik = this.padCik(cik);
    const response = await this.secFetch(`${DATA_BASE}/api/xbrl/companyfacts/CIK${paddedCik}.json`);
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `SEC EDGAR company facts error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as {
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
              { end: string; val: number; accn: string; fy: number; fp: string; form: string; filed: string; frame?: string }[]
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

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          cik: String(data.cik),
          company_name: data.entityName,
          key_financials: metrics,
          available_concepts: Object.keys(usGaap).length,
        }),
      }],
      isError: false,
    };
  }

  private async companyConcept(cik: string, concept: string): Promise<ToolResult> {
    const paddedCik = this.padCik(cik);
    const response = await this.secFetch(
      `${DATA_BASE}/api/xbrl/companyconcept/CIK${paddedCik}/us-gaap/${encodeURIComponent(concept)}.json`,
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{
          type: 'text',
          text: `SEC EDGAR company concept error: ${response.status} ${errText} — concept "${concept}" may not exist for CIK ${cik}`,
        }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      cik: number;
      entityName: string;
      tag: string;
      taxonomy: string;
      label: string;
      description: string;
      units: Record<
        string,
        { end: string; val: number; accn: string; fy: number; fp: string; form: string; filed: string; frame?: string }[]
      >;
    };

    const entries: {
      fiscal_year: number;
      period_end: string;
      value: number;
      filed: string;
      unit: string;
    }[] = [];

    for (const [unit, values] of Object.entries(data.units)) {
      const annuals = values
        .filter((e) => e.form === '10-K' && e.frame !== undefined)
        .sort((a, b) => (b.fy ?? 0) - (a.fy ?? 0));

      for (const entry of annuals) {
        entries.push({
          fiscal_year: entry.fy,
          period_end: entry.end,
          value: entry.val,
          filed: entry.filed,
          unit,
        });
      }
    }

    return {
      content: [{
        type: 'text',
        text: this.truncate({
          cik: String(data.cik),
          company_name: data.entityName,
          concept: data.tag,
          label: data.label,
          description: data.description,
          annual_values: entries,
        }),
      }],
      isError: false,
    };
  }
}
