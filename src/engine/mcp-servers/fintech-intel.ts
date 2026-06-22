/**
 * Fintech Intel MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST upstream: Financial Modeling Prep (financialmodelingprep.com)
// Base URL: https://financialmodelingprep.com/api/v3
// Auth: API key query parameter (apikey) — free tier available at financialmodelingprep.com
// Docs: https://site.financialmodelingprep.com/developer/docs/
// Category: finance
// Rate limits: free tier ~250 requests/day; paid tiers vary
//
// Covers: fintech / banking competitive intelligence — company profiles,
// key metrics, financial ratios, growth data, peer search, sector performance,
// and bank-specific health indicators.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://financialmodelingprep.com/api/v3';

interface FintechIntelConfig {
  apiKey: string;
  baseUrl?: string;
}

export class FintechIntelMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: FintechIntelConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Fintech Intel: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Fintech Intel: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'fintech-intel',
      displayName: 'Fintech Intel',
      version: '1.0.0',
      category: 'finance' as const,
      keywords: [
        'fintech competitive analysis',
        'banking sector benchmarking',
        'market intelligence snapshot',
        'regulatory compliance scoring',
        'institutional health assessment',
        'neobank performance metrics',
        'credit union benchmarking',
        'digital banking trends',
        'SWOT analysis fintech',
        'peer group comparison',
        'company profile',
        'financial ratios',
        'key metrics',
        'financial growth',
        'bank health',
        'sector performance',
        'market snapshot',
        'financial modeling prep',
      ],
      toolNames: [
        'resolve_entity',
        'entity_profile',
        'compare_entities',
        'recent_changes',
        'validate_claim',
        'fintech_company_deep_dive',
        'fintech_bank_health_check',
        'fintech_market_snapshot',
      ],
      description:
        'Conduct in-depth competitive benchmarking of fintech firms, assess bank health via financial and operational metrics, and generate real-time market snapshots for strategic decision-making. Compare peer performance, evaluate regulatory compliance, and track industry trends to inform M&A, investment, or product strategy.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'apikey' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'resolve_entity',
        description:
          'Search for fintech companies, banks, or financial institutions by name or keyword. Returns matching ticker symbols and company names to use in subsequent tools.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Company name, keyword, or partial ticker (e.g., "JPMorgan", "SoFi", "Stripe")',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return (default: 10, max: 50)',
            },
            exchange: {
              type: 'string',
              description: 'Filter by exchange (e.g., NASDAQ, NYSE, EURONEXT). Optional.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'entity_profile',
        description:
          'Retrieve the full company profile for a fintech or banking entity by ticker symbol. Returns sector, industry, description, market cap, stock price, employees, and headquarters.',
        inputSchema: {
          type: 'object',
          properties: {
            symbol: {
              type: 'string',
              description: 'Ticker symbol (e.g., "JPM", "SOFI", "PYPL", "SQ")',
            },
          },
          required: ['symbol'],
        },
      },
      {
        name: 'compare_entities',
        description:
          'Compare key financial and operational metrics for one or more fintech / banking entities side-by-side. Returns revenue per share, P/E, P/B, debt-to-equity, ROE, ROA, free cash flow yield, and more.',
        inputSchema: {
          type: 'object',
          properties: {
            symbols: {
              type: 'string',
              description: 'Comma-separated ticker symbols to compare (e.g., "JPM,BAC,WFC,SOFI")',
            },
            period: {
              type: 'string',
              description: 'Reporting period: "annual" (default) or "quarter"',
            },
            limit: {
              type: 'number',
              description: 'Number of historical periods to return per symbol (default: 1)',
            },
          },
          required: ['symbols'],
        },
      },
      {
        name: 'recent_changes',
        description:
          'Retrieve recent financial growth metrics for a fintech or banking entity: revenue growth, net income growth, EPS growth, free cash flow growth, and balance sheet trends.',
        inputSchema: {
          type: 'object',
          properties: {
            symbol: {
              type: 'string',
              description: 'Ticker symbol (e.g., "V", "MA", "AFRM")',
            },
            period: {
              type: 'string',
              description: 'Reporting period: "annual" (default) or "quarter"',
            },
            limit: {
              type: 'number',
              description: 'Number of periods to return (default: 4)',
            },
          },
          required: ['symbol'],
        },
      },
      {
        name: 'validate_claim',
        description:
          'Validate financial health claims about a fintech or bank using standardized ratios: liquidity ratios, profitability ratios, leverage ratios, efficiency ratios, and valuation ratios.',
        inputSchema: {
          type: 'object',
          properties: {
            symbol: {
              type: 'string',
              description: 'Ticker symbol of the entity to evaluate (e.g., "GS", "MS", "COIN")',
            },
            period: {
              type: 'string',
              description: 'Reporting period: "annual" (default) or "quarter"',
            },
            limit: {
              type: 'number',
              description: 'Number of historical periods to include (default: 2)',
            },
          },
          required: ['symbol'],
        },
      },
      {
        name: 'fintech_company_deep_dive',
        description:
          'Full competitive intelligence deep-dive on a fintech company: combines company profile, key metrics, financial ratios, and income statement summary into a single structured report for M&A, investment, or strategic analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            symbol: {
              type: 'string',
              description: 'Ticker symbol of the target fintech company (e.g., "PYPL", "SQ", "SOFI", "UPST")',
            },
            period: {
              type: 'string',
              description: 'Reporting period for financial data: "annual" (default) or "quarter"',
            },
          },
          required: ['symbol'],
        },
      },
      {
        name: 'fintech_bank_health_check',
        description:
          'Assess the financial health of a bank or credit institution. Returns capital adequacy indicators, asset quality ratios, net interest margin, return on assets, return on equity, efficiency ratio, and liquidity metrics.',
        inputSchema: {
          type: 'object',
          properties: {
            symbol: {
              type: 'string',
              description: 'Ticker symbol of the bank or financial institution (e.g., "JPM", "BAC", "C", "WFC")',
            },
            period: {
              type: 'string',
              description: 'Reporting period: "annual" (default) or "quarter"',
            },
            limit: {
              type: 'number',
              description: 'Number of periods to include in the health trend (default: 4)',
            },
          },
          required: ['symbol'],
        },
      },
      {
        name: 'fintech_market_snapshot',
        description:
          'Get a real-time market snapshot for the fintech or banking sector: sector performance, top gainers/losers within financial services, and summary market breadth. Useful for macro trend monitoring.',
        inputSchema: {
          type: 'object',
          properties: {
            sector: {
              type: 'string',
              description:
                'Sector to snapshot. Defaults to "Financial Services". Other options: "Technology", "Banking", "Insurance".',
            },
            exchange: {
              type: 'string',
              description: 'Exchange filter: "NASDAQ" or "NYSE" (default: both)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'resolve_entity':           return this.resolveEntity(args);
        case 'entity_profile':           return this.entityProfile(args);
        case 'compare_entities':         return this.compareEntities(args);
        case 'recent_changes':           return this.recentChanges(args);
        case 'validate_claim':           return this.validateClaim(args);
        case 'fintech_company_deep_dive': return this.fintechCompanyDeepDive(args);
        case 'fintech_bank_health_check': return this.fintechBankHealthCheck(args);
        case 'fintech_market_snapshot':  return this.fintechMarketSnapshot(args);
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

  private qs(params: Record<string, string | number | undefined>): string {
    const parts: string[] = [`apikey=${encodeURIComponent(this.apiKey)}`];
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
      }
    }
    return parts.join('&');
  }

  private async get(path: string, params: Record<string, string | number | undefined> = {}): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}?${this.qs(params)}`;
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

  private async resolveEntity(args: Record<string, unknown>): Promise<ToolResult> {
    const query = String(args.query ?? '').trim();
    if (!query) {
      return { content: [{ type: 'text', text: 'resolve_entity: query is required' }], isError: true };
    }
    return this.get('/search', {
      query,
      limit: (args.limit as number | undefined) ?? 10,
      exchange: args.exchange as string | undefined,
    });
  }

  private async entityProfile(args: Record<string, unknown>): Promise<ToolResult> {
    const symbol = String(args.symbol ?? '').trim().toUpperCase();
    if (!symbol) {
      return { content: [{ type: 'text', text: 'entity_profile: symbol is required' }], isError: true };
    }
    return this.get(`/profile/${encodeURIComponent(symbol)}`);
  }

  private async compareEntities(args: Record<string, unknown>): Promise<ToolResult> {
    const symbols = String(args.symbols ?? '').trim().toUpperCase();
    if (!symbols) {
      return { content: [{ type: 'text', text: 'compare_entities: symbols is required' }], isError: true };
    }
    const period = (args.period as string | undefined) ?? 'annual';
    const limit = (args.limit as number | undefined) ?? 1;
    // Fetch key-metrics for each symbol and merge results
    const symbolList = symbols.split(',').map((s) => s.trim()).filter(Boolean);
    const results: Record<string, unknown>[] = [];
    for (const sym of symbolList) {
      const r = await this.get(`/key-metrics/${encodeURIComponent(sym)}`, { period, limit });
      if (r.isError) return r;
      try {
        const parsed = JSON.parse(r.content[0].text);
        results.push({ symbol: sym, metrics: parsed });
      } catch {
        results.push({ symbol: sym, raw: r.content[0].text });
      }
    }
    return { content: [{ type: 'text', text: this.truncate(results) }], isError: false };
  }

  private async recentChanges(args: Record<string, unknown>): Promise<ToolResult> {
    const symbol = String(args.symbol ?? '').trim().toUpperCase();
    if (!symbol) {
      return { content: [{ type: 'text', text: 'recent_changes: symbol is required' }], isError: true };
    }
    return this.get(`/financial-growth/${encodeURIComponent(symbol)}`, {
      period: (args.period as string | undefined) ?? 'annual',
      limit: (args.limit as number | undefined) ?? 4,
    });
  }

  private async validateClaim(args: Record<string, unknown>): Promise<ToolResult> {
    const symbol = String(args.symbol ?? '').trim().toUpperCase();
    if (!symbol) {
      return { content: [{ type: 'text', text: 'validate_claim: symbol is required' }], isError: true };
    }
    return this.get(`/ratios/${encodeURIComponent(symbol)}`, {
      period: (args.period as string | undefined) ?? 'annual',
      limit: (args.limit as number | undefined) ?? 2,
    });
  }

  private async fintechCompanyDeepDive(args: Record<string, unknown>): Promise<ToolResult> {
    const symbol = String(args.symbol ?? '').trim().toUpperCase();
    if (!symbol) {
      return { content: [{ type: 'text', text: 'fintech_company_deep_dive: symbol is required' }], isError: true };
    }
    const period = (args.period as string | undefined) ?? 'annual';

    // Fetch profile, key-metrics, ratios, and income-statement in parallel
    const [profileR, metricsR, ratiosR, incomeR] = await Promise.all([
      this.get(`/profile/${encodeURIComponent(symbol)}`),
      this.get(`/key-metrics/${encodeURIComponent(symbol)}`, { period, limit: 2 }),
      this.get(`/ratios/${encodeURIComponent(symbol)}`, { period, limit: 2 }),
      this.get(`/income-statement/${encodeURIComponent(symbol)}`, { period, limit: 2 }),
    ]);

    for (const r of [profileR, metricsR, ratiosR, incomeR]) {
      if (r.isError) return r;
    }

    const deepDive = {
      symbol,
      period,
      profile: this.safeParse(profileR.content[0].text),
      keyMetrics: this.safeParse(metricsR.content[0].text),
      ratios: this.safeParse(ratiosR.content[0].text),
      incomeStatement: this.safeParse(incomeR.content[0].text),
    };
    return { content: [{ type: 'text', text: this.truncate(deepDive) }], isError: false };
  }

  private async fintechBankHealthCheck(args: Record<string, unknown>): Promise<ToolResult> {
    const symbol = String(args.symbol ?? '').trim().toUpperCase();
    if (!symbol) {
      return { content: [{ type: 'text', text: 'fintech_bank_health_check: symbol is required' }], isError: true };
    }
    const period = (args.period as string | undefined) ?? 'annual';
    const limit = (args.limit as number | undefined) ?? 4;

    // Bank health: key metrics + ratios over multiple periods for trend analysis
    const [metricsR, ratiosR, growthR] = await Promise.all([
      this.get(`/key-metrics/${encodeURIComponent(symbol)}`, { period, limit }),
      this.get(`/ratios/${encodeURIComponent(symbol)}`, { period, limit }),
      this.get(`/financial-growth/${encodeURIComponent(symbol)}`, { period, limit }),
    ]);

    for (const r of [metricsR, ratiosR, growthR]) {
      if (r.isError) return r;
    }

    const healthReport = {
      symbol,
      period,
      periods: limit,
      keyMetrics: this.safeParse(metricsR.content[0].text),
      ratios: this.safeParse(ratiosR.content[0].text),
      financialGrowth: this.safeParse(growthR.content[0].text),
    };
    return { content: [{ type: 'text', text: this.truncate(healthReport) }], isError: false };
  }

  private async fintechMarketSnapshot(args: Record<string, unknown>): Promise<ToolResult> {
    const sector = (args.sector as string | undefined) ?? 'Financial Services';
    const exchange = args.exchange as string | undefined;

    // Sector performance + top gainers/losers filtered to financial services
    const [sectorR, gainersR] = await Promise.all([
      this.get('/sector-performance'),
      this.get('/stock_market/gainers'),
    ]);

    if (sectorR.isError) return sectorR;
    if (gainersR.isError) return gainersR;

    // Filter sector performance to the requested sector
    let sectorData: unknown = this.safeParse(sectorR.content[0].text);
    if (Array.isArray(sectorData)) {
      sectorData = sectorData.filter(
        (s: unknown) =>
          typeof s === 'object' &&
          s !== null &&
          typeof (s as Record<string, unknown>).sector === 'string' &&
          ((s as Record<string, unknown>).sector as string)
            .toLowerCase()
            .includes(sector.toLowerCase()),
      );
    }

    // Filter gainers to financial sector if exchange specified
    let gainersData: unknown = this.safeParse(gainersR.content[0].text);
    if (exchange && Array.isArray(gainersData)) {
      gainersData = (gainersData as Array<Record<string, unknown>>).filter(
        (g) =>
          typeof g.exchangeShortName === 'string' &&
          g.exchangeShortName.toUpperCase() === exchange.toUpperCase(),
      );
    }

    const snapshot = {
      requestedSector: sector,
      exchange: exchange ?? 'all',
      sectorPerformance: sectorData,
      topGainers: Array.isArray(gainersData) ? (gainersData as unknown[]).slice(0, 10) : gainersData,
    };
    return { content: [{ type: 'text', text: this.truncate(snapshot) }], isError: false };
  }

  private safeParse(text: string): unknown {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
}
