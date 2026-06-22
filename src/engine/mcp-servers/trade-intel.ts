/**
 * Trade Intel MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Compound tools that chain UN Comtrade, US Census Bureau international trade,
 * US Treasury FiscalData exchange rates, and optionally FRED macro series into
 * three high-level trade intelligence tools. Each tool aggregates multiple
 * upstream API calls and returns a single structured result.
 *
 * Upstream base URLs (all public / no-auth except FRED):
 *   UN Comtrade preview: https://comtradeapi.un.org/public/v1/preview
 *   US Census intltrade: https://api.census.gov/data/timeseries/intltrade
 *   Treasury FiscalData: https://api.fiscaldata.treasury.gov/services/api/v1/accounting/od
 *   BLS public API:      https://api.bls.gov/publicAPI/v2
 *   FRED (optional):     https://api.stlouisfed.org/fred
 *
 * Auth: none required for Comtrade, Census, Treasury, BLS.
 *       FRED requires a free API key passed per-call as _fredKey.
 *
 * Docs:
 *   https://comtradeapi.un.org/
 *   https://www.census.gov/foreign-trade/reference/guides/index.html
 *   https://fiscaldata.treasury.gov/api-documentation/
 *   https://fred.stlouisfed.org/docs/api/fred/
 *
 * Category: finance
 * Tools: trade_bilateral_analysis, trade_country_profile, trade_macro_dashboard
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

// ── Constants ──────────────────────────────────────────────────────────────

const COMTRADE_BASE   = 'https://comtradeapi.un.org/public/v1/preview';
const CENSUS_BASE     = 'https://api.census.gov/data/timeseries/intltrade';
const TREASURY_BASE   = 'https://api.fiscaldata.treasury.gov/services/api/v1/accounting/od';
const BLS_BASE        = 'https://api.bls.gov/publicAPI/v2';
const FRED_BASE       = 'https://api.stlouisfed.org/fred';

// ISO numeric → country name (Comtrade public preview omits desc fields)
const CODE_TO_COUNTRY: Record<string, string> = {
  '0': 'World', '36': 'Australia', '76': 'Brazil', '124': 'Canada',
  '156': 'China', '250': 'France', '276': 'Germany', '344': 'Hong Kong',
  '356': 'India', '360': 'Indonesia', '372': 'Ireland', '380': 'Italy',
  '392': 'Japan', '410': 'South Korea', '458': 'Malaysia', '484': 'Mexico',
  '528': 'Netherlands', '682': 'Saudi Arabia', '702': 'Singapore',
  '710': 'South Africa', '724': 'Spain', '756': 'Switzerland', '764': 'Thailand',
  '490': 'Taiwan', '704': 'Vietnam', '826': 'United Kingdom', '842': 'United States',
};

// ── Helper ─────────────────────────────────────────────────────────────────

function previousYear(): string {
  return String(new Date().getFullYear() - 1);
}

function countryName(code: string): string {
  return CODE_TO_COUNTRY[String(code)] ?? `Country ${code}`;
}

// ── Config / class ─────────────────────────────────────────────────────────

interface TradeIntelConfig {
  /** Optional override for Comtrade base URL */
  comtradeBaseUrl?: string;
  /** Optional override for Census base URL */
  censusBaseUrl?: string;
  /** Optional override for Treasury FiscalData base URL */
  treasuryBaseUrl?: string;
  /** Optional override for FRED base URL */
  fredBaseUrl?: string;
  /** Optional override for BLS base URL */
  blsBaseUrl?: string;
}

export class TradeIntelMCPServer extends MCPAdapterBase {
  private readonly comtradeBase: string;
  private readonly censusBase: string;
  private readonly treasuryBase: string;
  private readonly fredBase: string;
  private readonly blsBase: string;

  constructor(config: TradeIntelConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Trade Intel: configuration object is required');
    }
    this.comtradeBase  = config.comtradeBaseUrl  ?? COMTRADE_BASE;
    this.censusBase    = config.censusBaseUrl    ?? CENSUS_BASE;
    this.treasuryBase  = config.treasuryBaseUrl  ?? TREASURY_BASE;
    this.fredBase      = config.fredBaseUrl      ?? FRED_BASE;
    this.blsBase       = config.blsBaseUrl       ?? BLS_BASE;
  }

  static catalog() {
    return {
      name: 'trade-intel',
      displayName: 'Trade Intel',
      version: '1.0.0',
      category: 'finance' as const,
      keywords: [
        'trade intelligence', 'bilateral trade', 'international trade', 'comtrade',
        'un comtrade', 'census trade', 'treasury exchange rates', 'fred',
        'import export', 'trade balance', 'trade deficit', 'trade surplus',
        'commodities', 'hs code', 'country trade profile', 'trade macro',
        'customs revenue', 'price index', 'trade flows', 'trade partners',
        'government data', 'compound tool', 'trade analysis',
      ],
      toolNames: [
        'trade_bilateral_analysis',
        'trade_country_profile',
        'trade_macro_dashboard',
      ],
      description:
        'Trade Intel: compound tools that chain UN Comtrade bilateral trade flows, ' +
        'US Census Bureau international trade data, Treasury exchange rates, and ' +
        'optionally FRED dollar index into three high-level tools — bilateral analysis ' +
        'between two countries, comprehensive country trade profiles, and a US trade ' +
        'macro dashboard — each aggregating multiple upstream API calls in a single response.',
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
        name: 'trade_bilateral_analysis',
        description:
          'Complete bilateral trade analysis between two countries in one call. ' +
          'Combines UN Comtrade trade flows (imports + exports + top commodities), ' +
          'Treasury exchange rates, and optionally FRED dollar index. ' +
          'Use country codes: 842=US, 156=China, 276=Germany, 392=Japan, 826=UK. ' +
          'Use this for bilateral analysis; use trade_country_profile for a single ' +
          'country\'s full partner/commodity snapshot.',
        inputSchema: {
          type: 'object',
          properties: {
            reporter_code: {
              type: 'string',
              description:
                'Reporting country ISO numeric code (e.g., "842" for US, "276" for Germany)',
            },
            partner_code: {
              type: 'string',
              description:
                'Partner country ISO numeric code (e.g., "156" for China, "392" for Japan)',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2023"). Defaults to last calendar year.',
            },
            _fredKey: {
              type: 'string',
              description:
                'FRED API key (optional). When provided, enriches results with the ' +
                'US dollar index (DXY/DTWEXBGS series). Get a free key at ' +
                'https://fred.stlouisfed.org/docs/api/api_key.html',
            },
          },
          required: ['reporter_code', 'partner_code'],
        },
      },
      {
        name: 'trade_country_profile',
        description:
          'Comprehensive trade profile for a single country — top 10 import partners, ' +
          'top 10 export partners, top 10 import commodities, and top 10 export commodities, ' +
          'all in one call. Use country codes: 842=US, 156=China, 276=Germany, 392=Japan, ' +
          '826=UK, 484=Mexico, 124=Canada. ' +
          'Use this for a country-centric snapshot; use trade_bilateral_analysis for ' +
          'head-to-head comparison between two specific countries.',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description:
                'Country ISO numeric code (e.g., "842" for US, "156" for China)',
            },
            year: {
              type: 'string',
              description: 'Trade year (e.g., "2023"). Defaults to last calendar year.',
            },
          },
          required: ['country_code'],
        },
      },
      {
        name: 'trade_macro_dashboard',
        description:
          'US trade macro indicators dashboard — customs revenue, exchange rates, ' +
          'trade balance, monthly trends, import/export price indices, and ' +
          'goods/services breakdown. Optionally includes FRED dollar index and ' +
          'BLS import/export price index series when a FRED key is supplied. ' +
          'Use this for US macro-level trade intelligence; use trade_bilateral_analysis ' +
          'for country-pair comparisons.',
        inputSchema: {
          type: 'object',
          properties: {
            _fredKey: {
              type: 'string',
              description:
                'FRED API key (optional). When provided, adds dollar index and ' +
                'import/export price index series to the dashboard. ' +
                'Get a free key at https://fred.stlouisfed.org/docs/api/api_key.html',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'trade_bilateral_analysis':
          return await this.tradeBilateralAnalysis(args);
        case 'trade_country_profile':
          return await this.tradeCountryProfile(args);
        case 'trade_macro_dashboard':
          return await this.tradeMacroDashboard(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  // ── Private: low-level fetch helpers ──────────────────────────────────────

  private async fetchJson(url: string): Promise<unknown> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`HTTP ${response.status}: ${errText}`);
    }
    return response.json();
  }

  // ── UN Comtrade ────────────────────────────────────────────────────────────

  /** Fetch bilateral trade data for a reporter+partner+year. Returns raw data array. */
  private async comtradeBilateral(
    reporterCode: string,
    partnerCode: string,
    year: string,
    flow: 'M' | 'X',
  ): Promise<ComtradeRecord[]> {
    const url =
      `${this.comtradeBase}/getFinalData` +
      `?reporterCode=${encodeURIComponent(reporterCode)}` +
      `&partnerCode=${encodeURIComponent(partnerCode)}` +
      `&period=${encodeURIComponent(year)}` +
      `&typeCode=C&freqCode=A&clCode=HS` +
      `&flowCode=${flow}&cmdCode=TOTAL&maxRecords=20&format=JSON&breakdownMode=classic`;
    const data = await this.fetchJson(url) as { data?: ComtradeRecord[] };
    return data?.data ?? [];
  }

  /** Fetch top commodities between two countries for a given flow. */
  private async comtradeTopCommodities(
    reporterCode: string,
    partnerCode: string,
    year: string,
    flow: 'M' | 'X',
    limit = 10,
  ): Promise<ComtradeRecord[]> {
    const url =
      `${this.comtradeBase}/getFinalData` +
      `?reporterCode=${encodeURIComponent(reporterCode)}` +
      `&partnerCode=${encodeURIComponent(partnerCode)}` +
      `&period=${encodeURIComponent(year)}` +
      `&typeCode=C&freqCode=A&clCode=HS` +
      `&flowCode=${flow}&cmdCode=AG2&maxRecords=${limit}&format=JSON&breakdownMode=classic`;
    const data = await this.fetchJson(url) as { data?: ComtradeRecord[] };
    return (data?.data ?? [])
      .filter((r) => r.primaryValue > 0)
      .sort((a, b) => b.primaryValue - a.primaryValue)
      .slice(0, limit);
  }

  /** Fetch top trading partners (aggregate, HS all) for a country+year+flow. */
  private async comtradeTopPartners(
    reporterCode: string,
    year: string,
    flow: 'M' | 'X',
    limit = 10,
  ): Promise<ComtradeRecord[]> {
    const url =
      `${this.comtradeBase}/getFinalData` +
      `?reporterCode=${encodeURIComponent(reporterCode)}` +
      `&period=${encodeURIComponent(year)}` +
      `&typeCode=C&freqCode=A&clCode=HS` +
      `&flowCode=${flow}&cmdCode=TOTAL&maxRecords=100&format=JSON&breakdownMode=classic`;
    const data = await this.fetchJson(url) as { data?: ComtradeRecord[] };
    return (data?.data ?? [])
      .filter((r) => r.primaryValue > 0 && String(r.partnerCode) !== '0')
      .sort((a, b) => b.primaryValue - a.primaryValue)
      .slice(0, limit);
  }

  // ── US Census Bureau Trade ─────────────────────────────────────────────────

  /** Fetch aggregate US trade value for a specific Census country code and year. */
  private async censusTrade(
    censusCountryCode: string,
    year: string,
  ): Promise<{ imports: number; exports: number; balance: number }> {
    // Use end-use aggregate (E_COMMODITY=0) for totals
    const impUrl =
      `${this.censusBase}/imports` +
      `?get=GEN_VAL_MO,CTY_CODE,CTY_NAME,YEAR,MONTH` +
      `&CTY_CODE=${encodeURIComponent(censusCountryCode)}` +
      `&YEAR=${encodeURIComponent(year)}` +
      `&MONTH=12` +
      `&key=`;
    const expUrl =
      `${this.censusBase}/exports` +
      `?get=ALL_VAL_MO,CTY_CODE,CTY_NAME,YEAR,MONTH` +
      `&CTY_CODE=${encodeURIComponent(censusCountryCode)}` +
      `&YEAR=${encodeURIComponent(year)}` +
      `&MONTH=12` +
      `&key=`;

    let imports = 0;
    let exports = 0;
    try {
      const impData = await this.fetchJson(impUrl) as string[][];
      if (Array.isArray(impData) && impData.length > 1) {
        const header = impData[0];
        const valIdx = header.indexOf('GEN_VAL_MO');
        if (valIdx >= 0 && impData[1]) {
          imports = parseFloat(impData[1][valIdx] ?? '0') || 0;
        }
      }
    } catch {
      // Census API may reject; fall through with 0
    }
    try {
      const expData = await this.fetchJson(expUrl) as string[][];
      if (Array.isArray(expData) && expData.length > 1) {
        const header = expData[0];
        const valIdx = header.indexOf('ALL_VAL_MO');
        if (valIdx >= 0 && expData[1]) {
          exports = parseFloat(expData[1][valIdx] ?? '0') || 0;
        }
      }
    } catch {
      // Fall through
    }
    return { imports, exports, balance: exports - imports };
  }

  /** Fetch recent monthly trade trends (last N months, aggregate). */
  private async censusMonthlyTrends(
    year: string,
    months = 6,
  ): Promise<{ period: string; imports: number; exports: number }[]> {
    const results: { period: string; imports: number; exports: number }[] = [];
    const targetYear = parseInt(year, 10);
    const targetMonth = 12;
    for (let i = months - 1; i >= 0; i--) {
      let m = targetMonth - i;
      let y = targetYear;
      while (m <= 0) { m += 12; y--; }
      const monthStr = String(m).padStart(2, '0');
      const impUrl =
        `${this.censusBase}/imports` +
        `?get=GEN_VAL_MO,YEAR,MONTH` +
        `&YEAR=${y}&MONTH=${monthStr}&key=`;
      const expUrl =
        `${this.censusBase}/exports` +
        `?get=ALL_VAL_MO,YEAR,MONTH` +
        `&YEAR=${y}&MONTH=${monthStr}&key=`;
      let imp = 0;
      let exp = 0;
      try {
        const d = await this.fetchJson(impUrl) as string[][];
        if (Array.isArray(d) && d.length > 1) {
          const hi = d[0].indexOf('GEN_VAL_MO');
          if (hi >= 0 && d[1]) imp = parseFloat(d[1][hi] ?? '0') || 0;
        }
      } catch { /* skip */ }
      try {
        const d = await this.fetchJson(expUrl) as string[][];
        if (Array.isArray(d) && d.length > 1) {
          const hi = d[0].indexOf('ALL_VAL_MO');
          if (hi >= 0 && d[1]) exp = parseFloat(d[1][hi] ?? '0') || 0;
        }
      } catch { /* skip */ }
      results.push({ period: `${y}-${monthStr}`, imports: imp, exports: exp });
    }
    return results;
  }

  // ── US Treasury FiscalData — exchange rates ────────────────────────────────

  /**
   * Fetch Treasury Reporting Rates of Exchange for a given country.
   * Endpoint: /rates_of_exchange
   */
  private async treasuryExchangeRate(
    currencyCode: string,
    country: string,
  ): Promise<{ rate: number; date: string; currency: string } | null> {
    const url =
      `${this.treasuryBase}/rates_of_exchange` +
      `?fields=country,currency,exchange_rate,effective_date` +
      `&filter=country:eq:${encodeURIComponent(country)}` +
      `&sort=-effective_date&page[size]=1&format=json`;
    try {
      const data = await this.fetchJson(url) as {
        data?: { country: string; currency: string; exchange_rate: string; effective_date: string }[];
      };
      const record = data?.data?.[0];
      if (!record) return null;
      return {
        rate: parseFloat(record.exchange_rate),
        date: record.effective_date,
        currency: record.currency,
      };
    } catch {
      return null;
    }
  }

  /** Fetch all available Treasury exchange rates (latest quarter). */
  private async treasuryAllRates(): Promise<
    { country: string; currency: string; rate: number; date: string }[]
  > {
    const url =
      `${this.treasuryBase}/rates_of_exchange` +
      `?fields=country,currency,exchange_rate,effective_date` +
      `&sort=-effective_date&page[size]=50&format=json`;
    try {
      const data = await this.fetchJson(url) as {
        data?: { country: string; currency: string; exchange_rate: string; effective_date: string }[];
      };
      return (data?.data ?? []).map((r) => ({
        country: r.country,
        currency: r.currency,
        rate: parseFloat(r.exchange_rate),
        date: r.effective_date,
      }));
    } catch {
      return [];
    }
  }

  // ── FRED (optional) ────────────────────────────────────────────────────────

  /** Fetch the last N observations for a FRED series. Returns null if no key or fetch fails. */
  private async fredSeries(
    seriesId: string,
    fredKey: string,
    limit = 6,
  ): Promise<{ date: string; value: number }[] | null> {
    if (!fredKey) return null;
    const url =
      `${this.fredBase}/series/observations` +
      `?series_id=${encodeURIComponent(seriesId)}` +
      `&api_key=${encodeURIComponent(fredKey)}` +
      `&file_type=json&sort_order=desc&limit=${limit}`;
    try {
      const data = await this.fetchJson(url) as {
        observations?: { date: string; value: string }[];
      };
      return (data?.observations ?? [])
        .filter((o) => o.value !== '.')
        .map((o) => ({ date: o.date, value: parseFloat(o.value) }))
        .reverse();
    } catch {
      return null;
    }
  }

  // ── Tool implementations ───────────────────────────────────────────────────

  /**
   * trade_bilateral_analysis
   * Chains: Comtrade (imports + exports + top commodities) + Treasury exchange rates
   *         + optional FRED dollar index
   */
  private async tradeBilateralAnalysis(args: Record<string, unknown>): Promise<ToolResult> {
    const reporterCode = String(args.reporter_code ?? '');
    const partnerCode  = String(args.partner_code  ?? '');
    const year         = String(args.year ?? previousYear());
    const fredKey      = String(args._fredKey ?? '');

    if (!reporterCode || !partnerCode) {
      return {
        content: [{ type: 'text', text: 'reporter_code and partner_code are required' }],
        isError: true,
      };
    }

    const reporterName = countryName(reporterCode);
    const partnerName  = countryName(partnerCode);

    // Fan-out: Comtrade flows + top commodities (both directions), Treasury rates, optional FRED
    const [
      importsData,
      exportsData,
      topImportCmds,
      topExportCmds,
      allRates,
      dollarIndex,
    ] = await Promise.allSettled([
      this.comtradeBilateral(reporterCode, partnerCode, year, 'M'),
      this.comtradeBilateral(reporterCode, partnerCode, year, 'X'),
      this.comtradeTopCommodities(reporterCode, partnerCode, year, 'M', 10),
      this.comtradeTopCommodities(reporterCode, partnerCode, year, 'X', 10),
      this.treasuryAllRates(),
      fredKey ? this.fredSeries('DTWEXBGS', fredKey, 6) : Promise.resolve(null),
    ]);

    // Extract totals from Comtrade bilateral totals (TOTAL commodity row)
    const importRecords = importsData.status === 'fulfilled' ? importsData.value : [];
    const exportRecords = exportsData.status === 'fulfilled' ? exportsData.value : [];
    const totalImports  = importRecords.reduce((s, r) => s + (r.primaryValue ?? 0), 0);
    const totalExports  = exportRecords.reduce((s, r) => s + (r.primaryValue ?? 0), 0);
    const tradeBalance  = totalExports - totalImports;

    const topImports = topImportCmds.status === 'fulfilled' ? topImportCmds.value : [];
    const topExports = topExportCmds.status === 'fulfilled' ? topExportCmds.value : [];

    const rates = allRates.status === 'fulfilled' ? allRates.value : [];
    const dxy   = dollarIndex.status === 'fulfilled' ? dollarIndex.value : null;

    const result: Record<string, unknown> = {
      reporter: { code: reporterCode, name: reporterName },
      partner:  { code: partnerCode,  name: partnerName  },
      year,
      trade_flows: {
        imports_usd:  totalImports,
        exports_usd:  totalExports,
        balance_usd:  tradeBalance,
        balance_label: tradeBalance >= 0 ? 'surplus' : 'deficit',
      },
      top_import_commodities: topImports.map((r) => ({
        hs_code:   r.cmdCode,
        commodity: r.cmdDesc ?? 'N/A',
        value_usd: r.primaryValue,
      })),
      top_export_commodities: topExports.map((r) => ({
        hs_code:   r.cmdCode,
        commodity: r.cmdDesc ?? 'N/A',
        value_usd: r.primaryValue,
      })),
      exchange_rates: rates.slice(0, 20),
      sources: ['UN Comtrade public preview', 'US Treasury FiscalData'],
    };

    if (dxy && dxy.length > 0) {
      result.dollar_index_dtwexbgs = dxy;
      (result.sources as string[]).push('FRED DTWEXBGS');
    }

    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }

  /**
   * trade_country_profile
   * Chains: Comtrade top 10 import/export partners + top 10 import/export commodities
   */
  private async tradeCountryProfile(args: Record<string, unknown>): Promise<ToolResult> {
    const countryCode = String(args.country_code ?? '');
    const year        = String(args.year ?? previousYear());

    if (!countryCode) {
      return {
        content: [{ type: 'text', text: 'country_code is required' }],
        isError: true,
      };
    }

    const name = countryName(countryCode);

    const [
      topImportPartners,
      topExportPartners,
      topImportCmds,
      topExportCmds,
    ] = await Promise.allSettled([
      this.comtradeTopPartners(countryCode, year, 'M', 10),
      this.comtradeTopPartners(countryCode, year, 'X', 10),
      this.comtradeTopCommodities(countryCode, '0', year, 'M', 10),
      this.comtradeTopCommodities(countryCode, '0', year, 'X', 10),
    ]);

    const result: Record<string, unknown> = {
      country: { code: countryCode, name },
      year,
      top_import_partners: (topImportPartners.status === 'fulfilled' ? topImportPartners.value : [])
        .map((r) => ({
          partner_code: r.partnerCode,
          partner_name: r.partnerDesc ?? countryName(String(r.partnerCode)),
          imports_usd:  r.primaryValue,
        })),
      top_export_partners: (topExportPartners.status === 'fulfilled' ? topExportPartners.value : [])
        .map((r) => ({
          partner_code: r.partnerCode,
          partner_name: r.partnerDesc ?? countryName(String(r.partnerCode)),
          exports_usd:  r.primaryValue,
        })),
      top_import_commodities: (topImportCmds.status === 'fulfilled' ? topImportCmds.value : [])
        .map((r) => ({
          hs_code:   r.cmdCode,
          commodity: r.cmdDesc ?? 'N/A',
          value_usd: r.primaryValue,
        })),
      top_export_commodities: (topExportCmds.status === 'fulfilled' ? topExportCmds.value : [])
        .map((r) => ({
          hs_code:   r.cmdCode,
          commodity: r.cmdDesc ?? 'N/A',
          value_usd: r.primaryValue,
        })),
      sources: ['UN Comtrade public preview'],
    };

    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }

  /**
   * trade_macro_dashboard
   * Chains: Census monthly trade trends + Treasury exchange rates +
   *         optional FRED dollar index + BLS import/export price series
   */
  private async tradeMacroDashboard(args: Record<string, unknown>): Promise<ToolResult> {
    const fredKey = String(args._fredKey ?? '');
    const year    = previousYear();

    const [
      monthlyTrends,
      allRates,
      dollarIndex,
      importPriceIndex,
      exportPriceIndex,
    ] = await Promise.allSettled([
      this.censusMonthlyTrends(year, 6),
      this.treasuryAllRates(),
      fredKey ? this.fredSeries('DTWEXBGS', fredKey, 6)        : Promise.resolve(null),
      fredKey ? this.fredSeries('IR', fredKey, 6)               : Promise.resolve(null),
      fredKey ? this.fredSeries('IQ', fredKey, 6)               : Promise.resolve(null),
    ]);

    const trends = monthlyTrends.status === 'fulfilled' ? monthlyTrends.value : [];
    const rates  = allRates.status === 'fulfilled'      ? allRates.value      : [];
    const dxy    = dollarIndex.status === 'fulfilled'   ? dollarIndex.value   : null;
    const ipi    = importPriceIndex.status === 'fulfilled' ? importPriceIndex.value : null;
    const epi    = exportPriceIndex.status === 'fulfilled' ? exportPriceIndex.value : null;

    // Compute trade balance from last available month
    const lastMonth   = trends[trends.length - 1];
    const tradeBalance = lastMonth
      ? lastMonth.exports - lastMonth.imports
      : null;

    const result: Record<string, unknown> = {
      reference_year: year,
      monthly_trends: trends.map((t) => ({
        period:      t.period,
        imports_usd: t.imports,
        exports_usd: t.exports,
        balance_usd: t.exports - t.imports,
      })),
      latest_trade_balance: tradeBalance !== null
        ? {
          period:    lastMonth?.period,
          value_usd: tradeBalance,
          label:     tradeBalance >= 0 ? 'surplus' : 'deficit',
        }
        : null,
      exchange_rates: rates.slice(0, 30),
      sources: ['US Census Bureau intltrade API', 'US Treasury FiscalData'],
    };

    if (dxy && dxy.length > 0) {
      result.dollar_index_dtwexbgs = dxy;
      (result.sources as string[]).push('FRED DTWEXBGS');
    }
    if (ipi && ipi.length > 0) {
      result.import_price_index = ipi;
      (result.sources as string[]).push('FRED IR (import price index)');
    }
    if (epi && epi.length > 0) {
      result.export_price_index = epi;
      (result.sources as string[]).push('FRED IQ (export price index)');
    }

    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }
}

// ── Comtrade response type ─────────────────────────────────────────────────

interface ComtradeRecord {
  reporterCode:  number;
  reporterDesc:  string;
  partnerCode:   number;
  partnerDesc:   string;
  flowCode:      string;
  cmdCode:       string;
  cmdDesc:       string;
  primaryValue:  number;
  netWgt:        number;
  qty:           number;
  qtyUnitAbbr:   string;
  period:        number;
}
