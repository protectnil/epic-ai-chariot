/**
 * USPTO TSDR Trademarks MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://tsdrapi.uspto.gov/ts/cd
// Auth: USPTO API key (free, register at https://account.uspto.gov/api-manager/)
//       Passed as the 'USPTO-API-KEY' header or the 'api_key' tool argument.
// Docs: https://tsdrapi.uspto.gov/
// Category: legal
// Rate limits: Determined by USPTO API plan tier

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface TrademarksConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class TrademarksMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config?: TrademarksConfig) {
    super();
    if (config === null) { throw new Error('TrademarksMCPServer: configuration object is required when provided'); }
    this.apiKey = config?.apiKey ?? '';
    this.baseUrl = config?.baseUrl ?? 'https://tsdrapi.uspto.gov/ts/cd';
  }

  static catalog() {
    return {
      name: 'trademarks',
      displayName: 'USPTO TSDR Trademarks',
      version: '1.0.0',
      category: 'legal',
      keywords: [
        'trademark', 'trademarks', 'uspto', 'tsdr', 'patent', 'intellectual property',
        'ip', 'serial number', 'registration', 'brand', 'mark', 'goods and services',
        'prosecution history', 'office action', 'status', 'owner',
      ],
      toolNames: [
        'get_trademark_by_serial',
        'get_trademark_by_registration',
        'get_trademark_documents',
      ],
      description: 'USPTO TSDR Trademarks: look up US trademark status, owner, filing dates, goods/services, and prosecution history via the USPTO TSDR API. Requires a free USPTO API key (register at account.uspto.gov/api-manager).',
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
        name: 'get_trademark_by_serial',
        description:
          'Look up a US trademark by serial number. Returns status, owner, filing/registration dates, goods/services, and classification. Requires a USPTO API key (free at account.uspto.gov).',
        inputSchema: {
          type: 'object',
          properties: {
            serial_number: {
              type: 'string',
              description: 'USPTO serial number (e.g., "97123456")',
            },
            api_key: {
              type: 'string',
              description:
                'USPTO API key. Register for free at https://account.uspto.gov/api-manager/ (optional if provided at construction time)',
            },
          },
          required: ['serial_number'],
        },
      },
      {
        name: 'get_trademark_by_registration',
        description:
          'Look up a US trademark by registration number. Returns status, owner, mark text, goods/services, and classification. Requires a USPTO API key.',
        inputSchema: {
          type: 'object',
          properties: {
            registration_number: {
              type: 'string',
              description: 'USPTO registration number (e.g., "1234567")',
            },
            api_key: {
              type: 'string',
              description: 'USPTO API key (optional if provided at construction time)',
            },
          },
          required: ['registration_number'],
        },
      },
      {
        name: 'get_trademark_documents',
        description:
          'Get the prosecution history (office actions, responses, etc.) for a trademark by serial number. Requires a USPTO API key.',
        inputSchema: {
          type: 'object',
          properties: {
            serial_number: {
              type: 'string',
              description: 'USPTO serial number',
            },
            api_key: {
              type: 'string',
              description: 'USPTO API key (optional if provided at construction time)',
            },
          },
          required: ['serial_number'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_trademark_by_serial':
          return this.getTrademarkBySerial(args);
        case 'get_trademark_by_registration':
          return this.getTrademarkByRegistration(args);
        case 'get_trademark_documents':
          return this.getTrademarkDocuments(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
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

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Resolve the API key: prefer per-call arg over constructor config.
   * Throws a user-friendly error if neither is present.
   */
  private resolveApiKey(args: Record<string, unknown>): string {
    const argKey = typeof args.api_key === 'string' ? args.api_key.trim() : '';
    if (argKey) return argKey;
    if (this.apiKey) return this.apiKey;
    throw new Error(
      'USPTO API key required. Register for free at https://account.uspto.gov/api-manager/ ' +
        'and pass as the api_key argument or supply it at adapter construction time.',
    );
  }

  /**
   * Execute a GET request against the TSDR API.
   * The USPTO TSDR API returns JSON when the Accept header requests it;
   * falls back to lightweight XML parsing for non-JSON responses.
   */
  private async tsdrRequest(path: string, apiKey: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'USPTO-API-KEY': apiKey,
        Accept: 'application/json',
        'User-Agent': 'epic-ai-chariot/1.0',
      },
    });

    if (response.status === 401 || response.status === 403) {
      return {
        content: [
          {
            type: 'text',
            text: 'Invalid or expired USPTO API key. Register at https://account.uspto.gov/api-manager/',
          },
        ],
        isError: true,
      };
    }

    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      return {
        content: [
          { type: 'text', text: `USPTO API error ${response.status}: ${body.slice(0, 200)}` },
        ],
        isError: true,
      };
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('json')) {
      const data = await response.json();
      return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
    }

    // TSDR may return XML — parse key fields and surface them as JSON
    const xml = await response.text();
    const parsed = this.parseXmlResponse(xml);
    return { content: [{ type: 'text', text: this.truncate(parsed) }], isError: false };
  }

  /**
   * Lightweight XML field extractor for TSDR responses that arrive as XML
   * despite an Accept: application/json header. Extracts the most useful
   * trademark data fields without a full XML parser dependency.
   */
  private parseXmlResponse(xml: string): Record<string, unknown> {
    const extract = (tag: string): string | null => {
      const match = xml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`));
      return match ? match[1].trim() : null;
    };

    return {
      serial_number:
        extract('serialNumber') ?? extract('ApplicationNumberText'),
      registration_number:
        extract('registrationNumber') ?? extract('RegistrationNumber'),
      mark_text:
        extract('markElement') ??
        extract('MarkVerbalElementText') ??
        extract('wordMark'),
      status:
        extract('markCurrentStatusExternalDescriptionText') ??
        extract('MarkCurrentStatusExternalDescriptionText'),
      status_date:
        extract('markCurrentStatusDate') ?? extract('MarkCurrentStatusDate'),
      filing_date: extract('applicationDate') ?? extract('ApplicationDate'),
      registration_date:
        extract('registrationDate') ?? extract('RegistrationDate'),
      owner_name: extract('partyName') ?? extract('EntityName'),
      attorney: extract('attorneyName'),
      goods_services:
        extract('classifiedGoodsServicesText') ??
        extract('GoodsServicesDescription'),
      international_class:
        extract('classNumber') ?? extract('ClassNumber'),
      raw_available: xml.length > 0,
    };
  }

  private async getTrademarkBySerial(
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    const apiKey = this.resolveApiKey(args);
    const sn = args.serial_number as string;
    return this.tsdrRequest(`/casestatus/sn${encodeURIComponent(sn)}/info`, apiKey);
  }

  private async getTrademarkByRegistration(
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    const apiKey = this.resolveApiKey(args);
    const rn = args.registration_number as string;
    return this.tsdrRequest(`/casestatus/rn${encodeURIComponent(rn)}/info`, apiKey);
  }

  private async getTrademarkDocuments(
    args: Record<string, unknown>,
  ): Promise<ToolResult> {
    const apiKey = this.resolveApiKey(args);
    const sn = args.serial_number as string;
    return this.tsdrRequest(`/casedocs/sn${encodeURIComponent(sn)}/docs`, apiKey);
  }
}
