/**
 * Solscan MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://pro-api.solscan.io/v2.0
// Auth: header `token: <api_key>` — free tier available at https://solscan.io/apis
// Docs: https://pro-api.solscan.io/pro-api-docs/v2.0/
// Category: blockchain
//
// Tools:
// - get_account_detail:  account overview (balance, owner, executable)
// - get_token_holdings:  SPL token balances held by an account
// - list_transfers:      recent SOL/SPL transfers for an account
// - get_token_meta:      SPL token metadata (name, symbol, supply, decimals)
// - get_transaction:     transaction detail by signature

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface SolscanConfig {
  apiKey: string;
  baseUrl?: string;
}

export class SolscanMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: SolscanConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Solscan: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Solscan: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://pro-api.solscan.io/v2.0';
  }

  static catalog() {
    return {
      name: 'solscan',
      displayName: 'Solscan',
      version: '1.0.0',
      category: 'blockchain',
      keywords: [
        'solscan', 'solana', 'sol', 'blockchain', 'explorer', 'spl token',
        'wallet', 'transaction', 'transfer', 'nft', 'defi', 'on-chain',
        'account', 'token holdings', 'block explorer',
      ],
      toolNames: [
        'get_account_detail',
        'get_token_holdings',
        'list_transfers',
        'get_token_meta',
        'get_transaction',
      ],
      description: 'Solscan Pro v2 API: explore Solana accounts, SPL token holdings, transfers, token metadata, and transaction details from the Solana block explorer.',
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
        name: 'get_account_detail',
        description:
          'Overview of a Solana account: SOL balance (lamports + UI), owner program, executable flag, rent epoch.',
        inputSchema: {
          type: 'object',
          properties: {
            address: { type: 'string', description: 'Solana public key (base58)' },
          },
          required: ['address'],
        },
      },
      {
        name: 'get_token_holdings',
        description:
          'SPL-token balances held by a Solana account. Returns mint, symbol, amount, decimals, USD value (if known).',
        inputSchema: {
          type: 'object',
          properties: {
            address: { type: 'string', description: 'Solana account public key' },
            page: { type: 'number', description: '1-based page (default 1)' },
            page_size: { type: 'number', description: '1-40 (default 20)' },
          },
          required: ['address'],
        },
      },
      {
        name: 'list_transfers',
        description:
          'Recent SOL and SPL token transfers for an account. Returns signature, timestamp, side (sent/received), token, amount, counterparty.',
        inputSchema: {
          type: 'object',
          properties: {
            address: { type: 'string', description: 'Solana account public key' },
            page: { type: 'number', description: '1-based page (default 1)' },
            page_size: { type: 'number', description: '1-40 (default 20)' },
          },
          required: ['address'],
        },
      },
      {
        name: 'get_token_meta',
        description:
          'Metadata for an SPL token mint: name, symbol, decimals, supply, icon, market cap, holders, social links.',
        inputSchema: {
          type: 'object',
          properties: {
            token_address: { type: 'string', description: 'SPL token mint address' },
          },
          required: ['token_address'],
        },
      },
      {
        name: 'get_transaction',
        description:
          'Transaction detail by signature: status, slot, block time, fee, balance changes, parsed instructions.',
        inputSchema: {
          type: 'object',
          properties: {
            signature: { type: 'string', description: 'Solana transaction signature (base58)' },
          },
          required: ['signature'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_account_detail':  return this.getAccountDetail(args);
        case 'get_token_holdings':  return this.getTokenHoldings(args);
        case 'list_transfers':      return this.listTransfers(args);
        case 'get_token_meta':      return this.getTokenMeta(args);
        case 'get_transaction':     return this.getTransaction(args);
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

  private async solscanGet(path: string, params: Record<string, string>): Promise<ToolResult> {
    const qs = new URLSearchParams(params);
    const url = `${this.baseUrl}${path}?${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        token: this.apiKey,
        Accept: 'application/json',
      },
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'Solscan: unauthorized — check the API key' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as { success?: boolean; data?: unknown; errors?: unknown; message?: string };
    if (data.success === false) {
      return {
        content: [{ type: 'text', text: `Solscan: ${data.message ?? 'unknown error'}` }],
        isError: true,
      };
    }
    const payload = { path, data: data.data ?? data };
    return { content: [{ type: 'text', text: this.truncate(payload) }], isError: false };
  }

  private reqStr(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return v;
  }

  private async getAccountDetail(args: Record<string, unknown>): Promise<ToolResult> {
    return this.solscanGet('/account/detail', {
      address: this.reqStr(args, 'address'),
    });
  }

  private async getTokenHoldings(args: Record<string, unknown>): Promise<ToolResult> {
    return this.solscanGet('/account/token-accounts', {
      address: this.reqStr(args, 'address'),
      type: 'token',
      page: String((args.page as number) ?? 1),
      page_size: String(Math.min(40, Math.max(1, (args.page_size as number) ?? 20))),
    });
  }

  private async listTransfers(args: Record<string, unknown>): Promise<ToolResult> {
    return this.solscanGet('/account/transfer', {
      address: this.reqStr(args, 'address'),
      page: String((args.page as number) ?? 1),
      page_size: String(Math.min(40, Math.max(1, (args.page_size as number) ?? 20))),
    });
  }

  private async getTokenMeta(args: Record<string, unknown>): Promise<ToolResult> {
    return this.solscanGet('/token/meta', {
      address: this.reqStr(args, 'token_address'),
    });
  }

  private async getTransaction(args: Record<string, unknown>): Promise<ToolResult> {
    return this.solscanGet('/transaction/detail', {
      tx: this.reqStr(args, 'signature'),
    });
  }
}
