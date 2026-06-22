/**
 * Blockstream Esplora Bitcoin Explorer MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

//
// Base URL (mainnet): https://blockstream.info/api
// Base URL (testnet): https://blockstream.info/testnet/api
// Auth: None required — free public Esplora REST API, no authentication needed.
// Docs: https://github.com/Blockstream/esplora/blob/master/API.md
// Rate limits: None published; fair-use.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface BlockstreamInfoConfig {
  /** Optional base URL override (default: https://blockstream.info/api) */
  baseUrl?: string;
}

export class BlockstreamInfoMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: BlockstreamInfoConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('BlockstreamInfo: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://blockstream.info/api';
  }

  static catalog() {
    return {
      name: 'blockstream-info',
      displayName: 'Blockstream Esplora — Bitcoin Explorer',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'bitcoin', 'btc', 'blockchain', 'block', 'transaction', 'txid',
        'address', 'mempool', 'fee', 'esplora', 'blockstream',
        'crypto', 'satoshi', 'utxo', 'on-chain', 'explorer',
      ],
      toolNames: [
        'tip_height',
        'block',
        'transaction',
        'tx_status',
        'address',
        'address_txs',
        'mempool',
        'fee_estimates',
      ],
      description: 'Blockstream Esplora API: query the Bitcoin blockchain — chain tip, blocks by hash or height, transactions, confirmation status, address stats and history, mempool size, and fee estimates.',
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
        name: 'tip_height',
        description: 'Current block height of the chain tip.',
        inputSchema: {
          type: 'object',
          properties: {
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
        },
      },
      {
        name: 'block',
        description: 'Block by 64-char hex hash or by height.',
        inputSchema: {
          type: 'object',
          properties: {
            hash_or_height: {
              type: 'string',
              description: 'Block hash (64-char hex) or numeric height as string (e.g. "840000").',
            },
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
          required: ['hash_or_height'],
        },
      },
      {
        name: 'transaction',
        description: 'Transaction details by txid.',
        inputSchema: {
          type: 'object',
          properties: {
            txid: {
              type: 'string',
              description: '64-char hex transaction ID.',
            },
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
          required: ['txid'],
        },
      },
      {
        name: 'tx_status',
        description: 'Confirmation status for a txid (block_height, block_hash, confirmed).',
        inputSchema: {
          type: 'object',
          properties: {
            txid: {
              type: 'string',
              description: '64-char hex transaction ID.',
            },
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
          required: ['txid'],
        },
      },
      {
        name: 'address',
        description: 'Address summary (chain stats + mempool stats).',
        inputSchema: {
          type: 'object',
          properties: {
            address: {
              type: 'string',
              description: 'Bitcoin address (e.g. "bc1q...").',
            },
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
          required: ['address'],
        },
      },
      {
        name: 'address_txs',
        description: 'Recent transactions for an address (mempool + confirmed).',
        inputSchema: {
          type: 'object',
          properties: {
            address: {
              type: 'string',
              description: 'Bitcoin address (e.g. "bc1q...").',
            },
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
          required: ['address'],
        },
      },
      {
        name: 'mempool',
        description: 'Mempool size and fee histogram.',
        inputSchema: {
          type: 'object',
          properties: {
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
        },
      },
      {
        name: 'fee_estimates',
        description: 'Recommended sat/vB fee rates by confirmation target.',
        inputSchema: {
          type: 'object',
          properties: {
            network: {
              type: 'string',
              description: 'mainnet (default) | testnet',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'tip_height':    return this.getTipHeight(args);
        case 'block':         return this.getBlock(args);
        case 'transaction':   return this.getTransaction(args);
        case 'tx_status':     return this.getTxStatus(args);
        case 'address':       return this.getAddress(args);
        case 'address_txs':   return this.getAddressTxs(args);
        case 'mempool':       return this.getMempool(args);
        case 'fee_estimates': return this.getFeeEstimates(args);
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

  /**
   * Resolve the Esplora base URL for the requested network.
   * Defaults to mainnet when network is absent or unrecognised.
   */
  private networkBase(args: Record<string, unknown>): string {
    const net = ((args.network as string) ?? 'mainnet').toLowerCase();
    if (net !== 'mainnet' && net !== 'testnet') {
      throw new Error('network must be "mainnet" or "testnet".');
    }
    if (net === 'testnet') return 'https://blockstream.info/testnet/api';
    // Honour a custom base URL only on mainnet (the override is used in tests).
    return this.baseUrl;
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async esploraGet(path: string, base: string): Promise<ToolResult> {
    const url = `${base}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Not found.' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    // Some Esplora endpoints return plain text (heights, hashes); detect by Content-Type.
    const ct = response.headers.get('content-type') ?? '';
    if (ct.includes('application/json')) {
      const data = await response.json();
      return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
    }
    const text = (await response.text()).trim();
    return { content: [{ type: 'text', text: this.truncate({ value: text }) }], isError: false };
  }

  private async getTipHeight(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    const result = await this.esploraGet('/blocks/tip/height', base);
    if (result.isError) return result;
    // Convert plain-text height string to a numeric object for consistency.
    try {
      const parsed = JSON.parse(result.content[0].text) as unknown;
      if (parsed && typeof parsed === 'object' && 'value' in (parsed as Record<string, unknown>)) {
        const val = (parsed as { value: string }).value;
        if (/^[0-9]+$/.test(val)) {
          return { content: [{ type: 'text', text: JSON.stringify({ height: Number(val) }, null, 2) }], isError: false };
        }
      }
    } catch { /* fall through to raw result */ }
    return result;
  }

  private async getBlock(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    const hoh = this.reqStr(args, 'hash_or_height', '"840000" or a 64-char hex hash');
    if (/^[0-9]+$/.test(hoh)) {
      // Height → resolve to hash first, then fetch block.
      const hashResult = await this.esploraGet(`/block-height/${encodeURIComponent(hoh)}`, base);
      if (hashResult.isError) return hashResult;
      let hash: string;
      try {
        const parsed = JSON.parse(hashResult.content[0].text) as unknown;
        hash = (parsed && typeof parsed === 'object' && 'value' in (parsed as Record<string, unknown>))
          ? String((parsed as { value: string }).value).trim()
          : String(parsed).trim();
      } catch {
        return { content: [{ type: 'text', text: 'Failed to parse block hash from height lookup.' }], isError: true };
      }
      return this.esploraGet(`/block/${encodeURIComponent(hash)}`, base);
    }
    return this.esploraGet(`/block/${encodeURIComponent(hoh)}`, base);
  }

  private async getTransaction(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    const txid = this.reqStr(args, 'txid', '"<64-char hex txid>"');
    return this.esploraGet(`/tx/${encodeURIComponent(txid)}`, base);
  }

  private async getTxStatus(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    const txid = this.reqStr(args, 'txid', '"<64-char hex txid>"');
    return this.esploraGet(`/tx/${encodeURIComponent(txid)}/status`, base);
  }

  private async getAddress(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    const address = this.reqStr(args, 'address', '"bc1q..."');
    return this.esploraGet(`/address/${encodeURIComponent(address)}`, base);
  }

  private async getAddressTxs(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    const address = this.reqStr(args, 'address', '"bc1q..."');
    return this.esploraGet(`/address/${encodeURIComponent(address)}/txs`, base);
  }

  private async getMempool(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    return this.esploraGet('/mempool', base);
  }

  private async getFeeEstimates(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.networkBase(args);
    return this.esploraGet('/fee-estimates', base);
  }
}
