/**
 * Blockchair Multi-Chain Block Explorer MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.blockchair.com
// Auth: None (free tier, keyless)
// Docs: https://blockchair.com/api/docs
// Category: crypto
// Rate limits: Free tier — no API key required; 429 returned on abuse

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.blockchair.com';

const SUPPORTED_CHAINS = new Set([
  'bitcoin',
  'bitcoin-cash',
  'litecoin',
  'bitcoin-sv',
  'dogecoin',
  'dash',
  'groestlcoin',
  'zcash',
  'ecash',
  'ethereum',
  'mixin',
  'monero',
  'stellar',
  'ripple',
  'cardano',
  'eos',
]);

export class BlockchairMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('BlockchairMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'blockchair',
      displayName: 'Blockchair — Multi-Chain Block Explorer',
      version: '1.0.0',
      category: 'crypto',
      keywords: [
        'blockchair', 'blockchain', 'bitcoin', 'ethereum', 'crypto',
        'block explorer', 'transaction', 'address', 'block', 'chain stats',
        'dogecoin', 'litecoin', 'ripple', 'cardano', 'monero', 'zcash',
        'node stats', 'dashboard', 'on-chain data', 'multi-chain',
      ],
      toolNames: ['stats', 'block', 'transaction', 'address', 'node'],
      description: 'Blockchair API: chain-wide statistics, block details, transaction lookup, address dashboards, and node software stats across 16+ blockchains — free and unauthenticated.',
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
        name: 'stats',
        description: 'Retrieve chain-wide statistics for a given blockchain (block count, transaction count, hash rate, difficulty, market data, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              description: `Blockchain identifier. Supported values: ${[...SUPPORTED_CHAINS].join(', ')}.`,
            },
          },
          required: ['chain'],
        },
      },
      {
        name: 'block',
        description: 'Retrieve block details by hash (hex string) or height (numeric string) for a given blockchain.',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              description: `Blockchain identifier. Supported values: ${[...SUPPORTED_CHAINS].join(', ')}.`,
            },
            hash_or_height: {
              type: 'string',
              description: 'Block hash (hex) or block height as a numeric string (e.g., "700000").',
            },
          },
          required: ['chain', 'hash_or_height'],
        },
      },
      {
        name: 'transaction',
        description: 'Retrieve transaction details by transaction ID (txid/txhash) for a given blockchain.',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              description: `Blockchain identifier. Supported values: ${[...SUPPORTED_CHAINS].join(', ')}.`,
            },
            txid: {
              type: 'string',
              description: 'Transaction hash/ID (hex string).',
            },
          },
          required: ['chain', 'txid'],
        },
      },
      {
        name: 'address',
        description: 'Retrieve an address dashboard including balance, transaction count, and recent transactions for a given blockchain.',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              description: `Blockchain identifier. Supported values: ${[...SUPPORTED_CHAINS].join(', ')}.`,
            },
            address: {
              type: 'string',
              description: 'Blockchain address to look up.',
            },
          },
          required: ['chain', 'address'],
        },
      },
      {
        name: 'node',
        description: 'Retrieve node software statistics for a given blockchain, including sync status, software version, and latest block.',
        inputSchema: {
          type: 'object',
          properties: {
            chain: {
              type: 'string',
              description: `Blockchain identifier. Supported values: ${[...SUPPORTED_CHAINS].join(', ')}.`,
            },
          },
          required: ['chain'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'stats':       return this.getStats(args);
        case 'block':       return this.getBlock(args);
        case 'transaction': return this.getTransaction(args);
        case 'address':     return this.getAddress(args);
        case 'node':        return this.getNode(args);
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

  private resolveChain(args: Record<string, unknown>): string {
    const chain = this.requireString(args, 'chain');
    const normalized = chain.toLowerCase();
    if (!SUPPORTED_CHAINS.has(normalized)) {
      throw new Error(`Unsupported chain "${chain}". Must be one of: ${[...SUPPORTED_CHAINS].join(', ')}.`);
    }
    return normalized;
  }

  private requireString(args: Record<string, unknown>, key: string): string {
    const value = args[key];
    if (typeof value !== 'string' || value.trim() === '') {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return value.trim();
  }

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 402) {
      return {
        content: [{ type: 'text', text: 'Blockchair: 402 — this request requires a paid plan.' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Blockchair API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getStats(args: Record<string, unknown>): Promise<ToolResult> {
    const chain = this.resolveChain(args);
    return this.get(`/${chain}/stats`);
  }

  private async getBlock(args: Record<string, unknown>): Promise<ToolResult> {
    const chain = this.resolveChain(args);
    const hashOrHeight = this.requireString(args, 'hash_or_height');
    return this.get(`/${chain}/dashboards/block/${encodeURIComponent(hashOrHeight)}`);
  }

  private async getTransaction(args: Record<string, unknown>): Promise<ToolResult> {
    const chain = this.resolveChain(args);
    const txid = this.requireString(args, 'txid');
    return this.get(`/${chain}/dashboards/transaction/${encodeURIComponent(txid)}`);
  }

  private async getAddress(args: Record<string, unknown>): Promise<ToolResult> {
    const chain = this.resolveChain(args);
    const address = this.requireString(args, 'address');
    return this.get(`/${chain}/dashboards/address/${encodeURIComponent(address)}`);
  }

  private async getNode(args: Record<string, unknown>): Promise<ToolResult> {
    const chain = this.resolveChain(args);
    return this.get(`/${chain}/nodes`);
  }
}
