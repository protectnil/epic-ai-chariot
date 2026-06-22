/**
 * Chainlist (EVM Chain Registry) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source (MIT) MCP wrapper source.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://chainid.network/chains.json
// Auth: None required — chainid.network is a public, unauthenticated registry.
// Docs: https://chainid.network/
// Rate limits: None documented; data updates slowly; cached per isolate for 1 hour.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const CHAINS_URL = 'https://chainid.network/chains.json';
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

interface Chain {
  name: string;
  chain: string;
  shortName: string;
  chainId: number;
  networkId?: number;
  nativeCurrency?: { name: string; symbol: string; decimals: number };
  rpc?: string[];
  explorers?: { name: string; url: string; standard?: string }[];
  faucets?: string[];
  infoURL?: string;
  status?: string; // active | deprecated | incubating
}

interface ChainlistConfig {
  /** Optional base URL override (default: https://chainid.network/chains.json) */
  baseUrl?: string;
}

// Module-level cache shared across adapter instances within one worker isolate.
let CACHE: { chains: Chain[]; expiresAt: number } | null = null;

export class ChainlistMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: ChainlistConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Chainlist: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? CHAINS_URL;
  }

  static catalog() {
    return {
      name: 'chainlist',
      displayName: 'Chainlist — EVM Chain Registry',
      version: '1.0.0',
      category: 'blockchain',
      keywords: [
        'chainlist', 'evm', 'chain', 'chainid', 'ethereum', 'polygon', 'arbitrum',
        'optimism', 'avalanche', 'bnb', 'rpc', 'explorer', 'testnet', 'mainnet',
        'native currency', 'web3', 'network', 'blockchain registry',
      ],
      toolNames: ['list_chains', 'get_chain', 'find_rpc'],
      description: 'Chainlist EVM chain registry: browse, filter, and look up every EVM-compatible chain by chainId or shortName, retrieve RPC endpoints, and explore chain metadata.',
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
        name: 'list_chains',
        description: 'Browse or filter the EVM chain registry. Returns a summary list of chains matching the given filters.',
        inputSchema: {
          type: 'object',
          properties: {
            testnet: {
              type: 'boolean',
              description: 'Include testnets only (true) or mainnets only (false). Omit to return all chains.',
            },
            name: {
              type: 'string',
              description: 'Case-insensitive substring filter applied to chain name.',
            },
            active: {
              type: 'boolean',
              description: 'Restrict to active/incubating chains only. Defaults to true (excludes deprecated).',
            },
          },
        },
      },
      {
        name: 'get_chain',
        description: 'Fetch the full metadata for a single chain by its numeric chainId (e.g. "1" for Ethereum mainnet) or shortName (e.g. "eth", "matic", "arb1").',
        inputSchema: {
          type: 'object',
          properties: {
            chain_id_or_short_name: {
              type: 'string',
              description: 'Numeric chain ID as a string (e.g. "137") or shortName (e.g. "matic").',
            },
          },
          required: ['chain_id_or_short_name'],
        },
      },
      {
        name: 'find_rpc',
        description: 'Return the list of RPC endpoint URLs for a chain. By default only HTTPS endpoints are returned (https_only=true).',
        inputSchema: {
          type: 'object',
          properties: {
            chain_id_or_short_name: {
              type: 'string',
              description: 'Numeric chain ID as a string or shortName.',
            },
            https_only: {
              type: 'boolean',
              description: 'When true (default), only https:// endpoints are returned. Pass false to include ws:// and http:// as well.',
            },
          },
          required: ['chain_id_or_short_name'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_chains': return this.listChains(args);
        case 'get_chain':   return this.getChain(args);
        case 'find_rpc':    return this.findRpc(args);
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async fetchChains(): Promise<Chain[]> {
    if (CACHE && CACHE.expiresAt > Date.now()) return CACHE.chains;
    const response = await this.fetchWithRetry(this.baseUrl, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Chainlist registry error: ${response.status} ${errText.slice(0, 200)}`);
    }
    const chains = (await response.json()) as Chain[];
    CACHE = { chains, expiresAt: Date.now() + CACHE_TTL_MS };
    return chains;
  }

  private findChain(chains: Chain[], id: string): Chain | undefined {
    const lower = id.toLowerCase().trim();
    if (/^\d+$/.test(lower)) {
      const n = Number(lower);
      return chains.find((c) => c.chainId === n);
    }
    return chains.find((c) => c.shortName.toLowerCase() === lower);
  }

  private summarize(c: Chain): Record<string, unknown> {
    return {
      chainId: c.chainId,
      name: c.name,
      shortName: c.shortName,
      nativeCurrency: c.nativeCurrency,
      rpc_count: c.rpc?.length ?? 0,
      explorers: c.explorers?.map((e) => e.url) ?? [],
      status: c.status ?? 'active',
    };
  }

  private async listChains(args: Record<string, unknown>): Promise<ToolResult> {
    const chains = await this.fetchChains();
    const wantTestnet = args.testnet as boolean | undefined;
    const nameFilter = (args.name as string | undefined)?.toLowerCase();
    const onlyActive = args.active !== false;

    const filtered = chains.filter((c) => {
      if (onlyActive && c.status && c.status !== 'active' && c.status !== 'incubating') return false;
      if (nameFilter && !c.name.toLowerCase().includes(nameFilter)) return false;
      if (wantTestnet !== undefined) {
        const looksTestnet = /testnet|sepolia|holesky|goerli|mumbai|fuji/i.test(c.name);
        if (wantTestnet && !looksTestnet) return false;
        if (!wantTestnet && looksTestnet) return false;
      }
      return true;
    });

    const result = { count: filtered.length, chains: filtered.map((c) => this.summarize(c)) };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getChain(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'chain_id_or_short_name', '"eth"');
    const chains = await this.fetchChains();
    const chain = this.findChain(chains, id);
    if (!chain) {
      return {
        content: [{ type: 'text', text: `Chainlist: no chain matching "${id}"` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(chain) }], isError: false };
  }

  private async findRpc(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'chain_id_or_short_name', '"eth"');
    const httpsOnly = args.https_only !== false;
    const chains = await this.fetchChains();
    const chain = this.findChain(chains, id);
    if (!chain) {
      return {
        content: [{ type: 'text', text: `Chainlist: no chain matching "${id}"` }],
        isError: true,
      };
    }
    const rpcs = (chain.rpc ?? [])
      .map((r) => r.replace(/\$\{[^}]+\}/g, '')) // strip ${INFURA_API_KEY} placeholders
      .filter((r) => r && (!httpsOnly || r.startsWith('https://')));
    const result = { chain_id: chain.chainId, short_name: chain.shortName, rpcs };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }
}
