/**
 * Phase R.eval test wrapper — minimal REST adapter used by the
 * secrets-flow eval to verify Case 1 (REST module) dispatch attaches the
 * vault-sourced apiKey to outbound requests.
 *
 * Sends the apiKey via the `X-API-Key` header so the mock vendor's
 * captured-request log shows whether the credential arrived.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */
import { MCPAdapterBase } from './base.js';

interface EvalRestWrapperConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class EvalRestWrapper extends MCPAdapterBase {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: EvalRestWrapperConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Phase R.eval REST test wrapper: configuration object is required');
    }
    this.apiKey = config.apiKey ?? '';
    this.baseUrl = config.baseUrl ?? 'http://127.0.0.1:1';
  }

  static catalog() {
    return {
      name: 'r-eval-rest-wrapper',
      displayName: 'Phase R.eval REST test wrapper',
      version: '1.0.0',
      category: 'test',
      keywords: ['eval'],
      toolNames: ['echo'],
      description: 'Test wrapper for the Phase R secrets-flow eval.',
      author: 'protectnil',
    };
  }

  get tools() {
    return [
      {
        name: 'echo',
        description: 'POST to the mock vendor with the apiKey in the X-API-Key header.',
        inputSchema: { type: 'object', properties: { msg: { type: 'string' } } },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    if (name !== 'echo') {
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }
    const headers: Record<string, string> = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    const response = await this.fetchWithRetry(`${this.baseUrl}/echo`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ msg: args.msg ?? '' }),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}

export default EvalRestWrapper;
