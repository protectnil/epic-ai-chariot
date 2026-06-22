/**
 * LibreTranslate MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: LibreTranslate (https://libretranslate.com/)
// Base URL: https://libretranslate.com
// Auth: None required for public endpoints
// Docs: https://libretranslate.com/docs/
// Category: language
// Rate limits: Public instance may impose rate limits; self-hosted instances unlimited

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://libretranslate.com';

export class TranslateMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'translate',
      displayName: 'LibreTranslate',
      version: '1.0.0',
      category: 'language',
      keywords: [
        'translate', 'translation', 'language', 'libretranslate', 'detect language',
        'multilingual', 'text translation', 'language detection', 'natural language',
        'localization', 'i18n', 'open source translation',
      ],
      toolNames: ['translate', 'detect_language', 'list_languages'],
      description: 'LibreTranslate: translate text between languages, detect the language of a string, and list all supported language codes — free public API, no authentication required.',
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
        name: 'translate',
        description:
          'Translate text from a source language to a target language. Returns the translated text.',
        inputSchema: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'The text to translate' },
            source: {
              type: 'string',
              description: 'Source language code (e.g. "en" for English, "es" for Spanish)',
            },
            target: {
              type: 'string',
              description: 'Target language code (e.g. "es" for Spanish, "fr" for French)',
            },
          },
          required: ['text', 'source', 'target'],
        },
      },
      {
        name: 'detect_language',
        description:
          'Detect the language of a text string. Returns an array of detected languages with confidence scores.',
        inputSchema: {
          type: 'object',
          properties: {
            text: { type: 'string', description: 'The text whose language should be detected' },
          },
          required: ['text'],
        },
      },
      {
        name: 'list_languages',
        description:
          'List all languages supported by the translation API. Returns language codes and names.',
        inputSchema: {
          type: 'object',
          properties: {},
          required: [],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'translate':       return this.translate(args);
        case 'detect_language': return this.detectLanguage(args);
        case 'list_languages':  return this.listLanguages();
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

  private async translate(args: Record<string, unknown>): Promise<ToolResult> {
    const text   = args.text   as string;
    const source = args.source as string;
    const target = args.target as string;

    const response = await this.fetchWithRetry(`${BASE_URL}/translate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ q: text, source, target }),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `LibreTranslate error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as { translatedText: string };
    const result = {
      source,
      target,
      original_text: text,
      translated_text: data.translatedText,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async detectLanguage(args: Record<string, unknown>): Promise<ToolResult> {
    const text = args.text as string;

    const response = await this.fetchWithRetry(`${BASE_URL}/detect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ q: text }),
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `LibreTranslate error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as Array<{ language: string; confidence: number }>;
    const result = {
      text,
      detections: data.map((entry) => ({
        language: entry.language,
        confidence: entry.confidence,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listLanguages(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${BASE_URL}/languages`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `LibreTranslate error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = await response.json() as Array<{ code: string; name: string }>;
    const result = {
      total: data.length,
      languages: data.map((lang) => ({
        code: lang.code,
        name: lang.name,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
