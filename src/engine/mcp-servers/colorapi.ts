/**
 * The Color API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://www.thecolorapi.com
// Auth: none (public, no key required)
// Docs: https://www.thecolorapi.com/docs
// Category: design
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.thecolorapi.com';

interface RawColor {
  hex: { value: string; clean: string };
  rgb: { r: number; g: number; b: number; value: string };
  hsl: { h: number; s: number; l: number; value: string };
  hsv: { h: number; s: number; v: number; value: string };
  cmyk: { c: number; m: number; y: number; k: number; value: string };
  name: { value: string; closest_named_hex: string; exact_match_name: boolean };
  contrast: { value: string };
}

interface RawSchemeResponse {
  mode: string;
  count: number;
  colors: RawColor[];
}

function formatColor(c: RawColor) {
  return {
    name: c.name.value,
    exact_name_match: c.name.exact_match_name,
    closest_named_hex: c.name.closest_named_hex,
    hex: c.hex.value,
    rgb: c.rgb.value,
    hsl: c.hsl.value,
    hsv: c.hsv.value,
    cmyk: c.cmyk.value,
    contrast: c.contrast.value,
  };
}

export class ColorAPIMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('ColorAPIMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'colorapi',
      displayName: 'The Color API',
      version: '1.0.0',
      category: 'design',
      keywords: [
        'color', 'colour', 'hex', 'rgb', 'hsl', 'hsv', 'cmyk',
        'color name', 'color scheme', 'palette', 'color conversion',
        'color identification', 'design', 'thecolorapi',
      ],
      toolNames: ['identify_color', 'generate_scheme', 'convert_color'],
      description: 'The Color API: identify colors by hex value, generate harmonious color schemes, and convert RGB to all color formats — free and unauthenticated.',
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
        name: 'identify_color',
        description: 'Identify a color by its hex value. Returns the color name, all format representations (RGB, HSL, HSV, CMYK), and contrast info.',
        inputSchema: {
          type: 'object',
          properties: {
            hex: {
              type: 'string',
              description: 'Hex color value without the # prefix (e.g. "FF5733").',
            },
          },
          required: ['hex'],
        },
      },
      {
        name: 'generate_scheme',
        description: 'Generate a color scheme from a seed hex color. Returns a set of harmonious colors based on the chosen mode.',
        inputSchema: {
          type: 'object',
          properties: {
            hex: {
              type: 'string',
              description: 'Seed hex color value without the # prefix (e.g. "FF5733").',
            },
            mode: {
              type: 'string',
              description: 'Color scheme mode. One of: monochrome, analogic, complement, triad, quad. Defaults to "monochrome".',
            },
            count: {
              type: 'number',
              description: 'Number of colors to return (1-10, default 5).',
            },
          },
          required: ['hex'],
        },
      },
      {
        name: 'convert_color',
        description: 'Convert an RGB color to all other color formats (hex, HSL, HSV, CMYK) and get its closest color name.',
        inputSchema: {
          type: 'object',
          properties: {
            r: { type: 'number', description: 'Red channel (0-255).' },
            g: { type: 'number', description: 'Green channel (0-255).' },
            b: { type: 'number', description: 'Blue channel (0-255).' },
          },
          required: ['r', 'g', 'b'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'identify_color':
          return this.identifyColor(args.hex as string);
        case 'generate_scheme':
          return this.generateScheme(
            args.hex as string,
            (args.mode as string | undefined) ?? 'monochrome',
            (args.count as number | undefined) ?? 5,
          );
        case 'convert_color':
          return this.convertColor(
            args.r as number,
            args.g as number,
            args.b as number,
          );
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

  private async identifyColor(hex: string): Promise<ToolResult> {
    const clean = hex.replace(/^#/, '');
    const url = `${this.baseUrl}/id?hex=${encodeURIComponent(clean)}`;
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
    const data = (await response.json()) as RawColor;
    return {
      content: [{ type: 'text', text: this.truncate(formatColor(data)) }],
      isError: false,
    };
  }

  private async generateScheme(hex: string, mode: string, count: number): Promise<ToolResult> {
    const clean = hex.replace(/^#/, '');
    const safeCount = Math.min(10, Math.max(1, count));
    const params = new URLSearchParams({
      hex: clean,
      mode,
      count: String(safeCount),
    });
    const url = `${this.baseUrl}/scheme?${params}`;
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
    const data = (await response.json()) as RawSchemeResponse;
    const result = {
      seed_hex: `#${clean}`,
      mode: data.mode,
      count: data.count,
      colors: data.colors.map(formatColor),
    };
    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }

  private async convertColor(r: number, g: number, b: number): Promise<ToolResult> {
    const params = new URLSearchParams({ rgb: `rgb(${r},${g},${b})` });
    const url = `${this.baseUrl}/id?${params}`;
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
    const data = (await response.json()) as RawColor;
    return {
      content: [{ type: 'text', text: this.truncate(formatColor(data)) }],
      isError: false,
    };
  }
}
