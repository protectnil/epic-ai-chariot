/**
 * wger Workout Manager REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://wger.de/api/v2  (wger Workout Manager — open source, MIT)
// Auth: None required for read endpoints
// Docs: https://wger.de/api/v2/
// Category: health
// Rate limits: None published for public read endpoints

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://wger.de/api/v2';

type RawExerciseTranslation = {
  id: number;
  name: string;
  description: string;
  language: number;
};

type RawExercise = {
  id: number;
  uuid: string;
  category: { id: number; name: string } | null;
  muscles: Array<{ id: number; name_en: string }>;
  muscles_secondary: Array<{ id: number; name_en: string }>;
  equipment: Array<{ id: number; name: string }>;
  translations: RawExerciseTranslation[];
};

type RawMuscle = {
  id: number;
  name_en: string;
  is_front: boolean;
};

type RawEquipment = {
  id: number;
  name: string;
};

type RawListResponse<T> = {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
};

export class WgerMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('WgerMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'wger',
      displayName: 'wger Workout Manager',
      version: '1.0.0',
      category: 'health',
      keywords: [
        'wger', 'workout', 'exercise', 'fitness', 'muscles', 'equipment',
        'strength training', 'gym', 'muscle groups', 'training', 'bodybuilding',
        'workout manager', 'open source fitness',
      ],
      toolNames: ['list_exercises', 'get_exercise', 'list_muscles', 'list_equipment'],
      description: 'wger Workout Manager: list and retrieve exercises, muscle groups, and equipment from the open-source wger fitness database.',
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
        name: 'list_exercises',
        description: 'List exercises from the wger database (English language only).',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of exercises to return. Defaults to 20.',
            },
          },
        },
      },
      {
        name: 'get_exercise',
        description: 'Get detailed information for a specific exercise by its numeric ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'The numeric wger exercise ID.',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'list_muscles',
        description: 'List all muscles tracked in the wger database.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_equipment',
        description: 'List all equipment types available in the wger database.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_exercises': return this.listExercises((args.limit as number | undefined) ?? 20);
        case 'get_exercise':   return this.getExercise(args.id as number);
        case 'list_muscles':   return this.listMuscles();
        case 'list_equipment': return this.listEquipment();
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private formatExercise(e: RawExercise): Record<string, unknown> {
    // Since wger API v2 moved name/description into a translations array,
    // prefer the English translation (language=2); fall back to first available.
    const translation =
      e.translations.find((t) => t.language === 2) ?? e.translations[0] ?? null;
    return {
      id: e.id,
      name: translation?.name ?? null,
      description: translation?.description
        ? translation.description.replace(/<[^>]*>/g, '').trim()
        : null,
      category: e.category?.name ?? null,
      muscles: e.muscles.map((m) => m.name_en),
      muscles_secondary: e.muscles_secondary.map((m) => m.name_en),
      equipment: e.equipment.map((eq) => eq.name),
    };
  }

  private async listExercises(limit: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/exerciseinfo/?format=json&language=2&limit=${encodeURIComponent(String(limit))}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawListResponse<RawExercise>;
    const result = {
      count: data.count,
      exercises: data.results.map((e) => this.formatExercise(e)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getExercise(id: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/exerciseinfo/${encodeURIComponent(String(id))}/?format=json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawExercise;
    return { content: [{ type: 'text', text: this.truncate(this.formatExercise(data)) }], isError: false };
  }

  private async listMuscles(): Promise<ToolResult> {
    const url = `${this.baseUrl}/muscle/?format=json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawListResponse<RawMuscle>;
    const result = {
      count: data.count,
      muscles: data.results.map((m) => ({ id: m.id, name: m.name_en, is_front: m.is_front })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listEquipment(): Promise<ToolResult> {
    const url = `${this.baseUrl}/equipment/?format=json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = (await response.json()) as RawListResponse<RawEquipment>;
    const result = {
      count: data.count,
      equipment: data.results.map((e) => ({ id: e.id, name: e.name })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
