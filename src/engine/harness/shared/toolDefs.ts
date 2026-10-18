/**
 * @epicai/chariot — Test Harness Canonical Tool Definitions
 * 8 tools shared across all three harness backends.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ToolInfo } from '../types.js';

// CHARIOT::§8.11::2 — "Each profile SHALL run eight canonical tools (list,
// search, read, write-shadow, delete-shadow, error-handling, auth-failure,
// rate-limit) ..." (CHARIOT-SPEC.md:824). This is the single source of truth
// for the name list; every backend (stdio/http/api) MUST register exactly
// these tools, in this order for display purposes (assertion order is
// order-insensitive per the clause, which does not specify an ordering).
// CHARIOT::§8.11::2 — the eight canonical tools per profile
export const CANONICAL_TOOL_NAMES = [
  'list', 'search', 'read', 'write-shadow',
  'delete-shadow', 'error-handling', 'auth-failure', 'rate-limit',
] as const;

export type CanonicalToolName = (typeof CANONICAL_TOOL_NAMES)[number];

// CHARIOT::§8.11::2
export const CANONICAL_TOOLS: ToolInfo[] = [
  {
    name: 'list',
    description: 'Lists shadow records with pagination. Proves list/discovery behavior against deterministic seed-1337 fixtures.',
    parameters: {
      type: 'object',
      properties: {
        offset: { type: 'number', description: 'Pagination offset (default 0)' },
        limit: { type: 'number', description: 'Page size, max 50 (default 10)' },
      },
    },
  },
  {
    name: 'search',
    description: 'Searches shadow records by query string against title/severity. Proves filtered-read behavior.',
    parameters: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query matched against title (substring) or severity (exact)' },
      },
      required: ['query'],
    },
  },
  {
    name: 'read',
    description: 'Reads a single shadow record by id. Proves single-resource fetch and not-found handling.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Record id to read' },
      },
      required: ['id'],
    },
  },
  {
    name: 'write-shadow',
    description: 'Creates or updates a record in the harness shadow store (never the real vendor). Proves write-path handling.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Record id to update; omit to create' },
        fields: { type: 'object', description: 'Fields to set on the record' },
      },
      required: ['fields'],
    },
  },
  {
    name: 'delete-shadow',
    description: 'Deletes a record from the harness shadow store by id. Proves delete-path and not-found handling.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Record id to delete' },
      },
      required: ['id'],
    },
  },
  {
    name: 'error-handling',
    description: 'Deterministically returns malformed/partial/sensitive/injection-bearing payloads. Proves parser and resilience behavior.',
    parameters: {
      type: 'object',
      properties: {
        variant: { type: 'number', description: 'Malformed variant index (0-3)' },
      },
    },
  },
  {
    name: 'auth-failure',
    description: 'Deterministically returns a structured authentication-failure result. Proves downstream auth-failure handling.',
    parameters: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'rate-limit',
    description: 'Deterministically returns a structured rate-limit-exceeded result with retry-after. Proves backoff/retry handling.',
    parameters: {
      type: 'object',
      properties: {},
    },
  },
];
