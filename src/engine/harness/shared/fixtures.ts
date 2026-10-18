/**
 * @epicai/chariot — Test Harness Fixtures
 * Deterministic test data factories, seeded with 1337.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { SeededRandom, SEED } from './seed.js';

export interface ShadowRecord {
  id: string;
  severity: string;
  title: string;
  cvss: number;
}

/** Auth token for the API harness backend */
export const API_AUTH_TOKEN = process.env.HARNESS_API_TOKEN ?? 'test-harness-token';

// CHARIOT::§8.11::2 — "... use deterministic mulberry32 fixtures seeded 1337 ..."
// (CHARIOT-SPEC.md:824). All shadow-store seed data and error-handling
// variants are generated from SeededRandom(SEED), never Math.random().
/** Deterministic shadow-store seed records, shared by every profile's list/search/read/write-shadow/delete-shadow tools. */
export function createShadowRecords(count: number = 25): ShadowRecord[] {
  const localRng = new SeededRandom(SEED);
  const severities = ['critical', 'high', 'medium', 'low'] as const;
  const results: ShadowRecord[] = [];
  for (let i = 0; i < count; i++) {
    results.push({
      id: `VULN-${1000 + i}`,
      severity: localRng.pick(severities),
      title: `Harness Vulnerability ${i + 1}`,
      cvss: Math.round(localRng.next() * 100) / 10,
    });
  }
  return results;
}

export const LIST_DEFAULT_LIMIT = 10;
export const LIST_MAX_LIMIT = 50;

export const SEARCH_PAYLOAD_MATCH = { query: 'Vulnerability 1' };
export const SEARCH_PAYLOAD_SEVERITY = { query: 'critical' };
export const SEARCH_PAYLOAD_NO_MATCH = { query: 'no-such-record-xyz' };

export const READ_PAYLOAD_MISSING = { id: 'VULN-does-not-exist' };

export const WRITE_SHADOW_PAYLOAD_CREATE = { fields: { severity: 'high', title: 'New Shadow Record', cvss: 7.5 } };
export const WRITE_SHADOW_PAYLOAD_UPDATE_FIELDS = { fields: { severity: 'low', title: 'Updated Title', cvss: 1.0 } };

export const DELETE_SHADOW_PAYLOAD_MISSING = { id: 'VULN-does-not-exist' };

export const ERROR_HANDLING_PAYLOAD_REDACTION = { variant: 2 };
export const ERROR_HANDLING_PAYLOAD_INJECTION = { variant: 3 };

export const AUTH_FAILURE_EXPECTED_CODE = 'AUTH_FAILURE';
export const RATE_LIMIT_EXPECTED_CODE = 'RATE_LIMIT_EXCEEDED';
