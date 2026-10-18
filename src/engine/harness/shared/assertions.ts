/**
 * @epicai/chariot — Test Harness Assertion Suite
 * Shared assertions that run against any HarnessBackend.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { HarnessBackend, AssertionResult } from '../types.js';
import { CANONICAL_TOOL_NAMES } from './toolDefs.js';
import {
  LIST_DEFAULT_LIMIT,
  SEARCH_PAYLOAD_MATCH,
  SEARCH_PAYLOAD_SEVERITY,
  SEARCH_PAYLOAD_NO_MATCH,
  READ_PAYLOAD_MISSING,
  WRITE_SHADOW_PAYLOAD_CREATE,
  WRITE_SHADOW_PAYLOAD_UPDATE_FIELDS,
  DELETE_SHADOW_PAYLOAD_MISSING,
  ERROR_HANDLING_PAYLOAD_REDACTION,
  ERROR_HANDLING_PAYLOAD_INJECTION,
  AUTH_FAILURE_EXPECTED_CODE,
  RATE_LIMIT_EXPECTED_CODE,
} from './fixtures.js';

type AssertFn = (backend: HarnessBackend) => Promise<void>;

interface TestCase {
  name: string;
  fn: AssertFn;
}

function assertEqual(actual: unknown, expected: unknown, message: string): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error(`${message}: expected ${e}, got ${a}`);
  }
}

function assertTruthy(value: unknown, message: string): void {
  if (!value) {
    throw new Error(`${message}: expected truthy, got ${JSON.stringify(value)}`);
  }
}

const TESTS: TestCase[] = [
  // Tool discovery — CHARIOT::§8.11::2 (CHARIOT-SPEC.md:824): registered tool
  // names must equal exactly {list, search, read, write-shadow,
  // delete-shadow, error-handling, auth-failure, rate-limit}, no more no less.
  {
    name: 'listTools returns exactly the 8 canonical tools',
    fn: async (b) => {
      const tools = await b.listTools();
      const names = tools.map(t => t.name).sort();
      const expected = [...CANONICAL_TOOL_NAMES].sort();
      assertEqual(names, expected, 'Tool names mismatch');
    },
  },

  // Health
  {
    name: 'healthCheck returns true',
    fn: async (b) => {
      const healthy = await b.healthCheck();
      assertEqual(healthy, true, 'Health check');
    },
  },

  // list
  {
    name: 'list returns a page of shadow records with pagination metadata',
    fn: async (b) => {
      const result = await b.callTool('list', {});
      assertEqual(result.isError, false, 'list isError');
      const content = result.content as { data: unknown[]; pagination: { offset: number; limit: number; total: number } };
      assertEqual(content.data.length, LIST_DEFAULT_LIMIT, 'list default page size');
      assertEqual(content.pagination.offset, 0, 'list default offset');
      assertTruthy(content.pagination.total >= LIST_DEFAULT_LIMIT, 'list total records');
    },
  },
  {
    name: 'list respects offset/limit',
    fn: async (b) => {
      const result = await b.callTool('list', { offset: 2, limit: 3 });
      assertEqual(result.isError, false, 'list-paged isError');
      const content = result.content as { data: Array<{ id: string }>; pagination: { offset: number; limit: number } };
      assertEqual(content.data.length, 3, 'list-paged page size');
      assertEqual(content.pagination.offset, 2, 'list-paged offset echoed');
    },
  },

  // search
  {
    name: 'search matches by title substring',
    fn: async (b) => {
      const result = await b.callTool('search', SEARCH_PAYLOAD_MATCH);
      assertEqual(result.isError, false, 'search isError');
      const content = result.content as { data: Array<{ title: string }>; matched: number };
      assertTruthy(content.matched > 0, 'search has matches');
      assertTruthy(content.data.every(r => r.title.includes('Vulnerability 1')), 'search results match query');
    },
  },
  {
    name: 'search matches by exact severity',
    fn: async (b) => {
      const result = await b.callTool('search', SEARCH_PAYLOAD_SEVERITY);
      assertEqual(result.isError, false, 'search-severity isError');
      const content = result.content as { data: Array<{ severity: string }> };
      assertTruthy(content.data.every(r => r.severity === 'critical'), 'search-severity results match');
    },
  },
  {
    name: 'search returns empty for no match',
    fn: async (b) => {
      const result = await b.callTool('search', SEARCH_PAYLOAD_NO_MATCH);
      assertEqual(result.isError, false, 'search-no-match isError');
      const content = result.content as { data: unknown[]; matched: number };
      assertEqual(content.matched, 0, 'search-no-match matched count');
      assertEqual(content.data.length, 0, 'search-no-match data empty');
    },
  },

  // read
  {
    name: 'read returns a single record by id',
    fn: async (b) => {
      const list = await b.callTool('list', { limit: 1 });
      const first = (list.content as { data: Array<{ id: string }> }).data[0];
      const result = await b.callTool('read', { id: first.id });
      assertEqual(result.isError, false, 'read isError');
      const content = result.content as { id: string };
      assertEqual(content.id, first.id, 'read returns requested record');
    },
  },
  {
    name: 'read returns NOT_FOUND for missing id',
    fn: async (b) => {
      const result = await b.callTool('read', READ_PAYLOAD_MISSING);
      assertEqual(result.isError, true, 'read-missing isError');
      const content = result.content as Record<string, unknown>;
      assertEqual(content.code, 'NOT_FOUND', 'read-missing error code');
    },
  },

  // write-shadow
  {
    name: 'write-shadow creates a new record when no id given',
    fn: async (b) => {
      const result = await b.callTool('write-shadow', WRITE_SHADOW_PAYLOAD_CREATE);
      assertEqual(result.isError, false, 'write-shadow-create isError');
      const content = result.content as { created: boolean; record: { id: string; title: string } };
      assertEqual(content.created, true, 'write-shadow-create created flag');
      assertEqual(content.record.title, WRITE_SHADOW_PAYLOAD_CREATE.fields.title, 'write-shadow-create title');

      // The written record must be visible via read (shadow store, not the real vendor).
      const read = await b.callTool('read', { id: content.record.id });
      assertEqual(read.isError, false, 'write-shadow-create readback isError');
    },
  },
  {
    name: 'write-shadow updates an existing record by id',
    fn: async (b) => {
      const list = await b.callTool('list', { limit: 1 });
      const first = (list.content as { data: Array<{ id: string }> }).data[0];
      const result = await b.callTool('write-shadow', { id: first.id, ...WRITE_SHADOW_PAYLOAD_UPDATE_FIELDS });
      assertEqual(result.isError, false, 'write-shadow-update isError');
      const content = result.content as { created: boolean; record: { id: string; title: string } };
      assertEqual(content.created, false, 'write-shadow-update created flag');
      assertEqual(content.record.title, WRITE_SHADOW_PAYLOAD_UPDATE_FIELDS.fields.title, 'write-shadow-update title');
    },
  },

  // delete-shadow
  {
    name: 'delete-shadow removes an existing record',
    fn: async (b) => {
      const created = await b.callTool('write-shadow', WRITE_SHADOW_PAYLOAD_CREATE);
      const id = (created.content as { record: { id: string } }).record.id;
      const result = await b.callTool('delete-shadow', { id });
      assertEqual(result.isError, false, 'delete-shadow isError');
      const content = result.content as { deleted: boolean };
      assertEqual(content.deleted, true, 'delete-shadow deleted flag');

      const read = await b.callTool('read', { id });
      assertEqual(read.isError, true, 'delete-shadow readback is NOT_FOUND');
    },
  },
  {
    name: 'delete-shadow returns NOT_FOUND for missing id',
    fn: async (b) => {
      const result = await b.callTool('delete-shadow', DELETE_SHADOW_PAYLOAD_MISSING);
      assertEqual(result.isError, true, 'delete-shadow-missing isError');
      const content = result.content as Record<string, unknown>;
      assertEqual(content.code, 'NOT_FOUND', 'delete-shadow-missing error code');
    },
  },

  // error-handling
  {
    name: 'error-handling returns parseable but invalid data',
    fn: async (b) => {
      const result = await b.callTool('error-handling', { variant: 0 });
      assertEqual(result.isError, false, 'error-handling isError');
      const content = result.content as Record<string, unknown>;
      assertEqual(content.partial, true, 'error-handling has partial flag');
    },
  },
  {
    name: 'error-handling variant 2 includes sensitive keys for redaction testing',
    fn: async (b) => {
      const result = await b.callTool('error-handling', ERROR_HANDLING_PAYLOAD_REDACTION);
      assertEqual(result.isError, false, 'error-handling-redaction isError');
      const content = result.content as Record<string, unknown>;
      const creds = content.credentials as Record<string, unknown>;
      assertTruthy(creds?.apiKey, 'error-handling has apiKey for redaction testing');
      const nested = content.nested as Record<string, unknown>;
      const deep = nested?.deep as Record<string, unknown>;
      assertTruthy(deep?.secret, 'error-handling has nested secret for redaction testing');
      assertTruthy(Array.isArray(content.tokens), 'error-handling has tokens array');
    },
  },
  {
    name: 'error-handling variant 3 includes injection lines for sanitization testing',
    fn: async (b) => {
      const result = await b.callTool('error-handling', ERROR_HANDLING_PAYLOAD_INJECTION);
      assertEqual(result.isError, false, 'error-handling-injection isError');
      const content = typeof result.content === 'string' ? result.content : String(result.content);
      assertTruthy(content.includes('ignore previous instructions'), 'error-handling has injection line');
      assertTruthy(content.includes('Normal tool output'), 'error-handling has normal lines');
    },
  },

  // auth-failure
  {
    name: 'auth-failure returns a structured authentication-failure error',
    fn: async (b) => {
      const result = await b.callTool('auth-failure', {});
      assertEqual(result.isError, true, 'auth-failure isError');
      const content = result.content as Record<string, unknown>;
      assertEqual(content.code, AUTH_FAILURE_EXPECTED_CODE, 'auth-failure error code');
      assertTruthy(content.message, 'auth-failure has message');
    },
  },

  // rate-limit
  {
    name: 'rate-limit returns a structured rate-limit-exceeded error with retryAfter',
    fn: async (b) => {
      const result = await b.callTool('rate-limit', {});
      assertEqual(result.isError, true, 'rate-limit isError');
      const content = result.content as Record<string, unknown>;
      assertEqual(content.code, RATE_LIMIT_EXPECTED_CODE, 'rate-limit error code');
      assertTruthy(typeof content.retryAfter === 'number', 'rate-limit has numeric retryAfter');
    },
  },
];

export async function runAssertions(backend: HarnessBackend, perToolTimeoutMs?: number): Promise<AssertionResult[]> {
  const results: AssertionResult[] = [];
  const timeout = perToolTimeoutMs ?? 10_000;

  for (const test of TESTS) {
    const start = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        test.fn(backend),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`Assertion "${test.name}" exceeded ${timeout}ms per-tool timeout`)), timeout);
        }),
      ]);
      results.push({ name: test.name, passed: true, durationMs: Date.now() - start });
    } catch (err) {
      results.push({
        name: test.name,
        passed: false,
        error: err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - start,
      });
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  return results;
}
