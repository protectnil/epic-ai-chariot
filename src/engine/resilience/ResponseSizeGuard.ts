/**
 * @epicai/chariot — Response Size Guard
 * Standalone guard module.
 * Re-exposes the response-size cap constant and check function so
 * eval-30 and eval-31 can import from dist/engine/resilience/ResponseSizeGuard.js.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** Cap upstream tool response payload size at 1 MiB. */
export const MAX_RESPONSE_BYTES = 1_048_576;

export class ResponseTooLargeError extends Error {
  readonly statusCode = 413;
  readonly status = 413;
  constructor(byteLength: number) {
    super(`Response size ${byteLength} bytes exceeds MAX_RESPONSE_BYTES (${MAX_RESPONSE_BYTES}). Response truncated.`);
    this.name = 'ResponseTooLargeError';
  }
}

/**
 * Assert that byteLength <= MAX_RESPONSE_BYTES.
 * 1_048_576 → accepted. 1_048_577 → throws ResponseTooLargeError.
 */
export function checkResponseBytes(byteLength: number): void {
  if (byteLength > MAX_RESPONSE_BYTES) {
    throw new ResponseTooLargeError(byteLength);
  }
}
