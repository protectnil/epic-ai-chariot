/**
 * @epicai/chariot — Error Classifier
 * Classifies errors as transient (retry) or permanent (fail fast).
 * Different retry strategies for different error types.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * §8.7::2 — CHARIOT-SPEC.md:769: "buckets exceptions into `transient`,
 * `permanent`, `policy`, `unknown`. Each bucket has a different retry policy."
 *
 * `rate-limited` and `timeout` were shipped as separate categories; both are
 * kinds of TRANSIENT failure and keep their own backoff via distinct rules
 * rather than distinct categories. `policy` (an authorization/policy denial) is
 * never retried — retrying a denial cannot change the answer and only burns
 * quota. `unknown` is the fallback: retried, but less eagerly than a positively
 * identified transient fault, and never silently reported as transient.
 */
export type ErrorCategory = 'transient' | 'permanent' | 'policy' | 'unknown';

export interface ClassifiedError {
  category: ErrorCategory;
  retryable: boolean;
  maxRetries: number;
  backoffMs: number;
  originalError: Error;
  message: string;
}

interface ClassificationRule {
  patterns: string[];
  result: Omit<ClassifiedError, 'originalError' | 'message'>;
  prefix: string;
}

// Rule order is the classification priority. Transient matches BEFORE timeout
// so 5xx server errors (e.g. "504 Gateway Timeout") are treated as transient
// retries rather than client-side timeouts — the HTTP semantic dominates the
// keyword match. Pure timeouts without HTTP codes still hit the timeout rule.
// AbortError instances short-circuit to timeout regardless of message text.
const CLASSIFICATION_RULES: ClassificationRule[] = [
  {
    // Rate limiting is a TRANSIENT fault with its own, longer backoff.
    patterns: ['429', 'rate limit', 'too many requests'],
    result: { category: 'transient', retryable: true, maxRetries: 5, backoffMs: 5000 },
    prefix: 'Rate limited',
  },
  {
    patterns: ['500', '502', '503', '504', 'econnreset', 'econnrefused', 'epipe', 'network', 'fetch failed'],
    result: { category: 'transient', retryable: true, maxRetries: 3, backoffMs: 1000 },
    prefix: 'Transient error',
  },
  {
    // Timeouts are transient too, with their own intermediate backoff.
    patterns: ['timeout', 'timed out', 'aborted'],
    result: { category: 'transient', retryable: true, maxRetries: 3, backoffMs: 2000 },
    prefix: 'Timeout',
  },
  {
    // §8.7::2 — a policy/authorization DENIAL: a deliberate decision, not a
    // malformed or missing resource. Never retried; retrying cannot change the
    // verdict. Placed AFTER the transient rules on purpose, preserving the
    // documented priority above: a 5xx that merely mentions "permission" is
    // still a transient server fault, not a denial.
    patterns: ['policy', 'denied', 'egress', 'forbidden', 'unauthorized', 'permission', '401', '403'],
    result: { category: 'policy', retryable: false, maxRetries: 0, backoffMs: 0 },
    prefix: 'Policy denial',
  },
  {
    patterns: ['404', '400', 'not found', 'invalid'],
    result: { category: 'permanent', retryable: false, maxRetries: 0, backoffMs: 0 },
    prefix: 'Permanent error',
  },
];

export class ErrorClassifier {
  static classify(error: unknown): ClassifiedError {
    const err = error instanceof Error ? error : new Error(String(error));
    const message = err.message.toLowerCase();

    // AbortError name short-circuits to the timeout rule regardless of message text.
    if (err.name === 'AbortError') {
      // §8.7::2 — 'timeout' is no longer a category; the timeout RULE is still
      // distinct (its own backoff) and is selected by its prefix.
      const rule = CLASSIFICATION_RULES.find((r) => r.prefix === 'Timeout');
      if (rule) {
        return { ...rule.result, originalError: err, message: `${rule.prefix}: ${err.message}` };
      }
    }

    for (const rule of CLASSIFICATION_RULES) {
      if (rule.patterns.some((p) => message.includes(p))) {
        return { ...rule.result, originalError: err, message: `${rule.prefix}: ${err.message}` };
      }
    }

    // §8.7::2 — an unmatched error is `unknown`, NOT `transient`. Reporting an
    // unclassified fault as a positively-identified transient one hides the
    // classifier's own coverage gaps; it is still retried, but less eagerly.
    return {
      category: 'unknown',
      retryable: true,
      maxRetries: 2,
      backoffMs: 1000,
      originalError: err,
      message: `Unknown error (retrying): ${err.message}`,
    };
  }

  /**
   * Execute a function with retry logic based on error classification.
   */
  static async withRetry<T>(
    fn: () => Promise<T>,
    options?: { maxRetries?: number; onRetry?: (error: ClassifiedError, attempt: number) => void },
  ): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await fn();
      } catch (error) {
        const classified = this.classify(error);

        const maxRetries = options?.maxRetries ?? classified.maxRetries;
        if (!classified.retryable || attempt >= maxRetries) {
          throw classified.originalError;
        }

        if (options?.onRetry) {
          options.onRetry(classified, attempt);
        }

        // Exponential backoff with jitter
        const backoff = classified.backoffMs * Math.pow(2, attempt);
        const jitter = Math.random() * backoff * 0.2; // 20% jitter
        await new Promise(resolve => setTimeout(resolve, backoff + jitter));
      }
    }
  }
}
