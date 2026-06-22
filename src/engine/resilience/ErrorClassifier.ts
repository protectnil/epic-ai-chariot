/**
 * @epicai/chariot — Error Classifier
 * Classifies errors as transient (retry) or permanent (fail fast).
 * Different retry strategies for different error types.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export type ErrorCategory = 'transient' | 'permanent' | 'rate-limited' | 'timeout';

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
    patterns: ['429', 'rate limit', 'too many requests'],
    result: { category: 'rate-limited', retryable: true, maxRetries: 5, backoffMs: 5000 },
    prefix: 'Rate limited',
  },
  {
    patterns: ['500', '502', '503', '504', 'econnreset', 'econnrefused', 'epipe', 'network', 'fetch failed'],
    result: { category: 'transient', retryable: true, maxRetries: 3, backoffMs: 1000 },
    prefix: 'Transient error',
  },
  {
    patterns: ['timeout', 'timed out', 'aborted'],
    result: { category: 'timeout', retryable: true, maxRetries: 3, backoffMs: 2000 },
    prefix: 'Timeout',
  },
  {
    patterns: ['401', '403', '404', '400', 'unauthorized', 'forbidden', 'not found', 'invalid', 'permission'],
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
      const rule = CLASSIFICATION_RULES.find((r) => r.result.category === 'timeout');
      if (rule) {
        return { ...rule.result, originalError: err, message: `${rule.prefix}: ${err.message}` };
      }
    }

    for (const rule of CLASSIFICATION_RULES) {
      if (rule.patterns.some((p) => message.includes(p))) {
        return { ...rule.result, originalError: err, message: `${rule.prefix}: ${err.message}` };
      }
    }

    return {
      category: 'transient',
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
