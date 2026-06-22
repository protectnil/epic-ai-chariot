/**
 * @epicai/chariot — JSON Depth Guard
 * Standalone guard module.
 * Re-exposes the JSON depth constant and check function so
 * eval-30 and eval-31 can import from dist/engine/resilience/JsonDepthGuard.js.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** Reject arg JSON that nests deeper than this. */
export const MAX_JSON_DEPTH = 32;

export class JsonDepthExceededError extends Error {
  readonly statusCode = 400;
  readonly status = 400;
  constructor(depth: number) {
    super(`JSON nesting depth ${depth} exceeds MAX_JSON_DEPTH (${MAX_JSON_DEPTH}).`);
    this.name = 'JsonDepthExceededError';
  }
}

/**
 * Iteratively measure the nesting depth of value.
 * Throws JsonDepthExceededError when depth > MAX_JSON_DEPTH.
 * depth-32 object → accepted. depth-33 → throws.
 * Iterative (not recursive) so the guard cannot itself stack-overflow.
 */
export function checkJsonDepth(value: unknown, maxDepth: number = MAX_JSON_DEPTH): void {
  // Stack of [node, currentDepth]. Depth is the level of the node itself.
  const stack: Array<[unknown, number]> = [[value, 0]];
  while (stack.length > 0) {
    const popped = stack.pop();
    if (!popped) break;
    const [node, depth] = popped;
    if (node === null || typeof node !== 'object') continue;
    if (depth > maxDepth) {
      throw new JsonDepthExceededError(depth);
    }
    if (Array.isArray(node)) {
      for (const child of node) stack.push([child, depth + 1]);
    } else {
      for (const key of Object.keys(node as Record<string, unknown>)) {
        stack.push([(node as Record<string, unknown>)[key], depth + 1]);
      }
    }
  }
}
