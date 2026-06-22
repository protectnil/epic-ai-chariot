/**
 * @epicai/chariot — Tool Depth and Fan-out Guards
 * Standalone guard module.
 * Re-exposes the depth/fanout constants and check functions as a module so
 * eval-30 and eval-31 can import from dist/engine/resilience/DepthGuard.js.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** Maximum recursive tool-call depth per logical request. */
export const MAX_TOOL_DEPTH = 8;

/** Maximum total tool-call fan-out per logical request. */
export const MAX_TOOL_FANOUT = 32;

export class ToolDepthExceededError extends Error {
  readonly statusCode = 429;
  readonly status = 429;
  constructor(depth: number) {
    super(`Tool call depth ${depth} exceeds MAX_TOOL_DEPTH (${MAX_TOOL_DEPTH}).`);
    this.name = 'ToolDepthExceededError';
  }
}

export class ToolFanoutExceededError extends Error {
  readonly statusCode = 429;
  readonly status = 429;
  constructor(fanout: number) {
    super(`Tool call fanout ${fanout} exceeds MAX_TOOL_FANOUT (${MAX_TOOL_FANOUT}).`);
    this.name = 'ToolFanoutExceededError';
  }
}

/**
 * Assert that depth <= MAX_TOOL_DEPTH.
 * depth 8 → accepted. depth 9 → throws ToolDepthExceededError.
 */
export function checkToolDepth(depth: number): void {
  if (depth > MAX_TOOL_DEPTH) {
    throw new ToolDepthExceededError(depth);
  }
}

/**
 * Assert that fanout <= MAX_TOOL_FANOUT.
 * fanout 32 → accepted. fanout 33 → throws ToolFanoutExceededError.
 */
export function checkToolFanout(fanout: number): void {
  if (fanout > MAX_TOOL_FANOUT) {
    throw new ToolFanoutExceededError(fanout);
  }
}
