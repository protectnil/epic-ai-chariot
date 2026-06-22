/**
 * @epicai/chariot — CLI Display Helpers
 * Pure functions for formatting CLI output. No I/O, no dependencies.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** Map an adapter's `type` field to its display label. */
export function adapterTypeLabel(type: string | undefined): string {
  if (type === 'mcp') return 'MCP';
  if (type === 'both') return 'REST+MCP';
  return 'REST';
}
