/**
 * VirtualCatalog — manages VirtualAdapterDefinitions
 *
 * Validates definitions against the live adapter catalog (via the
 * supplied AdapterToolLookup). Stores them in-memory keyed by id.
 * Exposes a flat list suitable for the routing layer to index
 * alongside real adapters.
 *
 * This module does NOT route tool calls. Dispatching a virtual-adapter
 * tool invocation to the underlying real adapter is the federation
 * layer's job. See P2-8a for that wiring.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  VirtualAdapterDefinition,
  VirtualValidationResult,
  AdapterToolLookup,
} from './types.js';

const ID_PATTERN = /^[a-z0-9][a-z0-9_-]{1,63}$/;

export class VirtualCatalog {
  private readonly defs = new Map<string, VirtualAdapterDefinition>();
  private readonly lookup: AdapterToolLookup;

  constructor(lookup: AdapterToolLookup) {
    this.lookup = lookup;
  }

  /**
   * Validate a definition without storing it. Use this to surface
   * errors in admin UI before the user clicks save.
   */
  validate(def: VirtualAdapterDefinition): VirtualValidationResult {
    if (!ID_PATTERN.test(def.id)) {
      return {
        ok: false,
        reason: 'invalid-id',
        message:
          `Virtual adapter id "${def.id}" must match ${ID_PATTERN} ` +
          '(lowercase, starts with alnum, length 2-64, hyphen/underscore allowed).',
      };
    }

    if (this.defs.has(def.id)) {
      return {
        ok: false,
        reason: 'duplicate-id',
        message: `A virtual adapter with id "${def.id}" already exists.`,
      };
    }

    if (!def.sources || def.sources.length === 0) {
      return {
        ok: false,
        reason: 'empty-sources',
        message: 'Virtual adapter must have at least one source.',
      };
    }

    for (const src of def.sources) {
      const tools = this.lookup(src.adapterId);
      if (tools === null) {
        return {
          ok: false,
          reason: 'unknown-source-adapter',
          message:
            `Source adapter "${src.adapterId}" not found in the live catalog. ` +
            'Verify the adapter is installed and not revoked.',
        };
      }
      const toolSet = new Set(tools);
      for (const t of src.toolNames) {
        if (!toolSet.has(t)) {
          return {
            ok: false,
            reason: 'unknown-source-tool',
            message:
              `Tool "${t}" is not exposed by source adapter "${src.adapterId}". ` +
              `That adapter exposes ${tools.length} tool(s).`,
          };
        }
      }
    }

    return { ok: true };
  }

  /**
   * Store a definition after validating it. Returns the validation
   * result; on `ok: false` the definition is NOT stored.
   */
  add(def: VirtualAdapterDefinition): VirtualValidationResult {
    const result = this.validate(def);
    if (!result.ok) return result;
    this.defs.set(def.id, def);
    return { ok: true };
  }

  /** Replace an existing definition. Validates as if for a new id. */
  update(def: VirtualAdapterDefinition): VirtualValidationResult {
    if (!this.defs.has(def.id)) {
      return {
        ok: false,
        reason: 'unknown-source-adapter', // closest match — caller asked to update something that does not exist
        message: `No virtual adapter with id "${def.id}" exists.`,
      };
    }
    // Temporarily remove so duplicate-id check passes for the same id.
    this.defs.delete(def.id);
    const result = this.validate(def);
    if (!result.ok) return result;
    this.defs.set(def.id, def);
    return { ok: true };
  }

  /** Remove a virtual adapter. Returns true if it existed. */
  remove(id: string): boolean {
    return this.defs.delete(id);
  }

  get(id: string): VirtualAdapterDefinition | undefined {
    return this.defs.get(id);
  }

  list(): VirtualAdapterDefinition[] {
    return [...this.defs.values()];
  }

  get size(): number {
    return this.defs.size;
  }

  /**
   * Resolve a (virtualAdapterId, toolName) pair to its underlying real
   * (adapterId, toolName). Returns null if no such mapping exists.
   * Federation layer uses this to dispatch a virtual-adapter tool call
   * to the actual adapter.
   *
   * Resolution semantics: scans `sources` in order; the first source
   * that exposes the tool wins. Definitions where two sources expose
   * the same tool name are valid (the operator may want a single
   * virtual tool name to fall through to whichever underlying adapter
   * is listed first), but the second source is shadowed.
   */
  resolveTool(
    virtualAdapterId: string,
    toolName: string,
  ): { adapterId: string; toolName: string } | null {
    const def = this.defs.get(virtualAdapterId);
    if (!def) return null;
    for (const src of def.sources) {
      if (src.toolNames.includes(toolName)) {
        return { adapterId: src.adapterId, toolName };
      }
    }
    return null;
  }

  /** Aggregate tool names exposed by a virtual adapter. Deduped. */
  toolsOf(virtualAdapterId: string): string[] {
    const def = this.defs.get(virtualAdapterId);
    if (!def) return [];
    const seen = new Set<string>();
    const out: string[] = [];
    for (const src of def.sources) {
      for (const t of src.toolNames) {
        if (!seen.has(t)) {
          seen.add(t);
          out.push(t);
        }
      }
    }
    return out;
  }
}

/**
 * Convenience: build a Map-backed lookup from an array of
 * `{ adapterId, toolNames }` pairs. Useful for tests and for
 * integrators with their own catalog representation.
 */
export function lookupFromMap(
  source: Array<{ adapterId: string; toolNames: string[] }>,
): AdapterToolLookup {
  const m = new Map(source.map((e) => [e.adapterId, e.toolNames]));
  return (id: string) => m.get(id) ?? null;
}
