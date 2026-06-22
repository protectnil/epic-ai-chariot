/**
 * Virtual adapter construct — types
 *
 * A VirtualAdapter is a synthetic catalog entry that exposes a
 * curated subset of tools drawn from one or more real adapters.
 * Use case: an enterprise admin wants the "Support Engineer" role
 * to see only `read_*` tools across Datadog, PagerDuty, and Jira —
 * not the full surface of any of them, and not as three separate
 * adapter selections in the routing UI.
 *
 * The virtual adapter appears to the routing layer as a normal
 * AdapterCatalogEntry. RBAC + the orchestrator do not need to know
 * it is composed; only the federation call layer needs to dispatch
 * tool invocations back to the underlying real adapter.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** A subset of tools from one underlying real adapter. */
export interface VirtualSource {
  /** The real adapter's slug (matches AdapterCatalogEntry.id or .name). */
  adapterId: string;
  /**
   * Tool names exposed from this source. Must be present in the source
   * adapter's `toolNames`. Empty list means "expose nothing from this
   * source" — useful when toggling a source on/off without removing it.
   */
  toolNames: string[];
}

export interface VirtualAdapterDefinition {
  /** Synthetic adapter id, distinct from any real adapter id. */
  id: string;
  /** Human-readable label for the routing UI / catalog listing. */
  displayName: string;
  /** Optional category tag used by the classifier; defaults to 'misc'. */
  category?: string;
  /** Optional description shown in admin UI. */
  description?: string;
  /** One or more underlying real adapters and the tools to expose from each. */
  sources: VirtualSource[];
}

/** Outcome of validating a definition against the real catalog. */
export type VirtualValidationResult =
  | { ok: true }
  | {
      ok: false;
      /** Stable reason code for callers to switch on. */
      reason:
        | 'duplicate-id'
        | 'unknown-source-adapter'
        | 'unknown-source-tool'
        | 'empty-sources'
        | 'invalid-id';
      /** Human-readable detail; safe to surface in admin UI. */
      message: string;
    };

/**
 * Lookup contract for the validator. Returns null when the adapter is
 * unknown. Returns the list of tool names (lowercased canonical) when
 * known. Implementations: a real catalog bridge in production; a
 * Map-backed stub in tests.
 */
export type AdapterToolLookup = (adapterId: string) => string[] | null;
