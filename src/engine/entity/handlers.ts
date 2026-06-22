/**
 * @epicai/chariot — Entity Resolution Tool Handlers
 * Handler implementations for chariot_resolve_entity, chariot_compare_entities,
 * chariot_entity_profile.  Mirrors the structure of toolHandlers.ts so both the
 * MCP path (registerChariotTools) and the REST path can invoke them uniformly.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ChariotState } from '../server/ChariotState.js';
import { EntityResolver } from './EntityResolver.js';
import { estimateResponseTokens } from '../server/toolHandlers.js';
import type { CallContext } from '../server/toolHandlers.js';

// =============================================================================
// Arg shapes
// =============================================================================

export interface ResolveEntityArgs {
  /** The entity identifier or search string to resolve. */
  entity: string;
  /**
   * Optional explicit adapter list. When omitted the resolver fans out
   * across all adapters in the catalog (capped at 12 by default).
   */
  adapterIds?: string[];
  /**
   * Maximum number of adapters to probe in parallel.
   * Defaults to 12. Raise only when a broader sweep is needed.
   */
  maxAdapters?: number;
}

export interface CompareEntitiesArgs {
  /** First entity. */
  entityA: string;
  /** Second entity. */
  entityB: string;
  /** Optional adapter scope — same semantics as ResolveEntityArgs.adapterIds. */
  adapterIds?: string[];
  maxAdapters?: number;
}

export interface EntityProfileArgs {
  /** Entity identifier to profile. */
  entity: string;
  adapterIds?: string[];
  maxAdapters?: number;
}

// =============================================================================
// Result envelope
// =============================================================================

export interface EntityHandlerResult {
  content: string;
  isError: boolean;
  estimatedTokenCost?: number;
}

// =============================================================================
// Handlers
// =============================================================================

/**
 * chariot_resolve_entity — fan-out entity resolution across the adapter catalog.
 *
 * Queries every adapter that exposes a search/lookup tool, aggregates the
 * evidence, and returns a canonical record with source attribution.
 *
 * SECURITY: `ctx` (caller tenantId/auth/localMode) is threaded into the
 * resolver so every fan-out adapter call is RBAC- and tenant-checked.
 */
export async function handleResolveEntity(
  args: ResolveEntityArgs,
  state: ChariotState,
  ctx?: CallContext,
): Promise<EntityHandlerResult> {
  try {
    const resolver = new EntityResolver(state);
    const result = await resolver.resolve(args.entity, {
      adapterIds: args.adapterIds,
      maxAdapters: args.maxAdapters,
    }, ctx);
    const content = JSON.stringify(result);
    return {
      content,
      isError: false,
      estimatedTokenCost: estimateResponseTokens(result),
    };
  } catch (err) {
    const content = JSON.stringify({
      error: 'Entity resolution failed',
      message: err instanceof Error ? err.message : String(err),
      entity: args.entity,
    });
    return {
      content,
      isError: true,
      estimatedTokenCost: estimateResponseTokens(content),
    };
  }
}

/**
 * chariot_compare_entities — structural comparison of two entities.
 *
 * Resolves each entity independently then diffs their aggregated attribute
 * bags.  Returns a 0.0–1.0 similarity score and a per-field diff list.
 */
export async function handleCompareEntities(
  args: CompareEntitiesArgs,
  state: ChariotState,
  ctx?: CallContext,
): Promise<EntityHandlerResult> {
  try {
    const resolver = new EntityResolver(state);
    const result = await resolver.compare(args.entityA, args.entityB, {
      adapterIds: args.adapterIds,
      maxAdapters: args.maxAdapters,
    }, ctx);
    const content = JSON.stringify(result);
    return {
      content,
      isError: false,
      estimatedTokenCost: estimateResponseTokens(result),
    };
  } catch (err) {
    const content = JSON.stringify({
      error: 'Entity comparison failed',
      message: err instanceof Error ? err.message : String(err),
      entityA: args.entityA,
      entityB: args.entityB,
    });
    return {
      content,
      isError: true,
      estimatedTokenCost: estimateResponseTokens(content),
    };
  }
}

/**
 * chariot_entity_profile — build a structured profile for an entity.
 *
 * Aggregates all adapter-level data for the entity into a flat attribute
 * bag, infers entity type, and returns per-adapter raw data alongside
 * the flattened summary.
 */
export async function handleEntityProfile(
  args: EntityProfileArgs,
  state: ChariotState,
  ctx?: CallContext,
): Promise<EntityHandlerResult> {
  try {
    const resolver = new EntityResolver(state);
    const result = await resolver.profile(args.entity, {
      adapterIds: args.adapterIds,
      maxAdapters: args.maxAdapters,
    }, ctx);
    const content = JSON.stringify(result);
    return {
      content,
      isError: false,
      estimatedTokenCost: estimateResponseTokens(result),
    };
  } catch (err) {
    const content = JSON.stringify({
      error: 'Entity profile failed',
      message: err instanceof Error ? err.message : String(err),
      entity: args.entity,
    });
    return {
      content,
      isError: true,
      estimatedTokenCost: estimateResponseTokens(content),
    };
  }
}
