/**
 * @epicai/chariot — Correlator
 * Cross-source entity and event correlation across federated MCP servers.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type {
  CorrelationQuery,
  CorrelationResult,
  CorrelatedEntity,
  CorrelatedEvent,
  Tool,
  ToolResult,
} from '../types/index.js';

/**
 * Gated dispatch callback. FederationManager binds this to its own
 * `callTool`, so every Correlator invocation passes the full federation
 * gate stack: revocation re-check, input-schema validation, per-tool
 * approval, unload (beginCall/endCall) accounting, and egress policy.
 *
 * The Correlator MUST NOT hold raw adapter references — dispatching on a
 * raw adapter would bypass every one of those gates (the original
 * zero-day: revoked adapters still in the adapter map remained callable,
 * and no egress/approval evaluation ran on correlate() fan-out).
 */
export type CorrelatorDispatch = (
  toolName: string,
  args: Record<string, unknown>,
) => Promise<ToolResult>;

/**
 * One federated server visible to the Correlator: its name plus its
 * registry-namespaced tools (i.e. tool.name is `<server>:<tool>` so it can
 * be handed straight to the gated dispatch callback).
 */
export interface CorrelatorServer {
  name: string;
  tools: Tool[];
}

export class Correlator {
  /**
   * Correlate entities and events across multiple MCP servers.
   *
   * Fans out queries to each server's read-only search/query tool via the
   * gated dispatch callback, then joins results by entity ID to build a
   * unified timeline.
   */
  async correlate(
    query: CorrelationQuery,
    servers: ReadonlyArray<CorrelatorServer>,
    dispatch: CorrelatorDispatch,
  ): Promise<CorrelationResult> {
    const entities = new Map<string, CorrelatedEntity>();
    const timeline: CorrelatedEvent[] = [];
    const serversCovered: string[] = [];

    // Determine which servers to query
    const targetServers = query.servers
      ? servers.filter(s => (query.servers as string[]).includes(s.name))
      : [...servers];

    // Fan out queries to all target servers in parallel
    const queryPromises = targetServers.map(async ({ name: serverName, tools }) => {
      // Security boundary: the Correlator auto-executes a tool with
      // synthesized args, so it may ONLY select tools the adapter has
      // verifiably declared read-only via the MCP annotation
      // `readOnlyHint === true`. Name-substring heuristics are forbidden
      // here — they match destructive tools (`delete_by_query` contains
      // "query", `forget` contains "get") and let the adapter choose
      // which tool auto-executes. FAIL-CLOSED: when no tool carries a
      // verified read-only annotation, the server is skipped entirely.
      const searchTool = tools.find(t => t.annotations?.readOnlyHint === true);

      if (!searchTool) return { serverName, results: [] as ToolResult[] };

      // Query each entity on this server through the gated dispatch path
      // (revocation, schema validation, approval, unload, egress).
      const entityResults: ToolResult[] = [];
      for (const entityId of query.entities) {
        try {
          const result = await dispatch(searchTool.name, {
            query: entityId,
            timeRange: {
              start: query.timeRange.start.toISOString(),
              end: query.timeRange.end.toISOString(),
            },
          });
          entityResults.push(result);
        } catch {
          // Server doesn't have data for this entity (or the gate refused
          // dispatch by throwing). Gate refusals surfaced as isError
          // ToolResults are filtered below; thrown errors mean "no data
          // from this server for this entity" and are recorded as a miss.
        }
      }

      return { serverName, results: entityResults };
    });

    const serverResults = await Promise.allSettled(queryPromises);

    for (const settled of serverResults) {
      if (settled.status !== 'fulfilled') continue;
      const { serverName, results } = settled.value;
      if (results.length === 0) continue;

      serversCovered.push(serverName);

      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result.isError) continue;

        const entityId = query.entities[i];
        if (!entityId) continue;

        // Build entity correlation
        const existing = entities.get(entityId) ?? { id: entityId, sources: [] };
        existing.sources.push({
          server: serverName,
          data: typeof result.content === 'object' && result.content !== null
            ? result.content as Record<string, unknown>
            : { raw: result.content },
        });
        entities.set(entityId, existing);

        // Build timeline event
        timeline.push({
          timestamp: new Date(),
          server: serverName,
          tool: result.tool,
          entity: entityId,
          data: typeof result.content === 'object' && result.content !== null
            ? result.content as Record<string, unknown>
            : { raw: result.content },
        });
      }
    }

    // Sort timeline by timestamp
    timeline.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    return { entities, timeline, serversCovered };
  }
}
