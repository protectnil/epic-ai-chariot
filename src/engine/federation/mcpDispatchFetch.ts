/**
 * @epicai/chariot — MCP streamable-HTTP dispatch fetch (standalone-SSE suppression)
 *
 * CHARIOT §1.4: the MCP SDK's StreamableHTTPClientTransport, after the
 * `notifications/initialized` POST is accepted (202), opens a *standalone* long-
 * lived GET Server-Sent-Events stream to listen for server-initiated messages
 * (StreamableHTTPClientTransport._startOrAuthSse). That stream never closes for
 * the lifetime of the client.
 *
 * Chariot dispatch is strictly request/response: connect → callTool → close. It
 * registers no notification/request handlers and consumes nothing the server
 * pushes over the standalone GET stream, so that stream is pure liability. On
 * some remote MCP hosts (e.g. the curated open-data host mcp.olyport.com that
 * serves `pubmed`) the never-closing GET stream starves the subsequent
 * `tools/list` / `tools/call` POST on the same connection pool — the POST never
 * receives a response and the dispatch hangs until the 30s DISPATCH_TIMEOUT,
 * returning nothing. A direct request/response POST to the same endpoint answers
 * in <100ms, so the failure is entirely the standalone listening stream.
 *
 * Fix: hand the transport a fetch that answers the standalone GET with a
 * synthetic `405 Method Not Allowed`. The SDK treats a 405 on the GET as the
 * documented "server does not offer an SSE stream at the GET endpoint" case and
 * continues without opening the stream (streamableHttp.js _startOrAuthSse). Every
 * POST — initialize, notifications/initialized, tools/list, tools/call, and any
 * POST whose *response* is itself an SSE stream — is delegated untouched, so
 * per-request streaming responses are unaffected. Only the standalone server→
 * client listening stream is suppressed.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** The fetch shape the MCP SDK's transport `fetch` option expects. */
export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/**
 * Build a fetch for StreamableHTTPClientTransport that suppresses the SDK's
 * standalone GET SSE listening stream while delegating every other
 * request — all POSTs, including POST responses that stream via SSE — to
 * `baseFetch` (default: the global `fetch`).
 */
export function createMcpDispatchFetch(baseFetch: FetchLike = fetch): FetchLike {
  return (input, init) => {
    // The SDK sets method:'POST' explicitly for every JSON-RPC send; the ONLY
    // GET it issues is the standalone SSE listening stream in _startOrAuthSse.
    // A missing method defaults to GET per the fetch spec, so treat that as the
    // standalone stream too.
    const method = (init?.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (method === 'GET') {
      // 405 => SDK's _startOrAuthSse treats this as "no standalone SSE stream"
      // and returns without opening it. Null body is safe for the SDK's
      // `response.body?.cancel()` guard.
      return Promise.resolve(new Response(null, { status: 405, statusText: 'Method Not Allowed' }));
    }
    return baseFetch(input, init);
  };
}
