/**
 * @epicai/chariot — REST JSON API Transport
 * Plain node:http server exposing chariot_query, chariot_call, chariot_list,
 * and chariot_validate_claim as REST endpoints. Returns raw JSON — no MCP framing.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { IncomingMessage, ServerResponse, Server as HttpServer } from 'node:http';
import type { Server as HttpsServer } from 'node:https';
import { timingSafeEqual } from 'node:crypto';
import type { ChariotState } from '../ChariotState.js';
import type { TransportHandle } from '../TransportHandle.js';
import { handleQuery, handleCall, handleList, handleValidateClaim, DEFAULT_CALLS_PER_MINUTE } from '../toolHandlers.js';
import type { CallContext } from '../toolHandlers.js';
import type { EnterpriseSessionPayload } from '../../../iam/types.js';
import { createHttpServer, applySlowlorisGuards } from './tlsServer.js';
import type { TlsConfig } from './tlsServer.js';
import { MAX_REQUEST_BYTES } from './http.js';
// CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)/105) — the
// same GET /metrics (Prometheus format) surface src/engine/bin/setup.ts
// mounts on the Express-based `iamApp` for enterprise deployments, ALSO
// served here on the plain node:http REST transport so a non-enterprise
// (single-user) install with the exporter flag set still has the
// endpoint — REST binds independently of `enterpriseRequested`.
import {
  isPrometheusExporterEnabled,
  assertPrometheusExporterConfigValid,
  formatPrometheusMetrics,
} from '../../../observability/prometheusRoute.js';

/**
 * Express-augmented IncomingMessage shape — when the REST transport is
 * mounted behind `enterpriseAuthMiddleware()` (multi-tenant deployments)
 * it sets `req.enterpriseUser` and `req.tenantId`. Plain stand-alone REST
 * (single-user box) has neither.
 */
interface AuthAwareRequest extends IncomingMessage {
  enterpriseUser?: EnterpriseSessionPayload & { jti?: string };
  tenantId?: string;
  /** License-tier-derived rate limit override, if known. */
  callsPerMinute?: number;
}

/**
 * / / wiring on REST:
 *
 * Build the CallContext that handleCall requires. If the request carries
 * an authenticated enterprise session (from upstream middleware), the
 * RBAC grants on that session are forwarded; otherwise the context is
 * anonymous (NOT localMode) and handleCall denies by default.
 *
 * The previous code passed no context at all, which silently bypassed
 * RBAC, per-operation enforcement, and tool-name validation on every
 * REST call. This function closes that hole.
 */
/**
 * Single resolution order for the per-request tenant, shared by the
 * chariot_call context builder AND the chariot_query path so the two
 * cannot drift: verified middleware tenant → enterprise session tenant →
 * process fallback. Dropping this on the query path previously served
 * the PROCESS tenant's configured-adapter inventory (and shared one
 * context-budget bucket) to every authenticated tenant.
 */
function tenantIdFromRequest(req: AuthAwareRequest, fallbackTenantId: string): string {
  return req.tenantId ?? req.enterpriseUser?.tenantId ?? fallbackTenantId;
}

function callContextFromRequest(req: AuthAwareRequest, fallbackTenantId: string): CallContext {
  const auth = req.enterpriseUser;
  const tenantId = tenantIdFromRequest(req, fallbackTenantId);
  return {
    tenantId,
    auth: auth ? { allowedOperations: auth.allowedOperations, userId: auth.userId } : undefined,
    callsPerMinute: req.callsPerMinute ?? DEFAULT_CALLS_PER_MINUTE,
    // REST is NEVER localMode. Even single-user REST (no auth wired) is
    // process-boundary-crossing; trust must be expressed by an explicit
    // authenticated session, not by absence of one.
    localMode: false,
    // draft-04 §4.3 — thread the session jti so MCP-dispatch can read
    // the stored subject_token and call exchangeForIdJag(). The
    // enterpriseAuthMiddleware attaches `jti` to req.enterpriseUser
    // (declared in iam/middleware.ts global Express augmentation).
    ...(auth?.jti !== undefined ? { sessionJti: auth.jti } : {}),
    // Audit attribution: client IP from the request socket
    // so the serve-path ActionRecord (recordDispatch) carries sourceIp.
    // req.socket.remoteAddress is undefined only if the socket has already
    // been destroyed — never fabricated.
    ...(req.socket.remoteAddress !== undefined ? { sourceIp: req.socket.remoteAddress } : {}),
  };
}

// =============================================================================
// Internal helpers
// =============================================================================

/**
 * Raised by readBody when the request body exceeds MAX_REQUEST_BYTES so the
 * caller can answer HTTP 413 instead of buffering an unbounded payload
 * (CHARIOT §22.1).
 */
class PayloadTooLargeError extends Error {}

/**
 * Read the request body into a string, aborting as soon as the byte count
 * exceeds `cap`. Rejects with PayloadTooLargeError on overflow (caller
 * answers 413); the stream is paused so TCP backpressure stalls the sender.
 * A declared Content-Length over the cap is rejected before any body read.
 */
function readBody(req: IncomingMessage, cap: number = MAX_REQUEST_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > cap) {
      req.pause();
      reject(new PayloadTooLargeError());
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    req.on('data', (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > cap) {
        settled = true;
        req.pause();
        reject(new PayloadTooLargeError());
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!settled) {
        settled = true;
        resolve(Buffer.concat(chunks).toString('utf8'));
      }
    });
    req.on('error', (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
  });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

// =============================================================================
// bindRest
// =============================================================================

/**
 * Bind a plain REST JSON API.
 *
 * Auth: if CHARIOT_REST_TOKEN is set, every request must carry
 * `Authorization: Bearer <token>`. Separate from CHARIOT_HTTP_TOKEN so
 * the two transports can have different tokens when run simultaneously.
 *
 * Tool-layer errors (isError:true) are returned with HTTP 200.
 * HTTP 4xx/5xx indicates transport-level failure (bad request, auth, crash).
 *
 * Response shape: raw JSON — NOT wrapped in MCP content envelope.
 *
 * @param state        Shared ChariotState.
 * @param port         TCP port. Pass 0 for a random available port.
 * @param getTenantId  Process-lifetime constant; never from request body.
 * @param tlsConfig    Optional TLS/mTLS config. Absent (default): plain
 *                     node:http, unchanged from pre-mTLS behavior. See
 *                     tlsServer.ts for the cert/key/ca semantics.
 */
export async function bindRest(
  state: ChariotState,
  port: number,
  getTenantId: () => string,
  tlsConfig?: TlsConfig,
): Promise<TransportHandle> {
  // CHARIOT::§16.3 (rulings item 91(3)/105) — fail-fast here (not only in
  // setup.ts's enterprise-bootstrap branch) so a non-enterprise,
  // REST-only install that sets CHARIOT_PROMETHEUS_EXPORTER=1 without
  // CHARIOT_METRICS_TOKEN is refused too, regardless of caller.
  assertPrometheusExporterConfigValid();

  const requiredToken = process.env.CHARIOT_REST_TOKEN;

  // refuse to start REST when no authentication is configured
  // and no explicit opt-in has been granted. The plain node:http server
  // does not run an Express middleware chain, so there is no place for
  // enterpriseAuthMiddleware / licenseGateMiddleware to attach. Without
  // CHARIOT_REST_TOKEN, every tool call lands with auth=undefined, the
  // CallContext degrades to anonymous-not-localMode, and the operator is
  // relying on toolHandlers' default RBAC deny to be the only barrier
  // between the open port and the customer's adapter credentials. The
  // explicit opt-in CHARIOT_ALLOW_UNAUTHENTICATED_REST=true preserves
  // the local-development workflow but forces operators to acknowledge
  // the trust posture deliberately.
  const allowUnauth = process.env.CHARIOT_ALLOW_UNAUTHENTICATED_REST === 'true';
  if (!requiredToken && !allowUnauth) {
    throw new Error(
      'Refusing to bind REST transport: CHARIOT_REST_TOKEN is not set ' +
      'and CHARIOT_ALLOW_UNAUTHENTICATED_REST is not "true". Set ' +
      'CHARIOT_REST_TOKEN to a strong secret for production deployments, ' +
      'or set CHARIOT_ALLOW_UNAUTHENTICATED_REST=true to explicitly ' +
      'accept the unauthenticated-loopback risk for local development.',
    );
  }

  const httpServer: HttpServer | HttpsServer = createHttpServer((req, res) => {
    void (async () => {
    // CHARIOT::§16.3 (CHARIOT-SPEC.md:1375, rulings item 91(3)/105) — GET
    // /metrics, gated on its OWN CHARIOT_METRICS_TOKEN bearer token (NOT
    // CHARIOT_REST_TOKEN below — a Prometheus scraper carries the metrics
    // token, not the REST API token), and only when the exporter flag is
    // set. Checked BEFORE the general REST bearer-token gate below so
    // this route's auth is fully independent of REST's own token
    // (mirrors prometheusRoute.ts's Express router for the enterprise
    // path — same token env var, same 401/503 semantics).
    if (req.method === 'GET' && req.url === '/metrics') {
      if (!isPrometheusExporterEnabled()) {
        send(res, 404, { error: 'Not found' });
        return;
      }
      const metricsToken = process.env.CHARIOT_METRICS_TOKEN;
      if (!metricsToken) {
        res.statusCode = 503;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('metrics exporter misconfigured: no token\n');
        return;
      }
      const authHeader = req.headers['authorization'];
      const expectedAuth = `Bearer ${metricsToken}`;
      const authorized =
        typeof authHeader === 'string'
        && (() => {
          const a = Buffer.from(authHeader);
          const b = Buffer.from(expectedAuth);
          return a.length === b.length && timingSafeEqual(a, b);
        })();
      if (!authorized) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('unauthorized\n');
        return;
      }
      if (!state.chariotMetrics) {
        res.statusCode = 503;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end('metrics not available\n');
        return;
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.end(formatPrometheusMetrics(state.chariotMetrics.getSummary()));
      return;
    }

    // Auth check. Constant-time bearer comparison (CHARIOT §10.1):
    // mirrors the HTTP transport's crypto.timingSafeEqual pattern so the
    // shared REST token cannot be recovered byte-by-byte via response timing.
    // The length guard short-circuits before timingSafeEqual (which throws on
    // unequal-length buffers) without comparing bytes on a length mismatch.
    if (requiredToken) {
      const auth = req.headers['authorization'];
      const expected = `Bearer ${requiredToken}`;
      const bearerMatches =
        typeof auth === 'string'
        && (() => {
          const a = Buffer.from(auth);
          const b = Buffer.from(expected);
          return a.length === b.length && timingSafeEqual(a, b);
        })();
      if (!bearerMatches) {
        send(res, 401, { error: 'Unauthorized' });
        return;
      }
    }

    // GET /v1/health
    if (req.method === 'GET' && req.url === '/v1/health') {
      const { createRequire } = await import('node:module');
      const { fileURLToPath } = await import('node:url');
      const require = createRequire(fileURLToPath(import.meta.url));
      const pkg = require('../../../../package.json') as { version: string };
      send(res, 200, { status: 'ok', version: pkg.version, transport: 'rest' });
      return;
    }

    // GET /v1/catalog/stats
    if (req.method === 'GET' && req.url === '/v1/catalog/stats') {
      send(res, 200, {
        totalAdapters: state.allAdapters.length,
        configuredAdapters: state.configuredAdapterIds.size,
        loadedAt: state.loadedAt,
        // Effective Tier-1 retrieval mode ('hybrid' | 'bm25-only') so a
        // certification run can assert the four-signal stack is actually
        // live instead of trusting the build label (§4.3/§4.4).
        retrievalMode: state.retrievalMode,
        // Wiz practice 7 (feed #23): percentage of loaded adapters whose
        // catalog-publication verification passed. null when the metrics
        // feed hasn't run (e.g. a synthetic ChariotState in tests).
        supplyChainIntegrityPercent: state.chariotMetrics?.getSupplyChainIntegrityPercent() ?? null,
      });
      return;
    }

    // Only POST for tool endpoints
    if (req.method !== 'POST') {
      send(res, 404, { error: 'Not found' });
      return;
    }

    let bodyStr: string;
    try {
      bodyStr = await readBody(req);
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        send(res, 413, { error: `Request body exceeds ${MAX_REQUEST_BYTES}-byte limit` });
      } else {
        send(res, 400, { error: 'Failed to read request body' });
      }
      return;
    }

    let body: Record<string, unknown>;
    try {
      body = JSON.parse(bodyStr) as Record<string, unknown>;
    } catch {
      send(res, 400, { error: 'Invalid JSON body' });
      return;
    }

    // Tenant identity is always process-configured — never from body
    void getTenantId();

    try {
      if (req.url === '/v1/tools/query') {
        if (typeof body['query'] !== 'string') {
          send(res, 400, { error: 'query field (string) is required' });
          return;
        }
        // Thread the caller's verified tenant into the query context —
        // handleQueryImpl keys getConfiguredAdapters() and the per-tenant
        // context-budget meter off it (tenant-isolation seam, see the
        // QueryContext doc in toolHandlers.ts).
        const result = await handleQuery({
          query: body['query'] as string,
          detail: body['detail'] as 'full' | 'summary' | undefined,
          discover: body['discover'] as boolean | undefined,
        }, state, { tenantId: tenantIdFromRequest(req as AuthAwareRequest, getTenantId()) });
        send(res, 200, result);
        return;
      }

      if (req.url === '/v1/tools/call') {
        if (typeof body['adapter'] !== 'string' || typeof body['tool'] !== 'string') {
          send(res, 400, { error: 'adapter (string) and tool (string) fields are required' });
          return;
        }
        const result = await handleCall({
          adapter: body['adapter'] as string,
          tool: body['tool'] as string,
          args: body['args'] as Record<string, unknown> | undefined,
        }, state, callContextFromRequest(req as AuthAwareRequest, getTenantId()));
        send(res, 200, result);
        return;
      }

      if (req.url === '/v1/tools/list') {
        const result = await handleList({
          category: body['category'] as string | undefined,
          search: body['search'] as string | undefined,
        }, state);
        send(res, 200, result);
        return;
      }

      if (req.url === '/v1/tools/validate_claim') {
        if (typeof body['claim'] !== 'string') {
          send(res, 400, { error: 'claim field (string) is required' });
          return;
        }
        const result = await handleValidateClaim({
          claim: body['claim'] as string,
          evidence: typeof body['evidence'] === 'string' ? body['evidence'] as string : '',
        }, state, callContextFromRequest(req as AuthAwareRequest, getTenantId()));
        send(res, 200, result);
        return;
      }

      send(res, 404, { error: 'Not found' });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      send(res, 500, { error: msg });
    }
    })();
  }, tlsConfig);

 // Defend against Slowloris-class attacks (slow-header, slow-body).
  // headersTimeout: abort if the full request headers are not received within 10 s.
  // requestTimeout: abort if the full request (headers + body) is not complete within 30 s.
  // keepAliveTimeout: release idle keep-alive connections after 5 s (below typical LB idle timeouts).
  applySlowlorisGuards(httpServer);

  const boundPort = await new Promise<number>((resolve, reject) => {
    httpServer.listen(port, () => {
      const addr = httpServer.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      } else {
        reject(new Error('bindRest: could not determine bound port'));
      }
    });
    httpServer.on('error', reject);
  });

  return {
    port: boundPort,
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          resolve(); // drain timeout
        }, 5000);
        httpServer.close((err) => {
          clearTimeout(timeout);
          if (err) reject(err); else resolve();
        });
      });
    },
  };
}
