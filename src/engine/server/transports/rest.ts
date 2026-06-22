/**
 * @epicai/chariot — REST JSON API Transport
 * Plain node:http server exposing chariot_query, chariot_call, chariot_list,
 * and chariot_validate_claim as REST endpoints. Returns raw JSON — no MCP framing.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createServer } from 'node:http';
import type { Server, IncomingMessage, ServerResponse } from 'node:http';
import type { ChariotState } from '../ChariotState.js';
import type { TransportHandle } from '../TransportHandle.js';
import { handleQuery, handleCall, handleList, handleValidateClaim, DEFAULT_CALLS_PER_MINUTE } from '../toolHandlers.js';
import type { CallContext } from '../toolHandlers.js';
import type { EnterpriseSessionPayload } from '../../../iam/types.js';

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
function callContextFromRequest(req: AuthAwareRequest, fallbackTenantId: string): CallContext {
  const auth = req.enterpriseUser;
  const tenantId = req.tenantId ?? auth?.tenantId ?? fallbackTenantId;
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
  };
}

// =============================================================================
// Internal helpers
// =============================================================================

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', () => resolve(body));
    req.on('error', reject);
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
 */
export async function bindRest(
  state: ChariotState,
  port: number,
  getTenantId: () => string,
): Promise<TransportHandle> {
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

  const httpServer: Server = createServer((req, res) => {
    void (async () => {
    // Auth check
    if (requiredToken) {
      const auth = req.headers['authorization'];
      if (auth !== `Bearer ${requiredToken}`) {
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
    } catch {
      send(res, 400, { error: 'Failed to read request body' });
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
        const result = await handleQuery({
          query: body['query'] as string,
          detail: body['detail'] as 'full' | 'summary' | undefined,
          discover: body['discover'] as boolean | undefined,
        }, state);
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
  });

 // Defend against Slowloris-class attacks (slow-header, slow-body).
  // headersTimeout: abort if the full request headers are not received within 10 s.
  // requestTimeout: abort if the full request (headers + body) is not complete within 30 s.
  // keepAliveTimeout: release idle keep-alive connections after 5 s (below typical LB idle timeouts).
  httpServer.headersTimeout = 10_000;
  httpServer.requestTimeout = 30_000;
  httpServer.keepAliveTimeout = 5_000;

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
