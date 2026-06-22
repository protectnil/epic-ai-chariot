/**
 * @epicai/chariot — Streamable-HTTP Transport
 * Binds a per-request McpServer to a node:http server over the MCP
 * Streamable-HTTP protocol in stateless SDK mode (sessionIdGenerator:
 * undefined). A fresh McpServer + transport is constructed per /mcp
 * request to avoid the SDK's "Already connected to a transport"
 * exception that fires on the singleton-server-with-many-transports
 * pattern; concurrent requests no longer race on the shared server's
 * _transport binding.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createServer } from 'node:http';
import type { IncomingMessage, RequestListener, Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { TransportHandle } from '../TransportHandle.js';

/**
 * Verified per-request session derived from the bearer JWT. Carries the
 * RBAC claims (allowedOperations, userId) and tenant alongside the session
 * id so the per-request McpServer can enforce per-operation RBAC and
 * tenant isolation instead of falling back to a process-wide localMode
 * trust grant (bug-tracker-ref). `auth` mirrors CallContext.auth's shape.
 */
export interface ResolvedMcpSession {
  /** Stable per-request session id (JWT jti) for the LLM06 surface-state gate. */
  sessionId: string;
  /** Verified tenant from the token — per-request, never the process-env tenant on this path. */
  tenantId: string;
  /** RBAC grants carried by the verified session. */
  auth: { allowedOperations?: Record<string, string[]>; userId: string };
}

/**
 * Per-request McpServer factory. Called once per /mcp request with the
 * verified session (claims + tenant) in JWT mode, or `undefined` in the
 * legacy shared-bearer mode. In shared-bearer mode the shared secret IS the
 * trust boundary (single-tenant loopback), so the factory wires
 * `localMode:true` (RBAC bypass) with the process tenant — NOT anonymous
 * deny-by-default. Implementations MUST return a fresh McpServer with all
 * tools registered; the transport calls server.connect on it once, handles
 * the request, then closes the transport on response close.
 */
export type McpServerFactory = (session: ResolvedMcpSession | undefined) => McpServer;

/**
 * Async session resolver. The caller (typically setup.ts) wires this to
 * IAM verifyToken so /mcp inherits the same revocation + epoch + jti
 * checks the /enterprise/oauth/* routes enforce, and returns the verified
 * claims (not just the jti) so RBAC + tenant isolation can be enforced
 * per request. Return null on any failure (missing header, bad signature,
 * expired, revoked, idle); the transport will refuse the request with 401
 * when JWT mode is on.
 */
export type SessionIdResolver = (req: IncomingMessage) => Promise<ResolvedMcpSession | null>;

export interface BindHttpOptions {
  /** Build a fresh McpServer per request. */
  createMcpServer: McpServerFactory;
  /**
   * Optional non-MCP listener (Express app mounting the IAM router +
   * /health). When set, requests under /enterprise/,
   * /.well-known/oauth-authorization-server, and /health are delegated
   * to it before the MCP /mcp path runs.
   */
  iamApp?: RequestListener;
  /**
   * Resolve a per-request session id from the bearer JWT using the IAM
   * layer's full verifyToken (signature + tenant epoch + user epoch +
   * jti revocation + idle timeout). Pass undefined to disable JWT-based
   * session derivation (legacy shared-secret mode).
   */
  resolveSessionId?: SessionIdResolver;
}

/**
 * Bind chariot's MCP gateway to a node:http listener on `port`.
 *
 * Authentication posture (fail-closed at startup):
 *
 *   - JWT mode (`opts.resolveSessionId` set): every /mcp request MUST
 *     carry an `Authorization: Bearer <jwt>` that resolves to a non-null
 *     session id. Resolver-null → 401. The resolved jti becomes the
 *     session id for the LLM06 surface-state gate.
 *
 *   - Shared-bearer mode (`CHARIOT_HTTP_TOKEN` env set, no resolver):
 *     every request MUST present the shared bearer via Authorization;
 *     timing-safe compare. sessionId stays undefined in this mode —
 *     used only for single-tenant loopback deployments.
 *
 *   - Neither configured: throws on bind. /mcp must be authenticated.
 */
export async function bindHttp(port: number, opts: BindHttpOptions): Promise<TransportHandle> {
  const { StreamableHTTPServerTransport } = await import(
    '@modelcontextprotocol/sdk/server/streamableHttp.js'
  );

  const requiredToken = process.env.CHARIOT_HTTP_TOKEN;
  const hasJwtMode = typeof opts.resolveSessionId === 'function';
  if (!requiredToken && !hasJwtMode) {
    throw new Error(
      'bindHttp: refusing to bind /mcp with no authentication. ' +
      'Set ENTERPRISE_JWT_SECRET (enables ID-JAG verifyToken path via ' +
      'opts.resolveSessionId) or CHARIOT_HTTP_TOKEN (legacy shared bearer).',
    );
  }

  const httpServer: Server = createServer((req, res) => {
    void (async () => {
      const url = req.url ?? '';

      // Shared-bearer auth gate (legacy). When CHARIOT_HTTP_TOKEN is set
      // it runs FIRST and rejects any request without the exact bearer —
      // including IAM/OAuth surfaces. /.well-known/oauth-authorization-
      // server and /health are exempted so monitoring + RFC 8414 probes
      // can reach the listener without the operator-side shared bearer;
      // tokens are not minted on those paths so the bypass does not
      // weaken issuance posture. The carve-out is restricted to safe
      // methods (GET, HEAD, OPTIONS) and to exact path matches with
      // explicit `?`/`/` continuations so a request to a sibling URI
      // such as `/.well-known/oauth-authorization-server-foo` cannot
      // slip through.
      const method = (req.method ?? '').toUpperCase();
      const isSafeMethod = method === 'GET' || method === 'HEAD' || method === 'OPTIONS';
      const exactOrSubpath = (path: string): boolean =>
        url === path || url.startsWith(path + '?') || url.startsWith(path + '/');
      const isPublicProbe = isSafeMethod && (
        exactOrSubpath('/health') || exactOrSubpath('/.well-known/oauth-authorization-server')
      );
      const auth = req.headers['authorization'];
      const expected = requiredToken !== undefined ? `Bearer ${requiredToken}` : undefined;
      const sharedBearerMatches =
        expected !== undefined
        && typeof auth === 'string'
        && (() => {
          const a = Buffer.from(auth);
          const b = Buffer.from(expected);
          return a.length === b.length && timingSafeEqual(a, b);
        })();

      if (requiredToken && !isPublicProbe && url !== '/mcp' && !sharedBearerMatches) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }

      // Delegate IAM/OAuth surfaces to the Express app (if mounted) AFTER
      // the shared-bearer gate. RFC 8414 discovery probes hit
      // `/.well-known/oauth-authorization-server` and the token POST hits
      // `/enterprise/oauth/token`. Both share the listener with `/mcp` so a
      // single chariot serve --http process is the complete Resource AS.
      // Path matches use the same boundary-aware helper so a sibling URI
      // like `/.well-known/oauth-authorization-server-foo` does not get
      // delegated and silently buffered by the IAM body parser.
      if (opts.iamApp && (
        url === '/enterprise' || url.startsWith('/enterprise/') ||
        exactOrSubpath('/.well-known/oauth-authorization-server') ||
        exactOrSubpath('/health')
      )) {
        opts.iamApp(req, res);
        return;
      }

      if (url !== '/mcp') {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      // Resolve per-request session id from the JWT when JWT mode is on.
      // In dual-auth mode (/mcp with BOTH CHARIOT_HTTP_TOKEN and
      // ENTERPRISE_JWT_SECRET configured), a valid shared bearer is accepted
      // locally and skips the JWT resolver; otherwise /mcp falls through to
      // JWT verification. Non-/mcp paths remain shared-bearer only.
      let resolvedSession: ResolvedMcpSession | undefined;
      if (sharedBearerMatches) {
        resolvedSession = undefined;
      } else if (hasJwtMode) {
        try {
          const resolved = await opts.resolveSessionId!(req);
          if (resolved === null) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'invalid_token',
              error_description: '/mcp requires a verifiable Authorization: Bearer JWT',
            }));
            return;
          }
          resolvedSession = resolved;
        } catch {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'invalid_token',
            error_description: 'session-id resolution failed',
          }));
          return;
        }
      } else if (requiredToken) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Unauthorized',
          error_description: '/mcp requires the configured shared bearer',
        }));
        return;
      }

      // Per-request McpServer + transport. Avoids the SDK's
      // single-transport-per-server invariant on the singleton pattern.
      // The transport is closed on response close so the server's
      // _transport binding clears. The verified session (claims + tenant)
      // is threaded into the factory so the per-request server enforces
      // RBAC + tenant isolation; undefined in shared-bearer mode →
      // single-tenant loopback (the shared secret IS the trust boundary),
      // wired localMode:true with the process tenant — NOT anonymous
      // deny-by-default (bug-tracker-ref).
      const perRequestServer = opts.createMcpServer(resolvedSession);
      const perRequestTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => {
        void perRequestTransport.close();
      });
      try {
        await perRequestServer.connect(perRequestTransport);
        await perRequestTransport.handleRequest(req, res);
      } catch {
        if (!res.headersSent) {
          res.writeHead(500);
          res.end('Internal error');
        }
      }
    })();
  });

  // Defend against Slowloris-class attacks (slow-header, slow-body).
  httpServer.headersTimeout = 10_000;
  httpServer.requestTimeout = 30_000;
  httpServer.keepAliveTimeout = 5_000;

  const boundPort = await new Promise<number>((resolve, reject) => {
    httpServer.listen(port, () => {
      const addr = httpServer.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      } else {
        reject(new Error('bindHttp: could not determine bound port'));
      }
    });
    httpServer.on('error', reject);
  });

  return {
    port: boundPort,
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          resolve(); // drain timeout — proceed with exit after 5 s
        }, 5000);
        httpServer.close((err) => {
          clearTimeout(timeout);
          if (err) reject(err); else resolve();
        });
      });
    },
  };
}
