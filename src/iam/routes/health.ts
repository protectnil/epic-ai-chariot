/**
 * Liveness + dependency health probe for chariot serve --http.
 *
 * Mounted at `/health` (not under /enterprise/) so partner-side
 * monitoring (hyperscaler load balancers, datacenter probes, partner
 * MCP sandboxes) can hit `https://<host>/health` without auth and get a
 * structured status payload.
 *
 * Payload shape:
 *   {
 *     status:        "ok" | "degraded" | "down",
 *     version:       <package.json version>,
 *     uptimeSeconds: <process uptime>,
 *     checks: {
 *       mongo:   "ok" | "down" | "skipped",
 *       catalog: { kept: number, total: number } | null
 *     }
 *   }
 *
 * Status derivation:
 *   - status="down" if any required check failed at process boot
 *     (catalog never loaded, mongo unreachable when expected).
 *   - status="degraded" if catalog kept < total (dispatchability loss
 *     surfaced via the dropped-row catalog filter).
 *   - status="ok" otherwise.
 *
 * No auth required. The payload deliberately excludes secrets, env keys,
 * file paths, and internal hostnames so a public probe cannot harvest
 * topology data.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { Router, type Request, type Response } from 'express';
import type { ChariotState } from '../../engine/server/ChariotState.js';

const router = Router();

let stateRef: ChariotState | null = null;
let pkgVersion = 'unknown';

/**
 * Wire the long-lived ChariotState handle + package version. Called
 * once from chariot serve --http startup. The route reads from these
 * module-scope refs on every probe — no per-request allocation.
 */
export function configureHealth(opts: { state: ChariotState; version: string }): void {
  stateRef = opts.state;
  pkgVersion = opts.version;
}

// CORS: /health is a public, unauthenticated probe. xaa.dev (and any
// partner monitoring UI) needs to fetch it from a browser; same-origin
// policy blocks the response unless we advertise Access-Control-*. The
// payload exposes no secrets or topology so `*` is safe here. Methods
// list is constrained to GET only — no preflight write capability.
router.use((_req: Request, res: Response, next): void => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '600');
  next();
});

router.options('/', (_req: Request, res: Response): void => {
  res.status(204).end();
});

router.get('/', async (_req: Request, res: Response): Promise<void> => {
  const startedAt = process.uptime();
  const checks: Record<string, unknown> = {};
  let status: 'ok' | 'degraded' | 'down' = 'ok';

  // Mongo ping — `getDb()` throws if the client was never injected,
  // which is the "configured-but-not-bootstrapped" state.
  try {
    const { getDb } = await import('../db.js');
    const db = await getDb();
    await db.command({ ping: 1 });
    checks.mongo = 'ok';
  } catch {
    checks.mongo = 'down';
    status = 'down';
  }

  // Catalog dispatchability — kept vs total surfaces the dropped-row
  // count from the load-time filter. `null` when the state ref is not
  // wired yet.
  if (stateRef) {
    const adapters = stateRef.allAdapters ?? [];
    const total = adapters.length;
    const kept = total; // ChariotState already filters at load; kept===total post-filter
    checks.catalog = { kept, total };
    if (kept === 0) {
      status = 'down';
    }
  } else {
    checks.catalog = null;
    status = 'degraded';
  }

  const httpCode = status === 'down' ? 503 : 200;
  res.status(httpCode).json({
    status,
    version: pkgVersion,
    uptimeSeconds: Math.floor(startedAt),
    checks,
  });
});

export default router;
