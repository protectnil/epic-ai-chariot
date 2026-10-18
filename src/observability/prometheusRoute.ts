/**
 * CHARIOT::§16.3 Metrics aggregator — the `GET /metrics` Prometheus surface
 * (CHARIOT-SPEC.md:1375, rulings item 91(3)).
 *
 * Quoted governing bytes (CHARIOT-SPEC.md:1375):
 *   "Surfaced via `GET /enterprise/{tenantId}/admin/metrics` (JSON) and
 *    `GET /metrics` (Prometheus format, when the Prometheus exporter is
 *    enabled)."
 *
 * Ruling (team-lead, rulings item 91(3)): `GET /metrics` is global (not
 * tenant-scoped), mounted only when `CHARIOT_PROMETHEUS_EXPORTER=1`, and
 * REQUIRES a bearer token `CHARIOT_METRICS_TOKEN` — enabled without a
 * token is a startup refusal, not a silently-unauthenticated endpoint.
 * `assertPrometheusExporterConfigValid()` is the fail-fast check a caller
 * runs at boot, mirroring this repo's existing fail-fast pattern for
 * ENTERPRISE_JWT_SECRET / CHARIOT_PUBLIC_BASE_URL (src/engine/bin/setup.ts).
 */
import { Router } from 'express';
import type { Request, Response } from 'express';
import { timingSafeEqual } from 'node:crypto';
import type { ChariotMetrics } from './metrics.js';

export function isPrometheusExporterEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.CHARIOT_PROMETHEUS_EXPORTER === '1';
}

/**
 * Fail-fast startup check: CHARIOT_PROMETHEUS_EXPORTER=1 with no
 * CHARIOT_METRICS_TOKEN set is refused (throws) rather than silently
 * binding an unauthenticated /metrics endpoint. Call this once at boot,
 * unconditionally (it is a no-op when the exporter flag is unset or '0').
 */
export function assertPrometheusExporterConfigValid(env: NodeJS.ProcessEnv = process.env): void {
  if (isPrometheusExporterEnabled(env) && !env.CHARIOT_METRICS_TOKEN) {
    throw new Error(
      'Chariot startup: CHARIOT_PROMETHEUS_EXPORTER=1 requires CHARIOT_METRICS_TOKEN to be set; refusing to bind an unauthenticated /metrics endpoint.',
    );
  }
}

function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function gaugeLine(name: string, value: number, labels?: Record<string, string>): string {
  if (!labels || Object.keys(labels).length === 0) return `${name} ${value}`;
  const labelStr = Object.entries(labels)
    .map(([k, v]) => `${k}="${escapeLabelValue(v)}"`)
    .join(',');
  return `${name}{${labelStr}} ${value}`;
}

/**
 * Render a ChariotMetrics.getSummary() snapshot as Prometheus text
 * exposition format (each series preceded by its own HELP/TYPE comment,
 * per the format's own convention — this is descriptive text, not a
 * governed-clause byte match, so no spec-quote is pinned to it).
 */
export function formatPrometheusMetrics(summary: ReturnType<ChariotMetrics['getSummary']>): string {
  const lines: string[] = [];
  const gauge = (name: string, help: string, value: number, labels?: Record<string, string>): void => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} gauge`);
    lines.push(gaugeLine(name, value, labels));
  };

  gauge('chariot_sessions_created_total', 'Sessions created', summary.sessions.created);
  gauge('chariot_sessions_revoked_total', 'Sessions revoked', summary.sessions.revoked);
  gauge('chariot_auth_failures_total', 'Authentication failures', summary.sessions.authFailures);
  gauge('chariot_brute_force_events_total', 'Brute-force lockout events', summary.sessions.bruteForceEvents);
  gauge('chariot_rbac_access_granted_total', 'RBAC access grants', summary.rbac.granted);
  gauge('chariot_rbac_access_denied_total', 'RBAC access denials', summary.rbac.denied);
  gauge('chariot_vault_credentials_connected', 'Vault credentials connected', summary.vault.connected);
  gauge('chariot_vault_credentials_revoked', 'Vault credentials revoked', summary.vault.revoked);
  gauge('chariot_configured_adapters_total', 'Configured adapters', summary.adapters.total);
  gauge('chariot_adapter_errors_total', 'Adapters currently reporting errors', summary.adapters.withErrors);
  gauge('chariot_discovery_scans_total', 'Discovery scans completed', summary.discovery.scans);
  gauge('chariot_discovery_services_approved_total', 'Discovered services approved', summary.discovery.approved);
  gauge('chariot_discovery_services_rejected_total', 'Discovered services rejected', summary.discovery.rejected);
  // -1 is Prometheus convention for "no data yet" on a percent gauge whose
  // domain is [0,100] — never confusable with a real 0% (all failed).
  gauge('chariot_supply_chain_integrity_percent', 'Percent of adapters with verified signatures', summary.supplyChain.integrityPercent ?? -1);
  gauge('chariot_autonomy_pending_approvals', 'Autonomy decisions awaiting human approval', summary.autonomy.pendingApprovals);
  for (const [tier, count] of Object.entries(summary.autonomy.byTier)) {
    gauge('chariot_autonomy_decisions_total', 'Autonomy decisions by tier', count, { tier });
  }
  for (const [adapterId, usage] of Object.entries(summary.tokenUsageByAdapter)) {
    gauge('chariot_token_usage_total', 'Token usage by adapter', usage.tokens, { adapter: adapterId });
    gauge('chariot_token_cost_usd_total', 'Estimated token cost (USD) by adapter', usage.costUsd, { adapter: adapterId });
  }

  return lines.join('\n') + '\n';
}

/**
 * Build the `GET /metrics` router. `getMetrics` is a lazy accessor (not a
 * direct instance) so the router can be mounted before ChariotMetrics is
 * necessarily constructed, and always reads the CURRENT instance at
 * request time.
 */
export function createPrometheusMetricsRouter(getMetrics: () => ChariotMetrics | undefined): Router {
  const router = Router();

  router.get('/metrics', (req: Request, res: Response): void => {
    const token = process.env.CHARIOT_METRICS_TOKEN;
    if (!token) {
      // Defense in depth: assertPrometheusExporterConfigValid() should
      // have refused startup before this route could ever be mounted
      // without a token. Fail closed anyway if that invariant is ever
      // violated (e.g. the env var is unset AFTER boot).
      res.status(503).send('metrics exporter misconfigured: no token\n');
      return;
    }

    const authHeader = req.headers['authorization'];
    const expected = `Bearer ${token}`;
    const authorized =
      typeof authHeader === 'string'
      && (() => {
        const a = Buffer.from(authHeader);
        const b = Buffer.from(expected);
        return a.length === b.length && timingSafeEqual(a, b);
      })();

    if (!authorized) {
      res.status(401).send('unauthorized\n');
      return;
    }

    const metrics = getMetrics();
    if (!metrics) {
      res.status(503).send('metrics not available\n');
      return;
    }

    res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.status(200).send(formatPrometheusMetrics(metrics.getSummary()));
  });

  return router;
}
