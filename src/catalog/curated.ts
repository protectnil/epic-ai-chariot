/**
 * @epicai/chariot — Curated default adapter set
 *
 * Single source of truth imported by both `src/bin/chariot.ts` (the CLI's
 * `list` command) and `src/engine/bin/setup.ts` (the setup wizard) so
 * the two surfaces cannot drift.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export interface CuratedAdapter {
  /** Adapter id as it appears in the bundled registry (read from `chariot-adapter-bundle.json` at runtime). */
  id: string;
  /** Human-readable name surfaced in CLI tables and onboarding. */
  name: string;
  /** One-line description shown next to the name in `chariot list`. */
  desc: string;
  /** Approximate tool count, used only as a UX hint — the real count
   *  is read from the registry at runtime. */
  tools: number;
  /** Example query surfaced after `chariot setup` to demonstrate value. */
  demoQuery: string;
}

// helium-mcp removed from the curated set — it was
// advertised in `chariot list` but absent from the published catalog.
// `chariot add helium-mcp` printed "Adapter not found." A curated entry
// must be addable from the published bundle; restore helium-mcp here
// only after the upstream catalog entries land via the publish pipeline.
export const CHARIOT_CURATED: ReadonlyArray<CuratedAdapter> = [
  { id: 'pubmed',     name: 'PubMed',      desc: 'Search 36 million biomedical research papers', tools: 5,  demoQuery: 'Recent clinical trials on GLP-1 drugs for obesity' },
  { id: 'wikipedia',  name: 'Wikipedia',   desc: 'Ask questions answered from Wikipedia',         tools: 9,  demoQuery: 'History of the Turing Award' },
  { id: 'dns',        name: 'DNS Intel',   desc: 'DNS, WHOIS, and network intelligence lookups',  tools: 9,  demoQuery: 'DNS records and ASN for cloudflare.com' },
];

export const CHARIOT_CURATED_IDS: ReadonlyArray<string> =
  CHARIOT_CURATED.map((c) => c.id);

// ─── CH-43 — curated open-data tier resilience ───────────────────────────────
//
// The curated open-data adapters (PubMed, Wikipedia, DNS Intel, and the ~20
// gov / open-data MCP servers in the published catalog) are shipped with a
// SINGLE managed MCP host, `mcp.olyport.com`. One host is a SPOF: if it is
// unreachable (outage, or an air-gapped/offline deployment with no route to
// it) EVERY curated open-data adapter fails together.
//
// Chariot-side resolution (this file + the dispatch wiring in
// src/engine/server/toolHandlers.ts): operators can repoint the curated
// open-data tier OFF the single managed host onto their OWN mirror/proxy via
// `CHARIOT_CURATED_MCP_HOST`. This removes the HARD single-host dependence —
// an air-gapped operator runs a local mirror and sets the env var, and the
// protectNIL-managed host is no longer a hard requirement. The override is
// applied at dispatch to any streamable-http/SSE adapter whose serverUrl host
// is the default managed host, so it covers all ~20 curated open-data adapters
// without touching the signed catalog.
//
// Catalog-pipeline side (FLAGGED — NOT in this change): automatic health-based
// failover across MULTIPLE endpoints requires the signed adapter catalog
// (chariot-adapter-bundle.json) to carry per-adapter mirror serverUrls (e.g.
// `mcp.serverUrls: [primary, mirror]`). That catalog is produced and
// Ed25519-signed by the out-of-repo catalog build pipeline and is not
// hand-edited from this repo. Until those mirror endpoints exist in the
// catalog there is nothing to auto-fail-over TO, so the operator override
// above is the buildable in-repo lever.
export const CURATED_OPEN_DATA_DEFAULT_HOST = 'mcp.olyport.com';

/** Operator override for the curated open-data MCP host, or undefined when unset. */
export function resolveCuratedOpenDataHostOverride(): string | undefined {
  const v = process.env.CHARIOT_CURATED_MCP_HOST?.trim();
  return v && v.length > 0 ? v : undefined;
}

/**
 * If a curated-open-data host override is configured AND `serverUrl`'s host is
 * the default managed host, return `serverUrl` with scheme/host/port rewritten
 * to the operator's mirror; otherwise return `serverUrl` unchanged. The
 * override may be `host`, `host:port`, or `scheme://host[:port]`. Path and
 * query are preserved (e.g. `/pubmed/mcp`). Safe on non-URL input (returned
 * unchanged) so a malformed serverUrl can never throw on the dispatch path.
 */
export function applyCuratedHostOverride(serverUrl: string | undefined): string | undefined {
  if (!serverUrl) return serverUrl;
  const override = resolveCuratedOpenDataHostOverride();
  if (!override) return serverUrl;
  let u: URL;
  try {
    u = new URL(serverUrl);
  } catch {
    return serverUrl;
  }
  if (u.hostname !== CURATED_OPEN_DATA_DEFAULT_HOST) return serverUrl;
  try {
    const o = override.includes('://') ? new URL(override) : new URL(`https://${override}`);
    u.protocol = o.protocol;
    u.hostname = o.hostname;
    u.port = o.port; // '' clears any inherited port
    return u.toString();
  } catch {
    return serverUrl;
  }
}
