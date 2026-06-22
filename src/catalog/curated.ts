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

// bug-tracker-ref: helium-mcp removed from the curated set — it was
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
