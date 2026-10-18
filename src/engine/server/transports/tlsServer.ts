/**
 * @epicai/chariot — Shared TLS server helper
 * Single place that turns TLS/mTLS config into an http.Server or
 * https.Server, used by all three HTTP-surface binders (gateway.ts,
 * rest.ts, http.ts) so mutual-TLS logic isn't duplicated three times.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import type { RequestListener } from 'node:http';

/**
 * Optional TLS configuration for an HTTP surface. All fields are paths to
 * PEM files on disk.
 *
 *  - Neither `certPath` nor `keyPath` set → the surface is plain
 *    node:http, byte-for-byte the same as before mTLS support existed.
 *  - `certPath` + `keyPath` set, no `caPath` → one-way HTTPS (server
 *    authenticates to the client; client identity is not checked).
 *  - `certPath` + `keyPath` + `caPath` all set → mutual TLS: the server
 *    presents `caPath` as its trusted client-CA bundle and REQUIRES every
 *    connecting client to present a certificate signed by that CA. A
 *    client with no certificate, or one not signed by the CA, is
 *    rejected at the TLS handshake — the request never reaches
 *    application code (fail-closed).
 */
export interface TlsConfig {
  certPath?: string;
  keyPath?: string;
  /** Client CA bundle. Presence (alongside cert/key) turns on mutual TLS. */
  caPath?: string;
}

/** True when cert+key are both configured, i.e. the surface serves HTTPS at all. */
export function tlsEnabled(config: TlsConfig | undefined): boolean {
  return Boolean(config?.certPath && config?.keyPath);
}

/** True when TLS is enabled AND a client CA is configured, i.e. mutual TLS is on. */
export function mtlsEnabled(config: TlsConfig | undefined): boolean {
  return tlsEnabled(config) && Boolean(config?.caPath);
}

/**
 * Create an http.Server or https.Server depending on `tlsConfig`.
 *
 * Default (no `tlsConfig`, or `tlsConfig` missing cert/key): returns a
 * plain `http.createServer(handler)` — identical to pre-mTLS behavior,
 * NO regression.
 *
 * With cert+key: returns `https.createServer({ cert, key }, handler)`.
 *
 * With cert+key+ca: also sets `ca`, `requestCert: true`,
 * `rejectUnauthorized: true` so the TLS layer itself enforces mutual
 * authentication before any request handler runs.
 */
export function createHttpServer(
  handler: RequestListener,
  tlsConfig?: TlsConfig,
): http.Server | https.Server {
  if (!tlsEnabled(tlsConfig)) {
    return http.createServer(handler);
  }

  const options: https.ServerOptions = {
    cert: fs.readFileSync(tlsConfig!.certPath as string),
    key: fs.readFileSync(tlsConfig!.keyPath as string),
  };

  if (tlsConfig!.caPath) {
    options.ca = fs.readFileSync(tlsConfig!.caPath);
    options.requestCert = true;
    options.rejectUnauthorized = true;
  }

  return https.createServer(options, handler);
}

/**
 * Apply the shared Slowloris-class guards (slow-header, slow-body,
 * lingering keep-alive) to a server returned by createHttpServer.
 *
 * @types/node models https.Server as extending tls.Server rather than
 * http.Server, so it does not type headersTimeout/requestTimeout/
 * keepAliveTimeout even though the Node runtime sets them on every HTTP
 * server (http and https alike — https.Server reuses http.Server's
 * connection-listener implementation internally). The cast below is
 * confined to this one helper rather than repeated at each call site.
 */
export function applySlowlorisGuards(
  server: http.Server | https.Server,
  opts?: { headersTimeoutMs?: number; requestTimeoutMs?: number; keepAliveTimeoutMs?: number },
): void {
  const s = server as unknown as {
    headersTimeout: number;
    requestTimeout: number;
    keepAliveTimeout: number;
  };
  s.headersTimeout = opts?.headersTimeoutMs ?? 10_000;
  s.requestTimeout = opts?.requestTimeoutMs ?? 30_000;
  s.keepAliveTimeout = opts?.keepAliveTimeoutMs ?? 5_000;
}
