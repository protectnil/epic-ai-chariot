/**
 * One-shot private credential page (loopback).
 * Spec: CHARIOT-SPEC §17.3 (credentials entered outside the chat / server instructions); C4AMD §2 (three tools, unchanged).
 *
 * WHY: when the AI is the only interface, a person still has to give an
 * integration its API key — and the key must never pass through the chat or
 * the model. This module starts a throw-away HTTP listener on 127.0.0.1 that
 * serves ONE form for ONE adapter, writes what the person types straight to
 * the local credential store, then shuts down. The AI only ever sees the URL
 * and the words "stored" / "not yet".
 *
 * HARD PROPERTIES (each has a test):
 *   - binds 127.0.0.1 only, ephemeral port, never 0.0.0.0
 *   - the URL carries a 256-bit random token; any other path is 404
 *   - single use: after a successful submit the token is dead and the server closes
 *   - expires (default 10 min) and closes itself
 *   - Host header must be the loopback literal+port (DNS-rebinding defense)
 *   - a cross-origin POST (Origin present and not ours) is refused (CSRF defense)
 *   - only the requested keys are accepted; control characters are rejected;
 *     all values are validated BEFORE any is written (two-phase, as `chariot add`)
 *   - secrets are never logged and never echoed in any response
 *   - strict CSP, no external resources, no framing, no referrer, no caching
 *   - repeated bad requests close the portal
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { CREDENTIAL_VALUE_CONTROL_CHAR_RE } from '../../cli/credentials.js';

export type PortalEnd = 'stored' | 'expired' | 'closed';

export interface PortalOptions {
  /** Human name shown on the page. */
  adapterName: string;
  /** Exactly the credential keys to collect. */
  keys: readonly string[];
  /** Persist one key. Throws to reject (the portal then reports the key, never the value). */
  store: (key: string, value: string) => void;
  /**
   * Read the value a key holds now (undefined when absent) and put it back.
   * Together they let a failed multi-key write be undone. Without them a
   * failure after the first key was written closes the page instead of
   * leaving a half-written set behind a page that could be reused.
   */
  peek?: (key: string) => string | undefined;
  restore?: (key: string, previous: string | undefined) => void;
  /**
   * True while the key still needs a value. Re-checked at submit time: if
   * another page or process supplied any requested key meanwhile, this page
   * writes nothing and closes, and the next call re-evaluates.
   */
  isMissing?: (key: string) => boolean;
  ttlMs?: number;
  maxBadRequests?: number;
}

export interface PortalSession {
  /** The private URL to open in a browser on this machine. */
  url: string;
  /** Resolves once, when the portal ends. */
  completed: Promise<PortalEnd>;
  close(): void;
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_BODY_BYTES = 16 * 1024;

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>${esc(title)}</title><style>` +
    `body{margin:0;font:16px/1.6 system-ui,sans-serif;background:#F5EEE1;color:#0F0E0C;display:grid;place-items:center;min-height:100vh}` +
    `main{max-width:30rem;padding:2rem}h1{font-size:1.4rem;margin:0 0 .5rem}p{color:#4A463F}` +
    `label{display:block;margin:1rem 0 .25rem;font-weight:600}input{width:100%;box-sizing:border-box;padding:.7rem;font:inherit;border:1px solid #7A756E;border-radius:8px}` +
    `button{margin-top:1.25rem;padding:.8rem 1.4rem;border:0;border-radius:999px;background:#A8502F;color:#fff;font:inherit;font-weight:600;cursor:pointer}` +
    `.err{color:#9B1C1C}</style></head><body><main>${body}</main></body></html>`;
}

function formPage(adapterName: string, keys: readonly string[], error?: string): string {
  const fields = keys
    .map((k) => `<label for="${esc(k)}">${esc(k)}</label><input id="${esc(k)}" name="${esc(k)}" type="password" autocomplete="off" required>`)
    .join('');
  return page(
    'Enter credentials',
    `<h1>Connect ${esc(adapterName)}</h1>` +
      `<p>These values are saved on this computer only. Your AI never sees them.</p>` +
      (error ? `<p class="err" role="alert">${esc(error)}</p>` : '') +
      `<form method="post" autocomplete="off">${fields}<button type="submit">Save</button></form>`,
  );
}

function send(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(html);
}

function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(null));
  });
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export async function startCredentialPortal(opts: PortalOptions): Promise<PortalSession> {
  for (const k of opts.keys) {
    if (!KEY_RE.test(k)) throw new Error(`CredentialPortal: invalid key name ${JSON.stringify(k)}`);
  }
  if (opts.keys.length === 0) throw new Error('CredentialPortal: no keys to collect');

  const token = randomBytes(32).toString('base64url');
  const path = `/c/${token}`;
  const ttlMs = opts.ttlMs ?? 10 * 60_000;
  const maxBad = opts.maxBadRequests ?? 8;
  let bad = 0;
  let ended = false;
  // Set synchronously (before the first store) by the one submission that
  // writes, so a concurrent POST that finished reading its body cannot also
  // write. Cleared only if that store throws and the page stays open.
  let consumed = false;
  const expiresAt = Date.now() + ttlMs;
  let port = 0;
  let resolveEnd!: (e: PortalEnd) => void;
  const completed = new Promise<PortalEnd>((r) => { resolveEnd = r; });

  const server = createServer((req, res) => {
    void (async () => {
      // Expiry and single-use are enforced HERE, not by socket closure (which
      // is deferred to a later event-loop turn): a request that arrives, or
      // finishes reading its body, after the page ended or expired gets nothing.
      const dead = (): boolean => {
        if (!ended && Date.now() >= expiresAt) end('expired');
        return ended;
      };
      const host = (req.headers.host ?? '').toLowerCase();
      if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) {
        send(res, 403, page('Forbidden', '<h1>Forbidden</h1>'));
        return;
      }
      if (dead()) {
        send(res, 410, page('Gone', '<h1>This page is no longer available</h1>'));
        return;
      }
      // Origin, when sent, must be this page's own origin, i.e. exactly the
      // scheme + Host the request used (127.0.0.1 and localhost are distinct origins).
      const origin = req.headers.origin;
      if (origin !== undefined && origin !== `http://${host}`) {
        send(res, 403, page('Forbidden', '<h1>Forbidden</h1>'));
        return;
      }
      const url = req.url ?? '';
      if (!safeEqual(url.split('?')[0], path)) {
        send(res, 404, page('Not found', '<h1>Not found</h1>'));
        return;
      }
      // The ONLY way this page ever renders its form. Fields are shown solely
      // for keys that are still missing: if any requested key was supplied
      // meanwhile (another page, process or environment), nothing is rendered
      // and the page closes, so a key already present is never collected again.
      const stale = (): boolean => opts.isMissing !== undefined && !opts.keys.every((k) => opts.isMissing!(k));
      const showForm = (status: number, error?: string): void => {
        if (stale()) {
          send(res, 409, page('Already provided', '<h1>Nothing to save</h1><p>These values were provided another way. Ask your AI to try again.</p>'));
          end('closed');
          return;
        }
        send(res, status, formPage(opts.adapterName, opts.keys, error));
      };
      if (req.method === 'GET') {
        showForm(200);
        return;
      }
      if (req.method !== 'POST') {
        send(res, 405, page('Method not allowed', '<h1>Method not allowed</h1>'));
        return;
      }
      if (!(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/x-www-form-urlencoded')) {
        send(res, 415, page('Unsupported', '<h1>Unsupported</h1>'));
        return;
      }
      const raw = await readBody(req);
      if (raw === null) {
        send(res, 413, page('Too large', '<h1>Too large</h1>'));
        return;
      }
      if (dead() || consumed) {
        send(res, 410, page('Gone', '<h1>This page is no longer available</h1>'));
        return;
      }
      const form = new URLSearchParams(raw);
      const values: Array<[string, string]> = [];
      let problem: string | null = null;
      // Every submitted pair is checked, not only the first value of each
      // requested key: an unrequested key, a repeated key or a bad second
      // value rejects the whole submission and nothing is written.
      const seen = new Set<string>();
      for (const [k, v] of form.entries()) {
        if (!opts.keys.includes(k)) { problem = 'Unexpected field.'; break; }
        if (seen.has(k)) { problem = `${k} was sent more than once.`; break; }
        seen.add(k);
        if (v.length === 0) { problem = `${k} is required.`; break; }
        if (CREDENTIAL_VALUE_CONTROL_CHAR_RE.test(v)) { problem = `${k} contains a character that cannot be stored. Paste the plain value.`; break; }
      }
      if (problem === null) {
        for (const k of opts.keys) {
          const v = form.get(k);
          if (v === null) { problem = `${k} is required.`; break; }
          values.push([k, v]);
        }
      }
      if (problem !== null) {
        bad++;
        showForm(400, problem);
        if (bad >= maxBad) end('closed');
        return;
      }
      if (stale()) {
        send(res, 409, page('Already provided', '<h1>Nothing to save</h1><p>These values were provided another way. Ask your AI to try again.</p>'));
        end('closed');
        return;
      }
      consumed = true;
      const written: Array<[string, string | undefined]> = [];
      try {
        for (const [k, v] of values) {
          const previous = opts.peek ? opts.peek(k) : undefined;
          opts.store(k, v);
          written.push([k, previous]);
        }
      } catch {
        // Put back everything this submission wrote. Only a fully restored
        // store lets the page stay open; anything else closes it, so a
        // half-written credential set is never left behind a reusable page.
        let restored = written.length === 0;
        if (!restored && opts.restore && opts.peek) {
          try {
            for (const [k, previous] of [...written].reverse()) opts.restore(k, previous);
            restored = true;
          } catch { restored = false; }
        }
        if (restored) {
          consumed = false;
          bad++;
          showForm(500, 'Could not save. Try again.');
          if (bad >= maxBad) end('closed');
        } else {
          send(res, 500, page('Could not save', '<h1>Could not save</h1><p>Nothing more can be entered on this page. Ask your AI to try again.</p>'));
          end('closed');
        }
        return;
      }
      send(res, 200, page('Saved', `<h1>Saved</h1><p>${esc(opts.adapterName)} is connected. You can close this tab and go back to your AI.</p>`));
      end('stored');
    })();
  });

  const timer = setTimeout(() => end('expired'), ttlMs);
  timer.unref();

  function end(why: PortalEnd): void {
    if (ended) return;
    ended = true;
    clearTimeout(timer);
    // Let an in-flight response finish, then stop accepting and drop sockets.
    setImmediate(() => {
      server.close();
      server.closeAllConnections?.();
    });
    resolveEnd(why);
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  port = (server.address() as AddressInfo).port;

  return { url: `http://127.0.0.1:${port}${path}`, completed, close: () => end('closed') };
}
