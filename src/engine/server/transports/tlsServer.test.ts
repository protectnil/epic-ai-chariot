/**
 * @epicai/chariot — mutual TLS (mTLS) coverage for the shared TLS server
 * helper (tlsServer.ts), used by gateway.ts, rest.ts, and http.ts.
 *
 * Proves the fail-closed contract Wiz practice 5 ("mTLS through the
 * gateway") requires:
 *   - No tlsConfig (or cert/key absent) → plain node:http, byte-for-byte
 *     the same as before mTLS support existed. NO regression.
 *   - cert+key+ca configured  → the TLS layer itself REJECTS a client
 *     that presents no certificate, and REJECTS a client whose
 *     certificate is signed by a DIFFERENT CA — before any application
 *     code runs. A client with a certificate signed by the configured
 *     CA is ACCEPTED and gets a normal response.
 *
 * Real self-signed certs generated via openssl into a temp dir; real TLS
 * sockets over 127.0.0.1 — no mocking of node:tls/node:http/node:https.
 *
 * Run: node --test dist/engine/server/transports/tlsServer.test.js
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { createHttpServer, tlsEnabled, mtlsEnabled } from './tlsServer.js';
import type { TlsConfig } from './tlsServer.js';

interface Pem {
  keyPath: string;
  certPath: string;
}

let dir: string;
let trustedCa: Pem;
let untrustedCa: Pem;
let serverLeaf: Pem;
let validClientLeaf: Pem;
let untrustedClientLeaf: Pem;

function openssl(...args: string[]): void {
  execFileSync('openssl', args, { stdio: 'pipe' });
}

/** Self-signed CA cert + key. */
function genCa(prefix: string, cn: string): Pem {
  const keyPath = join(dir, `${prefix}-key.pem`);
  const certPath = join(dir, `${prefix}-cert.pem`);
  openssl(
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath,
    '-days', '2', '-nodes', '-subj', `/CN=${cn}`,
  );
  return { keyPath, certPath };
}

/**
 * Leaf cert (server or client) signed by the given CA. `sanExt`, when
 * given, is written to an -extfile so the leaf carries a
 * subjectAltName — required for the SERVER leaf so a client validating
 * the hostname/IP (as any real TLS client does) accepts it; client
 * leaves don't need one.
 */
function genLeaf(prefix: string, cn: string, ca: Pem, sanExt?: string): Pem {
  const keyPath = join(dir, `${prefix}-key.pem`);
  const csrPath = join(dir, `${prefix}-csr.pem`);
  const certPath = join(dir, `${prefix}-cert.pem`);
  openssl(
    'req', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', csrPath,
    '-nodes', '-subj', `/CN=${cn}`,
  );
  const signArgs = [
    'x509', '-req', '-in', csrPath, '-CA', ca.certPath, '-CAkey', ca.keyPath,
    '-CAcreateserial', '-out', certPath, '-days', '2',
  ];
  if (sanExt) {
    const extFilePath = join(dir, `${prefix}-ext.cnf`);
    writeFileSync(extFilePath, sanExt);
    signArgs.push('-extfile', extFilePath);
  }
  openssl(...signArgs);
  return { keyPath, certPath };
}

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'chariot-mtls-test-'));
  trustedCa = genCa('ca', 'Chariot Test CA');
  untrustedCa = genCa('rogue-ca', 'Rogue Test CA');
  serverLeaf = genLeaf('server', 'localhost', trustedCa, 'subjectAltName=IP:127.0.0.1,DNS:localhost\n');
  validClientLeaf = genLeaf('client-valid', 'valid-client', trustedCa);
  untrustedClientLeaf = genLeaf('client-rogue', 'rogue-client', untrustedCa);
});

after(() => {
  rmSync(dir, { recursive: true, force: true });
});

function listen(tlsConfig?: TlsConfig): Promise<{ server: http.Server | https.Server; port: number }> {
  return new Promise((resolve, reject) => {
    const server = createHttpServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    }, tlsConfig);
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve({ server, port: addr.port });
      } else {
        reject(new Error('listen: could not determine bound port'));
      }
    });
  });
}

function closeServer(server: http.Server | https.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

/** GET over plain HTTP; resolves with the response body. */
function httpGet(port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    http.get({ hostname: '127.0.0.1', port, timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (c: Buffer) => { data += c.toString(); });
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

/** GET over HTTPS with the given client identity/trust options; resolves with the response body, rejects on TLS/socket error. */
function httpsGet(port: number, opts: https.RequestOptions): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname: '127.0.0.1', port, method: 'GET', timeout: 5000, ...opts },
      (res) => {
        let data = '';
        res.on('data', (c: Buffer) => { data += c.toString(); });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.end();
  });
}

describe('tlsServer — default behavior (no regression)', () => {
  test('no tlsConfig → plain node:http server; plain HTTP request succeeds', async () => {
    assert.equal(tlsEnabled(undefined), false);
    assert.equal(mtlsEnabled(undefined), false);
    const { server, port } = await listen(undefined);
    try {
      assert.ok(server instanceof http.Server);
      const body = await httpGet(port);
      assert.equal(body, 'ok');
    } finally {
      await closeServer(server);
    }
  });

  test('cert+key without ca → one-way HTTPS, no client certificate required', async () => {
    const tlsConfig: TlsConfig = { certPath: serverLeaf.certPath, keyPath: serverLeaf.keyPath };
    assert.equal(tlsEnabled(tlsConfig), true);
    assert.equal(mtlsEnabled(tlsConfig), false);
    const { server, port } = await listen(tlsConfig);
    try {
      const { status, body } = await httpsGet(port, {
        ca: readFileSync(trustedCa.certPath),
        rejectUnauthorized: true,
      });
      assert.equal(status, 200);
      assert.equal(body, 'ok');
    } finally {
      await closeServer(server);
    }
  });
});

describe('tlsServer — mutual TLS fail-closed contract', () => {
  function mtlsConfig(): TlsConfig {
    return {
      certPath: serverLeaf.certPath,
      keyPath: serverLeaf.keyPath,
      caPath: trustedCa.certPath,
    };
  }

  test('client presenting NO certificate is REJECTED at the TLS layer', async () => {
    const { server, port } = await listen(mtlsConfig());
    try {
      await assert.rejects(() => httpsGet(port, {
        ca: readFileSync(trustedCa.certPath),
        rejectUnauthorized: true,
        // deliberately no cert/key — anonymous client
      }));
    } finally {
      await closeServer(server);
    }
  });

  test('client certificate signed by a DIFFERENT (untrusted) CA is REJECTED', async () => {
    const { server, port } = await listen(mtlsConfig());
    try {
      await assert.rejects(() => httpsGet(port, {
        ca: readFileSync(trustedCa.certPath),
        cert: readFileSync(untrustedClientLeaf.certPath),
        key: readFileSync(untrustedClientLeaf.keyPath),
        rejectUnauthorized: true,
      }));
    } finally {
      await closeServer(server);
    }
  });

  test('client certificate signed by the configured CA is ACCEPTED', async () => {
    const { server, port } = await listen(mtlsConfig());
    try {
      const { status, body } = await httpsGet(port, {
        ca: readFileSync(trustedCa.certPath),
        cert: readFileSync(validClientLeaf.certPath),
        key: readFileSync(validClientLeaf.keyPath),
        rejectUnauthorized: true,
      });
      assert.equal(status, 200);
      assert.equal(body, 'ok');
    } finally {
      await closeServer(server);
    }
  });
});
