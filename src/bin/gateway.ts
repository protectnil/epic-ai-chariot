#!/usr/bin/env node

/**
 * Epic AI® Chariot Gateway
 *
 * HTTP/HTTPS inference gateway with enterprise IAM integration.
 * Delegates core gateway functionality to the bundled Chariot engine InferenceGateway,
 * adding IAM middleware for authenticated multi-user access.
 *
 * Usage: chariot-gateway [--port 8000] [--tls-cert cert.pem] [--tls-key key.pem]
 */

import { applyChariotCatalogEnv } from '../catalog/artifacts.js';
import { enforceBootEntitlement } from '../license/boot-gate.js';

applyChariotCatalogEnv();

// CHARIOT-SPEC §23.1 / CH-24 — License Manager CheckoutLicense at gateway
// boot, before anything serves. No-op outside License Manager mode (offline
// Ed25519 §11 stays the default); in License Manager mode any denial or
// failure aborts boot (fail closed).
try {
  await enforceBootEntitlement();
} catch (err) {
  console.error(`Gateway startup refused: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

// Delegate to the Chariot engine gateway CLI (starts the InferenceGateway and
// its HTTP listener; the barrel '../engine/gateway/index.js' only exports
// classes and starts nothing). IAM middleware integrates at this layer.
await import('../engine/bin/gateway.js');
