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

applyChariotCatalogEnv();

// Delegate to Chariot engine gateway — IAM middleware integrates at this layer
await import('../engine/gateway/index.js');
