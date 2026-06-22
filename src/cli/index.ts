/**
 * @epicai/chariot/cli — Shared CLI Helpers
 * Barrel export for state, config, credentials, MCP client detection, and system probing.
 * Used by src/bin/chariot.ts (outer CLI) and src/engine/bin/setup.ts (engine setup).
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export type { AdapterState, ChariotConfig, McpClientInfo, SystemInfo } from './types.js';
export { CONFIG_FILE, ENV_FILE, EPIC_AI_DIR, STATE_FILE, commandExists, ensureDir, expandHome } from './paths.js';
export {
  loadConfig,
  loadState,
  readJsonFile,
  removeAdapterState,
  saveConfig,
  saveState,
  upsertAdapterState,
  withLastHealthCheck,
} from './state.js';
export { loadCredentials, loadCredentialsFrom, parseEnvFile, writeCredential, CREDENTIAL_VALUE_CONTROL_CHAR_RE } from './credentials.js';
export { detectMcpClients, detectSystem, writeMcpConfig } from './mcp-clients.js';
export type { McpEntry } from './mcp-clients.js';
export { adapterTypeLabel } from './display.js';
