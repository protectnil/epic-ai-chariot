/**
 * @epicai/chariot — Adapter Sandbox Types
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export type SandboxMode = 'none' | 'worker-thread' | 'process';

export type EgressEnforcement = 'networkpolicy' | 'netns-nftables' | 'sandbox-exec' | 'none';

export interface AdapterSandboxConfig {
  mode: SandboxMode;
  allowedEnvVars: string[];
  /**
   * Network/filesystem confinement fields. These are HONEST-SIGNAL fields:
   * a request for confinement (`egressEnforcement !== 'none'`, non-empty
   * `allowedHosts`, or `fileSystemAccess !== 'none'`) is only accepted when
   * the chosen `mode` can actually enforce it. If the runtime cannot apply
   * the requested confinement, `SandboxManager.create()` throws (fail-closed)
   * rather than spawning an unconfined process while these fields read as a
   * guarantee. The all-`'none'`/empty default declares NO confinement and is
   * an explicit choice to run unconfined.
   */
  allowedHosts: string[];
  egressEnforcement: EgressEnforcement;
  fileSystemAccess: 'none' | 'read-only';
  maxMemoryMb: number;
  timeoutMs: number;
}

export const DEFAULT_SANDBOX_CONFIG: AdapterSandboxConfig = {
  mode: 'process',
  allowedEnvVars: [],
  allowedHosts: [],
  egressEnforcement: 'none',
  fileSystemAccess: 'none',
  maxMemoryMb: 256,
  timeoutMs: 30_000,
};
