/**
 * Shared primitives for hash-chained, tamper-evident audit logs.
 *
 * Two chains exist in this codebase: the IAM-side per-tenant audit
 * trail (src/iam/services/audit.ts) and the CLI-side approval-action
 * log (src/cli/approval.ts). Both seed their first record's prev_hash
 * with the same all-zero SHA-256 sentinel. Defining the constant once
 * here keeps the two chains in lock-step if the hash family or seed
 * length ever changes.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/** All-zero SHA-256 hex used as the prev_hash of the first audit record. */
export const GENESIS_HASH = '0'.repeat(64);
