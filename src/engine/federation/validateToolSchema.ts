/**
 * @epicai/chariot — Per-tool input-schema validation.
 *
 * AgentProp-Bench (arXiv 2604.16706) reports parameter-level errors cascade to
 * a wrong final answer at 0.62 (range 0.46–0.73 across nine production LLMs).
 * This module is the single validation hook every federation-layer dispatch
 * goes through to reject malformed args BEFORE adapter dispatch. No retry
 * (validation is deterministic). No billing. Audit-trail records the rejection.
 *
 * Source-of-truth for the per-tool schema: `adapter.tools[i].inputSchema`
 * (Phase 3.x per-tool metadata). When the field is absent the validator returns
 * `{ valid: true, reason: 'no-schema' }` and a warn-once is emitted by the caller —
 * partial coverage is acceptable for adapters that have not been through Phase 3.x.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { z } from 'zod';

// recursive property shape. Arrays carry `items` (single JSON-Schema
// node describing element type); nested objects carry their own `properties` +
// `required` + `additionalProperties` so the validator can refuse deep-structure
// violations (spec §2.5 demands 0% cascade across all 5 transports).
export interface ToolInputSchemaProp {
  type?: string;
  description?: string;
  enum?: unknown[];
  // Recursive: nested arrays carry element type via `items`.
  items?: ToolInputSchemaProp;
  // Recursive: nested objects carry their own property shape.
  properties?: Record<string, ToolInputSchemaProp>;
  required?: string[];
  additionalProperties?: unknown;
}

export interface ToolInputSchema {
  type: 'object';
  properties: Record<string, ToolInputSchemaProp>;
  required?: string[];
  additionalProperties?: unknown;
}

interface AdapterWithTools {
  id?: string;
  tools?: Array<{ name: string; inputSchema?: ToolInputSchema }>;
}

export type ValidationResult =
  | { valid: true; reason?: 'no-schema' | 'ok' }
  | { valid: false; errors: Array<{ path: string; message: string; code: string }> };

const MAX_WARN_ONCE = 10_000;
const warnedAdapterTool = new Set<string>();

function warnOnceMissingSchema(adapterId: string, toolName: string): void {
  const key = `${adapterId}:${toolName}`;
  if (warnedAdapterTool.has(key)) return;
  // Cap retention: a dynamic adapter stream could grow this set unboundedly.
  // When at cap, drop the oldest insertion (Set preserves insertion order).
  if (warnedAdapterTool.size >= MAX_WARN_ONCE) {
    const oldest = warnedAdapterTool.values().next().value;
    if (oldest !== undefined) warnedAdapterTool.delete(oldest);
  }
  warnedAdapterTool.add(key);
  // Plain console.warn — the federation layer doesn't carry a logger
  // reference at this code path; operators forward stderr to their log
  // aggregator. The warn-once Set prevents log spam under high call volume.
  console.warn(
    `[chariot] adapter "${adapterId}" tool "${toolName}" has no usable inputSchema, skipping per-tool validation`,
  );
}

// recursive node→Zod compilation. Handles nested objects (with their
// own properties + required + additionalProperties) and arrays (with typed
// items). Without recursion, the validator would accept `[12345]` for a
// declared `array<string>` field and `{}` for a declared
// `object{required:[note]}` field, leaking cascades through 30% of the spec
// §2.3 fixture cells (measured 2026-05-18 prior to this fix).
//
// Depth guard: protects the chariot process against stack overflow from a
// maliciously or accidentally self-referential inputSchema. Mongo documents
// can carry arbitrary blobs in `inputSchema`; the JSON-Schema spec doesn't
// require acyclicity. At depth > MAX_SCHEMA_DEPTH the node compiles to
// `z.unknown()` (permissive on that subtree only — the outer schema gates
// remain in force).
//
// NOTE: `$ref` (JSON-Pointer reference) traversal is NOT supported here. If a
// future change adds $ref handling, replace this depth guard with a seen-set
// keyed on resolved schema identity to prevent infinite loops on self-
// referential schemas like `{$ref: "#"}`. The depth counter alone is not
// sufficient under reference resolution because the resolver could re-enter
// the same subtree faster than the counter increments.
const MAX_SCHEMA_DEPTH = 16;

function buildPropZod(prop: ToolInputSchemaProp, depth: number = 0): z.ZodTypeAny {
  if (depth > MAX_SCHEMA_DEPTH) return z.unknown();
  switch (prop.type) {
    case 'string':
      if (Array.isArray(prop.enum) && prop.enum.length > 0) {
        // Reviewer Simplify MINOR #4: heterogeneous enum arrays (e.g.,
        // integer enums declared on a string-typed field, or mixed) break
        // z.enum which only accepts string literals. Guard by checking
        // every element is a string; for non-string enums fall back to a
        // refine() membership check that works for any literal type
        // without forcing Zod's tuple constraints.
        if (prop.enum.every((e) => typeof e === 'string')) {
          return z.enum(prop.enum as [string, ...string[]]);
        }
        const allowed = prop.enum;
        return z.unknown().refine((v) => allowed.includes(v), {
          message: `value not in enum: ${JSON.stringify(allowed)}`,
        });
      }
      return z.string();
    case 'number':
      return z.number();
    case 'integer':
      return z.number().int();
    case 'boolean':
      return z.boolean();
    case 'array': {
      const itemSchema = prop.items ? buildPropZod(prop.items, depth + 1) : z.unknown();
      return z.array(itemSchema);
    }
    case 'object': {
      // Nested object: recurse into its properties + required.
      const nestedShape: Record<string, z.ZodTypeAny> = {};
      const nestedRequired = Array.isArray(prop.required) ? prop.required : [];
      for (const [k, p] of Object.entries(prop.properties ?? {})) {
        let zt = buildPropZod(p, depth + 1);
        if (!nestedRequired.includes(k)) zt = zt.optional();
        nestedShape[k] = zt;
      }
      // Two paths: no declared properties means open record (any keys
      // allowed) UNLESS additionalProperties:false explicitly closes it
      // — in which case the schema accepts only the empty object. With
      // declared properties, build a Zod object and apply .strict() when
      // additionalProperties:false. Order matters: the open-record path
      // must respect additionalProperties:false.
      if (Object.keys(nestedShape).length === 0) {
        if (prop.additionalProperties === false) {
          // Empty object with no extra keys.
          return z.object({}).strict();
        }
        return z.record(z.string(), z.unknown());
      }
      let nestedObj = z.object(nestedShape);
      if (prop.additionalProperties === false) {
        nestedObj = nestedObj.strict();
      }
      return nestedObj;
    }
    default:
      return z.unknown();
  }
}

function buildZodSchema(schema: ToolInputSchema): z.ZodTypeAny {
  const shape: Record<string, z.ZodTypeAny> = {};
  // Tolerate schemas that omit `required` entirely (treat as no required fields).
  const required = Array.isArray(schema.required) ? schema.required : [];
  for (const [key, prop] of Object.entries(schema.properties || {})) {
    let zType = buildPropZod(prop, 1);
    if (!required.includes(key)) {
      zType = zType.optional();
    }
    shape[key] = zType;
  }
  let obj = z.object(shape);
  if (schema.additionalProperties === false) {
    obj = obj.strict();
  }
  return obj;
}

/**
 * Validate `args` against the per-tool inputSchema on `adapter.tools[i]`.
 * The federation-layer keystone hook for .
 */
export function validateAgainstToolSchema(
  adapter: AdapterWithTools,
  toolName: string,
  args: Record<string, unknown>,
): ValidationResult {
  const adapterId = adapter.id ?? '<unknown>';
  const toolMeta = adapter.tools?.find((t) => t.name === toolName);
  if (!toolMeta || !toolMeta.inputSchema) {
    warnOnceMissingSchema(adapterId, toolName);
    // CHARIOT_SCHEMA_STRICT=true → fail-closed when an adapter declares no
    // input schema. Default fail-open preserves the framing documented in
    // this file's header; operators who want strict input validation opt in.
    if (process.env.CHARIOT_SCHEMA_STRICT === 'true') {
      return {
        valid: false,
        errors: [{ path: '<root>', message: 'tool input schema missing (CHARIOT_SCHEMA_STRICT enabled)', code: 'custom' }],
      };
    }
    return { valid: true, reason: 'no-schema' };
  }
  const schema = buildZodSchema(toolMeta.inputSchema);
  const parsed = schema.safeParse(args);
  if (parsed.success) {
    return { valid: true, reason: 'ok' };
  }
  const errors = parsed.error.issues.map((iss) => ({
    path: iss.path.join('.') || '<root>',
    message: iss.message,
    code: iss.code,
  }));
  return { valid: false, errors };
}
