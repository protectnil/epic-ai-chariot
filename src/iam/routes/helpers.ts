/**
 * IAM — Route Helpers
 *
 * Shared parameter parsers used by every admin-style route under
 * /enterprise. Extracted (Round-1 reuse pass 2026-05-25) so admin.ts
 * and admin-trust.ts (and future admin sub-routers) don't each
 * re-implement the same Express-5 param narrowing + ObjectId parsing
 * + Zod error formatting. Pure functions — no IO, no state — so a
 * later test can import them directly without spinning up Mongo.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { ObjectId } from 'mongodb';
import type { Request } from 'express';
import type { z } from 'zod';

/**
 * Narrow a single-segment route param to a non-empty string. Express 5
 * types `req.params[name]` as `string | string[]`; at runtime our
 * single-segment routes always carry a string. Returns null when the
 * param is missing, an array, or an empty string.
 */
export function getStringParam(req: Request, name: string): string | null {
  const value = req.params[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Parse a 24-hex-character ObjectId string. Returns the ObjectId on
 * success, or null if the input is not a valid 24-hex string. Use
 * instead of try/catch on `new ObjectId(...)`.
 */
export function parseObjectId(id: string | null): ObjectId | null {
  if (!id || !/^[0-9a-fA-F]{24}$/.test(id)) return null;
  return new ObjectId(id);
}

/**
 * Format a Zod ZodError into the "field.path: message; field2.path: ..."
 * string we return as the `detail` field of 400 responses across the
 * admin surface.
 */
export function detailFromZod(err: z.ZodError): string {
  return err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
}
