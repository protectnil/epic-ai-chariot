/**
 * IAM Module — Connection-String Redaction (CHARIOT rulings item 126,
 * unit W-IAM-REDACT).
 *
 * Root cause this unit closes: the shipped 3.1.1 gateway logged
 * "Chariot IAM bootstrap: mongo=<full URI with password> db=… redis=…" at
 * startup — a credential leak into any log sink. In the 4.0 tree, TWO
 * independent copies of a "redact the URI" helper already existed
 * (`src/iam/redactUri.ts`, and — despite that file's own doc comment
 * claiming it was "Extracted from engine/bin/setup.ts's prior local copy
 * ... so the two paths cannot drift" — an UN-MIGRATED local duplicate
 * still lived in `src/engine/bin/setup.ts`, never importing the shared
 * one) and NEITHER was applied to `src/iam/bootstrap.ts`'s
 * `throw new Error(...)` call whose template literal bare-interpolated
 * the raw mongoUri variable directly, which interpolated the RAW,
 * unredacted connection string (including any embedded username:password)
 * directly into a
 * thrown Error message — exactly the same class of leak the 3.1.1
 * incident named, just at a different call site. Two near-duplicate
 * redaction helpers coexisting, with one call site consulting neither, is
 * how this kind of gap happens — this module REPLACES both prior copies
 * as the single shared implementation.
 *
 * Contract (rulings item 126): reduce a connection-string URI to
 * scheme + host (+ port) + database/path ONLY before it is ever written
 * to a log line, thrown Error message, or emitted chariotEvent. Userinfo
 * (`user:pass@`) — the primary secret a connection string carries — is
 * REPLACED with the literal marker `<redacted>` when present (never
 * included, not even partially). The query string is DROPPED entirely
 * (not merely left as-is) — unlike the superseded `redactUri.ts`, which
 * preserved the full URL apart from userinfo — since a connection
 * string's query parameters are not guaranteed credential-free (e.g. a
 * driver-specific auth-mechanism property) and there is no safety
 * benefit to preserving them in a log line.
 *
 * Scheme-agnostic: `mongodb://`, `mongodb+srv://`, `redis://`, `rediss://`
 * (and any other scheme the WHATWG URL parser accepts) are all handled
 * identically — userinfo presence/absence is orthogonal to scheme, so no
 * scheme-specific branching is needed or present.
 */
export function redactConnectionString(uri: string): string {
  try {
    const u = new URL(uri);
    const hasUserinfo = u.username !== '' || u.password !== '';
    const db = u.pathname && u.pathname !== '/' ? u.pathname : '';
    const authority = hasUserinfo ? `<redacted>@${u.host}` : u.host;
    return `${u.protocol}//${authority}${db}`;
  } catch {
    // Not a parseable URL — suppress entirely rather than risk leaking
    // fragments of a malformed-but-still-credential-bearing string.
    return '<uri-redacted>';
  }
}
