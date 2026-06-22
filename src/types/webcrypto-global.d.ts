// WebCrypto `CryptoKey` global shim.
//
// `jose`'s `importJWK()` return type and the IAM DPoP / ID-JAG validator code
// reference the global `CryptoKey` interface. That global is provided either by
// `lib.dom`/`lib.webworker` (not enabled — they would redefine `fetch`/`BodyInit`
// and break Node fetch typing) or by a recent enough `@types/node`. To stay
// independent of the installed `@types/node` version (CI's clean install pins a
// version that does not declare it, which broke `npm run typecheck` in the
// release workflow), declare the global here.
//
// Empty by design: the type is used opaquely (constructed by `importJWK`, passed
// back into `jose`); no members are accessed. The empty interface merges cleanly
// with any `@types/node`-provided `CryptoKey` (no conflicting members) and
// provides it where that declaration is absent.
export {};

declare global {
  interface CryptoKey {}
}
