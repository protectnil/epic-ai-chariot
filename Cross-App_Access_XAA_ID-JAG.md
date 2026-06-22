# Epic AI® Chariot — Cross-App Access (XAA / ID-JAG)

Chariot is a **Cross-App Access (XAA)** resource server. XAA — realized over
OAuth 2.0 as the IETF **Identity Assertion Authorization Grant (ID-JAG)**,
`draft-ietf-oauth-identity-assertion-authz-grant` — lets an enterprise
identity provider broker scoped, short-lived access to another application's
API on behalf of a user, without a per-integration consent screen and without
static API keys. It is the MCP authorization pattern for secure
**agent-to-app** and **app-to-app** access, with the IdP as the single point
of policy, revocation, and audit.

> Status: ID-JAG is an active IETF Internet-Draft (`-04`), not yet a published
> RFC. Chariot tracks the draft and the surrounding OAuth RFCs it profiles.

## What Chariot implements

Chariot now implements the IETF Identity Assertion Authorization Grant
(`draft-ietf-oauth-identity-assertion-authz-grant`) as a Resource AS,
including RFC 7523 JWT-bearer grant exchange, RFC 9449 DPoP sender-constrained
tokens, RFC 8707 resource indicators, RFC 9396 rich authorization requests,
and RFC 7009 token revocation. A single `chariot serve --http` process exposes
the full surface: `/mcp`, `/enterprise/oauth/token`, `/enterprise/oauth/revoke`,
`/health`, and `/.well-known/oauth-authorization-server` (RFC 8414).

The practical result: an enterprise IdP can broker access to Chariot adapters
on behalf of users via a signed ID-JAG assertion. No per-app consent prompts.
No shared secrets between apps. No static API keys on the Chariot side. The
IdP stays the single point of policy, revocation, and audit for every
agent-to-app and app-to-app call.

## The flow

```
1. User Authentication (SSO)         RFC 7636 PKCE            → IdP
2. Token Exchange  (ID Token → ID-JAG)   RFC 8693            → IdP
3. JWT-Bearer Grant (ID-JAG → access token)  RFC 7523        → Chariot /enterprise/oauth/token
4. Tool call  (access token → MCP tools/call)                → Chariot /mcp
```

Verified end-to-end against the Okta **xaa.dev** Cross App Access sandbox:
SSO (RFC 7636 PKCE) → Token Exchange (RFC 8693) → ID-JAG JWT-bearer grant
(RFC 7523) → MCP `tools/call` all return `200` against a live deployment.

## Highlights

* **Stateless StreamableHTTP MCP transport** (`sessionIdGenerator: undefined`,
  `enableJsonResponse: true`). Per-request JWT signature verification derives a
  stable session key from the access-token `jti` claim and threads it through
  AsyncLocalStorage so the `chariot_query` → `chariot_call` surface-state gate
  stays enforceable for browser-origin MCP clients that do not echo
  `Mcp-Session-Id`.

* **Tenant resolved from the authenticated client**, not a request header. The
  Resource-AS tenant is derived from the presented `client_id`'s registration
  (draft §6.2); when the same `client_id` is registered in more than one tenant
  it is disambiguated by which registration the presented client credential
  authenticates against. The `aud_tenant` claim is a subject-keying dimension
  (draft §3.1 — `aud + aud_tenant + aud_sub` is unique within the Resource AS),
  NOT a tenant gate at the `/token` (Resource AS §4.4) endpoint; the §6.4
  tenant-context rule binds the IdP at ID-JAG issuance, not the Resource AS at
  redemption.

* **Sender-constrained tokens (RFC 9449 DPoP).** A `cnf` claim is enforced
  against the presented DPoP proof; a tenant may require sender-constrained
  tokens, in which case an unconstrained (Bearer) grant is rejected.

* **In-process per-`(tenantId, subjectKey)` and per-tenant audit mutexes** so
  same-subject token bursts serialize cleanly through `findOneAndUpdate` + the
  hash-chain CAS loop instead of thrashing E11000 retries under contention.

* **`/health`** probe with structured liveness + dependency status. Safe to
  expose publicly: no secrets, no env keys, no internal paths in the payload.

* **39 hermetic hard-gate evals** exercising the full spec surface: happy-path
  issuance, signature / expiry / audience / issuer rejection, `jti` replay,
  JWKS rotation, cross-tenant isolation, multi-tenant subject keying, RFC 8707
  resource narrowing, RFC 9396 RAR intersection, deprovisioned-user lockout,
  revocation, license gating, per-client rate limiting, RFC 9449 DPoP issuance
  + `cnf` enforcement + `ath` claim + proof replay + revocation, draft
  §3.1/§3.2 `sub_id` alias semantics, same-subject burst serialization, and
  cross-access-token isolation of the session-surface gate.

## Deployment

Production deployment (external state store, restart survival, the reference
`systemd` unit, and the full environment contract — `REDIS_URL`,
`MONGODB_URI`, secrets) is documented in
[`DEPLOYMENT-REGULATED-ENVIRONMENTS.md`](./DEPLOYMENT-REGULATED-ENVIRONMENTS.md)
under **Cross-App Access deployment**.
