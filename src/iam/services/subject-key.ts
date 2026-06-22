/**
 * IAM — Subject-Key → ExternalId derivation.
 *
 * Lifted into a standalone module to break the value-bearing import cycle
 * between id-jag-issuer.ts (which uses withSubjectLock at issuance time)
 * and subject-mutex.ts (which derives a lock key from the subject). Both
 * now depend on this module; neither depends on the other.
 *
 * The IETF ID-JAG draft (draft-ietf-oauth-identity-assertion-authz-grant)
 * defines several subject-identifier shapes; this function reduces every
 * shape to one injective external id used as the iam_users.externalId
 * primary key. Comparison rules per the draft are encoded per-variant.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { SubjectKey } from './id-jag-validator.js';

export function subjectKeyAsExternalId(key: SubjectKey): string {
  switch (key.kind) {
    case 'saml-nameid': {
      // SAML NameID values may legitimately contain ':', '=', and '\' (no
      // escaping is mandated by SAML). Without escaping, two distinct
      // (samlIssuer, nameid) tuples could collapse to the same byte
      // sequence — e.g. samlIssuer='Y', nameid='a:b' vs samlIssuer='Y:nameid=a',
      // nameid='b'. Each value is escaped (\ → \\, : → \c, = → \e) before
      // concatenation so the join is injective. Two saml-nameid sub_ids
      // that differ on any included member resolve to distinct local
      // subjects.
      const esc = (v: string): string => v.replace(/\\/g, '\\\\').replace(/:/g, '\\c').replace(/=/g, '\\e');
      const parts: string[] = [
        `iss=${esc(key.iss)}`,
        `saml_issuer=${esc(key.samlIssuer)}`,
        `nameid=${esc(key.nameid)}`,
      ];
      if (key.nameidFormat !== undefined) parts.push(`nameid_format=${esc(key.nameidFormat)}`);
      if (key.nameQualifier !== undefined) parts.push(`name_qualifier=${esc(key.nameQualifier)}`);
      if (key.spNameQualifier !== undefined) parts.push(`sp_name_qualifier=${esc(key.spNameQualifier)}`);
      if (key.spProvidedId !== undefined) parts.push(`sp_provided_id=${esc(key.spProvidedId)}`);
      return `id-jag-saml:${parts.join(':')}`;
    }
    case 'aud-sub':
      // When aud_tenant is present alongside aud_sub, the uniqueness
      // domain is (aud + aud_tenant + aud_sub). Two tokens with same
      // aud_sub but different aud_tenant must not collapse onto one
      // local subject.
      return key.audTenant !== undefined
        ? `id-jag:${key.iss}:aud_tenant=${key.audTenant}:aud_sub=${key.audSub}`
        : `id-jag:${key.iss}:aud_sub=${key.audSub}`;
    case 'sub-with-aud-tenant':
      return `id-jag:${key.iss}:aud_tenant=${key.audTenant}:sub=${key.sub}`;
    case 'sub-with-tenant':
      return `id-jag:${key.iss}:tenant=${key.tenant}:sub=${key.sub}`;
    case 'sub-only':
      return `id-jag:${key.iss}:sub=${key.sub}`;
    default: {
      // Exhaustiveness: TypeScript flags a missing case via this `never`
      // assignment. The throw is dead at runtime unless the union is
      // widened without updating this switch.
      const _exhaustive: never = key;
      throw new Error(`unhandled SubjectKey kind: ${JSON.stringify(_exhaustive)}`);
    }
  }
}
