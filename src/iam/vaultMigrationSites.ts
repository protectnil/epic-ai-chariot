/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10). Rulings item 59: "One-shot
 * MIGRATION ... walks every stored ciphertext, upgrades legacy ones,
 * reports counts {legacy, upgraded, failed, alreadyV2}".
 *
 * Machine-readable manifest of every persistence site `chariot vault
 * migrate` (src/bin/chariot.ts) MUST walk before it may write a tenant's
 * `iam_vault_migrations` marker. Gate finding F1 (2026-09-04): the
 * migration walked only the three Mongo collections directly, while
 * `masterKeyConsumers.ts` documents THREE MORE delegates of the same
 * credential-vault primitive — `src/engine/audit/chainSigner.ts` (sealed
 * signing-key artifact), `src/engine/recovery/SqliteCheckpointStore.ts`
 * (checkpoint rows), and `src/iam/services/session.ts` (Redis ID-JAG
 * subject_token records) — so a marker could be written while legacy
 * ciphertext remained in any of those three, a hard-cutover violation.
 *
 * `vaultMigrationSites.coverage.test.ts` (colocated) is the automated
 * enforcement: it source-scans this file's `module` for each entry and
 * fails if the named `walkerExport` is not actually exported there, and
 * source-scans `src/iam/vaultMigrate.ts` and fails if it does not reference
 * every `walkerExport` symbol — so an entry registered here with no real
 * walker, or a walker the CLI never calls, fails the suite instead of
 * silently under-covering the migration.
 *
 * Adding a NEW credential-vault-formula persistence site REQUIRES an
 * entry here in the SAME change, with a walker wired into
 * `chariot vault migrate` — the coverage test fails closed on drift.
 */

export type VaultMigrationSiteScope =
  /** Mongo collection(s), filtered by a real tenantId — walked inline by migrateTenant() in vaultMigrate.ts. */
  | 'per-tenant-mongo-inline'
  /** A named exported walker function, called once per real tenantId swept. */
  | 'per-tenant-exported-walker'
  /**
   * A named exported walker for a site with NO real per-tenant identity
   * (a single, process-wide artifact) — walked once per migration run,
   * under a fixed pseudo-tenant id, when that id is included in the sweep.
   */
  | 'pseudo-tenant-exported-walker';

export interface VaultMigrationSiteDescriptor {
  /** Stable identifier, used in test failure messages and CLI reporting. */
  readonly id: string;
  /** Repo-relative path of the file that owns this site's storage + walker. */
  readonly module: string;
  /**
   * Exported function name the CLI calls to walk this site, or `null` for
   * `per-tenant-mongo-inline` scope (the three original Mongo collections
   * migrateTenant() already sweeps directly — no separate export exists
   * for those, by design, since they share one Mongo connection/loop).
   */
  readonly walkerExport: string | null;
  readonly scope: VaultMigrationSiteScope;
  /** For a pseudo-tenant site, the fixed id it is swept under. */
  readonly pseudoTenantId?: string;
}

export const VAULT_MIGRATION_SITES: readonly VaultMigrationSiteDescriptor[] = [
  {
    id: 'iam_adapter_credentials',
    module: 'src/iam/vaultMigrate.ts',
    walkerExport: null,
    scope: 'per-tenant-mongo-inline',
  },
  {
    id: 'iam_tenants.oidc-client-secret',
    module: 'src/iam/vaultMigrate.ts',
    walkerExport: null,
    scope: 'per-tenant-mongo-inline',
  },
  {
    id: 'iam_id_jag_idp_clients',
    module: 'src/iam/vaultMigrate.ts',
    walkerExport: null,
    scope: 'per-tenant-mongo-inline',
  },
  {
    id: 'session-idjag-subject-token',
    module: 'src/iam/services/session.ts',
    walkerExport: 'walkLegacyIdJagSubjectTokens',
    scope: 'per-tenant-exported-walker',
  },
  {
    id: 'sqlite-checkpoint-store',
    module: 'src/engine/recovery/SqliteCheckpointStore.ts',
    walkerExport: 'walkLegacyCheckpointCiphertexts',
    scope: 'per-tenant-exported-walker',
  },
  {
    id: 'sealed-audit-signing-key',
    module: 'src/engine/audit/chainSigner.ts',
    walkerExport: 'walkSealedStoreLegacyArtifacts',
    scope: 'pseudo-tenant-exported-walker',
    pseudoTenantId: 'chariot-audit',
  },
] as const;
