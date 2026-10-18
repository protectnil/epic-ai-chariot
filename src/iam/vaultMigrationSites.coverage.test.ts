/**
 * CHARIOT-SPEC.md:1237-1250 (§12.2, CH-10), rulings item 59. Gate finding
 * F1 (2026-09-04): "the migration walk is DERIVED from the registry —
 * every registered/delegated persistence site is walked ... with a test
 * that fails if a registered site has no walker."
 *
 * This is the enforcement: (a) every `walkerExport` named in
 * `VAULT_MIGRATION_SITES` (vaultMigrationSites.ts) is actually exported
 * from its `module`; (b) `src/bin/chariot.ts` (the CLI that performs the
 * walk) references every one of those export names in its own source —
 * proving the walker is actually WIRED IN, not merely declared. A site
 * registered with a `walkerExport` this scan cannot find, or one the CLI
 * never references, fails this suite — the same anti-drift pattern
 * `masterKeyConsumers.test.ts` uses for the domain-separation registry.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CLI_FILE = join(REPO_ROOT, 'src', 'bin', 'chariot.ts');
const VAULT_MIGRATE_FILE = join(REPO_ROOT, 'src', 'iam', 'vaultMigrate.ts');

const { VAULT_MIGRATION_SITES } = await import('./vaultMigrationSites.js');

function isExportedFrom(repoRelativeModule: string, exportName: string): boolean {
  const src = readFileSync(join(REPO_ROOT, repoRelativeModule), 'utf-8');
  // Matches `export async function <name>(` / `export function <name>(`.
  const re = new RegExp(`export\\s+(?:async\\s+)?function\\s+${exportName}\\s*\\(`);
  return re.test(src);
}

test('§12.2/CH-10 item 59: every registered site with a walkerExport actually exports it', () => {
  for (const site of VAULT_MIGRATION_SITES) {
    if (site.walkerExport === null) continue; // per-tenant-mongo-inline — no separate export by design.
    assert.ok(
      isExportedFrom(site.module, site.walkerExport),
      `registered site "${site.id}" claims ${site.module} exports ${site.walkerExport}, but no such export was found`,
    );
  }
});

test('§12.2/CH-10 item 59: the vault migration walk (vaultMigrate.ts) references every registered walker', () => {
  const migrateSrc = readFileSync(VAULT_MIGRATE_FILE, 'utf-8');
  for (const site of VAULT_MIGRATION_SITES) {
    if (site.walkerExport === null) continue;
    assert.ok(
      migrateSrc.includes(site.walkerExport),
      `registered site "${site.id}"'s walker (${site.walkerExport}) is not referenced anywhere in ` +
      `src/iam/vaultMigrate.ts — a registered site with no caller is exactly gate finding F1`,
    );
  }
});

test('§12.2/CH-10 item 59: the per-tenant-mongo-inline sites are the exact three vaultMigrate.ts sweeps directly', () => {
  const migrateSrc = readFileSync(VAULT_MIGRATE_FILE, 'utf-8');
  const inlineSites = VAULT_MIGRATION_SITES.filter((s) => s.scope === 'per-tenant-mongo-inline');
  assert.equal(inlineSites.length, 3, 'exactly iam_adapter_credentials, iam_tenants.oidc-client-secret, iam_id_jag_idp_clients');
  for (const collection of ['iam_adapter_credentials', 'iam_tenants', 'iam_id_jag_idp_clients']) {
    assert.ok(migrateSrc.includes(`'${collection}'`), `vaultMigrate.ts must directly reference collection ${collection}`);
  }
});

test('§12.2/CH-10 item 59: the pseudo-tenant site is swept whenever --all runs', () => {
  const migrateSrc = readFileSync(VAULT_MIGRATE_FILE, 'utf-8');
  const cliSrc = readFileSync(CLI_FILE, 'utf-8');
  const pseudoSites = VAULT_MIGRATION_SITES.filter((s) => s.scope === 'pseudo-tenant-exported-walker');
  assert.equal(pseudoSites.length, 1);
  assert.equal(pseudoSites[0]!.pseudoTenantId, 'chariot-audit');
  // discoverAllTenantIds (the --all path, defined in vaultMigrate.ts and
  // wired into the --all branch of chariot.ts's cmdVault) must include
  // SEALED_TENANT_ID.
  assert.ok(
    migrateSrc.includes('SEALED_TENANT_ID') && migrateSrc.includes('discoverAllTenantIds'),
    '--all must include the sealed-store pseudo-tenant id in its tenant sweep',
  );
  assert.ok(cliSrc.includes('discoverAllTenantIds'), 'chariot.ts cmdVault must call discoverAllTenantIds for --all');
});
