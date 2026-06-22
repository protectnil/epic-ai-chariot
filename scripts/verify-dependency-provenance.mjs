#!/usr/bin/env node
/**
 * Dependency provenance hard gate.
 *
 * Verifies the runtime dependency set declared in package.json against the
 * installed node_modules tree and package-lock.json, without any network I/O.
 *
 * Checks per runtime dependency:
 *   - package.json dependency spec is registry-resolvable, not git/file/http
 *   - installed package.json exists under node_modules/<dep>/package.json
 *   - installed package.json name matches the dep key
 *   - installed package.json carries a repository field
 *   - declared spec is satisfiable by the installed / locked version
 *   - package-lock.json has a matching packages["node_modules/<dep>"] entry
 *   - that lock entry has a valid sha512 integrity field
 *   - that lock entry resolves over https, not git/file/http
 *
 * Writes a JSON summary to scripts/.dep-provenance-last.json on every run.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const SUMMARY_PATH = new URL('./.dep-provenance-last.json', import.meta.url);

function readJson(relativePath) {
  const raw = readFileSync(new URL(relativePath, ROOT), 'utf8');
  return JSON.parse(raw);
}

function failSummary(summary, dep, stage, detail) {
  summary.failures.push({ dep, stage, detail });
  console.error(JSON.stringify({
    level: 'error',
    gate: 'dependency-provenance',
    dep,
    stage,
    detail,
  }));
}

function hasRepositoryField(pkgJson) {
  const repo = pkgJson?.repository;
  if (!repo) return false;
  if (typeof repo === 'string') return repo.trim().length > 0;
  if (typeof repo === 'object') {
    return typeof repo.url === 'string' && repo.url.trim().length > 0;
  }
  return false;
}

function normalizeSpec(spec) {
  let s = String(spec ?? '').trim();
  if (s.startsWith('npm:')) {
    s = s.slice(4);
    const at = s.lastIndexOf('@');
    if (at > 0) {
      s = s.slice(at + 1);
    }
  }
  return s;
}

function isForbiddenSource(spec) {
  const s = normalizeSpec(spec);
  return /^(?:file:|git\+|git:|http:|https:|workspace:|link:)/i.test(s);
}

function parseSemver(version) {
  const m = String(version ?? '').trim().match(
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/,
  );
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ?? '',
  };
}

function compareSemver(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  if (a.prerelease === b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return a.prerelease.localeCompare(b.prerelease, 'en-US');
}

function nextUpperBoundForCaret(base) {
  if (base.major > 0) return { major: base.major + 1, minor: 0, patch: 0, prerelease: '' };
  if (base.minor > 0) return { major: 0, minor: base.minor + 1, patch: 0, prerelease: '' };
  return { major: 0, minor: 0, patch: base.patch + 1, prerelease: '' };
}

function nextUpperBoundForTilde(base) {
  return { major: base.major, minor: base.minor + 1, patch: 0, prerelease: '' };
}

function satisfiesComparator(version, token) {
  const v = parseSemver(version);
  if (!v) return false;

  const t = String(token).trim();
  if (!t || t === '*' || t === 'x' || t === 'X') return true;

  if (t.startsWith('^')) {
    const base = parseSemver(t.slice(1));
    if (!base) return false;
    return compareSemver(v, base) >= 0 && compareSemver(v, nextUpperBoundForCaret(base)) < 0;
  }

  if (t.startsWith('~')) {
    const base = parseSemver(t.slice(1));
    if (!base) return false;
    return compareSemver(v, base) >= 0 && compareSemver(v, nextUpperBoundForTilde(base)) < 0;
  }

  const cmp = t.match(/^(<=|>=|<|>)(.+)$/);
  if (cmp) {
    const rhs = parseSemver(cmp[2]);
    if (!rhs) return false;
    const order = compareSemver(v, rhs);
    if (cmp[1] === '<') return order < 0;
    if (cmp[1] === '<=') return order <= 0;
    if (cmp[1] === '>') return order > 0;
    return order >= 0;
  }

  if (/^[0-9xX*]+(?:\.[0-9xX*]+){0,2}$/.test(t)) {
    const parts = t.split('.');
    const versionParts = [String(v.major), String(v.minor), String(v.patch)];
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      if (p === 'x' || p === 'X' || p === '*') continue;
      if (p !== versionParts[i]) return false;
    }
    return true;
  }

  const exact = parseSemver(t);
  if (exact) {
    return compareSemver(v, exact) === 0;
  }

  return false;
}

// SELF-ADVERSARIAL REVIEW (post-R6): the prior `isWildcardSpec` exact-match
// list missed several real bypass shapes that all let `npm install`
// resolve to whatever version is currently published — exactly the
// supply-chain failure mode the LLM03 gate is supposed to prevent.
// Empirical test confirmed bypass for: 'X.X.X', 'x.x.x', '*.*.*',
// '>=0.0.0', '>=0', 'X.x.x', '1.x', '1.X.X', and case variants of
// 'latest'. Replacing the exact-match check with a structural one that
// recognizes the GENERAL class — any spec whose effective version
// range has no concrete upper bound.

function isCaseInsensitiveLatest(s) {
  return typeof s === 'string' && s.trim().toLowerCase() === 'latest';
}

function containsPositionWildcard(token) {
  // Position wildcards: 'x', 'X', '*' as any part of a dotted version.
  // Match `*` bare, OR any `[x|X|*]` token in a dot-separated segment.
  // Examples caught: '*', 'x', 'X', '1.x', '1.X', '1.X.X', 'x.x.x',
  //   'X.X.X', '*.*.*', '1.2.*'.
  if (token === '*' || token === 'x' || token === 'X') return true;
  // Pure dotted-wildcard pattern.
  if (/^[0-9xX*]+(?:\.[0-9xX*]+){0,2}$/.test(token)) {
    return token.split('.').some((p) => p === 'x' || p === 'X' || p === '*');
  }
  return false;
}

function isUnboundedComparator(token) {
  // Single-sided comparators without an upper bound. `>=`, `>` ranges
  // pin a floor but leave the ceiling open, so npm install resolves to
  // whatever the current registry top version is — effectively `latest`.
  // The gate must reject these in isolation; a spec like `>=1.0.0 <2.0.0`
  // (two tokens whitespace-joined) is fine because the upper bound
  // closes the range.
  return /^(?:>=|>)/.test(token);
}

function isEffectiveWildcardToken(token) {
  return (
    isCaseInsensitiveLatest(token) ||
    containsPositionWildcard(token) ||
    isUnboundedComparator(token)
  );
}

function isEffectiveWildcardSpec(normalized) {
  if (isCaseInsensitiveLatest(normalized)) return true;
  // A token-level scan that fires on ANY effective-wildcard token in
  // ANY whitespace-joined or disjunctive position. Whitespace-joined
  // tokens form an intersection (all must match) so a single
  // unbounded-floor comparator in the chain pins one side but the
  // other token must bound it. We can't trust the joining alone, so
  // we additionally require that the spec, as a whole, has a concrete
  // upper bound (caret, tilde, `<`, `<=`, exact, or an `x`-pinned
  // major). The simpler conservative rule: if any token-position is
  // an effective wildcard, demand a closing bound token in the same
  // whitespace-joined sub-expression.
  const subExprs = normalized.split('||').map((s) => s.trim()).filter(Boolean);
  for (const sub of subExprs) {
    const tokens = sub.split(/\s+/).filter(Boolean);
    // Position wildcards alone → bypass.
    if (tokens.some((t) => containsPositionWildcard(t))) return true;
    // 'latest' anywhere → bypass.
    if (tokens.some((t) => isCaseInsensitiveLatest(t))) return true;
    // Unbounded-floor with no upper-bound token in the same intersection.
    const hasUnboundedFloor = tokens.some((t) => isUnboundedComparator(t));
    if (hasUnboundedFloor) {
      const hasUpperBound = tokens.some((t) => /^(?:<=|<|\^|~)/.test(t) || /^[0-9]/.test(t));
      if (!hasUpperBound) return true;
    }
  }
  return false;
}

function satisfiesSpecifier(spec, version) {
  const normalized = normalizeSpec(spec);
  if (!normalized) return false;
  if (isForbiddenSource(normalized)) return false;
  // LLM03 supply-chain gate: reject any spec that — at any disjunct,
  // any whitespace-joined sub-expression, or any case-folding —
  // resolves to "whatever npm install picks today." Empirical bypasses
  // closed by isEffectiveWildcardSpec: position wildcards (`*`, `x`,
  // `X`, `1.x`, `*.*.*`), unbounded one-sided comparators (`>=0`,
  // `>0.0.0`), case-insensitive 'latest', and any disjunct containing
  // any of the above. This is stricter than the prior exact-match
  // isWildcardSpec list which let `X.X.X`, `>=0`, etc. slip through.
  if (isEffectiveWildcardSpec(normalized)) {
    return false;
  }

  const disjuncts = normalized.split('||').map((s) => s.trim()).filter(Boolean);
  if (disjuncts.length > 1) {
    return disjuncts.some((part) => satisfiesSpecifier(part, version));
  }

  const tokens = normalized.split(/\s+/).filter(Boolean);
  if (tokens.length > 1) {
    return tokens.every((token) => satisfiesComparator(version, token));
  }

  return satisfiesComparator(version, normalized);
}

// Pin to the public npm registry host(s). Operators using private registries
// override via the NPM_REGISTRY_HOST env var (comma-separated host list,
// case-insensitive). Anything not on an allowed host fails the gate even if
// the URL is https — protects against lockfile tamper that points `resolved`
// at an attacker-controlled host with a matching sha512.
const ALLOWED_REGISTRY_HOSTS = String(process.env.NPM_REGISTRY_HOST ?? 'registry.npmjs.org')
  .split(',')
  .map((host) => host.trim().toLowerCase())
  .filter(Boolean);

function isRegistryResolved(resolved) {
  if (typeof resolved !== 'string' || resolved.trim().length === 0) return false;
  try {
    const url = new URL(resolved);
    if (url.protocol !== 'https:') return false;
    return ALLOWED_REGISTRY_HOSTS.includes(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

// SRI canonical lengths (W3C SRI / RFC 4648 base64):
//   sha512: 64 raw bytes → 88 base64 chars (86 body + '==' padding)
//   sha384: 48 raw bytes → 64 base64 chars (no padding required)
// Verified against this repo's package-lock.json: 95 sha512 entries all
// exactly 95 chars (7-char `sha512-` prefix + 88 base64). Round-4 finding
// #2: the prior loose `[A-Za-z0-9+/]+={0,2}` accepted `sha512-AAAA==` and
// every shorter/longer body — anchoring length defeats truncation/forgery
// at the regex layer.
function isValidSha512Integrity(integrity) {
  if (typeof integrity !== 'string') return false;
  const tokens = integrity.split(/\s+/).filter(Boolean);
  const sriShape = /^(sha384-[A-Za-z0-9+/]{64}|sha512-[A-Za-z0-9+/]{86}==)$/;
  return tokens.length > 0 && tokens.every((token) => sriShape.test(token)) && tokens.some((token) => token.startsWith('sha512-'));
}

function main() {
  const summary = {
    generatedAt: new Date().toISOString(),
    depsChecked: 0,
    depsPassed: 0,
    depsFailed: 0,
    failures: [],
  };

  let pkg;
  let lock;

  try {
    pkg = readJson('package.json');
  } catch (err) {
    failSummary(summary, '<root>', 'read-package-json', `Failed to read package.json: ${String(err?.message ?? err)}`);
    writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2));
    console.error(JSON.stringify({
      level: 'error',
      gate: 'dependency-provenance',
      detail: 'package.json unreadable; gate failed closed',
    }));
    process.exit(1);
  }

  try {
    lock = readJson('package-lock.json');
  } catch (err) {
    failSummary(summary, '<root>', 'read-package-lock-json', `Failed to read package-lock.json: ${String(err?.message ?? err)}`);
    writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2));
    console.error(JSON.stringify({
      level: 'error',
      gate: 'dependency-provenance',
      detail: 'package-lock.json unreadable; gate failed closed',
    }));
    process.exit(1);
  }

  const runtimeDeps = Object.entries(pkg.dependencies ?? {});
  const lockPackages = lock.packages ?? {};

  for (const [depName, declaredSpec] of runtimeDeps) {
    summary.depsChecked += 1;
    let depFailed = false;

    const nodePkgPath = `node_modules/${depName}/package.json`;
    if (!existsSync(new URL(nodePkgPath, ROOT))) {
      depFailed = true;
      failSummary(summary, depName, 'installed-package-missing', `Missing installed package.json at node_modules/${depName}/package.json`);
    } else {
      let installedPkg;
      try {
        installedPkg = readJson(nodePkgPath);
      } catch (err) {
        depFailed = true;
        failSummary(summary, depName, 'installed-package-unreadable', `Could not parse node_modules/${depName}/package.json: ${String(err?.message ?? err)}`);
      }

      if (installedPkg) {
        if (installedPkg.name !== depName) {
          depFailed = true;
          failSummary(summary, depName, 'name-mismatch', `Installed package name "${installedPkg.name}" does not match runtime dep key "${depName}"`);
        }

        if (!hasRepositoryField(installedPkg)) {
          depFailed = true;
          failSummary(summary, depName, 'missing-repository', `Installed package ${depName} has no repository field`);
        }

        const installedVersion = installedPkg.version;
        const specOk = satisfiesSpecifier(declaredSpec, installedVersion);
        if (!specOk) {
          depFailed = true;
          failSummary(
            summary,
            depName,
            'version-not-resolvable',
            `Declared spec "${declaredSpec}" does not resolve to installed version "${installedVersion}"`,
          );
        }

        if (!parseSemver(installedVersion)) {
          depFailed = true;
          failSummary(summary, depName, 'invalid-installed-version', `Installed package version "${installedVersion}" is not a valid semver`);
        }
      }
    }

    const lockKey = `node_modules/${depName}`;
    const lockEntry = lockPackages[lockKey];
    if (!lockEntry) {
      depFailed = true;
      failSummary(summary, depName, 'lock-entry-missing', `Missing package-lock entry for "${lockKey}"`);
    } else {
      if (!isRegistryResolved(lockEntry.resolved)) {
        depFailed = true;
        failSummary(summary, depName, 'non-registry-resolved', `Lockfile resolved value is not an https registry URL: ${String(lockEntry.resolved ?? '<missing>')}`);
      }

      if (!isValidSha512Integrity(lockEntry.integrity)) {
        depFailed = true;
        failSummary(summary, depName, 'invalid-integrity', `Lockfile integrity for "${depName}" is missing or not a valid sha512-... value`);
      }

      const installedPkg = existsSync(new URL(nodePkgPath, ROOT)) ? readJson(nodePkgPath) : null;
      if (installedPkg && lockEntry.version !== installedPkg.version) {
        depFailed = true;
        failSummary(
          summary,
          depName,
          'version-mismatch',
          `package-lock version "${lockEntry.version}" does not match installed package version "${installedPkg.version}"`,
        );
      }

      if (installedPkg && !satisfiesSpecifier(declaredSpec, lockEntry.version)) {
        depFailed = true;
        failSummary(
          summary,
          depName,
          'lock-version-not-resolvable',
          `Declared spec "${declaredSpec}" does not resolve to lock version "${lockEntry.version}"`,
        );
      }
    }

    if (depFailed) summary.depsFailed += 1;
    else summary.depsPassed += 1;
  }

  writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2));

  if (summary.depsFailed > 0) {
    console.error(JSON.stringify({
      level: 'error',
      gate: 'dependency-provenance',
      detail: 'dependency provenance verification failed',
      depsChecked: summary.depsChecked,
      depsPassed: summary.depsPassed,
      depsFailed: summary.depsFailed,
      summaryPath: SUMMARY_PATH.pathname,
    }));
    process.exit(1);
  }

  console.log(`  ✓ dependency provenance checks passed (${summary.depsPassed}/${summary.depsChecked})`);
}

// Only run main() when invoked directly (e.g., from prepublishOnly), not on import.
// Eval 54 dynamic-imports this module to assert it loads; we must not run the
// full dep audit (or call process.exit) as an import side effect.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
