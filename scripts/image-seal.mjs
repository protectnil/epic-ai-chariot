/**
 * Shared helpers for the CH-54 image seal pipeline.
 *
 * These helpers stay intentionally small and dependency-free so they can be
 * reused by the release workflow, the ECS Lambda hook, and unit tests.
 */

function normalizeSha256Digest(digest) {
  const raw = typeof digest === 'string' ? digest.trim() : '';
  if (!raw) {
    throw new Error('image seal: digest is required');
  }

  const normalized = raw.toLowerCase().startsWith('sha256:') ? raw : `sha256:${raw}`;
  if (!/^sha256:[0-9a-f]{64}$/i.test(normalized)) {
    throw new Error(`image seal: invalid sha256 digest "${digest}"`);
  }

  return `sha256:${normalized.slice('sha256:'.length).toLowerCase()}`;
}

export function imageDigestRef(repository, digest) {
  const repo = typeof repository === 'string' ? repository.trim() : '';
  if (!repo) {
    throw new Error('image seal: repository is required');
  }
  return `${repo}@${normalizeSha256Digest(digest)}`;
}

// notationTrustPolicy() was removed: it was never imported (dead code). The
// trust policy ships as the static notation/trustpolicy.json and the
// Helm-rendered notation-trust-store ConfigMap — those are the single sources.

export function notationVerifyCommand({
  imageRef,
  pluginAwsRegion,
  pluginAwsProfile,
} = {}) {
  if (!imageRef || typeof imageRef !== 'string') {
    throw new Error('image seal: imageRef is required');
  }

  // No --trust-policy flag: `notation verify` has no such flag — it resolves
  // trustpolicy.json (and the trust store) from NOTATION_CONFIG, which the
  // caller exports to point at the shipped notation base dir.
  const args = ['verify', imageRef.trim()];
  if (pluginAwsRegion) {
    args.push('--plugin-config', `aws-region=${pluginAwsRegion}`);
  }
  if (pluginAwsProfile) {
    args.push('--plugin-config', `aws-profile=${pluginAwsProfile}`);
  }
  return args;
}

export function notationSignCommand({
  imageRef,
  signingProfileArn,
  pluginAwsRegion,
  pluginAwsProfile,
} = {}) {
  if (!imageRef || typeof imageRef !== 'string') {
    throw new Error('image seal: imageRef is required');
  }
  if (!signingProfileArn || typeof signingProfileArn !== 'string') {
    throw new Error('image seal: signingProfileArn is required');
  }

  const args = ['sign', imageRef.trim(), '--plugin', 'aws-signer', '--id', signingProfileArn.trim()];
  if (pluginAwsRegion) {
    args.push('--plugin-config', `aws-region=${pluginAwsRegion}`);
  }
  if (pluginAwsProfile) {
    args.push('--plugin-config', `aws-profile=${pluginAwsProfile}`);
  }
  return args;
}

export function notationTrustStorePaths(baseDir = '/opt/chariot/notation', {
  trustStoreType = 'signingAuthority',
  trustStoreNames = ['aws-signer-ts', 'aws-us-gov-signer-ts'],
} = {}) {
  const root = typeof baseDir === 'string' ? baseDir.trim() : '';
  if (!root) {
    throw new Error('image seal: baseDir is required');
  }

  const trustStoreDir = `${root}/truststore`;
  // notation discovers certs per NAMED trust store at
  // truststore/x509/<type>/<name>/ — a flat truststore/certs.pem is NOT read
  // (Notary Project trust-store spec; the trustpolicy references these names).
  const certDirs = trustStoreNames.map((name) => `${trustStoreDir}/x509/${trustStoreType}/${name}`);

  return {
    trustPolicyPath: `${root}/trustpolicy.json`,
    trustStoreDir,
    certDirs,
    certsPaths: certDirs.map((dir) => `${dir}/certs.pem`),
  };
}

export { normalizeSha256Digest };
