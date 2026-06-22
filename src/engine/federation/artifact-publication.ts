import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { confinePath } from '../keys/pathConfinement.js';

export interface ArtifactManifest {
  versionDir: string;
}

export function resolvePublishedArtifactDir(
  packageRoot: string,
  manifestFileName: string,
  fallbackDir?: string,
): string {
  const manifestPath = join(packageRoot, manifestFileName);
  if (!existsSync(manifestPath)) return fallbackDir ?? packageRoot;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as Partial<ArtifactManifest>;
    if (typeof manifest.versionDir === 'string' && manifest.versionDir.length > 0) {
 // a writable manifest cannot steer downstream loaders
      // outside `packageRoot`, even via symlink. On reject, fall through
      // to the package-root default so the legitimate bundle is still
      // found.
      const confined = confinePath(manifest.versionDir, packageRoot);
      if (confined.ok) return confined.resolved;
    }
  } catch {
    // fall through to the compatibility path
  }
  return fallbackDir ?? packageRoot;
}
