/**
 * @epicai/chariot — Docker dispatch integrity constants
 * Single source of truth for the docker-run image/digest format gates, shared
 * by the dispatcher (toolHandlers) and the dispatchability predicate
 * (ChariotState.isDispatchable) so the two cannot drift.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

/**
 * Safe docker image ref: lower-case [registry-host/]namespace/repo — two or
 * more "/"-separated segments (so registry-qualified refs like
 * ghcr.io/owner/img and gcr.io/proj/img are accepted), with no tag or digest
 * suffix and no shell-unsafe characters (prevents flag injection into the
 * docker run argv).
 */
export const DOCKER_SAFE_IMAGE_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/;

/** Immutable digest pin: "sha256:" + 64 lowercase hex chars. */
export const DOCKER_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/**
 * A docker-run adapter is dispatchable iff BOTH its image ref and digest are
 * present and well-formed. Used at load time (isDispatchable) so a
 * format-invalid docker row is undispatchable rather than dispatchable-then-
 * refused at call time.
 */
export function isValidDockerPin(dockerImage: unknown, dockerDigest: unknown): boolean {
  return (
    typeof dockerImage === 'string' && DOCKER_SAFE_IMAGE_RE.test(dockerImage) &&
    typeof dockerDigest === 'string' && DOCKER_DIGEST_RE.test(dockerDigest)
  );
}
