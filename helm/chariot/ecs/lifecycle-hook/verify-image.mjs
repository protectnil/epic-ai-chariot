import { promisify } from 'node:util';
import { execFile as execFileCb } from 'node:child_process';
import { existsSync } from 'node:fs';
import {
  ECSClient,
  StopTaskCommand,
  DescribeServiceRevisionsCommand,
} from '@aws-sdk/client-ecs';
import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import {
  imageDigestRef,
  notationTrustStorePaths,
  notationVerifyCommand,
} from '../../../../scripts/image-seal.mjs';

const execFile = promisify(execFileCb);

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;

function resolveRegion(hookDetails = {}) {
  return (
    hookDetails.awsRegion ||
    hookDetails.region ||
    process.env.AWS_REGION ||
    process.env.AWS_DEFAULT_REGION ||
    'us-east-1'
  );
}

/**
 * Build a digest-pinned image reference from an ECS ContainerImage
 * ({ image, imageDigest }). The digest is the source of truth — we always pin
 * to imageDigest, stripping any tag or pre-existing digest from `image` so a
 * tag-pinned task definition still yields a `repository@sha256:…` ref that
 * notation can verify against the exact manifest ECS is deploying. Returns null
 * when the digest is missing/malformed.
 */
function digestRefFromContainerImage(image, imageDigest) {
  if (typeof imageDigest !== 'string' || !SHA256_RE.test(imageDigest.trim())) {
    return null;
  }
  const digest = imageDigest.trim().toLowerCase();
  const raw = typeof image === 'string' ? image.trim() : '';
  if (!raw) return null;

  // Strip any existing @digest, then any trailing :tag (a colon AFTER the last
  // slash — a colon before the last slash is a registry-host port and must be
  // preserved).
  let repo = raw.split('@')[0];
  const lastSlash = repo.lastIndexOf('/');
  const lastColon = repo.lastIndexOf(':');
  if (lastColon > lastSlash) {
    repo = repo.slice(0, lastColon);
  }
  if (!repo) return null;
  return `${repo}@${digest}`;
}

/**
 * Resolve the image reference(s) ECS is ACTUALLY deploying, so verification is
 * bound to the deploying artifact rather than a static config string that an
 * actor with ecs:UpdateService could point elsewhere. Returns an array of
 * digest-pinned refs to verify.
 *
 * Precedence:
 *   1. When executionDetails.targetServiceRevisionArn is present (every real
 *      ECS deployment lifecycle hook), DescribeServiceRevisions is the source
 *      of truth: every container image in the deploying revision is verified,
 *      and hookDetails.imageReference (if set) is only a MANDATORY cross-check
 *      that must match one of the resolved images (fail closed on drift).
 *   2. When the event carries ECS deployment context (serviceArn/clusterArn)
 *      but no targetServiceRevisionArn, we cannot bind to the deploying image
 *      → fail closed.
 *   3. Only for a context-free manual/offline invocation do we fall back to
 *      verifying hookDetails.imageReference directly (still digest-pinned).
 */
async function resolveDeployingImageRefs({ hookDetails = {}, executionDetails = {}, ecsClient }) {
  let crossCheck = null;
  if (typeof hookDetails.imageReference === 'string' && hookDetails.imageReference.trim()) {
    crossCheck = hookDetails.imageReference.trim();
  } else if ((hookDetails.imageRepository || hookDetails.repository) && (hookDetails.imageDigest || hookDetails.digest)) {
    crossCheck = imageDigestRef(
      hookDetails.imageRepository || hookDetails.repository,
      hookDetails.imageDigest || hookDetails.digest,
    );
  }
  if (crossCheck && !crossCheck.includes('@sha256:')) {
    throw new Error('image seal: hookDetails.imageReference must be pinned by immutable digest');
  }

  const targetArn = executionDetails.targetServiceRevisionArn;

  if (targetArn) {
    const res = await ecsClient.send(
      new DescribeServiceRevisionsCommand({ serviceRevisionArns: [targetArn] }),
    );
    const revisions = res?.serviceRevisions ?? [];
    if (revisions.length === 0) {
      throw new Error(`could not resolve deploying service revision ${targetArn}`);
    }
    const containerImages = revisions[0].containerImages ?? [];
    if (containerImages.length === 0) {
      throw new Error(`deploying service revision ${targetArn} reports no container images`);
    }
    const refs = [];
    for (const ci of containerImages) {
      const ref = digestRefFromContainerImage(ci.image, ci.imageDigest);
      if (!ref) {
        throw new Error(
          `deploying container "${ci.containerName ?? 'unknown'}" has no resolvable image digest ` +
            `(image=${ci.image ?? 'unset'}, digest=${ci.imageDigest ?? 'unset'})`,
        );
      }
      refs.push(ref);
    }
    if (crossCheck && !refs.includes(crossCheck)) {
      throw new Error(
        `configured hookDetails.imageReference (${crossCheck}) does not match any image in the ` +
          `deploying revision [${refs.join(', ')}] — refusing to verify a proxy instead of the ` +
          'deploying artifact',
      );
    }
    return refs;
  }

  // No targetServiceRevisionArn. If this is nonetheless an ECS deployment event
  // (it carries deployment context), we cannot bind verification to the
  // deploying image and must fail closed rather than trust the config string.
  if (executionDetails.serviceArn || executionDetails.clusterArn || executionDetails.resourceArn) {
    throw new Error(
      'ECS deployment hook is missing executionDetails.targetServiceRevisionArn; cannot resolve the ' +
        'image being deployed — refusing to verify against the static hookDetails.imageReference',
    );
  }

  // Context-free manual/offline invocation: verify the supplied digest ref.
  if (!crossCheck) {
    throw new Error('image seal: hookDetails.imageReference or hookDetails.imageRepository + imageDigest is required');
  }
  return [crossCheck];
}

function resolveNotaryPaths(hookDetails = {}) {
  const baseDir = hookDetails.notationBaseDir || process.env.CHARIOT_NOTATION_BASE_DIR || '/opt/chariot/notation';
  return { ...notationTrustStorePaths(baseDir), baseDir };
}

function buildFailureMessage(imageRef, reason, executionDetails = {}) {
  const serviceArn = executionDetails.serviceArn || 'unknown-service';
  const deploymentArn = executionDetails.targetServiceRevisionArn || executionDetails.resourceArn || 'unknown-deployment';
  return [
    'chariot-gateway image signature verification failed',
    `image=${imageRef}`,
    `service=${serviceArn}`,
    `deployment=${deploymentArn}`,
    `reason=${reason}`,
  ].join(' ');
}

async function publishAlert({ snsClient, topicArn, subject, message, attributes = {} }) {
  if (!topicArn) return;
  await snsClient.send(new PublishCommand({
    TopicArn: topicArn,
    Subject: subject.slice(0, 100),
    Message: message,
    MessageAttributes: Object.fromEntries(
      Object.entries(attributes).map(([key, value]) => [
        key,
        { DataType: 'String', StringValue: String(value) },
      ]),
    ),
  }));
}

async function stopTaskIfRequested({ ecsClient, hookDetails = {}, executionDetails = {} }) {
  const stopTask = hookDetails.stopTask !== false;
  if (!stopTask) return;

  const clusterArn = hookDetails.clusterArn || executionDetails.clusterArn;
  const taskArn = hookDetails.taskArn || executionDetails.taskArn;
  if (!clusterArn || !taskArn) return;

  await ecsClient.send(new StopTaskCommand({
    cluster: clusterArn,
    task: taskArn,
    reason: hookDetails.stopReason || 'chariot image seal rejected invalid or absent signature',
  }));
}

/**
 * Emit the structured FAILED deny response, best-effort alerting + task-stop.
 * Shared by the resolution-failure path and the signature-verify-failure path
 * so a security deny always stops the task and alerts before returning FAILED.
 */
async function buildDenyResult({
  reason,
  imageRef,
  snsClient,
  ecsClient,
  hookDetails,
  executionDetails,
  paths,
}) {
  const message = buildFailureMessage(imageRef, reason, executionDetails);
  const subject = 'Chariot gateway image verification failed';
  const topicArn = hookDetails.snsTopicArn || process.env.CHARIOT_IMAGE_SEAL_SNS_TOPIC_ARN;

  try {
    await publishAlert({
      snsClient,
      topicArn,
      subject,
      message,
      attributes: {
        imageRef,
        serviceArn: executionDetails.serviceArn || '',
        deploymentArn: executionDetails.targetServiceRevisionArn || executionDetails.resourceArn || '',
        reason,
      },
    });
  } catch (alertError) {
    console.error('image-seal: alert publish failed', alertError);
  }

  try {
    await stopTaskIfRequested({ ecsClient, hookDetails, executionDetails });
  } catch (stopError) {
    console.error('image-seal: stop-task failed', stopError);
  }

  return {
    hookStatus: 'FAILED',
    hookDetails: {
      reason,
      verifiedImage: imageRef,
      alertedTo: topicArn || '',
      trustPolicyPath: paths.trustPolicyPath,
      trustStoreDir: paths.trustStoreDir,
    },
  };
}

export async function verifyImageSeal(event, deps = {}) {
  const hookDetails = event?.hookDetails ?? {};
  const executionDetails = event?.executionDetails ?? {};
  const region = resolveRegion(hookDetails);
  const paths = resolveNotaryPaths(hookDetails);
  const notationBinary = hookDetails.notationBinary || process.env.CHARIOT_NOTATION_BIN || 'notation';
  const pluginAwsProfile = hookDetails.awsProfile || process.env.AWS_PROFILE;
  const pluginAwsRegion = hookDetails.awsRegion || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;

  const snsClient = deps.snsClient ?? new SNSClient({ region });
  const ecsClient = deps.ecsClient ?? new ECSClient({ region });
  const runNotation = deps.execFile ?? ((file, args, options) => execFile(file, args, options));

  // Bind verification to the artifact ECS is actually deploying (source of
  // truth), NOT the static hookDetails.imageReference. A resolution failure or
  // an imageReference/deploying-image mismatch is a security deny (FAILED),
  // which also stops the task and alerts.
  let imageRefs;
  try {
    imageRefs = await resolveDeployingImageRefs({ hookDetails, executionDetails, ecsClient });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    const imageRefForMsg =
      (typeof hookDetails.imageReference === 'string' && hookDetails.imageReference.trim()) ||
      executionDetails.targetServiceRevisionArn ||
      'unresolved';
    return buildDenyResult({
      reason,
      imageRef: imageRefForMsg,
      snsClient,
      ecsClient,
      hookDetails,
      executionDetails,
      paths,
    });
  }

  // Every ref MUST already be digest-pinned (resolveDeployingImageRefs
  // guarantees it); assert defensively.
  for (const ref of imageRefs) {
    if (!ref.includes('@sha256:')) {
      throw new Error(`image seal: resolved image ref ${ref} is not pinned by immutable digest`);
    }
  }

  if (!existsSync(paths.trustPolicyPath)) {
    throw new Error(`image seal: trust policy not found at ${paths.trustPolicyPath}`);
  }
  // Assert the NAMED trust-store cert files (notation reads
  // truststore/x509/signingAuthority/<name>/, not the parent dir).
  for (const certsPath of paths.certsPaths) {
    if (!existsSync(certsPath)) {
      throw new Error(`image seal: trust store cert not found at ${certsPath} (notation named-store layout)`);
    }
  }

  // Verify EVERY image in the deploying revision. Any failure denies the whole
  // deployment (fail closed).
  for (const imageRef of imageRefs) {
    const verifyArgs = notationVerifyCommand({
      imageRef,
      pluginAwsRegion,
      pluginAwsProfile,
      trustPolicyPath: paths.trustPolicyPath,
    });
    try {
      await runNotation(notationBinary, verifyArgs, {
        env: {
          ...process.env,
          // notation resolves BOTH trustpolicy.json and the trust store from
          // NOTATION_CONFIG; without it the shipped trust dir is invisible and
          // verification cannot load its trust material (CH-54 fail-closed).
          NOTATION_CONFIG: paths.baseDir,
          AWS_REGION: pluginAwsRegion || region,
        },
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return buildDenyResult({
        reason,
        imageRef,
        snsClient,
        ecsClient,
        hookDetails,
        executionDetails,
        paths,
      });
    }
  }

  return {
    hookStatus: 'SUCCEEDED',
    hookDetails: {
      verifiedImage: imageRefs[0],
      verifiedImages: imageRefs,
      trustPolicyPath: paths.trustPolicyPath,
      trustStoreDir: paths.trustStoreDir,
    },
  };
}

export async function handler(event) {
  return verifyImageSeal(event);
}
