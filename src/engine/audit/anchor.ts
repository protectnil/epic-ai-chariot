/**
 * @epicai/chariot — Hash Chain External Anchor
 *
 * RFC-3161 Time-Stamp Protocol (TSP) client. Closes Mode 2 of
 * test/ai-evals/07-hash-chain-tamper.mjs: a self-contained hash chain
 * with no external genesis anchor cannot detect a full re-stitch
 * attack — an attacker who can rewrite every record can produce a
 * structurally valid chain whose head differs from the original. Once
 * the operator has obtained an RFC-3161 timestamp over a particular
 * head hash, ANY subsequent re-stitch will produce a head hash that
 * does not match the timestamped one — the rewrite becomes evident.
 *
 * TSA-AGNOSTIC by design (HARD — never violate):
 *   - The TSA URL is operator-configured via the `CHARIOT_TSA_URL`
 *     environment variable. NEVER hardcode a TSA endpoint or a TSA
 *     certificate in this module. Chariot is a self-hosted product;
 *     calling out to a vendor-chosen TSA on the customer's behalf
 *     would breach the air-gapped posture the product promises.
 *   - The TSA's signing certificate is supplied by the operator at
 *     verify time as a PEM string. The verifier does NOT walk a CA
 *     trust store; it checks that the TSA response was signed by the
 *     specific cert the operator pinned at deploy time.
 *
 * NOT IN THE HOT PATH (HARD — never violate):
 *   `anchorChainHead` performs a network call to the operator's TSA.
 *   The chain append path MUST NOT invoke this function. Anchoring is
 *   out-of-band, periodic, operator-driven (via `chariot audit anchor`
 *   CLI subcommand or a cron). The expected call site is a CLI
 *   handler, not the per-record append loop. Putting it in the hot
 *   path would make every audit write block on TSA reachability.
 *
 * Persistence contract:
 *   <packageRoot>/audit/anchors/<chain-id>-<epoch>.tsr
 *   - Raw `TimeStampResp` DER bytes from the TSA. No re-encoding.
 *   - Mode 0o644 on the file, 0o755 on the directory.
 *   - One file per anchoring event. NEVER overwrite.
 *
 * Implementation notes (RFC-3161 §2.4.1):
 *   TimeStampReq ::= SEQUENCE {
 *     version           INTEGER (v1(1)),
 *     messageImprint    MessageImprint,
 *     reqPolicy         OBJECT IDENTIFIER  OPTIONAL,
 *     nonce             INTEGER            OPTIONAL,
 *     certReq           BOOLEAN DEFAULT FALSE,
 *     extensions        [0] IMPLICIT Extensions OPTIONAL
 *   }
 *   MessageImprint ::= SEQUENCE {
 *     hashAlgorithm     AlgorithmIdentifier,   -- SHA-256 OID
 *     hashedMessage     OCTET STRING            -- the head hash bytes
 *   }
 *
 * SHA-256 OID: 2.16.840.1.101.3.4.2.1 — DER bytes
 * `06 09 60 86 48 01 65 03 04 02 01`
 *
 * The TimeStampResp is stored as-is and parsed by `verifyAnchor`. When
 * the operator supplies a pinned TSA certificate, the verifier parses
 * the RFC-3161 CMS SignedData, checks the signed attributes, validates
 * the TSTInfo messageImprint, and verifies the SignerInfo signature
 * with the pinned cert's public key. Without a pinned cert it falls
 * back to the original head-hash containment check used for re-stitch
 * detection.
 *
 * CLI surface (out of scope for this module — gap noted):
 *   `chariot audit anchor` — anchor the current chain head to the
 *                            operator-configured TSA and persist the
 *                            resulting TimeStampResp.
 *   Wired in src/bin/chariot.ts under the `audit` subcommand.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash, randomBytes, verify as verifySignature, X509Certificate } from 'node:crypto';
import { atomicWriteNew } from './auditFs.js';
import { DerBuffer, derSequence } from './der-buffer.js';
import { CHARIOT_ERROR_CODES } from '../types/index.js';

export interface AnchoredAttestation {
  chainId: string;
  headHash: string;        // hex
  anchoredAt: string;      // ISO-8601
  tsaUrl: string;
  tsrPath: string;         // absolute path to persisted TimeStampResp DER
  nonce: string;           // hex — the nonce used in the TimeStampReq
}

export interface AnchorVerifyResult {
  valid: boolean;
  tsaTime?: Date;
  reason?: string;
  code?: string;
}

const ID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const ID_CT_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const SHA256_OID = '2.16.840.1.101.3.4.2.1';

function parseDerNode(buf: Buffer, offset = 0): { tag: number; len: number; value: Buffer; end: number } {
  const tag = buf[offset];
  let len = buf[offset + 1];
  let lenBytes = 1;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = (len << 8) | buf[offset + 2 + i];
    }
    lenBytes = 1 + n;
  }
  const valStart = offset + 1 + lenBytes;
  const value = buf.subarray(valStart, valStart + len);
  return { tag, len, value, end: valStart + len };
}

function readSequenceChildren(seqBuf: Buffer): Array<{ tag: number; len: number; value: Buffer; end: number }> {
  const out: Array<{ tag: number; len: number; value: Buffer; end: number }> = [];
  let off = 0;
  while (off < seqBuf.length) {
    const node = parseDerNode(seqBuf, off);
    out.push(node);
    off = node.end;
  }
  return out;
}

function decodeOidValue(value: Buffer): string {
  if (value.length === 0) return '';
  const first = value[0];
  const parts = [Math.floor(first / 40), first % 40];
  let current = 0;
  for (let i = 1; i < value.length; i++) {
    current = (current << 7) | (value[i] & 0x7f);
    if ((value[i] & 0x80) === 0) {
      parts.push(current);
      current = 0;
    }
  }
  return parts.join('.');
}

function decodeIntegerValue(value: Buffer): number {
  let n = 0;
  for (const byte of value) {
    n = (n << 8) | byte;
  }
  return n;
}

function decodeGeneralizedTimeValue(value: Buffer): Date {
  const text = value.toString('ascii');
  const normalized = `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`;
  return new Date(normalized);
}


function parseTimeStampResp(tsr: Buffer): { status: number; timeStampToken?: Buffer } {
  const root = parseDerNode(tsr);
  if (root.tag !== 0x30) {
    throw new Error('TimeStampResp does not start with SEQUENCE tag');
  }
  const children = readSequenceChildren(root.value);
  if (children.length === 0) {
    throw new Error('TimeStampResp missing status');
  }
  const statusSeq = children[0];
  if (statusSeq.tag !== 0x30) {
    throw new Error('TimeStampResp status is not a SEQUENCE');
  }
  const statusChildren = readSequenceChildren(statusSeq.value);
  if (statusChildren.length === 0 || statusChildren[0].tag !== 0x02) {
    throw new Error('TimeStampResp status missing INTEGER');
  }
  const status = decodeIntegerValue(statusChildren[0].value);
  const tokenNode = children[1];
  return { status, timeStampToken: tokenNode?.value };
}

function parseTimeStampToken(tokenDer: Buffer): { contentType: string; signedDataDer: Buffer } {
  const root = parseDerNode(tokenDer);
  if (root.tag !== 0x30) {
    throw new Error('timeStampToken does not start with SEQUENCE tag');
  }
  const children = readSequenceChildren(root.value);
  if (children.length < 2 || children[0].tag !== 0x06) {
    throw new Error('timeStampToken missing contentType');
  }
  if (children[1].tag !== 0xa0) {
    throw new Error('timeStampToken missing explicit SignedData wrapper');
  }
  return {
    contentType: decodeOidValue(children[0].value),
    signedDataDer: children[1].value,
  };
}

function parseTstInfo(tstInfoDer: Buffer): { hashAlgorithm: string; hashedMessage: Buffer; genTime: Date } {
  const root = parseDerNode(tstInfoDer);
  if (root.tag !== 0x30) {
    throw new Error('TSTInfo does not start with SEQUENCE tag');
  }
  const children = readSequenceChildren(root.value);
  if (children.length < 5) {
    throw new Error('TSTInfo is missing required fields');
  }
  const messageImprint = children[2];
  if (messageImprint.tag !== 0x30) {
    throw new Error('TSTInfo messageImprint is not a SEQUENCE');
  }
  const imprintChildren = readSequenceChildren(messageImprint.value);
  if (imprintChildren.length < 2 || imprintChildren[0].tag !== 0x30 || imprintChildren[1].tag !== 0x04) {
    throw new Error('TSTInfo messageImprint is malformed');
  }
  const algChildren = readSequenceChildren(imprintChildren[0].value);
  if (algChildren.length === 0 || algChildren[0].tag !== 0x06) {
    throw new Error('TSTInfo messageImprint algorithm is malformed');
  }
  const genTimeNode = children[4];
  if (genTimeNode.tag !== 0x18) {
    throw new Error('TSTInfo genTime is not GeneralizedTime');
  }
  return {
    hashAlgorithm: decodeOidValue(algChildren[0].value),
    hashedMessage: Buffer.from(imprintChildren[1].value),
    genTime: decodeGeneralizedTimeValue(genTimeNode.value),
  };
}

function parseCertPublicKey(certPem: string) {
  return new X509Certificate(certPem).publicKey;
}

/**
 * Manually parse an RFC-5652 SignedData TLV body and verify the
 * SignerInfo signature against a pinned TSA public key.
 *
 * Returns { ok: true, tstInfoDer } on success or { ok: false, reason }
 * on any structural / cryptographic failure. Idempotent — every input
 * produces the same output for the same key.
 */
function verifySignedDataCms(
  signedDataValue: Buffer,
  pubKey: ReturnType<typeof parseCertPublicKey>,
): { ok: true; tstInfoDer: Buffer; eContent: Buffer } | { ok: false; reason: string } {
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET,
  //   encapContentInfo, certificates [0] IMPLICIT optional,
  //   crls [1] IMPLICIT optional, signerInfos SET }
  // The caller has already stripped the [0] EXPLICIT wrapper around
  // SignedData inside ContentInfo, so signedDataValue starts with the
  // SignedData SEQUENCE itself.
  const sdRoot = parseDerNode(signedDataValue);
  if (sdRoot.tag !== 0x30) return { ok: false, reason: 'SignedData is not a SEQUENCE' };
  const sdKids = readSequenceChildren(sdRoot.value);
  if (sdKids.length < 4) return { ok: false, reason: 'SignedData has too few fields' };

  // sdKids[0] = version INTEGER; sdKids[1] = digestAlgorithms SET;
  // sdKids[2] = encapContentInfo; remaining: optional certs/crls, then signerInfos SET.
  const encapInfo = sdKids[2];
  if (encapInfo.tag !== 0x30) return { ok: false, reason: 'encapContentInfo is not a SEQUENCE' };
  const eKids = readSequenceChildren(encapInfo.value);
  if (eKids.length < 1 || eKids[0].tag !== 0x06) {
    return { ok: false, reason: 'encapContentInfo missing eContentType OID' };
  }
  const eContentType = decodeOidValue(eKids[0].value);
  if (eContentType !== ID_CT_TST_INFO) {
    return { ok: false, reason: `eContentType is ${eContentType}, not TSTInfo` };
  }
  if (eKids.length < 2 || eKids[1].tag !== 0xa0) {
    return { ok: false, reason: 'encapContentInfo missing eContent [0] EXPLICIT' };
  }
  // eContent [0] EXPLICIT OCTET STRING — strip the OCTET STRING wrapper to get
  // the raw TSTInfo DER bytes.
  const eContentInner = parseDerNode(eKids[1].value);
  if (eContentInner.tag !== 0x04) {
    return { ok: false, reason: 'eContent inner is not OCTET STRING' };
  }
  const tstInfoDer = Buffer.from(eContentInner.value);

  // The signerInfos SET is the LAST element. Walk children to find it.
  let signerInfosSet: { tag: number; value: Buffer } | undefined;
  for (let i = 3; i < sdKids.length; i++) {
    if (sdKids[i].tag === 0x31) {
      signerInfosSet = sdKids[i];
      break;
    }
  }
  if (!signerInfosSet) return { ok: false, reason: 'SignedData missing signerInfos SET' };

  // First (and only required) SignerInfo.
  const siNode = parseDerNode(signerInfosSet.value);
  if (siNode.tag !== 0x30) return { ok: false, reason: 'SignerInfo is not a SEQUENCE' };
  const siKids = readSequenceChildren(siNode.value);
  if (siKids.length < 5) return { ok: false, reason: 'SignerInfo has too few fields' };

  // SignerInfo layout:
  //   version, sid, digestAlgorithm, signedAttrs[0] IMPLICIT optional,
  //   signatureAlgorithm, signature, unsignedAttrs[1] IMPLICIT optional.
  // We need digestAlgorithm, signedAttrs, signatureAlgorithm, signature.
  // sid is variable-shape; walk indices.
  // Pattern: siKids[0]=version (INTEGER 0x02), siKids[1]=sid, siKids[2]=digestAlg SEQ.
  const digestAlg = siKids[2];
  if (digestAlg.tag !== 0x30) return { ok: false, reason: 'SignerInfo digestAlgorithm missing' };
  const digAlgKids = readSequenceChildren(digestAlg.value);
  if (digAlgKids.length === 0 || digAlgKids[0].tag !== 0x06) {
    return { ok: false, reason: 'digestAlgorithm OID missing' };
  }
  if (decodeOidValue(digAlgKids[0].value) !== SHA256_OID) {
    return { ok: false, reason: 'digestAlgorithm is not SHA-256' };
  }

  // signedAttrs is the [0] IMPLICIT (tag 0xa0). May be absent — then we
  // verify the signature directly over eContent, but RFC-3161 §2.4.2
  // SHOULD always carry signedAttrs. We reject the no-signedAttrs case
  // because the TSP profile requires contentType + messageDigest at minimum.
  let signedAttrsNode: { tag: number; value: Buffer; len: number; end: number } | undefined;
  let cursorIdx = 3;
  if (siKids[cursorIdx].tag === 0xa0) {
    signedAttrsNode = siKids[cursorIdx];
    cursorIdx++;
  }
  if (!signedAttrsNode) {
    return { ok: false, reason: 'SignerInfo has no signedAttrs — RFC-3161 profile requires them' };
  }

  // Parse signedAttrs to find contentType + messageDigest.
  const attrChildren = readSequenceChildren(signedAttrsNode.value);
  let contentTypeOid: string | undefined;
  let messageDigest: Buffer | undefined;
  for (const attr of attrChildren) {
    if (attr.tag !== 0x30) continue;
    const akids = readSequenceChildren(attr.value);
    if (akids.length < 2 || akids[0].tag !== 0x06 || akids[1].tag !== 0x31) continue;
    const oid = decodeOidValue(akids[0].value);
    const valueSet = parseDerNode(akids[1].value);
    if (oid === ID_CONTENT_TYPE) {
      if (valueSet.tag !== 0x06) continue;
      contentTypeOid = decodeOidValue(valueSet.value);
    } else if (oid === ID_MESSAGE_DIGEST) {
      if (valueSet.tag !== 0x04) continue;
      messageDigest = Buffer.from(valueSet.value);
    }
  }
  if (!contentTypeOid || !messageDigest) {
    return { ok: false, reason: 'signedAttrs missing required contentType or messageDigest' };
  }
  if (contentTypeOid !== ID_CT_TST_INFO) {
    return { ok: false, reason: `signedAttrs contentType is ${contentTypeOid}, not TSTInfo` };
  }
  const expectedDigest = createHash('sha256').update(tstInfoDer).digest();
  if (!messageDigest.equals(expectedDigest)) {
    return { ok: false, reason: 'signedAttrs messageDigest does not match SHA-256(TSTInfo)' };
  }

  // signatureAlgorithm + signature follow signedAttrs.
  if (cursorIdx + 1 >= siKids.length) {
    return { ok: false, reason: 'SignerInfo missing signatureAlgorithm or signature' };
  }
  const sigAlgNode = siKids[cursorIdx];
  const sigNode = siKids[cursorIdx + 1];
  if (sigAlgNode.tag !== 0x30 || sigNode.tag !== 0x04) {
    return { ok: false, reason: 'SignerInfo signatureAlgorithm/signature malformed' };
  }
  const sigAlgKids = readSequenceChildren(sigAlgNode.value);
  if (sigAlgKids.length === 0 || sigAlgKids[0].tag !== 0x06) {
    return { ok: false, reason: 'signatureAlgorithm OID missing' };
  }
  const sigAlgOid = decodeOidValue(sigAlgKids[0].value);
  const signature = Buffer.from(sigNode.value);

  // When verifying, the IMPLICIT [0] tag (0xa0) on signedAttrs MUST be
  // replaced with the SET tag (0x31) and the same content. See RFC 5652
  // §5.4. Build that buffer here.
  const signedAttrsDer = Buffer.concat([
    Buffer.from([0x31]), // SET tag
    encodeDerLength(signedAttrsNode.len),
    signedAttrsNode.value,
  ]);

  // Verify with node:crypto. ECDSA / RSA / Ed25519 are the common TSA cases.
  let verifyOk = false;
  try {
    // RFC-8017 RSA: OIDs include 1.2.840.113549.1.1.{1,11} (rsaEncryption/sha256WithRSAEncryption)
    // ECDSA: 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
    // Ed25519: 1.3.101.112; Ed448: 1.3.101.113
    if (sigAlgOid === '1.3.101.112' || sigAlgOid === '1.3.101.113') {
      verifyOk = verifySignature(null, signedAttrsDer, pubKey, signature);
    } else {
      // RSA-PKCS1 and ECDSA both accept the digest name 'sha256' in node:crypto.verify.
      verifyOk = verifySignature('sha256', signedAttrsDer, pubKey, signature);
    }
  } catch (e) {
    return { ok: false, reason: `verify threw: ${(e as Error).message}` };
  }
  if (!verifyOk) {
    return { ok: false, reason: 'CMS SignerInfo signature did not verify against pinned TSA cert' };
  }

  return { ok: true, tstInfoDer, eContent: tstInfoDer };
}

const ID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

function encodeDerLength(len: number): Buffer {
  if (len < 128) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

// ── ASN.1 DER helpers ─────────────────────────────────────────────────────
//
// Only the SHA-256 AlgorithmIdentifier SEQUENCE is built here; all TLV
// writes go through DerBuffer (see ./der-buffer.ts).

// SHA-256 algorithm identifier: OID 2.16.840.1.101.3.4.2.1
// DER OBJECT IDENTIFIER bytes (pre-encoded): 06 09 60 86 48 01 65 03 04 02 01
const SHA256_OID_DER = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

function encodeSha256AlgorithmIdentifier(): Buffer {
  // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
  const db = new DerBuffer(20);
  db.null_();
  const nullBytes = db.toBuffer();
  return derSequence(SHA256_OID_DER, nullBytes);
}

// ── RFC-3161 TimeStampReq construction ─────────────────────────────────────

/**
 * Build an RFC-3161 TimeStampReq DER over a SHA-256 head hash.
 *
 * @param headHash 32-byte SHA-256 of the chain head (raw bytes, NOT hex)
 * @param nonce    Optional nonce bytes. If omitted, 16 random bytes.
 * @param certReq  Whether to request the TSA's cert in the response.
 *                 Defaults to true so the verifier can pin the cert.
 * @returns        DER-encoded TimeStampReq, ready to POST as
 *                 `application/timestamp-query`.
 */
export function buildTimeStampReq(
  headHash: Buffer,
  nonce?: Buffer,
  certReq: boolean = true,
): { der: Buffer; nonce: Buffer } {
  if (!Buffer.isBuffer(headHash) || headHash.length !== 32) {
    throw new TypeError('buildTimeStampReq: headHash must be a 32-byte SHA-256 Buffer');
  }
  const nonceBytes = nonce ?? randomBytes(16);

  // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  // Build the inner payload for the SEQUENCE (two pre-encoded TLVs concatenated):
  const algId = encodeSha256AlgorithmIdentifier();
  const octetDb = new DerBuffer(headHash.length + 4);
  octetDb.octetString(headHash);
  const miPayloadBuf = Buffer.concat([algId, octetDb.toBuffer()]);

  // TimeStampReq ::= SEQUENCE { version INTEGER, messageImprint, nonce INTEGER, certReq BOOLEAN }
  // Field order per RFC-3161 §2.4.1: version, messageImprint, [reqPolicy OPTIONAL], nonce, certReq
  const reqDb = new DerBuffer(miPayloadBuf.length + 64);
  reqDb.integer(1);                    // version v1
  reqDb.sequence(miPayloadBuf);        // messageImprint SEQUENCE
  reqDb.integerBytes(nonceBytes);      // nonce INTEGER (arbitrary-length positive)
  reqDb.boolean(certReq);             // certReq BOOLEAN

  return { der: derSequence(reqDb.toBuffer()), nonce: nonceBytes };
}

// ── Persistence helper ─────────────────────────────────────────────────────

function persistTsr(packageRoot: string, chainId: string, epoch: number, tsr: Buffer): string {
  const dir = join(packageRoot, 'audit', 'anchors');
  return atomicWriteNew(dir, `${chainId}-${epoch}.tsr`, tsr);
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Anchor the current hash-chain head to the operator-configured RFC-3161
 * TSA. Constructs a TimeStampReq DER, POSTs it to `CHARIOT_TSA_URL` (or
 * the explicit `tsaUrl` argument), and persists the raw TimeStampResp
 * to `<packageRoot>/audit/anchors/<chain-id>-<epoch>.tsr`.
 *
 * MUST NOT be called from the chain append hot path. See the module
 * header for the full TSA-agnostic + out-of-band rationale. The
 * expected call site is the `chariot audit anchor` CLI subcommand or
 * an operator cron.
 *
 * @throws if the TSA URL is not configured, the network call fails, or
 *         the TSA returns a non-2xx status. Errors are surfaced — the
 *         operator decides whether to retry, fall back to a different
 *         TSA, or mark the anchor cycle skipped.
 */
export async function anchorChainHead(opts: {
  chainId: string;
  headHash: Buffer;            // 32 raw bytes
  packageRoot: string;
  tsaUrl?: string;             // overrides CHARIOT_TSA_URL
  fetchImpl?: typeof fetch;    // injected for tests
  nowMs?: () => number;        // injected for tests
}): Promise<AnchoredAttestation> {
  const tsaUrl = opts.tsaUrl ?? process.env.CHARIOT_TSA_URL;
  if (!tsaUrl) {
    throw new Error(
      'anchorChainHead: no TSA configured. Set CHARIOT_TSA_URL or pass tsaUrl explicitly. ' +
        'Chariot ships TSA-agnostic — the operator chooses the timestamp authority.',
    );
  }
  if (!Buffer.isBuffer(opts.headHash) || opts.headHash.length !== 32) {
    throw new TypeError('anchorChainHead: headHash must be a 32-byte Buffer');
  }
  const { der, nonce } = buildTimeStampReq(opts.headHash);
  const f = opts.fetchImpl ?? fetch;
  const resp = await f(tsaUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: der,
  });
  if (!resp.ok) {
    throw new Error(`anchorChainHead: TSA ${tsaUrl} returned HTTP ${resp.status}`);
  }
  const tsr = Buffer.from(await resp.arrayBuffer());
  const epoch = (opts.nowMs ?? Date.now)();
  const tsrPath = persistTsr(opts.packageRoot, opts.chainId, epoch, tsr);
  return {
    chainId: opts.chainId,
    headHash: opts.headHash.toString('hex'),
    anchoredAt: new Date(epoch).toISOString(),
    tsaUrl,
    tsrPath,
    nonce: nonce.toString('hex'),
  };
}

/**
 * Anchor verifier. Without a pinned cert it performs the original
 * head-hash containment check to detect re-stitching. With a pinned
 * cert it parses the RFC-3161 TimeStampResp, verifies the CMS
 * SignedData signature over the signed attributes, checks the
 * TSTInfo messageImprint, and returns the TSA time on success.
 *
 * @param expectedHeadHash The 32 raw bytes of the head hash that was
 *                         supposedly anchored.
 * @param anchorPath       Filesystem path to the persisted .tsr.
 * @param tsaCertPem       Optional operator-pinned TSA cert PEM.
 */
export function verifyAnchor(
  expectedHeadHash: Buffer,
  anchorPath: string,
  tsaCertPem?: string,
): AnchorVerifyResult {
  if (!Buffer.isBuffer(expectedHeadHash) || expectedHeadHash.length !== 32) {
    return { valid: false, reason: 'expectedHeadHash must be 32-byte Buffer' };
  }

  let tsr: Buffer;
  try {
    tsr = readFileSync(anchorPath);
  } catch (e) {
    return { valid: false, reason: `cannot read anchor file: ${(e as Error).message}` };
  }

  if (tsaCertPem) {
    try {
      // 1. Parse the outer TimeStampResp wrapper.
      const resp = parseTimeStampResp(tsr);
      if (resp.status !== 0 && resp.status !== 1) {
        return {
          valid: false,
          reason: `TimeStampResp status is ${resp.status}, not granted (0) or grantedWithMods (1)`,
          code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
        };
      }
      if (!resp.timeStampToken) {
        return {
          valid: false,
          reason: 'TimeStampResp is missing a timeStampToken',
          code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
        };
      }

      // 2. Inside the timeStampToken (ContentInfo) find the SignedData.
      // resp.timeStampToken is the children-bytes of the [0] EXPLICIT
      // wrapper; we expect a ContentInfo: SEQUENCE { contentType OID,
      // content [0] EXPLICIT SignedData }. parseTimeStampToken below
      // expects the full ContentInfo SEQUENCE, so we re-encode it.
      const tokenSeqLen = encodeDerLength(resp.timeStampToken.length);
      const tokenWrapped = Buffer.concat([
        Buffer.from([0x30]),
        tokenSeqLen,
        resp.timeStampToken,
      ]);
      const token = parseTimeStampToken(tokenWrapped);
      if (token.contentType !== '1.2.840.113549.1.7.2') {
        return {
          valid: false,
          reason: `timeStampToken contentType is ${token.contentType}, not signedData`,
          code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
        };
      }

      // 3. Verify the SignedData / SignerInfo against the pinned cert.
      const certPublicKey = parseCertPublicKey(tsaCertPem);
      const verify = verifySignedDataCms(token.signedDataDer, certPublicKey);
      if (!verify.ok) {
        return {
          valid: false,
          reason: verify.reason,
          code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
        };
      }

      // 4. Parse TSTInfo and check the messageImprint matches the
      // expected head hash. This is the bind from chain → TSA token.
      const tstInfo = parseTstInfo(verify.tstInfoDer);
      if (tstInfo.hashAlgorithm !== SHA256_OID) {
        return {
          valid: false,
          reason: `TSTInfo messageImprint hashAlgorithm is ${tstInfo.hashAlgorithm}, not SHA-256`,
          code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
        };
      }
      if (!tstInfo.hashedMessage.equals(expectedHeadHash)) {
        return {
          valid: false,
          reason: 'TSTInfo messageImprint does not match expected head hash',
          code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
        };
      }

      return { valid: true, tsaTime: tstInfo.genTime };
    } catch (err) {
      return {
        valid: false,
        reason: err instanceof Error ? err.message : String(err),
        code: CHARIOT_ERROR_CODES.ANCHOR_VERIFY_FAILED,
      };
    }
  }

  if (tsr.length < 4 || tsr[0] !== 0x30) {
    return { valid: false, reason: 'TimeStampResp does not start with SEQUENCE tag' };
  }
  if (tsr.indexOf(expectedHeadHash) < 0) {
    return { valid: false, reason: 'TimeStampResp does not embed the expected head hash' };
  }
  return { valid: true };
}

/**
 * Read back a persisted anchor file. Convenience for the `chariot audit
 * anchor --list` CLI flow.
 */
export function loadAnchorBytes(anchorPath: string): Buffer {
  return readFileSync(anchorPath);
}
