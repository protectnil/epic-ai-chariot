/**
 * @epicai/chariot — DER Buffer (single-pass TLV builder)
 *
 * Replaces the per-tlv Buffer.from/concat allocations in anchor.ts with a
 * single pre-allocated `Buffer.allocUnsafe` that grows as needed.
 * Anchoring is out-of-band (not per-request), so this is an
 * efficiency/clarity win rather than a hot-path fix — the cleaner module
 * also makes the future DER parser stub simpler to add alongside it.
 *
 * Only the subset of DER primitives needed by RFC-3161 TimeStampReq is
 * implemented. This is intentionally NOT a general-purpose ASN.1 library.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

const INITIAL_CAPACITY = 256;
const GROWTH_FACTOR = 2;

export class DerBuffer {
  private buf: Buffer;
  private cursor: number;

  constructor(initialCapacity: number = INITIAL_CAPACITY) {
    this.buf = Buffer.allocUnsafe(initialCapacity);
    this.cursor = 0;
  }

  // ── Internal growth ────────────────────────────────────────────────────────

  private ensure(needed: number): void {
    const required = this.cursor + needed;
    if (required <= this.buf.length) return;
    let newLen = this.buf.length * GROWTH_FACTOR;
    while (newLen < required) newLen *= GROWTH_FACTOR;
    const next = Buffer.allocUnsafe(newLen);
    this.buf.copy(next, 0, 0, this.cursor);
    this.buf = next;
  }

  private writeByte(b: number): void {
    this.ensure(1);
    this.buf[this.cursor++] = b;
  }

  private writeBytes(src: Buffer): void {
    this.ensure(src.length);
    src.copy(this.buf, this.cursor);
    this.cursor += src.length;
  }

  // ── DER length encoding ────────────────────────────────────────────────────

  private writeLength(len: number): void {
    if (len < 0x80) {
      this.writeByte(len);
    } else {
      const bytes: number[] = [];
      let n = len;
      while (n > 0) {
        bytes.unshift(n & 0xff);
        n >>>= 8;
      }
      this.writeByte(0x80 | bytes.length);
      for (const b of bytes) this.writeByte(b);
    }
  }

  // ── Public TLV writer ──────────────────────────────────────────────────────

  /**
   * Append a TLV (tag–length–value) triple to the buffer. Returns `this`
   * for chaining, though callers typically use the named helpers below.
   */
  tlv(tag: number, value: Buffer): this {
    this.writeByte(tag);
    this.writeLength(value.length);
    this.writeBytes(value);
    return this;
  }

  // ── DER primitive helpers ──────────────────────────────────────────────────

  integer(n: number): this {
    if (n < 0) throw new RangeError('DerBuffer.integer: negative not supported');
    if (n === 0) return this.tlv(0x02, Buffer.from([0x00]));
    const bytes: number[] = [];
    let v = n;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v = Math.floor(v / 256);
    }
    if (bytes[0] & 0x80) bytes.unshift(0x00);
    return this.tlv(0x02, Buffer.from(bytes));
  }

  /** Arbitrarily-large positive integer (e.g. nonces). Pads if MSB is set. */
  integerBytes(src: Buffer): this {
    if (src.length === 0) return this.tlv(0x02, Buffer.from([0x00]));
    const value = src[0] & 0x80
      ? Buffer.concat([Buffer.from([0x00]), src])
      : src;
    return this.tlv(0x02, value);
  }

  octetString(value: Buffer): this {
    return this.tlv(0x04, value);
  }

  boolean(value: boolean): this {
    return this.tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
  }

  null_(): this {
    return this.tlv(0x05, Buffer.alloc(0));
  }

  /** Write a SEQUENCE (tag 0x30) wrapping an already-encoded child payload. */
  sequence(payload: Buffer): this {
    return this.tlv(0x30, payload);
  }

  // ── Output ─────────────────────────────────────────────────────────────────

  /**
   * Return the encoded bytes written so far as a new Buffer (a copy).
   * The DerBuffer can continue to be used after calling `toBuffer()`.
   */
  toBuffer(): Buffer {
    return Buffer.from(this.buf.subarray(0, this.cursor));
  }
}

/**
 * Encode a SEQUENCE wrapping one or more pre-encoded child Buffers.
 * Equivalent to `encodeSequence(...children)` from the original anchor.ts
 * inline DER builder — provided as a standalone function for call sites
 * that prefer the functional style over the builder pattern.
 */
export function derSequence(...children: Buffer[]): Buffer {
  const payload = Buffer.concat(children);
  const db = new DerBuffer(payload.length + 8);
  db.sequence(payload);
  return db.toBuffer();
}
