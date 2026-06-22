/**
 * @epicai/chariot — Redis Approval Queue
 * Redis-backed approval queue for production deployments.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { randomUUID } from 'node:crypto';
import type { RedisClientType } from 'redis';
import type {
  ActionContext,
  ActionDecision,
  PendingApproval,
} from '../../types/index.js';

interface RedisQueueConfig {
  host: string;
  port: number;
  password?: string;
  keyPrefix?: string;
  ttlMs: number;
}

/*
 * eslint-disable @typescript-eslint/no-explicit-any —
 * `any` is used for the redis field because `redis` is an optional
 * peer dependency loaded via dynamic import(). Its types are not
 * available at compile time when the peer dependency is not installed.
 */

/**
 * Redis-backed approval queue.
 * Each pending approval stored as a Redis key with TTL.
 * Requires optional peer dependency: npm install redis
 */
export class RedisQueue {
  private readonly config: RedisQueueConfig;
  private readonly keyPrefix: string;
  private redis: RedisClientType | null = null;
  private connected = false;

  constructor(config: RedisQueueConfig) {
    this.config = config;
    this.keyPrefix = config.keyPrefix ?? 'eai:approval:';
  }

  async connect(): Promise<void> {
    if (this.connected) return;
    try {
      const redisModule = await import('redis');
      this.redis = redisModule.createClient({
        socket: { host: this.config.host, port: this.config.port },
        password: this.config.password,
      }) as RedisClientType;
      await this.requireRedis().connect();
      this.connected = true;
    } catch (err) {
      throw new Error(`Redis connection failed: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
    }
  }

  async enqueue(context: ActionContext, tier: 'escalate' | 'approve'): Promise<PendingApproval> {
    await this.ensureConnected();

    const id = randomUUID();
    const now = new Date();
    const ttlSeconds = Math.ceil(this.config.ttlMs / 1000);

    const approval: PendingApproval = {
      id,
      action: context,
      tier,
      state: 'pending',
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.config.ttlMs),
    };

    await this.requireRedis().set(`${this.keyPrefix}${id}`, JSON.stringify(approval), { EX: ttlSeconds });
    await this.requireRedis().sAdd(`${this.keyPrefix}pending`, id);

    return approval;
  }

  async approve(actionId: string, approver: string): Promise<ActionDecision> {
    return this.decide(actionId, 'approved', approver);
  }

  async deny(actionId: string, approver: string, reason: string): Promise<ActionDecision> {
    return this.decide(actionId, 'denied', approver, reason);
  }

  async pending(): Promise<PendingApproval[]> {
    await this.ensureConnected();

    const redis = this.requireRedis();
    const ids: string[] = await redis.sMembers(`${this.keyPrefix}pending`);
    if (ids.length === 0) return [];

    const datas = await Promise.all(ids.map((id) => redis.get(`${this.keyPrefix}${id}`)));
    const results: PendingApproval[] = [];
    const stale: string[] = [];

    for (let i = 0; i < ids.length; i++) {
      const data = datas[i];
      if (data) {
        const approval = JSON.parse(data) as PendingApproval;
        if (approval.state === 'pending') results.push(approval);
      } else {
        stale.push(ids[i]);
      }
    }

    if (stale.length > 0) await redis.sRem(`${this.keyPrefix}pending`, stale);

    return results;
  }

  async pendingByTenant(tenantId: string): Promise<PendingApproval[]> {
    const all = await this.pending();
    return all.filter(a => a.action.persona === tenantId);
  }

  async get(actionId: string): Promise<PendingApproval | null> {
    await this.ensureConnected();
    const data = await this.requireRedis().get(`${this.keyPrefix}${actionId}`);
    return data ? JSON.parse(data) as PendingApproval : null;
  }

  async disconnect(): Promise<void> {
    if (this.redis) { await this.requireRedis().disconnect(); this.redis = null; }
    this.connected = false;
  }

  private async decide(
    actionId: string,
    state: 'approved' | 'denied',
    approver: string,
    reason?: string,
  ): Promise<ActionDecision> {
    await this.ensureConnected();

    const data = await this.requireRedis().get(`${this.keyPrefix}${actionId}`);
    if (!data) throw new Error(`Action "${actionId}" not found or expired`);

    const approval = JSON.parse(data) as PendingApproval;

    if (approval.state !== 'pending') {
      return {
        id: approval.id,
        action: approval.action.tool,
        tier: approval.tier,
        allowed: approval.state === 'approved',
        reason: approval.denyReason,
        approvedBy: approval.decidedBy,
        timestamp: approval.decidedAt ? new Date(approval.decidedAt) : new Date(),
      };
    }

    approval.state = state;
    approval.decidedAt = new Date();
    approval.decidedBy = approver;
    if (reason) approval.denyReason = reason;

    // Decided approvals should persist indefinitely for audit purposes — no TTL
    await this.requireRedis().set(`${this.keyPrefix}${actionId}`, JSON.stringify(approval));
    // Persist flag: remove any existing TTL so decided records are kept for audit
    await this.requireRedis().persist(`${this.keyPrefix}${actionId}`);
    await this.requireRedis().sRem(`${this.keyPrefix}pending`, actionId);

    return {
      id: approval.id,
      action: approval.action.tool,
      tier: approval.tier,
      allowed: state === 'approved',
      reason,
      approvedBy: approver,
      timestamp: new Date(),
    };
  }

  private async ensureConnected(): Promise<void> {
    if (!this.connected) await this.connect();
  }

  private requireRedis(): RedisClientType {
    if (!this.redis) throw new Error('Redis client not initialized; ensureConnected() must be called first');
    return this.redis;
  }
}
