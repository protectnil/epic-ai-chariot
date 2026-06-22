/**
 * @epicai/chariot — Memory Tool Handlers
 * Implements chariot_remember / chariot_recall / chariot_forget.
 * Delegates to state.memory (PersistentMemory) which owns all capacity,
 * importance, and encryption concerns. These handlers only validate args,
 * call the service, and return the standard MCP envelope.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { ChariotState } from './ChariotState.js';
import type { MemoryImportance, RecallOptions } from '../types/index.js';

// ---------------------------------------------------------------------------
// chariot_remember
// ---------------------------------------------------------------------------

export interface RememberArgs {
  content: string;
  type?: string;
  importance?: MemoryImportance;
}

export interface RememberResult {
  status: 'stored';
  id: string;
  type: string;
  importance: MemoryImportance;
  isError?: false;
}

export interface MemoryErrorResult {
  isError: true;
  error: string;
  message: string;
}

export async function handleRemember(
  args: RememberArgs,
  state: ChariotState,
  tenantId: string,
): Promise<RememberResult | MemoryErrorResult> {
  if (!state.memory) {
    return {
      isError: true,
      error: 'memory_unavailable',
      message: 'Memory service is not configured on this Chariot instance.',
    };
  }

  const type = args.type ?? 'general';
  const importance: MemoryImportance = args.importance ?? 'normal';

  try {
    const stored = await state.memory.etch(tenantId, {
      type,
      content: args.content,
      importance,
    });
    return {
      status: 'stored',
      id: stored.id,
      type: stored.type,
      importance: stored.importance,
    };
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === 'HIGH_IMPORTANCE_CAP_EXCEEDED') {
      return {
        isError: true,
        error: 'high_importance_cap_exceeded',
        message:
          'The high-importance memory cap has been reached for this user. ' +
          'Use importance "medium" or "normal", or forget an existing high-importance memory first.',
      };
    }
    return {
      isError: true,
      error: 'store_failed',
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

// ---------------------------------------------------------------------------
// chariot_recall
// ---------------------------------------------------------------------------

export interface RecallArgs {
  type?: string;
  importance?: MemoryImportance;
  limit?: number;
  sortBy?: RecallOptions['sortBy'];
}

export interface RecallResult {
  status: 'ok';
  memories: Array<{
    id: string;
    type: string;
    content: unknown;
    importance: MemoryImportance;
    createdAt: string;
    accessCount: number;
  }>;
  total: number;
  isError?: false;
}

export async function handleRecall(
  args: RecallArgs,
  state: ChariotState,
  tenantId: string,
): Promise<RecallResult | MemoryErrorResult> {
  if (!state.memory) {
    return {
      isError: true,
      error: 'memory_unavailable',
      message: 'Memory service is not configured on this Chariot instance.',
    };
  }

  try {
    const options: RecallOptions = {};
    if (args.type !== undefined) options.type = args.type;
    if (args.importance !== undefined) options.importance = args.importance;
    if (args.limit !== undefined) options.limit = args.limit;
    if (args.sortBy !== undefined) options.sortBy = args.sortBy;

    const memories = await state.memory.recall(tenantId, options);

    return {
      status: 'ok',
      total: memories.length,
      memories: memories.map(m => ({
        id: m.id,
        type: m.type,
        content: m.content,
        importance: m.importance,
        createdAt: m.createdAt.toISOString(),
        accessCount: m.accessCount,
      })),
    };
  } catch (err) {
    return {
      isError: true,
      error: 'recall_failed',
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

// ---------------------------------------------------------------------------
// chariot_forget
// ---------------------------------------------------------------------------

export interface ForgetArgs {
  id: string;
}

export interface ForgetResult {
  status: 'forgotten';
  id: string;
  isError?: false;
}

export async function handleForget(
  args: ForgetArgs,
  state: ChariotState,
  tenantId: string,
): Promise<ForgetResult | MemoryErrorResult> {
  if (!state.memory) {
    return {
      isError: true,
      error: 'memory_unavailable',
      message: 'Memory service is not configured on this Chariot instance.',
    };
  }

  try {
    await state.memory.forget(tenantId, args.id);
    return { status: 'forgotten', id: args.id };
  } catch (err) {
    return {
      isError: true,
      error: 'forget_failed',
      message: err instanceof Error ? err.message : String(err),
    };
  }
}
