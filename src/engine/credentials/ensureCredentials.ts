/**
 * Make sure an adapter has the credentials it needs BEFORE it is dispatched,
 * asking for them out of band when it does not.
 *
 * Spec: CHARIOT-SPEC §17.3 (credentials entered outside the chat / server instructions); C4AMD §2 (three tools, unchanged).
 *
 * The required-key set is computed exactly as `chariot add` computes it
 * (rest.envKey + effectiveEnvKeys + restEnvKeys), so the two surfaces can
 * never disagree about what an adapter needs.
 *
 * `prompter` is supplied only where an out-of-band prompt is safe: the
 * single-user local transport. In multi-tenant HTTP there is none, so this
 * returns `unavailable` and the existing credentials_pending path applies.
 */

import { effectiveEnvKeys, restEnvKeys, type AdapterCredentialShape } from '../types/canonical-credentialed-brands.js';
import { isEngineInternalCredentialKey } from '../../cli/credentials.js';

export interface MissingCredentialRequest {
  adapterId: string;
  adapterName: string;
  keys: string[];
}

export type CredentialPromptOutcome =
  | { kind: 'stored' }
  | { kind: 'pending'; url: string }
  | { kind: 'declined' }
  | { kind: 'unavailable' };

export type CredentialPrompter = (req: MissingCredentialRequest) => Promise<CredentialPromptOutcome>;

export type EnsureOutcome =
  | { kind: 'ok' }
  | { kind: 'pending'; url: string; keys: string[] }
  | { kind: 'declined'; keys: string[] }
  | { kind: 'unavailable'; keys: string[] };

/** Credential keys an adapter needs and does not yet have (store or process env). */
export function missingCredentialKeys(
  adapter: AdapterCredentialShape,
  creds: Record<string, string>,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const required: string[] = [];
  const add = (k: string | undefined): void => {
    if (k && !required.includes(k)) required.push(k);
  };
  add(adapter.rest?.envKey);
  for (const k of effectiveEnvKeys(adapter)) add(k);
  for (const f of restEnvKeys(adapter, creds)) add(f.envVar);
  return required.filter((k) => !isEngineInternalCredentialKey(k) && !creds[k] && !env[k]);
}

export async function ensureCredentials(args: {
  adapter: AdapterCredentialShape & { name?: string };
  prompter: CredentialPrompter | undefined;
  /**
   * Re-read the credential store. It is the authority both before prompting
   * and after a `stored` outcome: a person may have finished a private page
   * after an earlier call returned `pending` (or after the wait timed out), and
   * a credential removed from the store must count as absent.
   */
  reload: () => Record<string, string>;
  env?: NodeJS.ProcessEnv;
}): Promise<EnsureOutcome> {
  const env = args.env ?? process.env;
  const missing = missingCredentialKeys(args.adapter, args.reload(), env);
  if (missing.length === 0) return { kind: 'ok' };
  if (!args.prompter) return { kind: 'unavailable', keys: missing };

  let out: CredentialPromptOutcome;
  try {
    out = await args.prompter({ adapterId: args.adapter.id, adapterName: args.adapter.name ?? args.adapter.id, keys: missing });
  } catch {
    return { kind: 'unavailable', keys: missing };
  }
  if (out.kind === 'pending') return { kind: 'pending', url: out.url, keys: missing };
  if (out.kind === 'declined') return { kind: 'declined', keys: missing };
  if (out.kind === 'unavailable') return { kind: 'unavailable', keys: missing };

  // stored: the person completed the private page. Trust the store, not the claim.
  const fresh = args.reload();
  const still = missingCredentialKeys(args.adapter, fresh, env);
  return still.length === 0 ? { kind: 'ok' } : { kind: 'unavailable', keys: still };
}
