/**
 * Credential prompter for the single-user MCP transport.
 * Spec: CHARIOT-SPEC §17.3 (credentials entered outside the chat / server instructions); C4AMD §2 (three tools, unchanged).
 *
 * Opens the private credential page (CredentialPortal) and, where the AI
 * client supports MCP URL-mode elicitation, asks the client to send the person
 * there with its own native prompt — the MCP spec reserves URL mode for exactly
 * this case (secrets must not travel through form mode or the model).
 *
 * Clients without URL elicitation get the URL back as `pending`; the tool
 * result tells the AI to show it to the person and to ask them to say when
 * they have finished.
 *
 * One live portal per adapter: a second call while the page is still open
 * returns the same URL rather than starting another.
 */

import { randomUUID } from 'node:crypto';
import { writeCredential, removeCredential, loadCredentials } from '../../cli/credentials.js';
import { startCredentialPortal, type PortalOptions, type PortalSession } from './CredentialPortal.js';
import type { CredentialPrompter, MissingCredentialRequest } from './ensureCredentials.js';

export interface ElicitingServer {
  getClientCapabilities(): { elicitation?: { url?: unknown } } | undefined;
  elicitInput(
    params: { mode: 'url'; message: string; url: string; elicitationId: string },
    options?: { timeout?: number },
  ): Promise<{ action: string }>;
}

export interface PrompterDeps {
  server: ElicitingServer;
  start?: (o: PortalOptions) => Promise<PortalSession>;
  store?: (key: string, value: string) => void;
  /** How long to wait for the person to finish before returning `pending`. */
  waitMs?: number;
}

export function createCredentialPrompter(deps: PrompterDeps): CredentialPrompter {
  const start = deps.start ?? startCredentialPortal;
  const store = deps.store ?? writeCredential;
  const waitMs = deps.waitMs ?? 45_000;
  // Holds the PENDING session promise, registered synchronously, so two
  // concurrent calls for one adapter share one page instead of each starting one.
  const live = new Map<string, { session: Promise<PortalSession>; keys: string }>();

  return async (req: MissingCredentialRequest) => {
    const keyId = [...req.keys].sort().join('\n');
    let entry = live.get(req.adapterId);
    if (!entry || entry.keys !== keyId) {
      void entry?.session.then((old) => old.close(), () => {});
      const created = (async (): Promise<PortalSession> => start({
        adapterName: req.adapterName,
        keys: req.keys,
        store,
        // Only the production store can be read back and restored; an injected
        // `store` (tests) gets the portal's close-on-partial-failure behavior.
        ...(deps.store === undefined
          ? {
              isMissing: (k: string) => !loadCredentials()[k] && !process.env[k],
              peek: (k: string) => loadCredentials()[k],
              restore: (k: string, previous: string | undefined) => {
                if (previous === undefined) removeCredential([k]);
                else writeCredential(k, previous);
              },
            }
          : {}),
      }))();
      entry = { session: created, keys: keyId };
      live.set(req.adapterId, entry);
      const mine = entry;
      created.then(
        (s) => {
          void s.completed.finally(() => {
            if (live.get(req.adapterId) === mine) live.delete(req.adapterId);
          });
        },
        () => {
          if (live.get(req.adapterId) === mine) live.delete(req.adapterId);
        },
      );
    }
    const session = await entry.session;

    const caps = deps.server.getClientCapabilities();
    if (!caps?.elicitation || caps.elicitation.url === undefined) {
      return { kind: 'pending', url: session.url };
    }

    try {
      const answer = await deps.server.elicitInput({
        mode: 'url',
        message: `Enter the ${req.adapterName} credentials on a private page on this computer. Chariot does not show them to the AI.`,
        url: session.url,
        elicitationId: randomUUID(),
      });
      if (answer.action !== 'accept') {
        session.close();
        return { kind: 'declined' };
      }
    } catch {
      // The client advertised URL elicitation but could not complete it.
      return { kind: 'pending', url: session.url };
    }

    const end = await Promise.race([
      session.completed,
      new Promise<'wait'>((r) => setTimeout(() => r('wait'), waitMs).unref()),
    ]);
    if (end === 'stored') return { kind: 'stored' };
    return { kind: 'pending', url: session.url };
  };
}
