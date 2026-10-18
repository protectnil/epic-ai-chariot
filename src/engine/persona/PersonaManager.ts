/**
 * @epicai/chariot — Persona Manager
 * Register, switch, and manage personas for voice routing.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { PersonaConfig, ConversationContext } from '../types/index.js';
import { SystemPromptBuilder } from './SystemPromptBuilder.js';

// CHARIOT::§8.4.1::1 — the spec text (§8.4.1) names `INJECTION_PATTERNS` as
// "a line-prefix sanitizer in `PersonaManager.ts`". The implementation lives
// in the sibling module `injection-defense.ts` (shared by SystemPromptBuilder
// and Orchestrator to avoid duplicating the pattern set — see that file's
// header comment) rather than being defined inline here. Re-exporting it
// from this module makes `PersonaManager.ts` the on-disk home the spec cites
// (`import { INJECTION_PATTERNS } from './PersonaManager.js'` resolves) while
// keeping the single-source-of-truth definition the multiple consumers share.
export { INJECTION_PATTERNS, sanitizeInjectedContent } from './injection-defense.js';

export class PersonaManager {
  private readonly personas = new Map<string, PersonaConfig>();
  private activeName: string | null = null;

  /**
   * Register a persona. Chainable.
   */
  register(config: PersonaConfig): this {
    this.personas.set(config.name, config);
    if (this.activeName === null) {
      this.activeName = config.name;
    }
    return this;
  }

  /**
   * Switch to a registered persona. Chainable.
   * Throws if the persona is not registered.
   */
  switch(name: string): this {
    if (!this.personas.has(name)) {
      throw new Error(`Persona "${name}" is not registered. Available: ${this.list().map(p => p.name).join(', ')}`);
    }
    this.activeName = name;
    return this;
  }

  /**
   * Get the active persona configuration.
   * Throws if no persona is registered.
   */
  active(): PersonaConfig {
    if (!this.activeName) {
      throw new Error('No persona registered');
    }
    const persona = this.personas.get(this.activeName);
    if (!persona) {
      throw new Error(`Active persona "${this.activeName}" not found`);
    }
    return persona;
  }

  /**
   * List all registered personas.
   */
  list(): PersonaConfig[] {
    return Array.from(this.personas.values());
  }

  /**
   * Build a system prompt for the active persona with the given context.
   */
  buildSystemPrompt(context?: ConversationContext): string {
    return SystemPromptBuilder.build(this.active(), context);
  }

  /**
   * Check if a persona is registered.
   */
  has(name: string): boolean {
    return this.personas.has(name);
  }

  /**
   * Number of registered personas.
   */
  get size(): number {
    return this.personas.size;
  }
}
