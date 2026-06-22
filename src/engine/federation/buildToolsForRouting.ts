import type { ChariotRegistryEntry } from '../../catalog/artifacts.js';
import type { Tool } from '../types/index.js';

export function buildToolsForRoutingChariot(adapters: ChariotRegistryEntry[]): Tool[] {
  const tools: Tool[] = [];
  for (const adapter of adapters) {
    const toolNames = adapter.mcp?.toolNames ?? [];
    const base = {
      parameters: { type: 'object', properties: {} },
      server: adapter.id,
      tier: 'orchestrated' as const,
    };
    if (toolNames.length === 0) {
      tools.push({
        ...base,
        name: `${adapter.id}:default`,
        description: `${adapter.name} — ${adapter.description}`,
      });
      continue;
    }
    for (const t of toolNames) {
      tools.push({
        ...base,
        name: `${adapter.id}:${t}`,
        description: `${adapter.name} — ${t.replace(/_/g, ' ')} — ${adapter.description}`,
      });
    }
  }
  return tools;
}
