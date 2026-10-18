export type ToolDispatchMechanism = 'rest' | 'mcp';

export interface DispatchToolRecord {
  name: string;
  dispatchMechanisms: ToolDispatchMechanism[];
}

export interface DispatchAdapterShape {
  type?: string;
  rest?: { toolNames?: string[] };
  mcp?: { toolNames?: string[] };
  tools?: DispatchToolRecord[];
}

export function verifyToolDispatchIdentity(adapter: DispatchAdapterShape): void {
  if (adapter.type !== 'both') return;
  const restNames = adapter.rest?.toolNames;
  const mcpNames = adapter.mcp?.toolNames;
  if (!restNames || !mcpNames || !adapter.tools) {
    throw new Error('dual-surface adapter is missing tool-level routing fields');
  }
  const union = [...new Set([...restNames, ...mcpNames])].sort();
  if (adapter.tools.length !== union.length ||
      JSON.stringify(adapter.tools.map((tool) => tool.name)) !== JSON.stringify(union)) {
    throw new Error('dual-surface adapter tool union does not match its routed tools');
  }
  const restSet = new Set(restNames);
  const mcpSet = new Set(mcpNames);
  for (const tool of adapter.tools) {
    const expected = [
      ...(mcpSet.has(tool.name) ? ['mcp' as const] : []),
      ...(restSet.has(tool.name) ? ['rest' as const] : []),
    ];
    if (JSON.stringify(tool.dispatchMechanisms) !== JSON.stringify(expected)) {
      throw new Error(`tool ${tool.name} dispatch mechanisms disagree with its surfaces`);
    }
  }
}

/** Resolve the transport from the selected tool, never from adapter-level preference. */
export function resolveToolDispatchMechanism(
  adapter: DispatchAdapterShape,
  toolName: string,
): ToolDispatchMechanism | undefined {
  verifyToolDispatchIdentity(adapter);
  const tool = adapter.tools?.find((candidate) => candidate.name === toolName);
  if (tool) {
    const mechanisms = [...new Set(tool.dispatchMechanisms)];
    if (mechanisms.some((mechanism) => mechanism !== 'rest' && mechanism !== 'mcp')) {
      throw new Error(`tool ${toolName} declares an unknown dispatch mechanism`);
    }
    if (mechanisms.includes('rest')) return 'rest';
    if (mechanisms.includes('mcp')) return 'mcp';
    throw new Error(`tool ${toolName} declares no dispatch mechanism`);
  }

  const onRest = adapter.rest?.toolNames?.includes(toolName) ?? false;
  const onMcp = adapter.mcp?.toolNames?.includes(toolName) ?? false;
  if (adapter.type === 'both') {
    throw new Error(`dual-surface adapter is missing the tool-level route for ${toolName}`);
  }
  if (onRest || (adapter.rest && !adapter.mcp)) return 'rest';
  if (onMcp || (adapter.mcp && !adapter.rest)) return 'mcp';
  if (adapter.type === 'cli-bridge') return undefined;
  throw new Error(`tool ${toolName} is not declared on an executable surface`);
}
