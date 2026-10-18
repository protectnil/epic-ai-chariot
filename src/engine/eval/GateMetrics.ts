export type ArgumentComplexity = 'zero-arg' | 'simple-args' | 'nested-required';
export type DispatchMechanism = 'mcp' | 'rest' | 'cli-bridge';

export interface GcManifestRow {
  queryId: string;
  query: string;
  dedupeClusterId: string;
  family: string;
  adapterId: string;
  category: string;
  tailTool: boolean;
  argumentComplexity: ArgumentComplexity;
  dispatchMechanism: DispatchMechanism;
  goldToolId: string;
}

export interface GcObservation {
  queryId: string;
  selectedToolId?: string;
  submittedToolId?: string;
  argumentsSchemaValid: boolean;
  dispatchSucceeded: boolean;
}

export interface GcFloors {
  total: number;
  perFamily: number;
  distinctAdapters: number;
  perCategory: number;
  tailFraction: number;
  perArgumentComplexity: number;
  perDispatchMechanism: number;
  lcb: number;
}

export interface GateCell {
  successes: number;
  n: number;
  estimate: number;
  lcb: number;
  passed: boolean;
}

export interface GcGateResult {
  passed: boolean;
  aggregate: GateCell;
  mandatorySlices: Record<string, GateCell>;
  diagnosticSlices: Record<string, GateCell>;
  failuresByStage: { route: number; args: number; dispatch: number };
}

export const DEFAULT_GC_FLOORS: Readonly<GcFloors> = {
  total: 1000,
  perFamily: 25,
  distinctAdapters: 300,
  perCategory: 20,
  tailFraction: 0.10,
  perArgumentComplexity: 100,
  perDispatchMechanism: 100,
  lcb: 0.95,
};

export function wilsonLowerBound(successes: number, n: number, z = 1.6448536269514722): number {
  if (!Number.isInteger(successes) || !Number.isInteger(n) || n < 1 || successes < 0 || successes > n) {
    throw new RangeError('Wilson inputs require integer 0 <= successes <= n and n >= 1');
  }
  const estimate = successes / n;
  const z2 = z * z;
  return (
    estimate + z2 / (2 * n)
    - z * Math.sqrt((estimate * (1 - estimate) / n) + z2 / (4 * n * n))
  ) / (1 + z2 / n);
}

function gateCell(rows: readonly boolean[], threshold: number): GateCell {
  if (!rows.length) throw new Error('gated slice is empty');
  const successes = rows.filter(Boolean).length;
  const estimate = successes / rows.length;
  const lcb = wilsonLowerBound(successes, rows.length);
  return { successes, n: rows.length, estimate, lcb, passed: lcb >= threshold };
}

function census(rows: readonly GcManifestRow[], key: (row: GcManifestRow) => string): Map<string, number> {
  const result = new Map<string, number>();
  rows.forEach((row) => result.set(key(row), (result.get(key(row)) ?? 0) + 1));
  return result;
}

function requireFloor(name: string, values: Map<string, number>, keys: readonly string[], floor: number): void {
  const failures = keys.filter((key) => (values.get(key) ?? 0) < floor);
  if (failures.length) throw new Error(`${name} sampling floor failed: ${failures.slice(0, 5).join(', ')}`);
}

export function evaluateGcGate(
  manifest: readonly GcManifestRow[],
  observations: readonly GcObservation[],
  options: {
    applicableFamilies: readonly string[];
    catalogCategories: readonly string[];
    floors?: GcFloors;
  },
): GcGateResult {
  const floors = options.floors ?? DEFAULT_GC_FLOORS;
  if (manifest.length < floors.total) throw new Error('G-C total sampling floor failed');
  const queryIds = new Set<string>();
  const clusters = new Set<string>();
  for (const row of manifest) {
    if (!row.queryId || queryIds.has(row.queryId)) throw new Error('G-C query IDs must be unique');
    if (!row.dedupeClusterId || clusters.has(row.dedupeClusterId)) {
      throw new Error('G-C exact/near-duplicate clusters must be removed before metrics');
    }
    queryIds.add(row.queryId);
    clusters.add(row.dedupeClusterId);
  }
  requireFloor('query-family', census(manifest, (row) => row.family), options.applicableFamilies, floors.perFamily);
  if (new Set(manifest.map((row) => row.adapterId)).size < floors.distinctAdapters) {
    throw new Error('G-C distinct-adapter sampling floor failed');
  }
  requireFloor('category', census(manifest, (row) => row.category), options.catalogCategories, floors.perCategory);
  if (manifest.filter((row) => row.tailTool).length / manifest.length < floors.tailFraction) {
    throw new Error('G-C tail sampling floor failed');
  }
  const complexities: ArgumentComplexity[] = ['zero-arg', 'simple-args', 'nested-required'];
  const mechanisms: DispatchMechanism[] = ['mcp', 'rest', 'cli-bridge'];
  requireFloor(
    'argument-complexity', census(manifest, (row) => row.argumentComplexity),
    complexities, floors.perArgumentComplexity,
  );
  requireFloor(
    'dispatch-mechanism', census(manifest, (row) => row.dispatchMechanism),
    mechanisms, floors.perDispatchMechanism,
  );

  const observationById = new Map(observations.map((row) => [row.queryId, row]));
  if (observationById.size !== manifest.length || observations.some((row) => !queryIds.has(row.queryId))) {
    throw new Error('G-C observations must cover the frozen manifest exactly once');
  }
  const outcomes = manifest.map((row) => {
    const observed = observationById.get(row.queryId);
    if (!observed) throw new Error(`missing G-C observation ${row.queryId}`);
    const route = observed.selectedToolId === row.goldToolId
      && observed.submittedToolId === row.goldToolId;
    return {
      row,
      route,
      args: route && observed.argumentsSchemaValid,
      dispatch: route && observed.argumentsSchemaValid && observed.dispatchSucceeded,
    };
  });
  const mandatorySlices: Record<string, GateCell> = {};
  mandatorySlices.tail = gateCell(
    outcomes.filter(({ row }) => row.tailTool).map(({ dispatch }) => dispatch), floors.lcb,
  );
  for (const complexity of complexities) {
    mandatorySlices[`argument:${complexity}`] = gateCell(
      outcomes.filter(({ row }) => row.argumentComplexity === complexity)
        .map(({ dispatch }) => dispatch),
      floors.lcb,
    );
  }
  for (const mechanism of mechanisms) {
    mandatorySlices[`dispatch:${mechanism}`] = gateCell(
      outcomes.filter(({ row }) => row.dispatchMechanism === mechanism)
        .map(({ dispatch }) => dispatch),
      floors.lcb,
    );
  }
  const diagnosticSlices: Record<string, GateCell> = {};
  for (const dimension of ['family', 'adapterId', 'category'] as const) {
    for (const value of [...new Set(manifest.map((row) => row[dimension]))].sort()) {
      diagnosticSlices[`${dimension}:${value}`] = gateCell(
        outcomes.filter(({ row }) => row[dimension] === value)
          .map(({ dispatch }) => dispatch),
        floors.lcb,
      );
    }
  }
  const aggregate = gateCell(outcomes.map(({ dispatch }) => dispatch), floors.lcb);
  return {
    passed: aggregate.passed && Object.values(mandatorySlices).every((cell) => cell.passed),
    aggregate,
    mandatorySlices,
    diagnosticSlices,
    failuresByStage: {
      route: outcomes.filter(({ route }) => !route).length,
      args: outcomes.filter(({ route, args }) => route && !args).length,
      dispatch: outcomes.filter(({ args, dispatch }) => args && !dispatch).length,
    },
  };
}
