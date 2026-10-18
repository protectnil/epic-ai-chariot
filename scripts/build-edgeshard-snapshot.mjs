#!/usr/bin/env node
// Build TypeScript first. Secret material is read by the CLI from env only.
try {
  const { main } = await import('../dist/engine/bin/build-edgeshard-snapshot.js');
  main();
} catch (error) {
  // Native/ONNX errors may contain caller data: expose only a fixed status.
  console.error('EdgeShard production failed; verify the signed bundle, model files, native addon, license context and environment credentials.');
  process.exitCode = 1;
}
