/**
 * @epicai/chariot — Retrieval subsystem (§4 / §8.6)
 *
 * Public surface of the 4.0.0 hybrid retrieval rebuild: RRF fusion, the
 * EdgeShard-backed HybridRetriever, the LLM-free cross-encoder reranker, the
 * fail-closed VectorIndexVerifier admission gate, and the confidence/abstention
 * calibration. The native Edge binding loader is re-exported for the load path.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export * from './types.js';
export { RankFusion, DEFAULT_K } from './RankFusion.js';
export { CrossEncoderReranker } from './CrossEncoderReranker.js';
export {
  HybridRetriever,
  type HybridRetrieverConfig,
  type HybridRetrieverDeps,
  type RetrieverLogger,
} from './HybridRetriever.js';
export {
  VectorIndexVerifier,
  DEFAULT_RETRIEVAL_CONTRACT,
  COMPILED_SERIALIZER_HASH,
  type RetrievalContract,
  type AdmissionResult,
  type AdmissionCode,
  type AdmitOptions,
  type BundleEnvelope,
  type BundleManifest,
} from './VectorIndexVerifier.js';
export {
  scoreConfidence,
  absoluteSignal,
  relevanceSignal,
  DEFAULT_CONFIDENCE_CONFIG,
  type ConfidenceConfig,
  type ConfidenceVerdict,
} from './confidence.js';
export {
  wireHybridRetrieval,
  type ArtifactSource,
  type WireRetrievalOptions,
  type WireResult,
} from './loadRetrieval.js';
export {
  loadNativeEdge,
  getNativeEdgeLoadError,
  type NativeEdgeBinding,
  type NativeEdgeShard,
  type NativeDenseEncoder,
  type NativeQueryRequest,
  type NativeScoredPoint,
} from './nativeEdge.js';
