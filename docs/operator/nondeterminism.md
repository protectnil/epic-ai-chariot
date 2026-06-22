# Nondeterminism in Chariot Routing

**Audience:** Operators deploying or debugging Epic AI® Chariot  
**Date:** 2026-05-16  
**Related spec:** See the private spec directory for design context and open questions.

---

## 1. What Is Deterministic

Two components of the routing pipeline are fully deterministic given a fixed catalog corpus.

### Catalog load

The adapter bundle (`chariot-adapter-bundle.json`) is a static file loaded at startup. The in-memory catalog is identical across restarts for the same bundle file. There is no randomness in catalog loading.

### ToolPreFilter — sort, BM25, and pin

The pre-filter that narrows the full catalog to a ranked shortlist before the LLM sees it is deterministic for a fixed corpus, a fixed query string, **and a fixed health state across the registered servers**. Every sort in the pipeline carries an explicit lexicographic tie-break on `server:name` so equal-score tools always produce the same relative ordering.

**Health-state caveat.** `select()` (`ToolPreFilter.ts:L576`) and `selectSync()` (`L974`) are thin wrappers over one shared synchronous ranker, `selectInternal()` (`L596`); the optional `healthChecker` is consulted there (`L609`) and any tool whose server is reported `down` is dropped before scoring runs. If the connection-pool's view of an adapter flips from `connected` → `disconnected` (or back) between two otherwise-identical queries, the shortlist can change for that reason alone. The pre-filter itself adds no other source of variance. Because `select()`/`selectSync()` share `selectInternal()`, the sync and async shortlists are identical for the same query.

Key implementation sites in `src/engine/federation/ToolPreFilter.ts` (all within `selectInternal()`):

| Lines | Stage | Tie-break |
|-------|-------|-----------|
| 618–622 | Candidate set initial sort | `server:name` ASC |
| 831–833 | BM25 results sort | `b.score - a.score`, then `a.id < b.id` ASC |
| 839–850 | Per-server bucketing (server appearance order) | first-occurrence over the BM25-desc/id-asc list |
| 793–799 | Exact-name pin sort | compound-full-match first, then `b.minIdf - a.minIdf`, then `b.server.length - a.server.length` |

Ranking is BM25 only (real IDF with document-length normalization), followed by deterministic exact-name / canonical-vendor / phrase pins and a brand-token hoist — all pure arithmetic with fixed lexicographic tie-breaks, introducing no randomness of its own.

**Practical guarantee:** Given the same adapter bundle and the same query string, ToolPreFilter will return the same ranked shortlist every time.

---

## 2. What Is Not Deterministic

### Downstream LLM selection (Adaline failure mode 5)

After ToolPreFilter builds the shortlist (`≤ 8 tools` by default), Chariot passes it to the orchestrator LLM, which selects which tool to call. That LLM selection is **not deterministic in practice**, even at `temperature=0`.

Two mechanisms drive this:

**Inference precision (BF16 baseline variance).** Yuan et al. (NeurIPS 2025 Oral, "Understanding and Mitigating Numerical Sources of Nondeterminism in LLM Inference," arXiv:2506.09501) established that the numeric precision format used during inference — FP32, FP16, or BF16 — directly determines output variance. Under bfloat16 with greedy decoding, the paper reports up to 9% accuracy variation and 9,000-token response-length variation across GPU count, type, and batch-size configurations on a reasoning model; FP32 achieves near-perfect reproducibility, FP16 shows moderate variability, BF16 exhibits substantial instability. Production inference infrastructure runs predominantly on BF16 for throughput, so the same prompt, same model, same `temperature=0` setting can produce different outputs depending on the underlying hardware configuration.

**Batch invariance failure (dominant source).** Thinking Machines Lab ("Defeating Nondeterminism in LLM Inference," thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/) identified batch invariance failure as the most common production nondeterminism source. When an inference server handles multiple concurrent requests, dynamic batching changes the kernel reduction order, so the numerical computation path depends on what other queries happen to be batched alongside yours. A query processed alone may route to tool A; the same query processed in a batch with unrelated concurrent requests may route to tool B. Their headline experiment: 1,000 completions of "Tell me about Richard Feynman" through Qwen3-235B-A22B-Instruct at temperature=0 produced 80 unique completions under standard kernels (divergence first appearing at token 103); the same experiment with their batch-invariant kernels produced all 1,000 completions identical (companion library: github.com/thinking-machines-lab/batch_invariant_ops). This is not a bug in the inference server; it is a consequence of hardware-optimized computation graphs that prioritize throughput over bit-level reproducibility.

The Adaline Labs article "Building AI Agents That Don't Break in Production" (May 9, 2026) summarizes both findings for an operator audience:

> "The model will not get more consistent. The product needs to be designed for the model it already has."

---

## 3. Operator Implications

**Same query, different routes.** On separate runs — or even on concurrent runs if the inference server batches them — the same query string may produce different tool selections. ToolPreFilter will return the same shortlist each time; the LLM may choose differently from that shortlist.

**Intermittent behavior is expected, not a gateway defect.** Before filing a routing bug, verify whether the behavior is consistent on isolated, sequential runs. The `action` StreamEvent emitted per tool call carries the LLM-chosen `tool` and `server`; if you see those vary across otherwise-identical runs, the variance is LLM-side (the gateway shortlist is deterministic given a fixed corpus). The shortlist itself is NOT emitted on any StreamEvent variant today; to compare shortlists across runs, instrument `ToolPreFilter.select()` directly in your deployment.

**Temperature=0 is insufficient.** Setting `temperature=0` reduces one source of variance but does not eliminate batch invariance failure. Do not treat `temperature=0` as a determinism guarantee.

---

## 4. Mitigations

**Design the product for the model you have.** Operators should treat LLM tool selection as probabilistic, not deterministic:

- **Surface confidence where available.** If your LLM provider returns logprobs or token probabilities, use them to display a confidence indicator alongside tool-call results. When confidence is low, prompt the user or operator to confirm.

- **Allow operator correction.** Design workflows so that a routed tool call can be overridden or redirected without restarting the query. Chariot's tiered-autonomy (auto / escalate / approve) is the existing mechanism for approval flows — wire irreversible tool calls through the escalate or approve tier rather than the auto tier if routing consistency is critical.

- **Log adapter selections.** Every `action` StreamEvent emitted by the Orchestrator carries the LLM-chosen `tool` and `server` for that iteration. Log them per run. The full pre-LLM shortlist is NOT exposed on any StreamEvent variant today — to capture it for cross-run comparison, instrument `ToolPreFilter.select()` directly in your deployment (wrap it to log the returned `Tool[]` before it reaches the orchestrator). When a user reports unexpected routing and the captured shortlist is stable across runs, the variance is LLM-side.

- **Description quality is the highest-leverage knob.** Adaline Labs' Tool Selection Problem article (May 16, 2026) establishes that tool descriptions — not system prompts — are the primary signal the model uses at selection time. Ambiguous overlap between two tool descriptions is the most common description-level cause of selection variance. Writing distinct, negatively-constrained descriptions (what the tool does *and* when *not* to call it) reduces ambiguity and tightens the effective decision boundary.

- **Shortlist size.** A smaller shortlist presents fewer candidates for the LLM to disambiguate. Chariot's default `maxTools=8` is calibrated at the Adaline-recommended ceiling (10–12 tools). Reducing it further narrows the LLM's selection problem.

---

## 5. Related Work

| Reference | Claim |
|-----------|-------|
| Yuan et al., "Understanding and Mitigating Numerical Sources of Nondeterminism in LLM Inference," NeurIPS 2025 Oral, arXiv:2506.09501 | BF16 baseline variance: up to 9% accuracy / 9,000-token response-length variation across GPU and batch-size configurations under bfloat16 greedy decoding; FP32 achieves near-perfect reproducibility |
| Thinking Machines Lab, "Defeating Nondeterminism in LLM Inference," thinkingmachines.ai/blog | Batch invariance failure as dominant production nondeterminism source. Standard kernels: 80 unique outputs across 1,000 runs of the same prompt at temp=0 (Qwen3-235B-A22B-Instruct). Batch-invariant kernels: all 1,000 runs produce identical output. |
| Adaline Labs, "Building AI Agents That Don't Break in Production" (May 9, 2026), failure mode 5 (secondary) | Operator framing of the above two findings; temperature=0 insufficient |
| Adaline Labs, "The Tool Selection Problem" (May 16, 2026), failure mode 1 (ambiguous overlap) | Tool descriptions are the primary selection signal; ambiguous overlap is the most common cause of selection inconsistency |

---

*Epic AI® is a registered trademark of protectNIL Inc.*  
*IVA — Intelligent Virtual Assistant*
