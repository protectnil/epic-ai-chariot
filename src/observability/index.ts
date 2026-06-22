/**
 * Chariot Observability — AI-First Telemetry
 *
 * The primary consumer of observability in Chariot is the AI itself.
 * The emitter feeds structured events into MCP tools that the AI client
 * can query. Prometheus/OTEL export remains available for security teams
 * that want their own monitoring stack.
 *
 * Spec reference: Chapter 4 (Alert Architecture), Chapter 8 (Executive Briefing),
 * Chapter 10 (Autonomy Tiers)
 */

export { ChariotEmitter, type ChariotEvent, type ChariotEventType, type AlertSeverity } from './emitter.js';
export { ChariotMetrics } from './metrics.js';
export { AlertQueue, type PendingAlert } from './alerts.js';
