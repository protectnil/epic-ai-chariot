/**
 * The MCP `instructions` string Chariot sends on connect.
 * Spec: CHARIOT-SPEC §17.3 (credentials entered outside the chat / server instructions); C4AMD §2 (three tools, unchanged).
 *
 * Every MCP client hands this to its model, so any assistant (Claude, Codex,
 * Gemini, Kimi, Mistral, DeepSeek, …) opens with the same guidance and the
 * person can do everything by talking to their AI: the AI is the interface.
 * It is model-neutral on purpose: no vendor names, no client-specific syntax.
 *
 * It names exactly the three client-visible tools (C4AMD §2::1).
 */
export const CHARIOT_SERVER_INSTRUCTIONS =
  'Chariot MCP connects you to the user\'s company systems through integrations, on the user\'s own machine. ' +
  'To act on a request: use chariot_query (or chariot_list) to find the right integration and tool, then chariot_call to run it. ' +
  'Keep chariot_query queries at or below 1,024 characters; if a request is longer, summarize it while preserving concrete errors, metrics, and time windows. ' +
  'If no integration is connected yet, say in one sentence what Chariot is and offer to connect the first one: ask which tools the user works with. ' +
  'Never ask the user to type or paste a password, token or API key into the chat. When an integration needs credentials, ' +
  'chariot_call guides the user to enter them privately; relay that guidance and wait for them to finish, then retry. ' +
  'Some actions wait for the user\'s approval; when a call is held, say so plainly instead of retrying around it.';
