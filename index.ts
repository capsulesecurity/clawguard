import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { createMetricsProvider, type MetricsProvider } from "./metrics/index.js";

// =============================================================================
// Types
// =============================================================================

type ClawGuardConfig = {
  enabled?: boolean;
  logToolCalls?: boolean;
  securityCheckEnabled?: boolean;
  securityPrompt?: string;
  blockOnRisk?: boolean;
  timeoutMs?: number;
  maxContextWords?: number;
  gatewayHost?: string;
  gatewayPort?: number;
  metricsEnabled?: boolean;
  metricsClientId?: string;
};

type SecurityCheckResult = {
  isRisk: boolean;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  riskType: string;
  reason: string;
};

type ToolCallData = {
  toolName: string;
  params: Record<string, unknown>;
  sessionKey?: string;
  agentId?: string;
  timestamp: string;
};

type ChatCompletionResponse = {
  choices?: Array<{
    message?: {
      content?: string;
    };
  }>;
  error?: {
    message?: string;
  };
};

type Logger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
  debug?: (msg: string) => void;
};

// =============================================================================
// Constants
// =============================================================================

const PLUGIN_ID = "clawguard";
const PLUGIN_NAME = "ClawGuard";
const LOG_PREFIX = `[${PLUGIN_ID}]`;

const DEFAULT_MAX_CONTEXT_WORDS = 2000;
const DEFAULT_TIMEOUT_MS = 15_000;

const DEFAULT_SECURITY_PROMPT = `You are a security analyst reviewing tool calls. Your job is to catch genuinely malicious actions while allowing normal development work to proceed.

IMPORTANT: Most tool calls are legitimate. Only flag operations that show clear malicious intent or could cause serious harm. Normal software development activities (reading/writing code, running tests, git operations, installing packages, etc.) should almost always pass.

ONLY FLAG AS HIGH/CRITICAL RISK:
- Exfiltrating sensitive data to external servers (not just reading files locally)
- Executing obfuscated or clearly malicious code
- Attempting to compromise system security (backdoors, reverse shells)
- Destructive operations that contradict the user's explicit request
- Agent trying to deceive the user or bypass explicit safety instructions

DO NOT FLAG (these are normal operations):
- Reading/writing files in the project directory
- Running build commands, tests, or development scripts
- Git operations (commit, push, pull, etc.)
- Installing dependencies via npm/pip/etc.
- Reading config files, logs, or documentation
- File operations the user explicitly requested

SESSION CONTEXT:
{SESSION_CONTEXT}

TOOL CALL:
{TOOL_CALL_JSON}

Consider: If the user asked for this action in the session context, it's almost certainly legitimate.

Return ONLY valid JSON (no markdown fences):
{
  "isRisk": true/false,
  "riskLevel": "none" | "low" | "medium" | "high" | "critical",
  "riskType": "string describing the risk or 'none'",
  "reason": "brief explanation"
}`;

// =============================================================================
// Logging Utilities
// =============================================================================

function createLogger(baseLogger: Logger) {
  return {
    info: (msg: string) => baseLogger.info(`${LOG_PREFIX} ${msg}`),
    warn: (msg: string) => baseLogger.warn(`${LOG_PREFIX} ${msg}`),
    error: (msg: string) => baseLogger.error(`${LOG_PREFIX} ${msg}`),
    debug: (msg: string) => baseLogger.debug?.(`${LOG_PREFIX} ${msg}`),
  };
}

// =============================================================================
// Gateway HTTP Client
// =============================================================================

const DEFAULT_GATEWAY_HOST = "127.0.0.1";
const DEFAULT_GATEWAY_PORT = 18789;

function resolveGatewayUrl(config: ClawGuardConfig, apiConfig: Record<string, unknown> | undefined): string {
  const host = config.gatewayHost?.trim() || DEFAULT_GATEWAY_HOST;
  const port = config.gatewayPort ?? (apiConfig?.gateway as Record<string, unknown>)?.port ?? DEFAULT_GATEWAY_PORT;
  return `http://${host}:${port}`;
}

function resolveGatewayAuthToken(): string | null {
  return process.env.OPENCLAW_GATEWAY_TOKEN ?? process.env.OPENCLAW_GATEWAY_PASSWORD ?? null;
}

async function callGatewayChat(
  gatewayUrl: string,
  authToken: string | null,
  prompt: string,
  timeoutMs: number,
): Promise<string> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (authToken) {
      headers["Authorization"] = `Bearer ${authToken}`;
    }

    const response = await fetch(`${gatewayUrl}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: "openclaw:main",
        messages: [{ role: "user", content: prompt }],
        stream: false,
      }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorText = await response.text().catch(() => "Unknown error");
      throw new Error(`Gateway API error (${response.status}): ${errorText}`);
    }

    const data = (await response.json()) as ChatCompletionResponse;

    if (data.error) {
      throw new Error(`Gateway API error: ${data.error.message}`);
    }

    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      throw new Error("Gateway API returned empty response");
    }

    return content;
  } finally {
    clearTimeout(timeoutId);
  }
}

// =============================================================================
// Text Processing Utilities
// =============================================================================

function stripCodeFences(text: string): string {
  const trimmed = text.trim();
  const match = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  return match ? (match[1] ?? "").trim() : trimmed;
}

function normalizeWhitespace(text: string): string {
  return text
    .replace(/\s*\n+\s*/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// =============================================================================
// Session Context Loader
// =============================================================================

function extractTextFromContent(content: unknown): string | null {
  if (typeof content === "string") {
    const normalized = normalizeWhitespace(content);
    return normalized || null;
  }

  if (!Array.isArray(content)) {
    return null;
  }

  const parts: string[] = [];
  for (const block of content) {
    if (!block || typeof block !== "object") continue;

    const record = block as { type?: unknown; text?: unknown };
    if (record.type !== "text" || typeof record.text !== "string") continue;

    const normalized = normalizeWhitespace(record.text);
    if (normalized) {
      parts.push(normalized);
    }
  }

  return parts.length > 0 ? parts.join(" ") : null;
}

function resolveStateDir(): string {
  return process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
}

function resolveSessionsDir(agentId: string): string {
  const normalizedAgentId = agentId.trim().toLowerCase() || "main";
  return path.join(resolveStateDir(), "agents", normalizedAgentId, "sessions");
}

function parseSessionKey(sessionKey: string): { agentId: string; sessionId?: string } {
  const parts = sessionKey.split(":").filter(Boolean);

  if (parts[0] === "agent" && parts.length >= 2) {
    return {
      agentId: parts[1] || "main",
      sessionId: parts.length >= 3 ? parts.slice(2).join("-") : undefined,
    };
  }

  return { agentId: "main" };
}

function truncateMessagesByWordCount(messages: string[], maxWords: number): string {
  const allText = messages.join("\n");
  const totalWords = allText.split(/\s+/).length;

  if (totalWords <= maxWords) {
    return allText;
  }

  // Work backwards to fit within word limit
  let wordCount = 0;
  let startIndex = messages.length;

  for (let i = messages.length - 1; i >= 0; i--) {
    const messageWords = messages[i]!.split(/\s+/).length;
    if (wordCount + messageWords > maxWords) break;
    wordCount += messageWords;
    startIndex = i;
  }

  const truncatedMessages = messages.slice(startIndex);
  return `(truncated to last ~${maxWords} words)\n${truncatedMessages.join("\n")}`;
}

async function loadSessionContext(
  sessionKey: string | undefined,
  agentId: string | undefined,
  maxWords: number,
  log: ReturnType<typeof createLogger>,
): Promise<string> {
  if (!sessionKey) {
    log.debug("No session key provided");
    return "(no session context available)";
  }

  const parsed = parseSessionKey(sessionKey);
  const resolvedAgentId = agentId || parsed.agentId;
  const sessionsDir = resolveSessionsDir(resolvedAgentId);

  try {
    const files = await fs.readdir(sessionsDir);
    const jsonlFiles = files.filter((f) => f.endsWith(".jsonl")).sort().reverse();

    if (jsonlFiles.length === 0) {
      log.debug(`No session files found in ${sessionsDir}`);
      return "(no session files found)";
    }

    // Find matching session file or use most recent
    let targetFile = parsed.sessionId
      ? jsonlFiles.find(
          (f) => f.includes(parsed.sessionId!) || f.startsWith(parsed.sessionId!.split("-")[0] || ""),
        )
      : undefined;

    targetFile = targetFile || jsonlFiles[0];

    const sessionFilePath = path.join(sessionsDir, targetFile!);
    log.debug(`Loading session from ${sessionFilePath}`);

    const content = await fs.readFile(sessionFilePath, "utf-8");
    const messages = parseSessionMessages(content);

    if (messages.length === 0) {
      return "(no messages in session)";
    }

    log.debug(`Loaded ${messages.length} messages from session`);
    return truncateMessagesByWordCount(messages, maxWords);
  } catch (err) {
    log.debug(`Failed to load session: ${String(err)}`);
    return `(failed to load session: ${String(err)})`;
  }
}

function parseSessionMessages(content: string): string[] {
  const lines = content.split("\n");
  const messages: string[] = [];

  for (const line of lines) {
    if (!line.trim()) continue;

    let record: unknown;
    try {
      record = JSON.parse(line);
    } catch {
      continue;
    }

    if (!record || typeof record !== "object") continue;

    const recordObj = record as { type?: unknown; message?: unknown };
    if (recordObj.type !== "message") continue;

    const message = recordObj.message as { role?: unknown; content?: unknown } | undefined;
    if (!message || typeof message.role !== "string") continue;
    if (message.role !== "user" && message.role !== "assistant") continue;

    const text = extractTextFromContent(message.content);
    if (!text) continue;

    const label = message.role === "user" ? "User" : "Assistant";
    messages.push(`${label}: ${text}`);
  }

  return messages;
}

// =============================================================================
// Security Check (LLM as a Judge)
// =============================================================================

function buildSecurityPrompt(
  template: string,
  toolCallJson: string,
  sessionContext: string,
): string {
  return template
    .replace("{TOOL_CALL_JSON}", toolCallJson)
    .replace("{SESSION_CONTEXT}", sessionContext);
}

function parseSecurityResult(text: string): SecurityCheckResult | null {
  const raw = stripCodeFences(text);

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (
    typeof parsed === "object" &&
    parsed !== null &&
    "isRisk" in parsed &&
    typeof (parsed as Record<string, unknown>).isRisk === "boolean"
  ) {
    return parsed as SecurityCheckResult;
  }

  return null;
}

async function runSecurityCheck(
  api: OpenClawPluginApi,
  config: ClawGuardConfig,
  toolCallJson: string,
  sessionContext: string,
  log: ReturnType<typeof createLogger>,
): Promise<SecurityCheckResult | null> {
  const timeoutMs = config.timeoutMs && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
  const promptTemplate = config.securityPrompt?.trim() || DEFAULT_SECURITY_PROMPT;
  const fullPrompt = buildSecurityPrompt(promptTemplate, toolCallJson, sessionContext);

  const gatewayUrl = resolveGatewayUrl(config, api.config as Record<string, unknown>);
  const authToken = resolveGatewayAuthToken();

  try {
    log.debug(`Running security check via gateway at ${gatewayUrl}`);

    const text = await callGatewayChat(gatewayUrl, authToken, fullPrompt, timeoutMs);

    if (!text) {
      log.warn("Security check LLM returned empty output");
      return null;
    }

    const securityResult = parseSecurityResult(text);

    if (!securityResult) {
      log.warn("Security check response missing required fields or invalid JSON");
      return null;
    }

    return securityResult;
  } catch (err) {
    log.error(`Security check failed: ${String(err)}`);
    return null;
  }
}

// =============================================================================
// Tool Call Handler
// =============================================================================

function buildToolCallData(
  toolName: string,
  params: Record<string, unknown>,
  sessionKey?: string,
  agentId?: string,
): ToolCallData {
  return {
    toolName,
    params,
    sessionKey,
    agentId,
    timestamp: new Date().toISOString(),
  };
}

function shouldBlockToolCall(result: SecurityCheckResult, blockOnRisk: boolean): boolean {
  return blockOnRisk && result.isRisk && ["high", "critical"].includes(result.riskLevel);
}

async function handleToolCall(
  event: { toolName: string; params: Record<string, unknown> },
  ctx: { sessionKey?: string; agentId?: string },
  api: OpenClawPluginApi,
  config: ClawGuardConfig,
  options: {
    logToolCalls: boolean;
    securityCheckEnabled: boolean;
    blockOnRisk: boolean;
    maxContextWords: number;
  },
  log: ReturnType<typeof createLogger>,
  metrics: MetricsProvider | null,
): Promise<{ block: true; blockReason: string } | undefined> {
  const { toolName, params } = event;
  const toolCallData = buildToolCallData(toolName, params, ctx.sessionKey, ctx.agentId);
  const toolCallJson = JSON.stringify(toolCallData, null, 2);

  // Log tool call if enabled
  if (options.logToolCalls) {
    log.info(`Tool call: ${toolName}\n${toolCallJson}`);
  }

  // Skip security check if disabled
  if (!options.securityCheckEnabled) {
    return undefined;
  }

  // Load session context
  const sessionContext = await loadSessionContext(
    ctx.sessionKey,
    ctx.agentId,
    options.maxContextWords,
    log,
  );

  // Run security check
  const result = await runSecurityCheck(api, config, toolCallJson, sessionContext, log);

  if (!result) {
    return undefined;
  }

  // Track metrics (non-sensitive data only)
  if (metrics) {
    metrics.track("security_check", { isRisk: result.isRisk }).catch(() => {});
  }

  // Log result
  if (result.isRisk) {
    log.warn(`Security risk detected: ${result.riskLevel} - ${result.riskType}`);
    log.warn(`Reason: ${result.reason}`);

    if (shouldBlockToolCall(result, options.blockOnRisk)) {
      log.warn(`Blocking tool call: ${toolName}`);
      return {
        block: true,
        blockReason: `Security risk detected (${result.riskLevel}): ${result.reason}`,
      };
    }
  } else {
    log.info(`Security check passed: ${result.reason}`);
  }

  return undefined;
}

// =============================================================================
// Plugin Definition
// =============================================================================

const clawGuardPlugin = {
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  description:
    "Security guard plugin - logs tool calls and uses LLM as a Judge to detect security risks before execution",

  configSchema: {
    jsonSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        enabled: {
          type: "boolean",
          description: "Enable or disable the security guard (default: true)",
        },
        logToolCalls: {
          type: "boolean",
          description: "Log full tool call JSON to logger.info (default: true)",
        },
        securityCheckEnabled: {
          type: "boolean",
          description: "Enable LLM-based security risk detection (default: true)",
        },
        securityPrompt: {
          type: "string",
          description: "Custom prompt for security risk detection (optional)",
        },
        blockOnRisk: {
          type: "boolean",
          description: "Block tool calls when security risk is detected (default: true)",
        },
        maxContextWords: {
          type: "number",
          description: "Maximum words of session context to include (default: 2000)",
        },
        timeoutMs: {
          type: "number",
          description: "Timeout for security check in milliseconds (default: 15000)",
        },
        gatewayHost: {
          type: "string",
          description: "Gateway host for LLM calls (default: 127.0.0.1)",
        },
        gatewayPort: {
          type: "number",
          description: "Gateway port for LLM calls (default: 18789)",
        },
        metricsEnabled: {
          type: "boolean",
          description: "Enable anonymous metrics collection (default: true)",
        },
        metricsClientId: {
          type: "string",
          description: "Metrics client ID (optional, uses default if not provided)",
        },
      },
    },
  },

  register(api: OpenClawPluginApi) {
    const config = (api.pluginConfig ?? {}) as ClawGuardConfig;
    const log = createLogger(api.logger);

    // Check if plugin is enabled
    if (config.enabled === false) {
      log.info("Plugin disabled via config");
      return;
    }

    // Parse configuration with defaults
    const options = {
      logToolCalls: config.logToolCalls !== false,
      securityCheckEnabled: config.securityCheckEnabled !== false,
      blockOnRisk: config.blockOnRisk !== false,
      maxContextWords:
        typeof config.maxContextWords === "number" && config.maxContextWords > 0
          ? config.maxContextWords
          : DEFAULT_MAX_CONTEXT_WORDS,
    };

    // Initialize metrics provider
    const metrics = createMetricsProvider({
      enabled: config.metricsEnabled !== false,
      clientId: config.metricsClientId ?? "",
    });

    // Register hook
    api.on("before_tool_call", async (event, ctx) => {
      return handleToolCall(event, ctx, api, config, options, log, metrics);
    });

    // Log initialization
    const metricsStatus = metrics ? "enabled" : "disabled";
    log.info(
      `Initialized (logging: ${options.logToolCalls}, security: ${options.securityCheckEnabled}, block: ${options.blockOnRisk}, metrics: ${metricsStatus})`,
    );
  },
};

export default clawGuardPlugin;
