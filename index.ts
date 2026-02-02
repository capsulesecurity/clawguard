import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

type CapsuleClawGuardConfig = {
  enabled?: boolean;
  logToolCalls?: boolean;
  securityCheckEnabled?: boolean;
  securityPrompt?: string;
  blockOnRisk?: boolean;
  provider?: string;
  model?: string;
  authProfileId?: string;
  timeoutMs?: number;
  maxContextWords?: number;
};

type RunEmbeddedPiAgentFn = (params: Record<string, unknown>) => Promise<unknown>;

const DEFAULT_MAX_CONTEXT_WORDS = 2000;

const DEFAULT_SECURITY_PROMPT = `You are a security analyst reviewing tool calls for potential security risks.

Analyze the following tool call and the session context to determine if it poses a security risk.

SECURITY RISKS TO CHECK FOR:
- Command injection (shell commands with untrusted input)
- Path traversal attacks (accessing files outside allowed directories)
- Sensitive data exposure (reading credentials, secrets, private keys)
- Destructive operations (deleting important files, dropping databases)
- Network attacks (unauthorized external requests, data exfiltration)
- Privilege escalation attempts
- Malicious file operations (writing to system directories)
- SQL injection patterns
- Code execution with untrusted input
- Rogue agent behavior (attempts to bypass safety controls, deceptive actions, unauthorized autonomous operations)

SESSION CONTEXT (recent conversation history):
{SESSION_CONTEXT}

TOOL CALL TO ANALYZE:
{TOOL_CALL_JSON}

INSTRUCTIONS:
- Consider the session context when evaluating the tool call
- Return ONLY a valid JSON object
- Do not wrap in markdown fences
- Do not include any commentary

RESPONSE FORMAT:
{
  "isRisk": true/false,
  "riskLevel": "none" | "low" | "medium" | "high" | "critical",
  "riskType": "string describing the type of risk or 'none'",
  "reason": "brief explanation of why this is or is not a risk"
}`;

async function loadRunEmbeddedPiAgent(): Promise<RunEmbeddedPiAgentFn> {
  // Source checkout (tests/dev)
  try {
    const mod = await import("../../src/agents/pi-embedded-runner.js");
    // oxlint-disable-next-line typescript/no-explicit-any
    if (typeof (mod as any).runEmbeddedPiAgent === "function") {
      // oxlint-disable-next-line typescript/no-explicit-any
      return (mod as any).runEmbeddedPiAgent;
    }
  } catch {
    // ignore
  }

  // Bundled install (built)
  const mod = await import("../../agents/pi-embedded-runner.js");
  if (typeof mod.runEmbeddedPiAgent !== "function") {
    throw new Error("Internal error: runEmbeddedPiAgent not available");
  }
  return mod.runEmbeddedPiAgent;
}

function stripCodeFences(s: string): string {
  const trimmed = s.trim();
  const m = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (m) {
    return (m[1] ?? "").trim();
  }
  return trimmed;
}

function collectText(payloads: Array<{ text?: string; isError?: boolean }> | undefined): string {
  const texts = (payloads ?? [])
    .filter((p) => !p.isError && typeof p.text === "string")
    .map((p) => p.text ?? "");
  return texts.join("\n").trim();
}

// Session file parsing utilities
function normalizeSessionText(value: string): string {
  return value
    .replace(/\s*\n+\s*/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractTextFromContent(content: unknown): string | null {
  if (typeof content === "string") {
    const normalized = normalizeSessionText(content);
    return normalized || null;
  }
  if (!Array.isArray(content)) {
    return null;
  }
  const parts: string[] = [];
  for (const block of content) {
    if (!block || typeof block !== "object") {
      continue;
    }
    const record = block as { type?: unknown; text?: unknown };
    if (record.type !== "text" || typeof record.text !== "string") {
      continue;
    }
    const normalized = normalizeSessionText(record.text);
    if (normalized) {
      parts.push(normalized);
    }
  }
  return parts.length > 0 ? parts.join(" ") : null;
}

function resolveStateDir(): string {
  const home = os.homedir();
  return process.env.OPENCLAW_STATE_DIR || path.join(home, ".openclaw");
}

function resolveSessionsDir(agentId: string): string {
  const stateDir = resolveStateDir();
  const normalizedAgentId = agentId.trim().toLowerCase() || "main";
  return path.join(stateDir, "agents", normalizedAgentId, "sessions");
}

async function loadSessionContext(
  sessionKey: string | undefined,
  agentId: string | undefined,
  maxWords: number,
): Promise<string> {
  if (!sessionKey) {
    return "(no session context available)";
  }

  // Parse agentId from sessionKey if not provided
  // Format: "agent:{agentId}:{rest}" or just use provided agentId
  let resolvedAgentId = agentId || "main";
  let sessionId: string | undefined;

  const parts = sessionKey.split(":").filter(Boolean);
  if (parts[0] === "agent" && parts.length >= 2) {
    resolvedAgentId = parts[1] || "main";
    // The session ID might be part of the key or we need to find the file
    if (parts.length >= 3) {
      sessionId = parts.slice(2).join("-");
    }
  }

  const sessionsDir = resolveSessionsDir(resolvedAgentId);

  try {
    // Try to find session files
    const files = await fs.readdir(sessionsDir);
    const jsonlFiles = files.filter((f) => f.endsWith(".jsonl")).sort().reverse();

    if (jsonlFiles.length === 0) {
      return "(no session files found)";
    }

    // Try to find a matching session file, or use the most recent one
    let targetFile: string | undefined;
    if (sessionId) {
      // Look for a file that matches the session ID
      targetFile = jsonlFiles.find(
        (f) => f.includes(sessionId) || f.startsWith(sessionId.split("-")[0] || ""),
      );
    }
    // Fall back to the most recent file
    if (!targetFile) {
      targetFile = jsonlFiles[0];
    }

    const sessionFilePath = path.join(sessionsDir, targetFile);
    const content = await fs.readFile(sessionFilePath, "utf-8");

    // Parse JSONL and extract messages
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

    if (messages.length === 0) {
      return "(no messages in session)";
    }

    // Limit by word count - take from the end (most recent) and work backwards
    const allText = messages.join("\n");
    const words = allText.split(/\s+/);

    if (words.length <= maxWords) {
      return allText;
    }

    // Take the last N words worth of content
    // Work backwards through messages to find how many we can fit
    let wordCount = 0;
    let startIndex = messages.length;

    for (let i = messages.length - 1; i >= 0; i--) {
      const messageWords = messages[i]!.split(/\s+/).length;
      if (wordCount + messageWords > maxWords) {
        break;
      }
      wordCount += messageWords;
      startIndex = i;
    }

    const truncatedMessages = messages.slice(startIndex);
    const truncatedText = truncatedMessages.join("\n");

    return `(truncated to last ~${maxWords} words)\n${truncatedText}`;
  } catch (err) {
    return `(failed to load session: ${String(err)})`;
  }
}

type SecurityCheckResult = {
  isRisk: boolean;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  riskType: string;
  reason: string;
};

async function runSecurityCheck(
  api: OpenClawPluginApi,
  config: CapsuleClawGuardConfig,
  toolCallJson: string,
  sessionContext: string,
): Promise<SecurityCheckResult | null> {
  const primary = api.config?.agents?.defaults?.model?.primary;
  const primaryProvider = typeof primary === "string" ? primary.split("/")[0] : undefined;
  const primaryModel =
    typeof primary === "string" ? primary.split("/").slice(1).join("/") : undefined;

  const provider =
    (typeof config.provider === "string" && config.provider.trim()) || primaryProvider || undefined;

  const model =
    (typeof config.model === "string" && config.model.trim()) || primaryModel || undefined;

  const authProfileId =
    (typeof config.authProfileId === "string" && config.authProfileId.trim()) || undefined;

  if (!provider || !model) {
    api.logger.warn(
      "[clawguard] Cannot run security check: no provider/model configured",
    );
    return null;
  }

  const timeoutMs =
    typeof config.timeoutMs === "number" && config.timeoutMs > 0 ? config.timeoutMs : 15_000;

  const promptTemplate = config.securityPrompt?.trim() || DEFAULT_SECURITY_PROMPT;
  const fullPrompt = promptTemplate
    .replace("{TOOL_CALL_JSON}", toolCallJson)
    .replace("{SESSION_CONTEXT}", sessionContext);

  let tmpDir: string | null = null;
  try {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-capsule-guard-"));
    const sessionId = `capsule-guard-${Date.now()}`;
    const sessionFile = path.join(tmpDir, "session.json");

    const runEmbeddedPiAgent = await loadRunEmbeddedPiAgent();

    const result = await runEmbeddedPiAgent({
      sessionId,
      sessionFile,
      workspaceDir: api.config?.agents?.defaults?.workspace ?? process.cwd(),
      config: api.config,
      prompt: fullPrompt,
      timeoutMs,
      runId: `capsule-guard-${Date.now()}`,
      provider,
      model,
      authProfileId,
      authProfileIdSource: authProfileId ? "user" : "auto",
      disableTools: true,
    });

    // oxlint-disable-next-line typescript/no-explicit-any
    const text = collectText((result as any).payloads);
    if (!text) {
      api.logger.warn("[clawguard] Security check LLM returned empty output");
      return null;
    }

    const raw = stripCodeFences(text);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      api.logger.warn("[clawguard] Security check LLM returned invalid JSON");
      return null;
    }

    // Validate the response structure
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "isRisk" in parsed &&
      typeof (parsed as Record<string, unknown>).isRisk === "boolean"
    ) {
      return parsed as SecurityCheckResult;
    }

    api.logger.warn("[clawguard] Security check response missing required fields");
    return null;
  } catch (err) {
    api.logger.warn(`[clawguard] Security check failed: ${String(err)}`);
    return null;
  } finally {
    if (tmpDir) {
      try {
        await fs.rm(tmpDir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  }
}

const capsuleClawGuardPlugin = {
  id: "clawguard",
  name: "ClawGuard",
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
        provider: { type: "string" },
        model: { type: "string" },
        authProfileId: { type: "string" },
        timeoutMs: { type: "number" },
      },
    },
  },

  register(api: OpenClawPluginApi) {
    const config = (api.pluginConfig ?? {}) as CapsuleClawGuardConfig;

    // Default: enabled
    const enabled = config.enabled !== false;
    if (!enabled) {
      api.logger.info("[clawguard] Plugin disabled via config");
      return;
    }

    // Default: log tool calls on
    const logToolCalls = config.logToolCalls !== false;
    // Default: security check on
    const securityCheckEnabled = config.securityCheckEnabled !== false;
    // Default: block on risk
    const blockOnRisk = config.blockOnRisk !== false;
    // Default: 2000 words max context
    const maxContextWords =
      typeof config.maxContextWords === "number" && config.maxContextWords > 0
        ? config.maxContextWords
        : DEFAULT_MAX_CONTEXT_WORDS;

    api.on("before_tool_call", async (event, ctx) => {
      const { toolName, params } = event;
      const timestamp = new Date().toISOString();

      // Build the tool call JSON object
      const toolCallData = {
        toolName,
        params,
        sessionKey: ctx.sessionKey,
        agentId: ctx.agentId,
        timestamp,
      };

      const toolCallJson = JSON.stringify(toolCallData, null, 2);

      // Log if enabled
      if (logToolCalls) {
        api.logger.info(`[clawguard] Tool call:\n${toolCallJson}`);
      }

      // Run security check if enabled
      if (securityCheckEnabled) {
        // Load session context for the judge
        const sessionContext = await loadSessionContext(ctx.sessionKey, ctx.agentId, maxContextWords);

        const securityResult = await runSecurityCheck(api, config, toolCallJson, sessionContext);

        if (securityResult) {
          if (securityResult.isRisk) {
            api.logger.warn(
              `[clawguard] Security risk detected: ${securityResult.riskLevel} - ${securityResult.riskType}`,
            );
            api.logger.warn(`[clawguard] Reason: ${securityResult.reason}`);

            if (blockOnRisk && ["high", "critical"].includes(securityResult.riskLevel)) {
              api.logger.warn(`[clawguard] Blocking tool call: ${toolName}`);
              return {
                block: true,
                blockReason: `Security risk detected (${securityResult.riskLevel}): ${securityResult.reason}`,
              };
            }
          } else {
            api.logger.info(
              `[clawguard] Security check passed: ${securityResult.reason}`,
            );
          }
        }
      }

      // Allow the tool call to proceed
      return undefined;
    });

    api.logger.info(
      `[clawguard] Initialized (logging: ${logToolCalls}, security: ${securityCheckEnabled}, block: ${blockOnRisk}, maxContextWords: ${maxContextWords})`,
    );
  },
};

export default capsuleClawGuardPlugin;
