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
};

type RunEmbeddedPiAgentFn = (params: Record<string, unknown>) => Promise<unknown>;

const DEFAULT_SECURITY_PROMPT = `You are a security analyst reviewing tool calls for potential security risks.

Analyze the following tool call and determine if it poses a security risk.

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

TOOL CALL TO ANALYZE:
{TOOL_CALL_JSON}

INSTRUCTIONS:
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
      "[capsule-claw-guard] Cannot run security check: no provider/model configured",
    );
    return null;
  }

  const timeoutMs =
    typeof config.timeoutMs === "number" && config.timeoutMs > 0 ? config.timeoutMs : 15_000;

  const promptTemplate = config.securityPrompt?.trim() || DEFAULT_SECURITY_PROMPT;
  const fullPrompt = promptTemplate.replace("{TOOL_CALL_JSON}", toolCallJson);

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
      api.logger.warn("[capsule-claw-guard] Security check LLM returned empty output");
      return null;
    }

    const raw = stripCodeFences(text);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      api.logger.warn("[capsule-claw-guard] Security check LLM returned invalid JSON");
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

    api.logger.warn("[capsule-claw-guard] Security check response missing required fields");
    return null;
  } catch (err) {
    api.logger.warn(`[capsule-claw-guard] Security check failed: ${String(err)}`);
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
  id: "capsule-claw-guard",
  name: "Capsule Claw Guard",
  description:
    "Security guard plugin - logs tool calls and uses LLM to detect security risks before execution",

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
      api.logger.info("[capsule-claw-guard] Plugin disabled via config");
      return;
    }

    // Default: log tool calls on
    const logToolCalls = config.logToolCalls !== false;
    // Default: security check on
    const securityCheckEnabled = config.securityCheckEnabled !== false;
    // Default: block on risk
    const blockOnRisk = config.blockOnRisk !== false;

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
        api.logger.info(`[capsule-claw-guard] Tool call:\n${toolCallJson}`);
      }

      // Run security check if enabled
      if (securityCheckEnabled) {
        const securityResult = await runSecurityCheck(api, config, toolCallJson);

        if (securityResult) {
          if (securityResult.isRisk) {
            api.logger.warn(
              `[capsule-claw-guard] Security risk detected: ${securityResult.riskLevel} - ${securityResult.riskType}`,
            );
            api.logger.warn(`[capsule-claw-guard] Reason: ${securityResult.reason}`);

            if (blockOnRisk && ["high", "critical"].includes(securityResult.riskLevel)) {
              api.logger.warn(`[capsule-claw-guard] Blocking tool call: ${toolName}`);
              return {
                block: true,
                blockReason: `Security risk detected (${securityResult.riskLevel}): ${securityResult.reason}`,
              };
            }
          } else {
            api.logger.info(
              `[capsule-claw-guard] Security check passed: ${securityResult.reason}`,
            );
          }
        }
      }

      // Allow the tool call to proceed
      return undefined;
    });

    api.logger.info(
      `[capsule-claw-guard] Initialized (logging: ${logToolCalls}, security: ${securityCheckEnabled}, block: ${blockOnRisk})`,
    );
  },
};

export default capsuleClawGuardPlugin;
