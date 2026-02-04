# ClawGuard by Capsule

![ClawGuard](clawguard.png)

A security guard plugin for OpenClaw that monitors and validates tool calls before execution using an **LLM as a Judge** approach for risk detection.

## Features

- **Tool Call Logging** - Logs full JSON of every tool call before execution
- **LLM as a Judge** - Uses a secondary LLM to judge and evaluate tool calls for security risks
- **Configurable Blocking** - Automatically blocks high/critical risk operations based on the judge's verdict
- **Custom Judge Prompts** - Override the default judging prompt for security evaluation

## Installation

```bash
openclaw plugins install @capsulesecurity/clawguard
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable or disable the plugin |
| `logToolCalls` | boolean | `true` | Log full tool call JSON to logger |
| `securityCheckEnabled` | boolean | `true` | Enable LLM as a Judge for security evaluation |
| `securityPrompt` | string | (built-in) | Custom prompt for the judge LLM |
| `blockOnRisk` | boolean | `true` | Block tool calls judged as high/critical risk |
| `timeoutMs` | number | `15000` | Timeout for judge evaluation in milliseconds |
| `maxContextWords` | number | `2000` | Maximum words of session context to include |
| `gatewayHost` | string | `127.0.0.1` | Gateway host for LLM calls |
| `gatewayPort` | number | `18789` | Gateway port for LLM calls |
| `metricsEnabled` | boolean | `true` | Enable anonymous usage metrics |
| `metricsClientId` | string | (built-in) | PostHog client ID for metrics |

### Example Configuration

```json
{
  "plugins": {
    "capsule-claw-guard": {
      "enabled": true,
      "logToolCalls": true,
      "securityCheckEnabled": true,
      "blockOnRisk": true,
      "timeoutMs": 20000
    }
  }
}
```

## Security Risks Evaluated

The judge LLM evaluates tool calls for:

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

## Custom Judge Prompt

You can provide a custom prompt for the judge LLM using the `securityPrompt` configuration option. Use `{TOOL_CALL_JSON}` as a placeholder for the tool call data:

```json
{
  "plugins": {
    "capsule-claw-guard": {
      "securityPrompt": "You are a security judge. Evaluate this tool call:\n{TOOL_CALL_JSON}\n\nReturn your verdict as JSON: {\"isRisk\": boolean, \"riskLevel\": \"none\"|\"low\"|\"medium\"|\"high\"|\"critical\", \"riskType\": string, \"reason\": string}"
    }
  }
}
```

## Requirements

The plugin makes HTTP calls to the OpenClaw Gateway's `/v1/chat/completions` endpoint for LLM evaluation. This requires:

1. **Gateway running**: The OpenClaw gateway must be running and accessible
2. **Enable chat completions endpoint**: Set `gateway.http.endpoints.chatCompletions.enabled` to `true` in your config:
   ```bash
   openclaw config set gateway.http.endpoints.chatCompletions.enabled true
   ```
3. **Authentication** (optional): If your gateway requires authentication, set one of:
   - `OPENCLAW_GATEWAY_TOKEN` environment variable
   - `OPENCLAW_GATEWAY_PASSWORD` environment variable

## How It Works

1. The plugin hooks into `before_tool_call` events
2. Logs the full tool call JSON (if logging enabled)
3. Loads the session context from session files (limited by `maxContextWords`)
4. Sends both the tool call and session context to the judge LLM for security evaluation
5. The judge returns a verdict with risk level and reasoning
6. If judged as high/critical risk and blocking is enabled, the tool call is blocked
7. All verdicts are logged for audit purposes

## Anonymous Metrics

ClawGuard collects anonymous usage metrics to help improve the plugin. Metrics include:

- Security check events (whether a risk was detected)
- No sensitive data, tool call contents, or user information is collected

Metrics are sent to PostHog and are enabled by default. To disable:

```bash
openclaw config set plugins.clawguard.metricsEnabled false
```

## Session Context

The plugin loads conversation history from the session files to provide context for the judge LLM. This allows the judge to make more informed decisions by understanding the conversation flow that led to the tool call.

- Session files are located at `~/.openclaw/agents/{agentId}/sessions/*.jsonl`
- The context is limited by word count (default: 2000 words) to manage token usage
- Most recent messages are prioritized when truncating
- Only user and assistant messages are included (system messages are filtered out)

## License

MIT
