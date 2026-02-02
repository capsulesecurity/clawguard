# ClawGuard by Capsule

A security guard plugin for OpenClaw that monitors and validates tool calls before execution using an **LLM as a Judge** approach for risk detection.

## Features

- **Tool Call Logging** - Logs full JSON of every tool call before execution
- **LLM as a Judge** - Uses a secondary LLM to judge and evaluate tool calls for security risks
- **Configurable Blocking** - Automatically blocks high/critical risk operations based on the judge's verdict
- **Custom Judge Prompts** - Override the default judging prompt for security evaluation

## Installation

Add the plugin to your OpenClaw configuration:

```json
{
  "plugins": ["@openclaw/capsule-claw-guard"]
}
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable or disable the plugin |
| `logToolCalls` | boolean | `true` | Log full tool call JSON to logger |
| `securityCheckEnabled` | boolean | `true` | Enable LLM as a Judge for security evaluation |
| `securityPrompt` | string | (built-in) | Custom prompt for the judge LLM |
| `blockOnRisk` | boolean | `true` | Block tool calls judged as high/critical risk |
| `provider` | string | (auto) | Override provider for the judge LLM |
| `model` | string | (auto) | Override model for the judge LLM |
| `authProfileId` | string | (auto) | Auth profile for the judge LLM |
| `timeoutMs` | number | `15000` | Timeout for judge evaluation in milliseconds |

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

## How It Works

1. The plugin hooks into `before_tool_call` events
2. Logs the full tool call JSON (if logging enabled)
3. Sends the tool call to the judge LLM for security evaluation
4. The judge returns a verdict with risk level and reasoning
5. If judged as high/critical risk and blocking is enabled, the tool call is blocked
6. All verdicts are logged for audit purposes

## License

MIT
