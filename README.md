# ClawGuard by Capsule

A security guard plugin for OpenClaw that monitors and validates tool calls before execution using LLM-based risk detection.

## Features

- **Tool Call Logging** - Logs full JSON of every tool call before execution
- **LLM Security Analysis** - Uses AI to detect potential security risks in tool calls
- **Configurable Blocking** - Automatically blocks high/critical risk operations
- **Custom Security Prompts** - Override the default security analysis prompt

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
| `securityCheckEnabled` | boolean | `true` | Enable LLM-based security risk detection |
| `securityPrompt` | string | (built-in) | Custom prompt for security analysis |
| `blockOnRisk` | boolean | `true` | Block tool calls flagged as high/critical risk |
| `provider` | string | (auto) | Override LLM provider for security checks |
| `model` | string | (auto) | Override LLM model for security checks |
| `authProfileId` | string | (auto) | Auth profile for security check LLM |
| `timeoutMs` | number | `15000` | Timeout for security check in milliseconds |

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

## Security Risks Detected

The plugin analyzes tool calls for:

- Command injection (shell commands with untrusted input)
- Path traversal attacks (accessing files outside allowed directories)
- Sensitive data exposure (reading credentials, secrets, private keys)
- Destructive operations (deleting important files, dropping databases)
- Network attacks (unauthorized external requests, data exfiltration)
- Privilege escalation attempts
- Malicious file operations (writing to system directories)
- SQL injection patterns
- Code execution with untrusted input

## Custom Security Prompt

You can provide a custom security prompt using the `securityPrompt` configuration option. Use `{TOOL_CALL_JSON}` as a placeholder for the tool call data:

```json
{
  "plugins": {
    "capsule-claw-guard": {
      "securityPrompt": "Analyze this tool call for risks:\n{TOOL_CALL_JSON}\n\nReturn JSON: {\"isRisk\": boolean, \"riskLevel\": \"none\"|\"low\"|\"medium\"|\"high\"|\"critical\", \"riskType\": string, \"reason\": string}"
    }
  }
}
```

## How It Works

1. The plugin hooks into `before_tool_call` events
2. Logs the full tool call JSON (if logging enabled)
3. Sends the tool call to the configured LLM for security analysis
4. If a high/critical risk is detected and blocking is enabled, the tool call is blocked
5. All security findings are logged for audit purposes

## License

MIT
