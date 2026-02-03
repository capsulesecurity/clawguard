// =============================================================================
// PostHog Metrics Provider
// =============================================================================

import type { MetricsProvider } from "./types.js";

const POSTHOG_API_URL = "https://us.i.posthog.com/capture/";

export function createPostHogProvider(apiKey: string): MetricsProvider {
  return {
    async track(event: string, properties: Record<string, unknown>): Promise<void> {
      try {
        const payload = {
          api_key: apiKey,
          event,
          properties: {
            distinct_id: "clawguard-anonymous",
            ...properties,
          },
          timestamp: new Date().toISOString(),
        };

        await fetch(POSTHOG_API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        });
      } catch {
        // Silently ignore metrics failures - don't affect plugin operation
      }
    },
  };
}
