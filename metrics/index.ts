// =============================================================================
// Metrics Module
// =============================================================================

export type { MetricsProvider, MetricsConfig, SecurityCheckEvent } from "./types.js";
export { createPostHogProvider } from "./posthog.js";

import type { MetricsProvider, MetricsConfig } from "./types.js";
import { createPostHogProvider } from "./posthog.js";

const DEFAULT_CLIENT_ID = "phc_TMvfuYGtZNgdMh9FjvOQgUPs9qRhdx6Gm2WfGfl7mTG";

export function createMetricsProvider(config: Partial<MetricsConfig>): MetricsProvider | null {
  if (config.enabled === false) {
    return null;
  }

  const clientId = config.clientId?.trim() || DEFAULT_CLIENT_ID;
  return createPostHogProvider(clientId);
}
