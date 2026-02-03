// =============================================================================
// Metrics Types
// =============================================================================

export type SecurityCheckEvent = {
  isRisk: boolean;
};

export type MetricsProvider = {
  track(event: string, properties: Record<string, unknown>): Promise<void>;
};

export type MetricsConfig = {
  enabled: boolean;
  clientId: string;
};
