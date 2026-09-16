export { DashboardConfigError, createDashboardHandler, maskIp, startDashboard } from "./server.js";
export { brokerSource, engineSource, managementApiSource, managementServerSource, storeSource, toDashboardSource } from "./source.js";
export type { DashboardSource, DashboardSourceLike, ManagementApiSourceOptions, StoreSourceOptions } from "./source.js";
export { DASHBOARD_CSS, DASHBOARD_MARKUP, renderDashboardPage } from "./page.js";
// Replaying a candidate rule set over recorded incidents, and reading a posted draft.
export { candidatePolicy, parseRules, previewPolicy } from "./preview.js";
export type { PreviewChange, PreviewOptions, PreviewResult } from "./preview.js";
// Counting what happened, apart from the incidents a page is holding.
export { FeedCounts } from "./counts.js";
export type { CountsSnapshot, FeedCountsOptions } from "./counts.js";
export type {
  DashboardAuth,
  DashboardBootstrap,
  DashboardControls,
  DashboardHandlerOptions,
  DashboardOptions,
  DashboardRedaction,
  DashboardRefusal,
  DashboardRequestHandler,
  DashboardSections,
  DashboardServer,
} from "./types.js";
