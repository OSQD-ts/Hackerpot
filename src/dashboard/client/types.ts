/**
 * The shapes the dashboard API answers in, as the browser sees them.
 *
 * Mirrored rather than imported. The server's own declarations sit beside `node:http`
 * types and the management API's store functions, and importing them into the DOM build
 * would type-check half the library under a lib it was never written for. They are small,
 * the server is the side that has to keep them stable, and `tests/dashboard-client.test.ts`
 * assigns a server value to each of these so the day they drift apart is a compile error
 * rather than a panel that quietly reads `undefined`.
 *
 * Every string in here except the ones the server itself chose (`id`, `timestamp`,
 * `respondedWith`) was written by whoever sent the request. That is the whole reason the
 * client never builds markup out of them.
 */

export interface Detection {
  detectorId: string;
  reason: string;
  score: number;
  metadata?: { readonly [key: string]: unknown } | undefined;
}

export interface IpEnrichment {
  category: string;
  global?: boolean | undefined;
  asn?: number | undefined;
  org?: string | undefined;
  country?: string | undefined;
}

/** One recorded honeypot hit. `HoneypotHit` on the server. */
export interface Incident {
  id: string;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  rawPath?: string | undefined;
  headers: { readonly [name: string]: string | readonly string[] | undefined };
  body?: string | undefined;
  fingerprint?: string | undefined;
  enrichment?: IpEnrichment | undefined;
  detections: readonly Detection[];
  shadowDetections?: readonly Detection[] | undefined;
  score: number;
  totalScore: number;
  respondedWith: string;
  downgradedFrom?: string | undefined;
}

export interface StatsSummary {
  totalIncidents: number;
  uniqueIps: number;
  byDetector: { readonly [detector: string]: number };
  byResponse: { readonly [response: string]: number };
  topOffenders: ReadonlyArray<{ ip: string; score: number; incidents: number }>;
  firstSeen?: string | undefined;
  lastSeen?: string | undefined;
}

export interface SessionStep {
  timestamp: string;
  method: string;
  path: string;
  detectors: readonly string[];
  score: number;
  totalScore: number;
  respondedWith: string;
}

export interface AttackSession {
  ip: string;
  score: number;
  incidents: number;
  detectors: readonly string[];
  responses: readonly string[];
  firstSeen: string;
  lastSeen: string;
  timeline: readonly SessionStep[];
}

export interface ActorGroup {
  fingerprint: string;
  ips: readonly string[];
  score: number;
  incidents: number;
  detectors: readonly string[];
  firstSeen: string;
  lastSeen: string;
}

export interface IocEntry {
  ip: string;
  score: number;
  incidents: number;
  detectors: readonly string[];
  firstSeen: string;
  lastSeen: string;
}

/** The server's `DashboardSections`, with every flag settled. */
export interface Sections {
  overview: boolean;
  incidents: boolean;
  statistics: boolean;
  sessions: boolean;
  actors: boolean;
  intel: boolean;
}

export type SectionName = keyof Sections;

/**
 * The screens, named after the section that decides whether each exists.
 *
 * One vocabulary rather than two on purpose. A tab called `stats` beside a section called
 * `statistics` is the mismatch that made `hide: { stats: true }` do nothing at all in the
 * sibling project's element; here the name you hide is the name you list.
 */
export type TabName = SectionName;

/** Where the page opens when embedded, since an element has no URL of its own to read. */
export interface BootView {
  tab?: TabName;
  ip?: string;
  detector?: string;
}

/** `DashboardBootstrap` on the server, plus what the element adds before handing it over. */
export interface Boot {
  base: string;
  title: string;
  instance: string;
  version: string;
  sections: Sections;
  links: ReadonlyArray<{ label: string; href: string }>;
  source: string;
  redaction: { credentials: boolean; maskIp: boolean };
  view?: BootView | undefined;
}
