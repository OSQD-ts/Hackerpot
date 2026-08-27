import { IpAllowlist } from "./allowlist.js";

export interface IpEnrichment {
  /** Special-use classification: public, private, loopback, cgnat, link-local, reserved, documentation, multicast. */
  category: string;
  /** Whether this is a globally-routable public address (vs. a local/special-use one). */
  global: boolean;
  /** Autonomous System number — only when a data-backed enricher supplies it. */
  asn?: number;
  /** Owning organization / ISP — only from a data-backed enricher. */
  org?: string;
  /** Two-letter country code — only from a data-backed enricher. */
  country?: string;
}

export interface IpEnricher {
  /** Classify / annotate a source IP. Return undefined to add nothing. */
  enrich(ip: string): IpEnrichment | undefined | Promise<IpEnrichment | undefined>;
}

// Special-use ranges (RFC 5735 / 6890 / 4193 / 6598), most-specific categories first.
// Each is a CIDR matcher reused from the allowlist — no external data, no dependency.
const RANGES: Array<{ category: string; nets: IpAllowlist }> = [
  { category: "loopback", nets: new IpAllowlist(["127.0.0.0/8", "::1/128"]) },
  { category: "link-local", nets: new IpAllowlist(["169.254.0.0/16", "fe80::/10"]) },
  { category: "cgnat", nets: new IpAllowlist(["100.64.0.0/10"]) },
  { category: "private", nets: new IpAllowlist(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]) },
  { category: "documentation", nets: new IpAllowlist(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"]) },
  { category: "benchmarking", nets: new IpAllowlist(["198.18.0.0/15"]) },
  { category: "multicast", nets: new IpAllowlist(["224.0.0.0/4", "ff00::/8"]) },
  { category: "reserved", nets: new IpAllowlist(["0.0.0.0/8", "240.0.0.0/4"]) },
];

/**
 * A dependency-free enricher that classifies a source IP into its special-use
 * category (loopback, private, CGNAT, link-local, documentation, multicast,
 * reserved) or "public". No bundled geo/ASN data — that would mean shipping a
 * multi-megabyte database and keeping it current. For geo/ASN, implement `IpEnricher`
 * over your own data source (e.g. a MaxMind GeoLite2 reader) and pass it as the
 * engine's `enricher`; its `asn`/`org`/`country` ride alongside this classification.
 *
 * A private/loopback/CGNAT source hitting an internet-facing honeypot is itself a
 * signal — it usually means a misconfigured proxy is leaking internal clients, or the
 * `X-Forwarded-For` chain is being trusted when it shouldn't be.
 */
export function defaultIpEnricher(): IpEnricher {
  return {
    enrich(ip: string): IpEnrichment {
      for (const { category, nets } of RANGES) {
        if (nets.allows(ip)) return { category, global: false };
      }
      return { category: "public", global: true };
    },
  };
}
