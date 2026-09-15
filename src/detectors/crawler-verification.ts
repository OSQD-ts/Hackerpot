import type { CrawlerRanges } from "../crawler-ranges.js";
import { cachingResolver, forwardConfirmedReverseDns, nodeDnsResolver, type DnsResolver } from "../internal/dns.js";
import type { Detection, DetectionContext, Detector } from "./types.js";

export interface VerifiableCrawler {
  id: string;
  name: string;
  /** Lowercase User-Agent substrings that claim this identity. */
  tokens: string[];
  /** Domains the operator's reverse DNS resolves under. Empty for a crawler verifiable only by published ranges. */
  domains: string[];
  /** Ids of the published range lists covering this crawler (see `PUBLISHED_CRAWLER_RANGES`). Default `[id]`. */
  rangeIds?: string[];
}

/**
 * Crawlers whose operators publish a way to verify them: forward-confirmed reverse DNS, a
 * list of address ranges, or both. From bothandlerjs's signature list. The range-only
 * crawlers (no `domains`) are checked only once published ranges are installed; without
 * them nothing can confirm or refute the claim, so nothing is said.
 */
export const verifiableCrawlers: VerifiableCrawler[] = [
  {
    id: "googlebot",
    name: "Googlebot",
    tokens: ["googlebot", "google-inspectiontool", "storebot-google", "googleother", "google-extended", "google-cloudvertexbot", "adsbot-google", "mediapartners-google", "feedfetcher-google"],
    domains: ["googlebot.com", "google.com", "googleusercontent.com"],
    rangeIds: ["googlebot", "google-special"],
  },
  { id: "bingbot", name: "Bingbot", tokens: ["bingbot", "adidxbot", "msnbot", "bingpreview"], domains: ["search.msn.com"] },
  { id: "applebot", name: "Applebot", tokens: ["applebot"], domains: ["applebot.apple.com"] },
  { id: "yandexbot", name: "YandexBot", tokens: ["yandexbot", "yandeximages", "yandexmobilebot", "yandexaccessibilitybot"], domains: ["yandex.ru", "yandex.net", "yandex.com"] },
  { id: "baiduspider", name: "Baiduspider", tokens: ["baiduspider"], domains: ["baidu.com", "baidu.jp"] },
  { id: "yahoo-slurp", name: "Yahoo! Slurp", tokens: ["yahoo! slurp"], domains: ["crawl.yahoo.net", "yahoo.com"] },
  { id: "sogou", name: "Sogou Spider", tokens: ["sogou web spider", "sogou inst spider"], domains: ["sogou.com"] },
  { id: "seznambot", name: "SeznamBot", tokens: ["seznambot"], domains: ["seznam.cz"] },
  { id: "naver-yeti", name: "Naver Yeti", tokens: ["yeti/", "yeti-mobile"], domains: ["naver.com"] },
  { id: "petalbot", name: "PetalBot", tokens: ["petalbot", "aspiegel"], domains: ["petalsearch.com", "aspiegel.com"] },
  { id: "coccoc", name: "Coc Coc Bot", tokens: ["coccocbot"], domains: ["coccoc.com"] },
  { id: "ahrefsbot", name: "AhrefsBot", tokens: ["ahrefsbot", "ahrefssiteaudit"], domains: ["ahrefs.com", "ahrefs.net"] },
  { id: "pinterestbot", name: "Pinterestbot", tokens: ["pinterestbot"], domains: ["pinterest.com"] },
  { id: "gptbot", name: "GPTBot", tokens: ["gptbot"], domains: [] },
  { id: "oai-searchbot", name: "OAI-SearchBot", tokens: ["oai-searchbot"], domains: [] },
  { id: "chatgpt-user", name: "ChatGPT-User", tokens: ["chatgpt-user"], domains: [] },
  { id: "duckduckbot", name: "DuckDuckBot", tokens: ["duckduckbot"], domains: [] },
];

export interface CrawlerVerificationOptions {
  /** Where DNS answers come from. Default: Node's resolver behind a cache. Inject one for tests or a custom resolver. */
  resolver?: DnsResolver;
  /** The crawlers to verify. Default `verifiableCrawlers`. */
  crawlers?: VerifiableCrawler[];
  /** Score for a refuted claim. Default 10. */
  score?: number;
  /**
   * Treat an address with no PTR record as a forged claim. Default true: every operator
   * this applies to publishes PTR records so that servers can check them. Set false if
   * your resolver cannot be trusted to tell NXDOMAIN from a failure.
   */
  treatMissingPtrAsForgery?: boolean;
  respondWith?: string;
  /**
   * Published address ranges, filled by `refreshCrawlerRanges` or `startCrawlerRangeRefresh`.
   * An address inside a claimed crawler's ranges is confirmed without any DNS lookup. One
   * outside them is refuted only for a crawler that publishes no DNS proof; otherwise DNS
   * decides, because a list can be a refresh behind.
   */
  ranges?: CrawlerRanges;
}

/**
 * Confirms or refutes a User-Agent that claims to be a well-known crawler, by
 * forward-confirmed reverse DNS. Adapted from bothandlerjs.
 *
 * - **Refuted:** the client named a crawler whose operator publishes a DNS proof, and the
 *   proof says no. A "Googlebot" on a VPS is a deliberate impersonation, so the detection
 *   is marked as proof (`certain`).
 * - **Confirmed:** `ctx.verifiedCrawler` is set, and the volume detectors after this one
 *   (`rate-spike`, `path-bruteforce`) skip the request, so a real crawler's ordinary pace
 *   never gets it blocked. Decoys and payload detectors still apply.
 * - **No answer** (a timeout, SERVFAIL): nothing at all. A resolver hiccup must never
 *   brand the real Googlebot an impersonator.
 *
 * DNS is consulted only for a request whose User-Agent claims one of `crawlers`, and
 * answers are cached. Put it before the volume detectors, as `buildDetectors` does. Not in
 * `defaultDetectors()`: it makes network lookups.
 */
/**
 * Whether a lowercased User-Agent claims to be `token`, rather than merely mentioning it.
 *
 * Clients that want the treatment a crawler gets describe themselves as *like* it: Feedly's
 * fetcher sends `Feedly/1.0 (+http://www.feedly.com/fetcher.html; like FeedFetcher-Google)`.
 * Read as a claim, that is Google's feed fetcher from an address Google's DNS does not
 * vouch for, which this detector reports as proof of impersonation, and a feed reader gets
 * blocked for being honest about what it resembles. An occurrence introduced by "like" is a
 * comparison, not an identity, and is skipped.
 */
function claimsToken(userAgent: string, token: string): boolean {
  let index = userAgent.indexOf(token);
  while (index !== -1) {
    if (!/\blike\s+$/.test(userAgent.slice(Math.max(0, index - 8), index))) return true;
    index = userAgent.indexOf(token, index + token.length);
  }
  return false;
}

export function crawlerVerificationDetector(options: CrawlerVerificationOptions = {}): Detector {
  const crawlers = options.crawlers ?? verifiableCrawlers;
  const score = options.score ?? 10;
  const missingPtrIsForgery = options.treatMissingPtrAsForgery ?? true;
  // Created on first use, so building a detector that never sees a claimed crawler costs nothing.
  let resolver = options.resolver;

  return {
    id: "crawler-verification",
    description: "A User-Agent claims to be a well-known crawler that its reverse DNS refutes",
    async inspect(ctx: DetectionContext): Promise<Detection | undefined> {
      const raw = ctx.headers["user-agent"];
      const userAgent = (Array.isArray(raw) ? raw[0] : raw)?.toLowerCase();
      if (!userAgent) return undefined;
      const claim = crawlers.find((crawler) => crawler.tokens.some((token) => claimsToken(userAgent, token)));
      if (!claim) return undefined;

      const ranges = options.ranges;
      if (ranges !== undefined) {
        const answers = (claim.rangeIds ?? [claim.id]).map((id) => ranges.contains(id, ctx.ip)).filter((answer) => answer !== undefined);
        if (answers.includes(true)) {
          ctx.verifiedCrawler = claim.id;
          return undefined;
        }
        if (answers.length > 0 && claim.domains.length === 0) {
          const detection: Detection = {
            detectorId: "crawler-verification",
            reason: `Claims to be ${claim.name}, but the address is outside every range its operator publishes`,
            score,
            certain: true,
            metadata: { crawler: claim.id, cause: "outside-published-ranges" },
          };
          if (options.respondWith) detection.respondWith = options.respondWith;
          return detection;
        }
      }
      // No DNS proof exists for a range-only crawler, and without its ranges there is no answer.
      if (claim.domains.length === 0) return undefined;

      resolver ??= cachingResolver(nodeDnsResolver());
      const outcome = await forwardConfirmedReverseDns(resolver, ctx.ip, claim.domains);
      if (outcome.status === "verified") {
        ctx.verifiedCrawler = claim.id;
        return undefined;
      }
      if (outcome.status === "indeterminate") return undefined;
      if (outcome.cause === "no-ptr" && !missingPtrIsForgery) return undefined;

      const detection: Detection = {
        detectorId: "crawler-verification",
        reason: `Claims to be ${claim.name}, but DNS refutes it: ${outcome.reason}`,
        score,
        certain: true,
        metadata: { crawler: claim.id, cause: outcome.cause, ...(outcome.hostname !== undefined ? { hostname: outcome.hostname } : {}) },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
