import { plain } from "./headers.js";
import { benign, unwanted } from "./schema.js";
import type { Header } from "./headers.js";
import type { TrafficCase } from "./schema.js";

/**
 * Automation almost every site wants to keep serving.
 *
 * Search crawlers bring the traffic. Link unfurlers render the share cards. Monitors tell
 * you the site is up. Feed readers are how a chunk of your audience actually reads you.
 * Getting any of these wrong is not a security incident — it is a slow, quiet loss that
 * surfaces weeks later as a ranking drop or a dead preview, with nothing in the logs
 * pointing at the cause.
 *
 * The runner holds these to a lower bar than people but a real one: nothing `certain`,
 * nothing blocked, nothing the case forbids. A search crawler with a bare curl-like UA
 * may trip `scanner-signature` on suspicion and that is tolerated; being *proven* a
 * threat, or blocked, is not.
 */

// Documentation addresses (RFC 5737) stand in for the operators' real crawl ranges. A
// verifiable crawler is only worth testing if the verification can actually succeed, so
// each verified case pins an address and declares the DNS or range answer that confirms it.
export const GOOGLEBOT_IP = "198.51.100.10";
export const GOOGLEBOT_PTR = "crawl-198-51-100-10.googlebot.com";
export const BINGBOT_IP = "198.51.100.11";
export const BINGBOT_PTR = "msnbot-198-51-100-11.search.msn.com";
export const DUCKDUCKBOT_IP = "203.0.113.10";
export const GPTBOT_IP = "192.0.2.10";

/**
 * Fictional published crawler ranges, keyed by the id `verifiableCrawlers` uses. The
 * library ships no address data — a range baked into a release is wrong by the time it is
 * installed — so the corpus supplies these to the engine under test the way an operator's
 * refresh would, and the range-only crawlers (no reverse DNS) can then be confirmed.
 */
export const CORPUS_CRAWLER_RANGES: Readonly<Record<string, readonly string[]>> = {
  duckduckbot: ["203.0.113.0/24"],
  gptbot: ["192.0.2.0/24"],
};

const GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const BINGBOT_UA = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)";

const CRAWLER_ACCEPT: Header = ["Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"];
const CRAWLER_ENCODING: Header = ["Accept-Encoding", "gzip, deflate, br"];

/** A crawler request from a pinned address, with the negotiation headers a real fetcher sends. */
function fromAddress(userAgent: string, ip: string, path = "/"): TrafficCase["requests"][number] {
  return { path, ip, headers: [["Host", "shop.example"], ["User-Agent", userAgent], CRAWLER_ACCEPT, CRAWLER_ENCODING, ["Connection", "keep-alive"]], httpVersion: "1.1" };
}

export const BENIGN_BOT_CASES: TrafficCase[] = [
  // ---------------------------------------------------------------------------
  // Crawlers whose identity can actually be confirmed. These must not be refuted,
  // because a policy that allows verified crawlers is worthless if verification
  // never succeeds — and the DNS-outage case is the one that must never accuse.
  // ---------------------------------------------------------------------------
  benign({
    id: "googlebot-verified-fcrdns",
    title: "Googlebot, confirmed by forward-confirmed reverse DNS",
    category: "search-crawler",
    provenance: "Google documents FCrDNS under googlebot.com as the verification method",
    requires: ["crawler-verification"],
    requests: [fromAddress(GOOGLEBOT_UA, GOOGLEBOT_IP, "/products/42")],
    dns: { reverse: { [GOOGLEBOT_IP]: [GOOGLEBOT_PTR] }, forward: { [GOOGLEBOT_PTR]: [GOOGLEBOT_IP] } },
    expect: { neverDetectors: ["crawler-verification", "scanner-signature"] },
    tags: ["verification"],
  }),
  benign({
    id: "bingbot-verified-fcrdns",
    title: "Bingbot, confirmed by DNS under search.msn.com",
    category: "search-crawler",
    provenance: "Microsoft documents FCrDNS under search.msn.com",
    requires: ["crawler-verification"],
    requests: [fromAddress(BINGBOT_UA, BINGBOT_IP, "/")],
    dns: { reverse: { [BINGBOT_IP]: [BINGBOT_PTR] }, forward: { [BINGBOT_PTR]: [BINGBOT_IP] } },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification"],
  }),
  benign({
    id: "googlebot-dns-unavailable",
    title: "Googlebot when the resolver is not answering",
    category: "search-crawler",
    provenance: "A DNS outage must not turn every crawler into an accused forgery — silence is not disproof",
    notes: "The single most important negative crawler case. A timeout is indeterminate, so crawler-verification says nothing and the real crawler is served.",
    requires: ["crawler-verification"],
    requests: [fromAddress(GOOGLEBOT_UA, "198.51.100.12", "/")],
    dns: { unavailable: true },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification", "regression"],
  }),
  benign({
    id: "duckduckbot-in-published-range",
    title: "DuckDuckBot from an address inside its published range",
    category: "search-crawler",
    provenance: "DuckDuckGo publishes address ranges and no reverse DNS, so ranges are the only way to confirm it",
    requires: ["crawler-verification", "published-ranges"],
    requests: [fromAddress("Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)", DUCKDUCKBOT_IP, "/")],
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification", "ranges"],
  }),
  benign({
    id: "gptbot-in-published-range",
    title: "GPTBot from an address inside its published range",
    category: "ai-crawler",
    provenance: "OpenAI publishes GPTBot ranges; a fetch from inside them is confirmed without any lookup",
    requires: ["crawler-verification", "published-ranges"],
    requests: [fromAddress("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot", GPTBOT_IP, "/blog/launch")],
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification", "ranges"],
  }),

  benign({
    id: "applebot-verified-fcrdns",
    title: "Applebot, confirmed by DNS under applebot.apple.com",
    category: "search-crawler",
    provenance: "Apple documents FCrDNS under applebot.apple.com",
    requires: ["crawler-verification"],
    requests: [fromAddress("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", "198.51.100.13")],
    dns: { reverse: { "198.51.100.13": ["17-198-51-100-13.applebot.apple.com"] }, forward: { "17-198-51-100-13.applebot.apple.com": ["198.51.100.13"] } },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification"],
  }),
  benign({
    id: "yandexbot-verified-fcrdns",
    title: "YandexBot, confirmed by DNS under yandex.com",
    category: "search-crawler",
    provenance: "Yandex documents FCrDNS under yandex.ru / yandex.net / yandex.com",
    requires: ["crawler-verification"],
    requests: [fromAddress("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "198.51.100.14")],
    dns: { reverse: { "198.51.100.14": ["spider-198-51-100-14.yandex.com"] }, forward: { "spider-198-51-100-14.yandex.com": ["198.51.100.14"] } },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification"],
  }),
  benign({
    id: "baiduspider-verified-fcrdns",
    title: "Baiduspider, confirmed by DNS under baidu.com",
    category: "search-crawler",
    provenance: "Baidu documents FCrDNS under *.crawl.baidu.com",
    requires: ["crawler-verification"],
    requests: [fromAddress("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "198.51.100.15")],
    dns: { reverse: { "198.51.100.15": ["baiduspider-198-51-100-15.crawl.baidu.com"] }, forward: { "baiduspider-198-51-100-15.crawl.baidu.com": ["198.51.100.15"] } },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification"],
  }),
  benign({
    id: "petalbot-verified-fcrdns",
    title: "PetalBot, confirmed by DNS under aspiegel.com",
    category: "search-crawler",
    provenance: "Huawei's PetalBot verifies under petalsearch.com / aspiegel.com",
    requires: ["crawler-verification"],
    requests: [fromAddress("Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)", "198.51.100.16")],
    dns: { reverse: { "198.51.100.16": ["petalbot-198-51-100-16.aspiegel.com"] }, forward: { "petalbot-198-51-100-16.aspiegel.com": ["198.51.100.16"] } },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification"],
  }),
  benign({
    id: "pinterestbot-verified-fcrdns",
    title: "Pinterestbot, confirmed by DNS under pinterest.com",
    category: "search-crawler",
    provenance: "Pinterest documents FCrDNS under pinterest.com",
    requires: ["crawler-verification"],
    requests: [fromAddress("Mozilla/5.0 (compatible; Pinterestbot/1.0; +http://www.pinterest.com/bot.html)", "198.51.100.17")],
    dns: { reverse: { "198.51.100.17": ["crawl-198-51-100-17.pinterest.com"] }, forward: { "crawl-198-51-100-17.pinterest.com": ["198.51.100.17"] } },
    expect: { neverDetectors: ["crawler-verification"] },
    tags: ["verification"],
  }),

  // ---------------------------------------------------------------------------
  // Monitors: they check that the site answers. Blocking one makes it lie about
  // being down.
  // ---------------------------------------------------------------------------
  benign({ id: "uptimerobot", title: "UptimeRobot polling the homepage", category: "uptime-monitor", provenance: "UptimeRobot's documented User-Agent", requests: [plain("Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)")] }),
  benign({ id: "pingdom", title: "Pingdom checking availability", category: "uptime-monitor", provenance: "Pingdom.com_bot documented UA", requests: [plain("Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)")] }),
  benign({ id: "statuscake", title: "StatusCake uptime check", category: "uptime-monitor", provenance: "StatusCake's documented monitor UA", requests: [plain("StatusCake/1.0 (+https://www.statuscake.com)")] }),

  // ---------------------------------------------------------------------------
  // Link unfurlers: they render the preview card when someone shares a URL.
  // ---------------------------------------------------------------------------
  benign({ id: "slackbot-unfurl", title: "Slack expanding a shared link", category: "link-unfurler", provenance: "Slack's link-expanding UA, documented at api.slack.com/robots", requests: [plain("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", [["Accept", "text/html,application/xhtml+xml"]])] }),
  benign({ id: "discordbot-unfurl", title: "Discord fetching a link preview", category: "link-unfurler", provenance: "Discordbot's documented UA", requests: [plain("Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)")] }),
  benign({ id: "twitterbot-card", title: "Twitterbot fetching a summary card", category: "link-unfurler", provenance: "Twitterbot's documented UA", requests: [plain("Twitterbot/1.0")] }),
  benign({ id: "facebook-externalhit", title: "facebookexternalhit rendering a share preview", category: "link-unfurler", provenance: "Meta's crawler for share previews", requests: [plain("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)")] }),
  benign({ id: "telegram-preview", title: "TelegramBot fetching a link preview", category: "link-unfurler", provenance: "TelegramBot's documented UA", requests: [plain("TelegramBot (like TwitterBot)")] }),
  benign({ id: "whatsapp-preview", title: "WhatsApp fetching a link preview", category: "link-unfurler", provenance: "WhatsApp's documented preview UA", requests: [plain("WhatsApp/2.23.20.0")] }),
  benign({ id: "linkedin-preview", title: "LinkedInBot fetching a post preview", category: "link-unfurler", provenance: "LinkedInBot's documented UA", requests: [plain("LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/3.1 +http://www.linkedin.com)")] }),

  // ---------------------------------------------------------------------------
  // Feeds and archives.
  // ---------------------------------------------------------------------------
  benign({ id: "feedly-reader", title: "Feedly polling an RSS feed", category: "feed-reader", provenance: "Feedly's feed-fetcher UA", requests: [plain("Feedly/1.0 (+http://www.feedly.com/fetcher.html)", [["Accept", "application/rss+xml,application/atom+xml,text/xml"]], "shop.example")] }),
  benign({ id: "feedbin-reader", title: "Feedbin fetching a feed", category: "feed-reader", provenance: "Feedbin's documented feed UA", requests: [plain("Feedbin feed-id:1 - 5 subscribers")] }),
  benign({ id: "archive-org-crawler", title: "The Internet Archive crawling a page", category: "archive", provenance: "archive.org_bot, the Wayback Machine's crawler", requests: [plain("Mozilla/5.0 (compatible; archive.org_bot; +http://archive.org/details/archive.org_bot)")] }),
  benign({ id: "newsblur-reader", title: "NewsBlur fetching a feed", category: "feed-reader", provenance: "NewsBlur's feed-fetcher UA", requests: [plain("NewsBlur Feed Fetcher - 12 subscribers - https://www.newsblur.com")] }),
  benign({ id: "mastodon-preview", title: "A Mastodon instance fetching a link preview", category: "link-unfurler", provenance: "Mastodon fetches preview cards with an http.rb UA naming the instance", requests: [plain("http.rb/5.1.1 (Mastodon/4.2.1; +https://mastodon.social/)")] }),
  benign({ id: "amazonbot-crawl", title: "Amazonbot crawling a page", category: "search-crawler", provenance: "Amazonbot's documented UA; verifiable by DNS but here taken at its word", requests: [plain("Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)")] }),

  // ---------------------------------------------------------------------------
  // Unwanted, but not hostile: honest SEO and market-intelligence crawlers. How a
  // site treats these is a business decision, not a security one, so the runner does
  // not hold them to the benign bar.
  // ---------------------------------------------------------------------------
  unwanted({ id: "semrushbot", title: "SemrushBot crawling for SEO intelligence", category: "seo-crawler", provenance: "SemrushBot's documented UA", requests: [plain("Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)")] }),
  unwanted({ id: "mj12bot", title: "MJ12bot building a link index", category: "seo-crawler", provenance: "Majestic's MJ12bot UA", requests: [plain("Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)")] }),
];
