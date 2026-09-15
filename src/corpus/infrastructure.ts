import { infrastructure } from "./schema.js";
import type { Header, } from "./headers.js";
import type { CaseRequest, TrafficCase } from "./schema.js";

/**
 * Machinery in the request path.
 *
 * Health probes, origin pulls, webhooks and load-balancer checks are not people and not
 * attackers — they are the plumbing that keeps a service reachable. Most of it belongs in
 * an allowlist or an ignored-paths list rather than in front of a detector, but a corpus
 * that omits it cannot prove the detectors stay quiet when it is not, and "the honeypot
 * marked our Stripe webhook as an attack" is a real way to lose events. Held to the same
 * bar as a benign bot: nothing certain, nothing blocked.
 */

const probe = (userAgent: string, path: string, host = "shop.example", extra: readonly Header[] = []): CaseRequest => ({
  path,
  headers: [["Host", host], ["User-Agent", userAgent], ["Accept", "*/*"], ...extra],
  httpVersion: "1.1",
});

const webhook = (userAgent: string, path: string, body: string, extra: readonly Header[] = []): CaseRequest => ({
  method: "POST",
  path,
  headers: [["Host", "hooks.shop.example"], ["User-Agent", userAgent], ["Content-Type", "application/json"], ["Accept", "*/*"], ...extra],
  body,
  httpVersion: "1.1",
});

export const INFRASTRUCTURE_CASES: TrafficCase[] = [
  // ---- Health probes -------------------------------------------------------
  infrastructure({ id: "k8s-liveness-probe", title: "A Kubernetes kubelet liveness probe", category: "health-probe", provenance: "kube-probe is the User-Agent the kubelet's HTTP prober sends", requests: [probe("kube-probe/1.30", "/healthz")] }),
  infrastructure({ id: "k8s-readiness-probe", title: "A Kubernetes readiness probe", category: "health-probe", provenance: "The same prober against the readiness endpoint", requests: [probe("kube-probe/1.30", "/readyz")] }),
  infrastructure({ id: "elb-health-check", title: "An AWS Elastic Load Balancer health check", category: "health-probe", provenance: "ELB-HealthChecker/2.0 is the documented UA of the AWS load balancer", requests: [probe("ELB-HealthChecker/2.0", "/health")] }),
  infrastructure({ id: "gcp-health-check", title: "A Google Cloud load-balancer health check", category: "health-probe", provenance: "GoogleHC is the UA of GCP's health-check prober", requests: [probe("GoogleHC/1.0", "/health")] }),
  infrastructure({ id: "consul-health-check", title: "A Consul service health check", category: "health-probe", provenance: "Consul's HTTP health check UA", requests: [probe("Consul Health Check", "/status")] }),

  // ---- Origin pulls --------------------------------------------------------
  infrastructure({ id: "cloudfront-origin-pull", title: "A CloudFront edge pulling from the origin", category: "cdn-origin-pull", provenance: "Amazon CloudFront is the UA a CloudFront edge presents to an origin", requests: [probe("Amazon CloudFront", "/assets/app.js", "shop.example", [["Via", "1.1 abcdef.cloudfront.net (CloudFront)"], ["X-Amz-Cf-Id", "EXAMPLEabcdef=="]])] }),
  infrastructure({ id: "fastly-origin-pull", title: "A Fastly edge pulling from the origin", category: "cdn-origin-pull", provenance: "Fastly forwards the client UA and adds Fastly-specific forwarding headers", requests: [probe("Mozilla/5.0 (compatible; Fastly)", "/images/hero.avif", "shop.example", [["Fastly-Client-Ip", "203.0.113.7"], ["X-Forwarded-For", "203.0.113.7"]])] }),

  // ---- Load-balancer and mesh checks --------------------------------------
  infrastructure({ id: "haproxy-check", title: "An HAProxy backend health check", category: "load-balancer", provenance: "HAProxy's httpchk sends a minimal request with a configured UA", requests: [{ method: "OPTIONS", path: "/", headers: [["Host", "shop.example"], ["User-Agent", "HAProxy/2.9 health-check"]], httpVersion: "1.1" }] }),
  infrastructure({ id: "envoy-mesh-probe", title: "An Envoy sidecar health probe", category: "load-balancer", provenance: "Envoy's health-check filter presents a configurable UA against a mesh endpoint", requests: [probe("Envoy/1.29 health-check", "/healthz/ready")] }),

  // ---- Webhooks ------------------------------------------------------------
  infrastructure({
    id: "stripe-webhook",
    title: "A Stripe webhook delivering an event",
    category: "webhook",
    provenance: "Stripe posts signed JSON events with a documented UA and a Stripe-Signature header",
    requests: [webhook("Stripe/1.0 (+https://stripe.com/docs/webhooks)", "/webhooks/stripe", JSON.stringify({ id: "evt_1P", type: "payment_intent.succeeded", data: { object: { id: "pi_1P", amount: 2000, currency: "usd" } } }), [["Stripe-Signature", "t=1747300000,v1=abc123"]])],
  }),
  infrastructure({
    id: "github-webhook",
    title: "A GitHub webhook delivering a push event",
    category: "webhook",
    provenance: "GitHub-Hookshot is the documented UA; the event and signature ride in X-GitHub-* headers",
    requests: [webhook("GitHub-Hookshot/044aadd", "/webhooks/github", JSON.stringify({ ref: "refs/heads/main", pusher: { name: "octocat" }, commits: [{ id: "abc", message: "Fix a bug" }] }), [["X-GitHub-Event", "push"], ["X-Hub-Signature-256", "sha256=deadbeef"]])],
  }),
  infrastructure({
    id: "shopify-webhook",
    title: "A Shopify webhook delivering an order",
    category: "webhook",
    provenance: "Shopify posts JSON order events with an HMAC header and a documented UA",
    requests: [webhook("Shopify-Captain-Hook", "/webhooks/shopify/orders", JSON.stringify({ id: "820982911946154508", email: "buyer@example.com", total_price: "39.99" }), [["X-Shopify-Topic", "orders/create"], ["X-Shopify-Hmac-Sha256", "base64hmac=="]])],
  }),
];
