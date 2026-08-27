import { decoyPathDetector } from "./decoy-paths.js";
import { pathBruteforceDetector } from "./path-bruteforce.js";
import { credentialBruteforceDetector } from "./credential-bruteforce.js";
import { rateSpikeDetector } from "./rate-spike.js";
import { scannerSignatureDetector } from "./scanner-signature.js";
import { payloadInjectionDetector } from "./payload-injection.js";
import { suspiciousMethodDetector } from "./suspicious-method.js";
import { sensitiveFileDetector } from "./sensitive-file.js";
import { headerAnomalyDetector } from "./header-anomaly.js";
import { ssrfProbeDetector } from "./ssrf-probe.js";
import { openRedirectDetector } from "./open-redirect.js";
import { crlfInjectionDetector } from "./crlf-injection.js";
import { webShellDetector } from "./web-shell.js";
import { nosqlInjectionDetector } from "./nosql-injection.js";
import { graphqlAbuseDetector } from "./graphql-abuse.js";
import { jwtWeaknessDetector } from "./jwt-weakness.js";
import { clientAnomalyDetector } from "./client-anomaly.js";
import { prototypePollutionDetector } from "./prototype-pollution.js";
import { insecureDeserializationDetector } from "./insecure-deserialization.js";
import { hostHeaderInjectionDetector } from "./host-header-injection.js";
import { repeatActorDetector } from "./repeat-actor.js";
import type { Detector } from "./types.js";

export type { Detection, DetectionContext, Detector, RequestFacts } from "./types.js";
export { decoyPathDetector, defaultDecoyPaths } from "./decoy-paths.js";
export type { DecoyPath } from "./decoy-paths.js";
export { pathBruteforceDetector } from "./path-bruteforce.js";
export type { PathBruteforceOptions } from "./path-bruteforce.js";
export { credentialBruteforceDetector } from "./credential-bruteforce.js";
export type { CredentialBruteforceOptions } from "./credential-bruteforce.js";
export { rateSpikeDetector } from "./rate-spike.js";
export type { RateSpikeOptions } from "./rate-spike.js";
export { scannerSignatureDetector, scannerUserAgentPatterns } from "./scanner-signature.js";
export type { ScannerSignatureOptions } from "./scanner-signature.js";
export { payloadInjectionDetector, injectionSignatures } from "./payload-injection.js";
export type { PayloadInjectionOptions, InjectionSignature } from "./payload-injection.js";
export { suspiciousMethodDetector, defaultSuspiciousMethods } from "./suspicious-method.js";
export type { SuspiciousMethodOptions } from "./suspicious-method.js";
export { sensitiveFileDetector, sensitiveFilePatterns } from "./sensitive-file.js";
export type { SensitiveFileOptions } from "./sensitive-file.js";
export { headerAnomalyDetector } from "./header-anomaly.js";
export type { HeaderAnomalyOptions } from "./header-anomaly.js";
export { ssrfProbeDetector } from "./ssrf-probe.js";
export type { SsrfProbeOptions } from "./ssrf-probe.js";
export { openRedirectDetector } from "./open-redirect.js";
export type { OpenRedirectOptions } from "./open-redirect.js";
export { crlfInjectionDetector } from "./crlf-injection.js";
export type { CrlfInjectionOptions } from "./crlf-injection.js";
export { webShellDetector, webShellPatterns } from "./web-shell.js";
export type { WebShellOptions } from "./web-shell.js";
export { nosqlInjectionDetector } from "./nosql-injection.js";
export type { NosqlInjectionOptions } from "./nosql-injection.js";
export { graphqlAbuseDetector } from "./graphql-abuse.js";
export type { GraphqlAbuseOptions } from "./graphql-abuse.js";
export { jwtWeaknessDetector } from "./jwt-weakness.js";
export type { JwtWeaknessOptions } from "./jwt-weakness.js";
export { clientAnomalyDetector } from "./client-anomaly.js";
export type { ClientAnomalyOptions } from "./client-anomaly.js";
export { prototypePollutionDetector } from "./prototype-pollution.js";
export type { PrototypePollutionOptions } from "./prototype-pollution.js";
export { insecureDeserializationDetector } from "./insecure-deserialization.js";
export type { InsecureDeserializationOptions } from "./insecure-deserialization.js";
export { hostHeaderInjectionDetector } from "./host-header-injection.js";
export type { HostHeaderInjectionOptions } from "./host-header-injection.js";
export { repeatActorDetector } from "./repeat-actor.js";
export type { RepeatActorOptions } from "./repeat-actor.js";
export { honeytokenDetector } from "./honeytoken.js";
export type { HoneytokenOptions, Honeytoken } from "./honeytoken.js";
export { PortScanSentinel } from "./port-scan.js";
export type { PortScanEvent, PortScanSentinelOptions } from "./port-scan.js";

/**
 * The detector set used when none is configured explicitly. honeytokenDetector
 * is intentionally excluded — it requires you to supply the seeded token values
 * — so add it yourself via `extraDetectors` once you have planted some.
 */
export function defaultDetectors(): Detector[] {
  return [
    decoyPathDetector(),
    payloadInjectionDetector(),
    ssrfProbeDetector(),
    nosqlInjectionDetector(),
    prototypePollutionDetector(),
    insecureDeserializationDetector(),
    graphqlAbuseDetector(),
    jwtWeaknessDetector(),
    crlfInjectionDetector(),
    webShellDetector(),
    headerAnomalyDetector(),
    hostHeaderInjectionDetector(),
    sensitiveFileDetector(),
    openRedirectDetector(),
    suspiciousMethodDetector(),
    credentialBruteforceDetector(),
    pathBruteforceDetector(),
    scannerSignatureDetector(),
    clientAnomalyDetector(),
    rateSpikeDetector(),
    repeatActorDetector(),
  ];
}
