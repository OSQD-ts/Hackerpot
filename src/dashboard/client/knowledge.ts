/**
 * What each detector is looking for and what each response does, in words.
 *
 * The incident detail pairs every detection with its goal (what the attacker was after)
 * and its method (how the detector recognised it), and every response with what it did
 * and why the policy chose it. That is the difference between a list of ids and a page
 * an on-call engineer who has never read the detector source can act on.
 *
 * Looked up through `Map`, never through a plain object: a detector id is a string off
 * the wire, and `INFO["constructor"]` on an object literal is a function rather than
 * "unknown detector".
 */

export interface DetectorInfo {
  goal: string;
  how: string;
}

export interface ResponseInfo {
  does: string;
  why: string;
}

const DETECTORS: ReadonlyArray<[string, DetectorInfo]> = [
  ["decoy-path", { goal: "Requested a bait path that only exists as a trap: a leaked secrets file, admin panel, or known-vulnerable endpoint. No legitimate user knows these URLs.", how: "The path is matched against a curated list of decoy routes (exact or regex) that shadow the targets real-world scanners probe for." }],
  ["payload-injection", { goal: "Tried to exploit the app by smuggling code or traversal sequences: SQL injection, XSS, command or template injection, path traversal, Log4Shell, or XXE.", how: "The path, query, selected headers, and body are URL-decoded and scanned for known exploitation-payload signatures." }],
  ["credential-bruteforce", { goal: "Hammered a login endpoint from one IP: credential stuffing or password spraying to guess an account.", how: "Counts write requests (POST/PUT/PATCH) to auth-like paths from the same IP within a sliding window; fires once they exceed the attempt threshold." }],
  ["path-bruteforce", { goal: "Enumerated the site by walking a wordlist, trying to discover hidden files and endpoints.", how: "Counts the number of distinct paths one IP requests within a window. A real user revisits a small set, a scanner hits many unique ones." }],
  ["header-anomaly", { goal: "Sent a request no normal client produces: open-proxy probing, HTTP request smuggling, or a Shellshock exploit.", how: "Inspects the request line and headers for an absolute-form target, conflicting Content-Length and Transfer-Encoding, a `() {` payload, or a missing Host." }],
  ["sensitive-file", { goal: "Hunted for leaked files: backups, database dumps, source copies, editor swap files, or VCS and IDE metadata.", how: "The path is matched against risky file-type patterns (for example `.bak`, `.sql`, `~`, `/.svn/`, `.DS_Store`)." }],
  ["suspicious-method", { goal: "Used an HTTP verb a browser or API client never sends (WebDAV methods, or TRACE/TRACK/DEBUG) to probe server configuration.", how: "Flags any request method outside the normal set (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)." }],
  ["scanner-signature", { goal: "Scanned the site with an off-the-shelf tool, or a bare scripting client instead of a real browser.", how: "Matches the User-Agent against known tool signatures (sqlmap, nikto, nmap, gobuster and others); a missing User-Agent is flagged too. Easily spoofed, so it scores low and mainly corroborates." }],
  ["rate-spike", { goal: "Flooded the server with requests from one IP: aggressive scraping, or the volume side of an automated attack.", how: "Counts total requests from the IP in a short window and fires past a high threshold. Low score on its own; it mostly stacks with a more specific detection." }],
  ["repeat-actor", { goal: "Rotated through several source IPs while keeping the same client signature, spreading a scan across addresses to stay under any per-IP rate limit or block.", how: "The actor fingerprint (header order and UA family) is looked up in the registry of fingerprints seen attacking recently; firing means this signature has already scored detections from several distinct IPs inside the window. The registry only holds IPs that already tripped a detector, so ordinary users on the same browser build are never correlated into a phantom actor." }],
  ["honeytoken", { goal: "Replayed a fake credential planted as bait. Holding it means they harvested it from a decoy: strong evidence of an actual breach, not just scanning.", how: "The request (query, headers, cookies, body) is scanned for the exact seeded token values you configured." }],
  ["ssrf-probe", { goal: "Tried to make the server itself fetch an internal address (cloud metadata at 169.254.169.254, loopback, or a private range) or a non-HTTP scheme like file:// to read local files.", how: "Query values, selected headers, and the body are scanned for URLs targeting internal or metadata hosts or dangerous URL schemes." }],
  ["open-redirect", { goal: "Passed an off-site target through a redirect parameter to bounce a victim off your trusted domain: the setup for phishing or an OAuth redirect_uri abuse.", how: "Redirect-style parameters (next, url, redirect, return and similar) are checked for a protocol-relative //host, an absolute off-site URL, or an @ or backslash trick." }],
  ["crlf-injection", { goal: "Smuggled a carriage return and line feed into the request to inject response headers (Set-Cookie, Location), poison a cache, or split the HTTP response.", how: "The path, query values, and selected headers are scanned for raw or encoded CR/LF sequences, especially ones followed by a smuggled header." }],
  ["web-shell", { goal: "Reached for a backdoor: a known web-shell filename, a script sitting in an upload directory, or a script URL carrying a command-execution parameter. This is post-exploitation, not just scanning.", how: "The path and query are matched against web-shell filename patterns, upload-directory script patterns, and command-execution parameter patterns." }],
  ["nosql-injection", { goal: "Smuggled a MongoDB operator into a query or JSON body. The classic is an auth bypass like password={$ne:null}, but the same shapes drive blind data extraction and $where JavaScript execution.", how: "Query keys are checked for the param[$ne] bracket form, and query values and the body for a \"$ne\", \"$where\" or \"$regex\" operator key. Matched as a key, never as bare text, so a value that merely contains a $ does not trip it." }],
  ["graphql-abuse", { goal: "Mapped the whole API through GraphQL schema introspection, or sent a pathologically deep nested query to exhaust server resources.", how: "The path, query and body are scanned for introspection tokens (__schema, IntrospectionQuery), and requests that look like GraphQL are checked for brace nesting deeper than the configured limit." }],
  ["jwt-weakness", { goal: "Tried to forge a JSON Web Token by presenting one whose header declares alg \"none\" (unsigned, so the attacker can claim any identity) or one with an empty signature.", how: "JWTs in the Authorization and cookie headers and the query are decoded and their header's alg is checked. A legitimate token is always signed, so this is a high-confidence, low-false-positive signal." }],
  ["client-anomaly", { goal: "Claimed to be a mainstream browser in the User-Agent while sending none of the Accept, Accept-Language or Accept-Encoding headers a real browser always sends: a script wearing a browser's name.", how: "If the UA matches a browser pattern but all of those headers are absent, it is flagged. A weak, easily evaded signal, so it scores low and mainly corroborates." }],
  ["prototype-pollution", { goal: "Injected a __proto__ or constructor.prototype key so a naive merge writes onto Object.prototype: a Node-specific vector that escalates from a config tweak to remote code execution.", how: "Query keys, query values, and the body are checked for __proto__, or constructor accessing prototype. Matched as a key or access, so prose mentioning the words does not trip it." }],
  ["insecure-deserialization", { goal: "Sent a serialized-object payload (Java, PHP, .NET, Python, Ruby, or Node) to be deserialized: a top remote-code-execution class when a server deserializes attacker-controlled objects.", how: "The body, cookies, headers, and query are scanned for each format's distinctive magic bytes or markers (Java rO0AB, PHP O:n:, .NET AAEAAAD, pickle opcodes and others)." }],
  ["host-header-injection", { goal: "Manipulated the Host (or X-Forwarded-Host) header to poison password-reset links, absolute URLs, or a web cache.", how: "Malformed or duplicated Host headers are always flagged; with a configured canonical host set, any Host or X-Forwarded-Host outside it is flagged too." }],
  ["smtp-auth-bruteforce", { goal: "Guessed mail-account credentials against the SMTP honeypot through repeated AUTH LOGIN or PLAIN attempts.", how: "The SMTP honeypot offers AUTH, captures the submitted username and password, and always answers 535 so the attacker keeps trying." }],
  ["smtp-open-relay", { goal: "Tried to use the mail server as an open relay, MAIL FROM an external sender to an external recipient, to send spam through someone else's infrastructure.", how: "The SMTP honeypot compares the MAIL FROM and RCPT TO domains against its configured local domains; external to external is relay abuse." }],
  ["smtp-spam", { goal: "Delivered a message body through the relay attempt: the actual spam or phishing payload.", how: "The SMTP honeypot accepts DATA and captures the message instead of sending it anywhere." }],
  ["smtp-user-enumeration", { goal: "Probed which mailboxes exist using VRFY or EXPN, to build a target list.", how: "The SMTP honeypot logs every VRFY and EXPN command and answers noncommittally." }],
  ["ssh-auth-bruteforce", { goal: "Guessed SSH login credentials, the single most common automated attack on the internet. The captured username and password are the bot's actual guess.", how: "The SSH honeypot completes the real SSH handshake, captures the submitted username and password, and rejects every attempt. No shell is ever granted." }],
  ["ssh-publickey-probe", { goal: "Offered a public key for SSH authentication: either spraying stolen keys or checking which keys are accepted.", how: "The SSH honeypot records the username, key algorithm, and a SHA256 fingerprint of the offered key, then rejects it." }],
  ["ssh-scan", { goal: "Connected to the SSH port and grabbed the version banner without trying to log in: reconnaissance and fingerprinting.", how: "The SSH honeypot records the client's identification string for connections that handshake but never attempt a credential." }],
];

const RESPONSES: ReadonlyArray<[string, ResponseInfo]> = [
  ["decoy-content", { does: "Serves convincing fake content (a fake .env, a fake admin login page) so the probe looks like it succeeded.", why: "Keeps the attacker engaged with the decoy, and captures what they do next, instead of tipping them off with an error." }],
  ["not-found", { does: "Returns a plain 404, revealing nothing.", why: "The probe itself was the signal; for a first-touch or low-score hit there is no reason to escalate yet." }],
  ["redirect", { does: "Bounces the client to another decoy, for example a fake login page.", why: "Steers the attacker deeper into the trap." }],
  ["tarpit", { does: "Holds the response open for several seconds, longer as suspicion grows, before answering.", why: "Wastes the attacker's wall-clock time and ties up a slot in their scanner's connection pool. Chosen once an IP looks moderately suspicious." }],
  ["drip-feed", { does: "Trickles a never-ending response out one byte at a time.", why: "Pins the attacker's connection open indefinitely: a slowloris pointed back at them." }],
  ["large-payload", { does: "Streams a large junk download.", why: "Soaks up the attacker's bandwidth and storage if they save what they scrape." }],
  ["block", { does: "Marks the IP blocked: further requests get an immediate 403 before any detector runs.", why: "This IP's cumulative suspicion crossed the block threshold. It is a confirmed persistent attacker, so it is cut off and costs almost nothing to serve." }],
  ["fake-success", { does: "Returns a plausible success with a fake session token, as if the exploit or login worked.", why: "A sticky decoy: the attacker believes they are in and keeps going, so every follow-up request is more captured intent. Nothing real is granted." }],
  ["fake-data", { does: "Serves freshly synthesized fake secrets tailored to the request: a fake .env, an AWS credentials file, or a user table with bcrypt-shaped hashes.", why: "Every hit generates different plausible values, so the attacker cannot fingerprint the honeypot by diffing responses, and any credential they exfiltrate is noise. Nothing maps to anything real." }],
  ["gzip-bomb", { does: "Serves a few KB of gzip that inflates to tens of megabytes on the client.", why: "Punishes a naive scraper that decompresses everything it downloads: cheap for us, expensive for them." }],
  ["chaos", { does: "Answers unpredictably: a random 5xx, or a blob of random bytes.", why: "Breaks the assumptions of automated tooling that expects consistent, parseable responses, wasting its retries and confusing its fingerprinting." }],
  ["rate-limit", { does: "Returns a standard 429 Too Many Requests with a Retry-After header.", why: "A low-cost throttle for a high-volume IP that looks like ordinary rate limiting, revealing nothing about the honeypot." }],
  ["smtp-capture", { does: "Logs the SMTP abuse (auth attempt, relay, spam, or enumeration) without ever authenticating or relaying anything.", why: "The SMTP honeypot's whole job is to look usable while capturing intent; it always refuses the actual action." }],
  ["ssh-capture", { does: "Logs the SSH abuse (brute-force credentials, offered key, or version scan) without ever authenticating or opening a shell.", why: "The SSH honeypot completes the handshake to look real and capture the attempt, then rejects it. Credentials are recorded, never accepted." }],
];

const DETECTOR_INFO: ReadonlyMap<string, DetectorInfo> = new Map(DETECTORS);
const RESPONSE_INFO: ReadonlyMap<string, ResponseInfo> = new Map(RESPONSES);

export function detectorInfo(id: string): DetectorInfo | undefined {
  return DETECTOR_INFO.get(id);
}

export function responseInfo(id: string): ResponseInfo | undefined {
  return RESPONSE_INFO.get(id);
}
