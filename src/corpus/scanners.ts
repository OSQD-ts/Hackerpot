import { hostile, repeat } from "./schema.js";
import { plain } from "./headers.js";
import type { TrafficCase } from "./schema.js";

/**
 * Security scanners and wordlist tools.
 *
 * The crude end of hostile traffic: tools that announce themselves in the User-Agent, and
 * tools that give themselves away by shape — one address asking for hundreds of paths that
 * do not exist. A scanner naming itself is its own statement of what it is, so
 * `scanner-signature` marks the match as proof; a wordlist walk is caught by the volume
 * detectors instead, which is what still catches a scanner that has learned to lie about
 * its name.
 *
 * The wordlist cases carry `status: 404` on every request, because `path-bruteforce` in
 * middleware mode counts a path as enumeration only once the app has missed on it — a
 * scan that is almost all misses being exactly the thing that matters.
 */

const WORDLIST = ["admin", "backup", "old", "test", "config", "db", "dev", "staging", "hidden", "private", "secret", "tmp", "uploads", "data", "logs", "api", "www", "web", "assets", "internal", "beta", "cache"];

export const SCANNER_CASES: TrafficCase[] = [
  hostile({ id: "sqlmap-ua", title: "sqlmap announcing itself in the User-Agent", category: "scanner", provenance: "sqlmap's default User-Agent, unchanged by most operators", requests: [plain("sqlmap/1.8.3#stable (https://sqlmap.org)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "nikto-ua", title: "Nikto scanning the web root", category: "scanner", provenance: "Nikto embeds its name and version in the UA", requests: [plain("Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "nuclei-ua", title: "Nuclei running a template scan", category: "scanner", provenance: "ProjectDiscovery's Nuclei names itself in the UA by default", requests: [plain("Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "acunetix-ua", title: "Acunetix web vulnerability scan", category: "scanner", provenance: "Acunetix's scanner UA", requests: [plain("Mozilla/5.0 (compatible; acunetix-wvs)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "masscan-zgrab", title: "A zgrab banner grab from a mass scan", category: "scanner", provenance: "zgrab is the HTTP module of the masscan/zmap ecosystem and identifies itself", requests: [plain("Mozilla/5.0 zgrab/0.x")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "nmap-nse-http", title: "An Nmap HTTP script scan", category: "scanner", provenance: "The Nmap Scripting Engine names itself in its HTTP requests", requests: [plain("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "openvas-scan", title: "An OpenVAS vulnerability scan", category: "scanner", provenance: "OpenVAS / Greenbone identifies itself in the UA", requests: [plain("Mozilla/5.0 (compatible; OpenVAS)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "nessus-scan", title: "A Nessus vulnerability scan", category: "scanner", provenance: "Tenable's Nessus names itself in the UA", requests: [plain("Mozilla/4.0 (compatible; Nessus)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "dirb-scan", title: "A dirb content-discovery scan", category: "wordlist", provenance: "dirb's default UA identifies the tool", requests: [plain("Mozilla/4.0 (compatible; DIRB v2.22; +http://dirb.sourceforge.net)")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "wfuzz-scan", title: "A Wfuzz fuzzing run", category: "wordlist", provenance: "Wfuzz names itself in its default UA", requests: [plain("Wfuzz/3.1.0")], expect: { detectors: ["scanner-signature"], certain: true } }),
  hostile({ id: "no-user-agent", title: "A request with no User-Agent at all", category: "scanner", provenance: "A great deal of opportunistic automation sends no UA; a browser always sends one", requests: [{ headers: [["Host", "shop.example"], ["Accept", "*/*"]], httpVersion: "1.1" }], expect: { detectors: ["scanner-signature"] } }),

  hostile({
    id: "gobuster-directory-walk",
    title: "gobuster walking a directory wordlist, almost all misses",
    category: "wordlist",
    provenance: "gobuster's default UA plus its behaviour: many distinct paths from one address, nearly all 404",
    notes: "Fires scanner-signature on the name and path-bruteforce on the shape. Under the middleware's miss-counting, path-bruteforce fires from the request after the threshold rather than on it, so the walk is sized past it.",
    requests: repeat({ headers: [["Host", "shop.example"], ["User-Agent", "gobuster/3.6"], ["Accept", "*/*"]], httpVersion: "1.1", status: 404 }, 22, 700, (index) => `/${WORDLIST[index % WORDLIST.length]}-${index}`),
    expect: { detectors: ["path-bruteforce", "scanner-signature"], certain: true },
  }),
  hostile({
    id: "ffuf-fuzzing-walk",
    title: "ffuf fuzzing paths from a wordlist",
    category: "wordlist",
    provenance: "ffuf's default UA and its high-rate distinct-path enumeration",
    requests: repeat({ headers: [["Host", "shop.example"], ["User-Agent", "Fuzz Faster U Fool v2.1.0-dev"], ["Accept", "*/*"]], httpVersion: "1.1", status: 404 }, 20, 400, (index) => `/api/${WORDLIST[index % WORDLIST.length]}/${index}`),
    // ffuf's UA string does not itself match a scanner pattern, so this is caught purely
    // on shape — which is the point: a wordlist tool renamed still walks like one.
    expect: { detectors: ["path-bruteforce"] },
  }),
  hostile({
    id: "feroxbuster-recursive-walk",
    title: "feroxbuster recursively enumerating directories",
    category: "wordlist",
    provenance: "feroxbuster names itself and enumerates recursively",
    requests: repeat({ headers: [["Host", "shop.example"], ["User-Agent", "feroxbuster/2.10.1"], ["Accept", "*/*"]], httpVersion: "1.1", status: 404 }, 20, 500, (index) => `/${WORDLIST[index % WORDLIST.length]}/${WORDLIST[(index + 3) % WORDLIST.length]}`),
    expect: { detectors: ["path-bruteforce", "scanner-signature"], certain: true },
  }),
  hostile({
    id: "wpscan-enumeration",
    title: "WPScan enumerating a WordPress install",
    category: "wordlist",
    provenance: "WPScan probes the standard WordPress entry points, several of which are decoy paths",
    notes: "WPScan's UA is not on the scanner list, so this is caught by the decoy paths it reaches — wp-login.php and xmlrpc.php — rather than by its name.",
    requests: ["/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-config.php.bak", "/wp-json/wp/v2/users"].map((path, index) => ({ headers: [["Host", "shop.example"], ["User-Agent", "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)"], ["Accept", "*/*"]] as ReadonlyArray<readonly [string, string]>, path, atMs: index * 500 })),
    expect: { detectors: ["decoy-path"] },
  }),
];
