import dgram from "node:dgram";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { IncidentBroker, SyslogSink, WebhookDispatcher, parseConfigText, renderAlert, truncateBytes } from "../src/index.js";
import type { HoneypotHit, Incident } from "../src/index.js";

function hit(partial: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    timestamp: "2026-09-01T09:14:00.000Z",
    ip: "198.51.100.7",
    method: "GET",
    path: "/.env",
    headers: { "user-agent": "sqlmap/1.7" },
    detections: [{ detectorId: "sensitive-file", reason: "requested /.env", score: 10 }],
    score: 10,
    totalScore: 25,
    respondedWith: "tarpit",
    ...partial,
  };
}

describe("chat alert rendering", () => {
  it("leaves the native format alone, so an existing receiver keeps working", () => {
    const { body } = renderAlert("hackerpot", hit({ body: "payload" }));
    const parsed = JSON.parse(body) as { type: string; incident: Incident };
    expect(parsed.type).toBe("incident");
    expect(parsed.incident.id).toBe("11111111-2222-3333-4444-555555555555");
    expect(parsed.incident.body).toBe("payload");
  });

  it("defuses a Slack channel mention hidden in an attacker-chosen path", () => {
    // Slack builds mentions out of angle brackets, so a path can carry one.
    const { body } = renderAlert("slack", hit({ path: "/<!channel> hi" }));
    const parsed = JSON.parse(body) as { text: string };
    expect(parsed.text).toContain("&lt;!channel&gt;");
    expect(parsed.text).not.toContain("<!channel>");
  });

  it("stops Slack from fetching a URL an attacker planted in a path", () => {
    const { body } = renderAlert("slack", hit({ path: "/?next=https://attacker.example/beacon" }));
    const parsed = JSON.parse(body) as { unfurl_links: boolean; unfurl_media: boolean };
    expect(parsed.unfurl_links).toBe(false);
    expect(parsed.unfurl_media).toBe(false);
  });

  it("cannot page a whole Discord server through a captured path", () => {
    const { body } = renderAlert("discord", hit({ path: "/@everyone" }));
    const parsed = JSON.parse(body) as { content: string; allowed_mentions: { parse: string[] } };
    // Escaped in the text…
    expect(parsed.content).toContain("\\@everyone");
    // …and, whatever the text says, guaranteed inert by the platform's own switch.
    expect(parsed.allowed_mentions.parse).toEqual([]);
  });

  it("keeps a captured newline from forging extra lines in the alert", () => {
    // Without flattening, this reads in the channel as a second, fabricated field.
    const forged = "/x\nsource: 127.0.0.1  ·  score: 0 (total 0)";
    const { body } = renderAlert("slack", hit({ path: forged }));
    const parsed = JSON.parse(body) as { text: string };
    const sourceLines = parsed.text.split("\n").filter((l) => l.startsWith("source:"));
    expect(sourceLines).toHaveLength(1);
    expect(sourceLines[0]).toContain("198.51.100.7");
  });

  it("withholds the attacker-controlled body from a chat channel unless asked", () => {
    const payload = "<?php system($_GET['c']); ?>";
    const quiet = JSON.parse(renderAlert("discord", hit({ body: payload })).body) as { content: string };
    expect(quiet.content).not.toContain("system");

    const loud = JSON.parse(renderAlert("discord", hit({ body: payload }), { omitBody: false }).body) as { content: string };
    expect(loud.content).toContain("body:");

    // The native format is the other way round: a receiver that asked for the incident
    // gets the whole incident.
    const native = JSON.parse(renderAlert("hackerpot", hit({ body: payload })).body) as { incident: Incident };
    expect(native.incident.body).toBe(payload);
  });

  it("stays inside Discord's hard message limit however long the capture was", () => {
    const { body } = renderAlert("discord", hit({ path: `/${"A".repeat(5000)}`, body: "B".repeat(5000) }), { omitBody: false });
    const parsed = JSON.parse(body) as { content: string };
    expect(parsed.content.length).toBeLessThanOrEqual(1801);
  });

  it("routes the chosen format through the dispatcher", async () => {
    const bodies: string[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (_url: string, init: RequestInit) => {
      bodies.push(String(init.body));
      return new Response("", { status: 200 });
    }) as unknown as typeof fetch;
    try {
      const broker = new IncidentBroker();
      const dispatcher = new WebhookDispatcher({ webhooks: [{ url: "https://hooks.slack.example/x", format: "slack" }] });
      dispatcher.attach(broker);
      broker.publish(hit());
      await new Promise((r) => setTimeout(r, 100));
      dispatcher.detach();
    } finally {
      globalThis.fetch = original;
    }
    expect(bodies).toHaveLength(1);
    expect(JSON.parse(bodies[0]!)).toHaveProperty("text");
  });

  it("reads the format from TOML and rejects one it does not have", () => {
    const config = parseConfigText(
      '[management]\nenabled = true\napi_keys = ["k"]\n\n[[management.webhooks]]\nurl = "https://hooks.slack.com/services/x"\nformat = "slack"\n',
      "<test>",
    );
    expect(config.management.webhooks[0]!.format).toBe("slack");
    expect(() =>
      parseConfigText('[management]\nenabled = true\napi_keys = ["k"]\n\n[[management.webhooks]]\nurl = "https://h/x"\nformat = "teams"\n', "<test>"),
    ).toThrow(/must be one of/);
  });
});

describe("syslog sink", () => {
  let sink: SyslogSink | undefined;
  afterEach(async () => {
    await sink?.close();
    sink = undefined;
  });

  it("does not split a UTF-8 character when it truncates", () => {
    // "€" is three bytes; a naive slice at 2 leaves a lone continuation byte.
    const text = `${"a".repeat(10)}€`;
    const cut = truncateBytes(text, 12);
    expect(Buffer.byteLength(cut)).toBeLessThanOrEqual(12);
    expect(cut).toBe("a".repeat(10));
    expect(cut.includes("�")).toBe(false);
  });

  it("delivers a CEF line over UDP", async () => {
    const server = dgram.createSocket("udp4");
    const received = new Promise<string>((resolve) => server.once("message", (msg) => resolve(msg.toString())));
    await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", () => resolve()));
    const port = server.address().port;

    sink = new SyslogSink({ host: "127.0.0.1", port });
    sink.send(hit());
    const message = await received;
    server.close();

    expect(message).toMatch(/^<108>/); // facility 13, severity 4
    expect(message).toContain("CEF:0|hackerpot|hackerpot|");
    expect(message).toContain("src=198.51.100.7");
  });

  it("emits exactly one line even when the capture contains newlines", async () => {
    const server = dgram.createSocket("udp4");
    const received = new Promise<string>((resolve) => server.once("message", (msg) => resolve(msg.toString())));
    await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", () => resolve()));
    const port = server.address().port;

    sink = new SyslogSink({ host: "127.0.0.1", port, format: "json", includeBody: true });
    // A forged second record is what an unescaped newline buys an attacker here.
    sink.send(hit({ body: "a\n<108>Sep  1 09:14:00 hackerpot hackerpot: CEF:0|forged" }));
    const message = await received;
    server.close();

    expect(message.split("\n")).toHaveLength(1);
  });

  it("honours the score gate", async () => {
    const server = dgram.createSocket("udp4");
    let count = 0;
    server.on("message", () => (count += 1));
    await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", () => resolve()));
    const port = server.address().port;

    sink = new SyslogSink({ host: "127.0.0.1", port, minScore: 40 });
    sink.send(hit({ totalScore: 25 }));
    sink.send(hit({ totalScore: 50 }));
    await new Promise((r) => setTimeout(r, 120));
    server.close();

    expect(count).toBe(1);
  });

  it("delivers over TCP, one message per line", async () => {
    const lines: string[] = [];
    const server = net.createServer((socket) => {
      socket.on("data", (d) => lines.push(...d.toString().split("\n").filter(Boolean)));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as net.AddressInfo).port;

    sink = new SyslogSink({ host: "127.0.0.1", port, protocol: "tcp" });
    // start() opens the connection up front, so the first incident is not the one
    // that gets dropped while the socket is still connecting.
    sink.start();
    await new Promise((r) => setTimeout(r, 150));
    sink.send(hit());
    sink.send(hit({ id: "second" }));
    await new Promise((r) => setTimeout(r, 150));
    server.close();

    expect(lines).toHaveLength(2);
    expect(lines.every((l) => l.startsWith("<108>"))).toBe(true);
    expect(sink.droppedCount).toBe(0);
  });

  it("drops rather than queues while the TCP collector is unreachable, and says so once", async () => {
    const errors: string[] = [];
    // Nothing is listening on this port, so every send has nowhere to go.
    sink = new SyslogSink({ host: "127.0.0.1", port: 9, protocol: "tcp", onError: (e) => errors.push(e.message) });
    for (let i = 0; i < 100; i += 1) sink.send(hit({ id: `x${i}` }));
    await new Promise((r) => setTimeout(r, 200));

    expect(sink.droppedCount).toBe(100);
    // One outage report for a hundred lost messages, not a hundred.
    expect(errors.filter((e) => e.includes("being dropped")).length).toBe(1);
  });

  it("never throws into the hit path, whatever the transport does", async () => {
    sink = new SyslogSink({ host: "not-a-real-host.invalid", port: 514 });
    expect(() => sink!.send(hit())).not.toThrow();
    await new Promise((r) => setTimeout(r, 50));
  });

  it("forwards what a broker publishes, and stops on detach", async () => {
    const server = dgram.createSocket("udp4");
    let count = 0;
    server.on("message", () => (count += 1));
    await new Promise<void>((resolve) => server.bind(0, "127.0.0.1", () => resolve()));
    const port = server.address().port;

    const broker = new IncidentBroker();
    sink = new SyslogSink({ host: "127.0.0.1", port });
    sink.attach(broker);
    broker.publish(hit());
    await new Promise((r) => setTimeout(r, 100));
    sink.detach();
    broker.publish(hit());
    await new Promise((r) => setTimeout(r, 100));
    server.close();

    expect(count).toBe(1);
  });

  it("validates the TOML section", () => {
    const config = parseConfigText('[syslog]\nhost = "siem.internal"\nprotocol = "tcp"\nformat = "json"\nmin_score = 20\n', "<test>");
    expect(config.syslog).toMatchObject({ enabled: true, host: "siem.internal", port: 514, protocol: "tcp", format: "json", minScore: 20 });
    // Off unless a host is named — no accidental traffic to nowhere.
    expect(parseConfigText("", "<test>").syslog.enabled).toBe(false);
    expect(() => parseConfigText("[syslog]\nenabled = true\n", "<test>")).toThrow(/host.*required/);
    expect(() => parseConfigText('[syslog]\nhost = "x"\nfacility = 99\n', "<test>")).toThrow(/facility/);
    expect(() => parseConfigText('[syslog]\nhost = "x"\nseverity = 9\n', "<test>")).toThrow(/severity/);
    expect(() => parseConfigText('[syslog]\nhost = "x"\nmax_bytes = 64\n', "<test>")).toThrow(/max_bytes/);
    expect(() => parseConfigText('[syslog]\nhost = "x"\nprotocol = "sctp"\n', "<test>")).toThrow(/must be one of/);
  });
});
