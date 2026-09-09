/**
 * Telnet option negotiation, separated from the honeypot so it can be tested on its
 * own — it is the one piece of this protocol with real state, and the one an attacker
 * can drive directly with arbitrary bytes.
 *
 * Telnet interleaves control commands with the data stream: an IAC byte (0xFF) starts
 * a two- or three-byte command, or a variable-length sub-negotiation ended by IAC SE.
 * Anything that reads the stream as plain text without removing those bytes ends up
 * with 0xFF sequences inside the credentials it captures — and, worse, can be steered
 * into replying in a loop.
 *
 * Two properties this deliberately holds:
 *
 * 1. **Resumable across chunks.** The parser state survives between `feed()` calls, so
 *    a command split across TCP segments — which an attacker can produce at will by
 *    sending one byte at a time — is parsed as one command rather than leaking 0xFF
 *    into the data.
 * 2. **Bounded replies.** Every reply is capped, in total, by `maxReplies`. RFC 854
 *    negotiation is symmetric and a hostile peer can answer each of our refusals with
 *    another request forever; past the cap we simply stop talking and keep reading.
 *    A honeypot that can be made to generate unbounded traffic is an amplifier.
 */

export const IAC = 255;
export const DONT = 254;
export const DO = 253;
export const WONT = 252;
export const WILL = 251;
export const SB = 250;
export const SE = 240;

export const OPT_ECHO = 1;
export const OPT_SGA = 3;
export const OPT_TERMINAL_TYPE = 24;

type State = "data" | "iac" | "option" | "subneg" | "subneg-iac";

export interface TelnetCodecOptions {
  /** Options we announce WILL for on connect, and therefore must not re-answer. */
  announced?: number[];
  /** Ceiling on negotiation bytes we will ever send back. Default 64 replies. */
  maxReplies?: number;
  /** Cap on the bytes buffered for one sub-negotiation before it is discarded. Default 64. */
  maxSubnegBytes?: number;
}

export interface TelnetCodecResult {
  /** The stream with every telnet command removed — the actual keystrokes. */
  data: Buffer;
  /** Negotiation to write back, empty when there is nothing to say. */
  reply: Buffer;
  /** Terminal type, if this chunk completed a TERMINAL-TYPE sub-negotiation. */
  terminal?: string;
}

export class TelnetCodec {
  private state: State = "data";
  private command = 0;
  private subneg: number[] = [];
  private replies = 0;
  private readonly announced: Set<number>;
  private readonly maxReplies: number;
  private readonly maxSubnegBytes: number;
  /** Options already refused, so a repeated request doesn't earn a repeated refusal. */
  private readonly refused = new Set<number>();

  constructor(options: TelnetCodecOptions = {}) {
    this.announced = new Set(options.announced ?? [OPT_ECHO, OPT_SGA]);
    this.maxReplies = options.maxReplies ?? 64;
    this.maxSubnegBytes = options.maxSubnegBytes ?? 64;
  }

  /** The opening announcement: we drive echo, and we suppress go-ahead (line mode off). */
  static greeting(options: number[] = [OPT_ECHO, OPT_SGA]): Buffer {
    return Buffer.from(options.flatMap((opt) => [IAC, WILL, opt]));
  }

  feed(chunk: Buffer): TelnetCodecResult {
    const data: number[] = [];
    const reply: number[] = [];
    let terminal: string | undefined;

    for (const byte of chunk) {
      switch (this.state) {
        case "data":
          if (byte === IAC) this.state = "iac";
          else data.push(byte);
          break;

        case "iac":
          if (byte === IAC) {
            // IAC IAC is an escaped literal 0xFF in the data stream.
            data.push(IAC);
            this.state = "data";
          } else if (byte === DO || byte === DONT || byte === WILL || byte === WONT) {
            this.command = byte;
            this.state = "option";
          } else if (byte === SB) {
            this.subneg = [];
            this.state = "subneg";
          } else {
            // A two-byte command with no option (NOP, GA, AYT, …). Nothing to answer.
            this.state = "data";
          }
          break;

        case "option":
          this.negotiate(this.command, byte, reply);
          this.state = "data";
          break;

        case "subneg":
          if (byte === IAC) this.state = "subneg-iac";
          else if (this.subneg.length < this.maxSubnegBytes) this.subneg.push(byte);
          // Past the cap the payload is dropped on the floor; we still track the state
          // machine to its SE so the rest of the stream stays aligned.
          break;

        case "subneg-iac":
          if (byte === SE) {
            terminal = this.readTerminalType() ?? terminal;
            this.subneg = [];
            this.state = "data";
          } else if (byte === IAC) {
            // Escaped 0xFF inside the sub-negotiation payload.
            if (this.subneg.length < this.maxSubnegBytes) this.subneg.push(IAC);
            this.state = "subneg";
          } else {
            this.state = "subneg";
          }
          break;
      }
    }

    const result: TelnetCodecResult = { data: Buffer.from(data), reply: Buffer.from(reply) };
    if (terminal !== undefined) result.terminal = terminal;
    return result;
  }

  /**
   * Answers one negotiation.
   *
   * The policy is "no, to everything", with two rules that keep it from looping:
   * an option we already announced WILL for is never re-answered (the peer's DO is
   * the expected end of that exchange, not a new request), and each option is
   * refused at most once.
   */
  private negotiate(command: number, option: number, reply: number[]): void {
    if (this.replies >= this.maxReplies) return;

    if (command === DO) {
      if (this.announced.has(option)) return; // already agreed; answering again loops
      if (this.refused.has(option)) return;
      this.refused.add(option);
      reply.push(IAC, WONT, option);
    } else if (command === WILL) {
      // We want no options from the peer — except TERMINAL-TYPE, which costs nothing
      // and tells us which client family we are looking at.
      if (option === OPT_TERMINAL_TYPE) {
        reply.push(IAC, DO, OPT_TERMINAL_TYPE, IAC, SB, OPT_TERMINAL_TYPE, 1, IAC, SE);
      } else {
        if (this.refused.has(option)) return;
        this.refused.add(option);
        reply.push(IAC, DONT, option);
      }
    } else if (command === DONT) {
      if (this.refused.has(option)) return;
      this.refused.add(option);
      reply.push(IAC, WONT, option);
    } else {
      // WONT — the peer declining something. Nothing is owed in reply.
      return;
    }
    this.replies += 1;
  }

  /** Reads a completed TERMINAL-TYPE IS payload, if that is what just ended. */
  private readTerminalType(): string | undefined {
    // [TERMINAL-TYPE, IS(0), ...name]
    if (this.subneg[0] !== OPT_TERMINAL_TYPE || this.subneg[1] !== 0) return undefined;
    const name = Buffer.from(this.subneg.slice(2))
      .toString("latin1")
      .replace(/[^\x20-\x7e]/g, "")
      .trim();
    return name === "" ? undefined : name.slice(0, 64);
  }
}
