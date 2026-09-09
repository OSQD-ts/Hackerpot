/**
 * The scripted "shell" the interactive honeypots present after they let an
 * attacker in.
 *
 * Nothing here executes anything. Every response is a fixed string chosen to look
 * like a plausible Linux box, so the attacker keeps typing and we keep capturing —
 * the commands are the product, the output is only the bait that draws more of them.
 * There is no path from a captured command to a real process, in this module or in
 * its callers.
 *
 * Shared by the SSH and Telnet honeypots because they present the *same* fiction to
 * the same attackers: the credential-stuffing botnets that sweep 22 and 23 run the
 * identical recon (`uname -a`, `cat /proc/cpuinfo`, `/bin/busybox <APPLET>`) down
 * either pipe. One implementation means one place to make the illusion better.
 *
 * Line endings are CRLF throughout: both callers write to something the client
 * treats as a terminal (an SSH PTY, a Telnet stream in character mode), where a
 * bare LF moves down a line without returning to column 0 and the display stairsteps.
 */

export interface FakeShellOptions {
  /** Hostname this box claims to be. Appears in `uname -a` and `hostname`. */
  hostname?: string;
  /** The account the attacker believes they are. Appears in `whoami` / `id`. */
  user?: string;
}

const DEFAULT_HOSTNAME = "srv01";
const DEFAULT_USER = "root";
const KERNEL = "5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023";

/** The distro string a fresh login prints, for callers that open with a banner. */
export const FAKE_MOTD = "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)";

/**
 * A plausible-but-inert response to a shell command.
 *
 * Unrecognized commands get `command not found`, which is the honest-looking answer
 * and costs nothing. The recognized set is deliberately small and skewed toward what
 * the automated attackers actually run in the first ten seconds of a session: identity
 * (`whoami`, `id`), reconnaissance (`uname`, `cat /proc/cpuinfo`), and the BusyBox
 * applet probe that IoT droppers use to fingerprint a target before staging a payload.
 */
export function fakeShellOutput(command: string, options: FakeShellOptions = {}): string {
  const hostname = options.hostname ?? DEFAULT_HOSTNAME;
  const user = options.user ?? DEFAULT_USER;
  const parts = command.trim().split(/\s+/);
  const cmd = parts[0] ?? "";
  const args = parts.slice(1);
  if (cmd === "") return "";

  switch (cmd) {
    case "whoami":
      return `${user}\r\n`;
    case "id":
      return user === "root"
        ? "uid=0(root) gid=0(root) groups=0(root)\r\n"
        : `uid=1000(${user}) gid=1000(${user}) groups=1000(${user})\r\n`;
    case "pwd":
      return user === "root" ? "/root\r\n" : `/home/${user}\r\n`;
    case "hostname":
      return `${hostname}\r\n`;
    case "uname":
      // Bare `uname` prints only the kernel name; the flags every recon script
      // actually passes (-a, -m, -r) print the long form.
      return args.length === 0 ? "Linux\r\n" : `Linux ${hostname} ${KERNEL} x86_64 x86_64 x86_64 GNU/Linux\r\n`;
    case "busybox":
    case "/bin/busybox": {
      // The Mirai family's fingerprint: `/bin/busybox <APPLET>` with a nonsense applet
      // name, looking for the distinctive "applet not found" reply that proves a live
      // BusyBox device. Answering it exactly is what keeps the dropper talking.
      const applet = args[0];
      return applet === undefined
        ? "BusyBox v1.20.2 (2016-06-14 08:44:53 CST) multi-call binary.\r\n"
        : `${applet}: applet not found\r\n`;
    }
    case "cat":
      return catOutput(args[0], hostname);
    case "echo":
      // Droppers stage payloads with `echo -e '\x7f\x45...' > file`; echoing the
      // arguments back (minus the flags) is both realistic and inert.
      return `${args.filter((a) => !a.startsWith("-")).join(" ")}\r\n`;
    case "ps":
      return "  PID TTY          TIME CMD\r\n    1 ?        00:00:03 systemd\r\n  842 ?        00:00:00 sshd\r\n";
    case "free":
      return "               total        used        free\r\nMem:         2035116      412088     1623028\r\nSwap:              0           0           0\r\n";
    case "df":
      return "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n/dev/sda1       41152736 8214512  30821856  22% /\r\n";
    case "w":
    case "who":
      return `${user}     pts/0    10.0.0.5         09:14    0.00s  0.01s  0.00s -bash\r\n`;
    case "wget":
    case "curl":
    case "tftp":
      // The staging step. Report nothing useful and, above all, fetch nothing: the
      // URL has already been captured by the caller, which is the entire value here.
      return "";
    case "ls":
    case "dir":
    case "cd":
    case "export":
    case "chmod":
    case "rm":
    case "history":
      return "\r\n";
    default:
      return `${cmd}: command not found\r\n`;
  }
}

/** Contents for the handful of files worth reading on a box that isn't real. */
function catOutput(path: string | undefined, hostname: string): string {
  if (path === undefined) return "\r\n";
  if (path === "/etc/passwd") {
    return [
      "root:x:0:0:root:/root:/bin/bash",
      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
      "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
      "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
      "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
      "",
    ].join("\r\n");
  }
  if (path === "/etc/shadow") return "cat: /etc/shadow: Permission denied\r\n";
  if (path === "/etc/hostname") return `${hostname}\r\n`;
  if (path === "/proc/cpuinfo") {
    return "processor\t: 0\r\nmodel name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\r\ncpu MHz\t\t: 2400.000\r\n";
  }
  return `cat: ${path}: No such file or directory\r\n`;
}
