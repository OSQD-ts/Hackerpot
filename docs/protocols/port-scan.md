# Port-scan sentinel

Decoy TCP ports nothing legitimate should touch, and the sweeps that touch them.

← [Documentation](../index.md) · [Protocols](index.md)

---

`PortScanSentinel` listens on ports your real services do not use. Every inbound connection is
unsolicited by definition, so there is nothing to classify: a connection is a touch, and an
address touching several ports is a sweep. It runs below HTTP, independent of the detectors.

```ts
import { PortScanSentinel } from "@osqd/hackerpot";

const sentinel = new PortScanSentinel({
  ports: [8022, 9200, 7001],               // pick ports nothing of yours listens on
  banner: "SSH-2.0-OpenSSH_8.4",
  onEvent: (event) => console.warn("[port-scan]", event.ip, event.port, event.portsTouched, event.isScan),
});
await sentinel.listen();
```

## The event

```ts
interface PortScanEvent {
  ip: string;
  port: number;
  at: Date;
  portsTouched: number;   // distinct sentinel ports this address has touched so far
  isScan: boolean;        // true once portsTouched reaches scanThreshold
  banner?: string;        // bytes the client sent before disconnecting: often a protocol probe
}
```

## Options

| Option | Default | |
| --- | --- | --- |
| `ports` | — | required |
| `host` | all interfaces | |
| `scanThreshold` | `2` | distinct ports one address must touch to count as a sweep |
| `banner` | silent | a fake service banner sent on connect |
| `maxTrackedIps` | `10000` | addresses whose touched-port sets are remembered; least recently seen shed first |
| `retentionMs` | `3600000` | how long a touched-port set is remembered |
| `isAllowlisted` | — | an allowlisted source is never remembered or reported |
| `onEvent` | — | every touch |

The touched-ports map is the sentinel's only growth surface, and decoy ports exist to be
connected to by anything on the internet, so both bounds are required. Raise them to correlate
slower sweeps; the config refuses `0` for either, since that would never see a second port.

## In the standalone service

```toml
[port-scan]
ports = [8022, 9200, 7001]      # listing any port enables it
host = "0.0.0.0"
scan_threshold = 2
banner = "SSH-2.0-OpenSSH_8.4"  # "" stays silent
max_tracked_ips = 10000
retention_ms = 3600000
```

Or `SCAN_PORTS=8022,9200,7001` and `SCAN_BANNER=…` in the environment. The service logs each
touch as `kind: "port-touch"` and each sweep as `kind: "port-scan"`. Sentinel events go to the
log; they are not recorded as incidents in the store.

A port claimed by both the sentinel and another listener (the SSH honeypot on 2222, say) is a
startup error. With Docker, publish each sentinel port; the compose file does for 8022, 9200
and 7001.

## Related

- [Protocols overview](index.md)
- [nginx edge capture](../integration/nginx.md) — what the edge cannot see, including this
