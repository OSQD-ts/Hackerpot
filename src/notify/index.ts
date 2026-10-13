/**
 * Where incidents leave the process.
 *
 * Split the way bothandlerjs splits it — `types` for the contract, `hub` for the fan-out,
 * `sinks` for the destinations — so the two libraries are read the same way and a sink written
 * against one is recognisable to somebody who knows the other.
 */
export { NotificationHub } from "./hub.js";
export type { NotificationHubOptions } from "./hub.js";
export { consoleNotifier, notifyJsSink, syslogNotifySink, webhookNotifySink } from "./sinks.js";
export type { ConsoleNotifierOptions, NotifyJsSinkOptions } from "./sinks.js";
export type { NotifyEvent, NotifyEventType, NotifyFilter, NotifySink } from "./types.js";
