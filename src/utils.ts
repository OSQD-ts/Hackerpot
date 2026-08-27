export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function resolveDelay(delayMs: number | [number, number] | undefined): number {
  if (delayMs === undefined) return 0;
  return Array.isArray(delayMs) ? randomBetween(delayMs[0], delayMs[1]) : delayMs;
}
