export function relativeTime(timestampMilliseconds, nowMilliseconds = Date.now()) {
  if (!Number.isSafeInteger(timestampMilliseconds) || !Number.isSafeInteger(nowMilliseconds)) {
    throw new Error("Relative time requires integer millisecond timestamps");
  }
  const elapsed = Math.max(0, Math.floor((nowMilliseconds - timestampMilliseconds) / 1_000));
  if (elapsed < 60) return `${elapsed}s ago`;
  if (elapsed < 3_600) return `${Math.floor(elapsed / 60)}m ago`;
  if (elapsed < 86_400) return `${Math.floor(elapsed / 3_600)}h ago`;
  return `${Math.floor(elapsed / 86_400)}d ago`;
}
