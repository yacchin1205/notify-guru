export function expiredSessionIDs(sessions, now) {
  if (!Array.isArray(sessions)) {
    throw new Error("Stored sessions must be an array");
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error("Current time must be a non-negative safe integer");
  }
  const expired = [];
  for (const session of sessions) {
    if (session === null || typeof session !== "object" || Array.isArray(session)) {
      throw new Error("Stored session must be an object");
    }
    if (typeof session.sessionId !== "string" || session.sessionId.length === 0) {
      throw new Error("Stored session has an invalid identifier");
    }
    if (!Number.isSafeInteger(session.expiresAt) || session.expiresAt < 0) {
      throw new Error("Stored session has an invalid expiry time");
    }
    if (session.expiresAt <= now) {
      expired.push(session.sessionId);
    }
  }
  return expired;
}
