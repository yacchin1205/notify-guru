export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function joinSession(sessionId, body) {
  const result = await request(`/api/sessions/${sessionId}/join`, { method: "POST", body });
  requireExactKeys(result, ["joined", "expiresAt"]);
  if (result.joined !== true) {
    throw new Error("Join response did not confirm the device group");
  }
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function getEvents(session) {
  const result = await request(`/api/sessions/${session.sessionId}/events?groupId=${encodeURIComponent(session.groupId)}&after=${session.cursor}`, {
    token: session.groupAccessToken,
  });
  requireExactKeys(result, ["events", "expiresAt"]);
  if (!Array.isArray(result.events)) {
    throw new Error("events must be an array");
  }
  for (const event of result.events) {
    requireExactKeys(event, ["sequence", "eventId", "groupId", "nonce", "ciphertext", "createdAt"]);
    integerValue(event.sequence, "event.sequence");
    integerValue(event.createdAt, "event.createdAt");
    for (const field of ["eventId", "groupId", "nonce", "ciphertext"]) {
      stringValue(event[field], `event.${field}`);
    }
  }
  integerValue(result.expiresAt, "expiresAt");
  return result;
}

export async function postResponse(session, body) {
  const result = await request(`/api/sessions/${session.sessionId}/responses`, {
    method: "POST",
    token: session.groupAccessToken,
    body,
  });
  requireExactKeys(result, ["expiresAt"]);
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

async function request(path, options = {}) {
  const headers = new Headers();
  if (options.token !== undefined) {
    headers.set("authorization", `Bearer ${options.token}`);
  }
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
  }
  const response = await fetch(path, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (!response.ok) {
    const error = await response.json();
    requireExactKeys(error, ["error", "message"]);
    throw new ApiError(response.status, stringValue(error.error, "error"), stringValue(error.message, "message"));
  }
  if (response.status === 204) {
    return undefined;
  }
  return response.json();
}

function requireExactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("API response must be an object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("API response fields do not match the protocol");
  }
}

function stringValue(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function integerValue(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${field} must be a non-negative integer`);
  }
  return value;
}
