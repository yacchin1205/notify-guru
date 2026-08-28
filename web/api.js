export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function registerDevice(body) {
  const result = await request("/api/devices", { method: "POST", body });
  requireExactKeys(result, ["deviceId"]);
  return stringValue(result.deviceId, "deviceId");
}

export async function createDeviceRequest(body) {
  const result = await request("/api/device-requests", { method: "POST", body });
  requireExactKeys(result, ["requestId", "expiresAt"]);
  return { requestId: stringValue(result.requestId, "requestId"), expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function getDeviceRequest(identity, requestId, signature) {
  const result = await request(`/api/device-requests/${requestId}?deviceId=${identity.deviceId}`, { token: signature });
  const status = stringValue(result.status, "status");
  if (status === "approved") {
    requireExactKeys(result, ["status", "groupId", "expiresAt"]);
    return { status, groupId: stringValue(result.groupId, "groupId"), expiresAt: integerValue(result.expiresAt, "expiresAt") };
  }
  if (status !== "waiting" && status !== "expired") throw new Error("Unknown device request status");
  requireExactKeys(result, ["status", "expiresAt"]);
  return { status, expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function createDeviceGroup(body) {
  const result = await request("/api/groups", { method: "POST", body });
  requireExactKeys(result, ["created", "groupId"]);
  if (result.created !== true) throw new Error("Group creation was not confirmed");
  return stringValue(result.groupId, "groupId");
}

export async function getGroupState(identity) {
  const groupId = identity.group.groupId;
  const result = await request(`/api/groups/${groupId}/state?deviceId=${identity.deviceId}`, { token: identity.accessToken });
  requireExactKeys(result, ["groupId", "members", "keys", "packages", "sessions"]);
  if (stringValue(result.groupId, "groupId") !== groupId) throw new Error("Group state ID mismatch");
  for (const field of ["members", "keys", "packages", "sessions"]) {
    if (!Array.isArray(result[field])) throw new Error(`${field} must be an array`);
  }
  return result;
}

export async function registerGroupKey(identity, body) {
  const result = await request(`/api/groups/${identity.group.groupId}/keys?deviceId=${identity.deviceId}`, {
    method: "POST", token: identity.accessToken, body,
  });
  requireExactKeys(result, ["timestamp"]);
  return integerValue(result.timestamp, "timestamp");
}

export async function approveDeviceRequest(identity, requestId, body) {
  const result = await request(
    `/api/groups/${identity.group.groupId}/device-requests/${requestId}/approve?deviceId=${identity.deviceId}`,
    { method: "POST", token: identity.accessToken, body },
  );
  requireExactKeys(result, ["approved", "deviceId", "approvedByDeviceId"]);
  if (result.approved !== true) throw new Error("Device request approval was not confirmed");
  return stringValue(result.deviceId, "deviceId");
}

export async function removeDevice(identity, deviceId, body) {
  const result = await request(`/api/groups/${identity.group.groupId}/devices/${deviceId}?deviceId=${identity.deviceId}`, {
    method: "DELETE", token: identity.accessToken, body,
  });
  requireExactKeys(result, ["removed"]);
  if (result.removed !== true) throw new Error("Device removal was not confirmed");
}

export async function joinSession(sessionId, body) {
  const result = await request(`/api/sessions/${sessionId}/join`, { method: "POST", body });
  requireExactKeys(result, ["joined", "expiresAt"]);
  if (result.joined !== true) throw new Error("Session join was not confirmed");
  return integerValue(result.expiresAt, "expiresAt");
}

export async function getEvents(session, identity) {
  const result = await request(
    `/api/sessions/${session.sessionId}/events?groupId=${identity.group.groupId}&deviceId=${identity.deviceId}&after=${session.cursor}&includeActive=1`,
    { token: identity.accessToken },
  );
  requireExactKeys(result, ["events", "activeItemIds", "expiresAt"]);
  if (!Array.isArray(result.events)) throw new Error("events must be an array");
  if (!Array.isArray(result.activeItemIds) || result.activeItemIds.some((item) => typeof item !== "string")) {
    throw new Error("activeItemIds must be strings");
  }
  return {
    events: result.events,
    activeItemIds: result.activeItemIds,
    expiresAt: integerValue(result.expiresAt, "expiresAt"),
  };
}

export async function postResponse(session, identity, body) {
  const result = await request(`/api/sessions/${session.sessionId}/responses`, {
    method: "POST", token: identity.accessToken, body,
  });
  requireExactKeys(result, ["expiresAt"]);
  return integerValue(result.expiresAt, "expiresAt");
}

async function request(path, options = {}) {
  const headers = new Headers();
  if (options.token !== undefined) headers.set("authorization", `Bearer ${options.token}`);
  if (options.body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(path, {
    method: options.method ?? "GET", headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const result = await response.json();
  if (!response.ok) {
    requireExactKeys(result, ["error", "message"]);
    throw new ApiError(response.status, stringValue(result.error, "error"), stringValue(result.message, "message"));
  }
  return result;
}

function requireExactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("API response must be an object");
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("API response fields do not match the protocol");
  }
}

function stringValue(value, field) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function integerValue(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${field} must be a non-negative integer`);
  return value;
}
