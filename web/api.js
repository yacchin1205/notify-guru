export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export async function createDeviceGroup(body) {
  const result = await request("/api/groups", { method: "POST", body });
  requireExactKeys(result, ["created", "revision", "generation"]);
  if (result.created !== true || integerValue(result.revision, "revision") !== 1 || integerValue(result.generation, "generation") !== 1) {
    throw new Error("Group creation response is inconsistent");
  }
  return result;
}

export async function getGroupState(identity, afterGeneration = 0) {
  const groupId = identity.group.groupId;
  const result = await request(
    `/api/groups/${groupId}/state?deviceId=${identity.deviceId}&afterGeneration=${afterGeneration}`,
    { token: identity.accessToken },
  );
  requireExactKeys(result, [
    "groupId", "revision", "generation", "generationPublicKey", "devices", "packages", "pending", "transitions",
  ]);
  if (stringValue(result.groupId, "groupId") !== groupId) throw new Error("Group state ID mismatch");
  integerValue(result.revision, "revision");
  integerValue(result.generation, "generation");
  stringValue(result.generationPublicKey, "generationPublicKey");
  for (const field of ["devices", "packages", "pending", "transitions"]) {
    if (!Array.isArray(result[field])) throw new Error(`${field} must be an array`);
  }
  return result;
}

export async function createInvitation(identity, invitationId, invitationTokenHash) {
  const result = await request(
    `/api/groups/${identity.group.groupId}/invitations?deviceId=${identity.deviceId}`,
    { method: "POST", token: identity.accessToken, body: { invitationId, invitationTokenHash } },
  );
  requireExactKeys(result, ["created", "expiresAt"]);
  if (result.created !== true) throw new Error("Invitation was not created");
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function submitJoinRequest(invitation, identity) {
  const result = await request(`/api/groups/${invitation.groupId}/join-requests`, {
    method: "POST",
    body: {
      invitationId: invitation.invitationId,
      invitationToken: invitation.invitationToken,
      deviceId: identity.deviceId,
      deviceAccessTokenHash: await sha256Hex(identity.accessToken),
      deviceEncryptionPublicKey: identity.encryptionPublicKey,
      deviceSigningPublicKey: identity.signingPublicKey,
    },
  });
  requireExactKeys(result, ["requested", "expiresAt"]);
  if (result.requested !== true) throw new Error("Join request was not submitted");
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function getJoinRequest(invitation) {
  const result = await request(
    `/api/groups/${invitation.groupId}/join-requests/${invitation.invitationId}`,
    { token: invitation.invitationToken },
  );
  requireExactKeys(result, ["status"]);
  const status = stringValue(result.status, "status");
  if (!["waiting", "pending", "approved", "rejected", "expired"].includes(status)) {
    throw new Error("Unknown join request status");
  }
  return status;
}

export async function approveJoin(identity, invitationId, body) {
  return transitionRequest(
    `/api/groups/${identity.group.groupId}/join-requests/${invitationId}/approve?deviceId=${identity.deviceId}`,
    identity,
    body,
    "approved",
  );
}

export async function rejectJoin(identity, invitationId) {
  const result = await request(
    `/api/groups/${identity.group.groupId}/join-requests/${invitationId}/reject?deviceId=${identity.deviceId}`,
    { method: "POST", token: identity.accessToken },
  );
  requireExactKeys(result, ["rejected", "revision"]);
  if (result.rejected !== true) throw new Error("Join request was not rejected");
  return result;
}

export async function removeDevice(identity, deviceId, body) {
  return transitionRequest(
    `/api/groups/${identity.group.groupId}/devices/${deviceId}/remove?deviceId=${identity.deviceId}`,
    identity,
    body,
    "removed",
  );
}

export async function getGroupSessions(identity) {
  const result = await request(
    `/api/groups/${identity.group.groupId}/sessions?deviceId=${identity.deviceId}`,
    { token: identity.accessToken },
  );
  requireExactKeys(result, ["sessions"]);
  if (!Array.isArray(result.sessions)) throw new Error("sessions must be an array");
  for (const session of result.sessions) {
    requireExactKeys(session, ["sessionId", "creatorPublicKey", "expiresAt"]);
    stringValue(session.sessionId, "sessionId");
    stringValue(session.creatorPublicKey, "creatorPublicKey");
    integerValue(session.expiresAt, "expiresAt");
  }
  return result.sessions;
}

export async function joinSession(sessionId, body) {
  const result = await request(`/api/sessions/${sessionId}/v2/join`, { method: "POST", body });
  requireExactKeys(result, ["joined", "expiresAt"]);
  if (result.joined !== true) throw new Error("Join response did not confirm the device group");
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function getEvents(session, identity) {
  const result = await request(
    `/api/sessions/${session.sessionId}/v2/events?groupId=${identity.group.groupId}&deviceId=${identity.deviceId}&after=${session.cursor}`,
    { token: identity.accessToken },
  );
  requireExactKeys(result, ["events", "expiresAt"]);
  if (!Array.isArray(result.events)) throw new Error("events must be an array");
  for (const event of result.events) {
    requireExactKeys(event, ["sequence", "eventId", "groupId", "generation", "nonce", "ciphertext", "createdAt"]);
    integerValue(event.sequence, "event.sequence");
    integerValue(event.generation, "event.generation");
    integerValue(event.createdAt, "event.createdAt");
    for (const field of ["eventId", "groupId", "nonce", "ciphertext"]) stringValue(event[field], `event.${field}`);
  }
  integerValue(result.expiresAt, "expiresAt");
  return result;
}

export async function postResponse(session, identity, body) {
  const result = await request(`/api/sessions/${session.sessionId}/v2/responses`, {
    method: "POST",
    token: identity.accessToken,
    body,
  });
  requireExactKeys(result, ["expiresAt"]);
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

export async function getLegacyEvents(session) {
  const result = await request(
    `/api/sessions/${session.sessionId}/events?groupId=${encodeURIComponent(session.groupId)}&after=${session.cursor}`,
    { token: session.groupAccessToken },
  );
  requireExactKeys(result, ["events", "expiresAt"]);
  if (!Array.isArray(result.events)) throw new Error("events must be an array");
  return result;
}

export async function postLegacyResponse(session, body) {
  const result = await request(`/api/sessions/${session.sessionId}/responses`, {
    method: "POST", token: session.groupAccessToken, body,
  });
  requireExactKeys(result, ["expiresAt"]);
  return { expiresAt: integerValue(result.expiresAt, "expiresAt") };
}

async function transitionRequest(path, identity, body, confirmation) {
  const result = await request(path, { method: "POST", token: identity.accessToken, body });
  requireExactKeys(result, [confirmation, "revision", "generation"]);
  if (result[confirmation] !== true) throw new Error("Group transition was not accepted");
  integerValue(result.revision, "revision");
  integerValue(result.generation, "generation");
  return result;
}

async function request(path, options = {}) {
  const headers = new Headers();
  if (options.token !== undefined) headers.set("authorization", `Bearer ${options.token}`);
  if (options.body !== undefined) headers.set("content-type", "application/json");
  const response = await fetch(path, {
    method: options.method ?? "GET",
    headers,
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

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
