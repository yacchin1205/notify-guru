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

export function expiredInvitationIDs(invitations, now) {
  if (invitations === null || typeof invitations !== "object" || Array.isArray(invitations)) {
    throw new Error("Stored invitations must be an object");
  }
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error("Current time must be a non-negative safe integer");
  }
  const expired = [];
  for (const [invitationId, invitation] of Object.entries(invitations)) {
    if (invitation === null || typeof invitation !== "object" || Array.isArray(invitation)) {
      throw new Error("Stored invitation must be an object");
    }
    if (invitation.invitationId !== invitationId) {
      throw new Error("Stored invitation has an inconsistent identifier");
    }
    if (!Number.isSafeInteger(invitation.expiresAt) || invitation.expiresAt < 0) {
      throw new Error("Stored invitation has an invalid expiry time");
    }
    if (invitation.expiresAt <= now) expired.push(invitationId);
  }
  return expired;
}
