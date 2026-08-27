import { describe, expect, it } from "vitest";
import { expiredInvitationIDs, expiredSessionIDs } from "../web/expiry.js";

describe("local session expiry", () => {
  it("removes sessions at their known expiry without consulting the server", () => {
    const sessions = [
      { sessionId: "expired", expiresAt: 1_000, sharedKey: "sensitive" },
      { sessionId: "current", expiresAt: 1_001, sharedKey: "sensitive" },
    ];

    expect(expiredSessionIDs(sessions, 1_000)).toEqual(["expired"]);
  });

  it("fails fast on corrupt persisted expiry data", () => {
    expect(() => expiredSessionIDs([{ sessionId: "broken", expiresAt: Number.NaN }], 1_000)).toThrow(
      "invalid expiry time",
    );
  });
});

describe("device invitation expiry", () => {
  it("removes invitation secrets at their known expiry", () => {
    const invitations = {
      expired: { invitationId: "expired", expiresAt: 1_000, invitationToken: "secret" },
      current: { invitationId: "current", expiresAt: 1_001, invitationToken: "secret" },
    };

    expect(expiredInvitationIDs(invitations, 1_000)).toEqual(["expired"]);
  });

  it("fails fast on inconsistent invitation state", () => {
    expect(() => expiredInvitationIDs({ expected: { invitationId: "different", expiresAt: 1_000 } }, 1_000)).toThrow(
      "inconsistent identifier",
    );
  });
});
