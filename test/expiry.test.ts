import { describe, expect, it } from "vitest";
import { expiredSessionIDs } from "../web/expiry.js";

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
