import { env, reset, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

afterEach(reset);

describe("session relay", () => {
  it("relays opaque events and responses between a creator and a device group", async () => {
    const fixture = await createJoinedSession();

    const eventId = randomId();
    const event = await api(`/api/sessions/${fixture.sessionId}/events`, {
      method: "POST",
      token: fixture.managerToken,
      body: {
        eventId,
        groupId: fixture.groupId,
        nonce: "AAAAAAAAAAAAAAAA",
        ciphertext: "opaque_event_payload",
      },
    });
    expect(event.status).toBe(201);

    const events = await api(`/api/sessions/${fixture.sessionId}/events?groupId=${fixture.groupId}&after=0`, {
      token: fixture.groupToken,
    });
    expect(events.status).toBe(200);
    expect(events.json.events).toEqual([
      expect.objectContaining({
        eventId,
        groupId: fixture.groupId,
        nonce: "AAAAAAAAAAAAAAAA",
        ciphertext: "opaque_event_payload",
      }),
    ]);

    const responseId = randomId();
    const response = await api(`/api/sessions/${fixture.sessionId}/responses`, {
      method: "POST",
      token: fixture.groupToken,
      body: {
        responseId,
        groupId: fixture.groupId,
        nonce: "BBBBBBBBBBBBBBBB",
        ciphertext: "opaque_response_payload",
      },
    });
    expect(response.status).toBe(201);

    const responses = await api(`/api/sessions/${fixture.sessionId}/responses?after=0`, {
      token: fixture.managerToken,
    });
    expect(responses.status).toBe(200);
    expect(responses.json.responses).toEqual([
      expect.objectContaining({
        responseId,
        groupId: fixture.groupId,
        nonce: "BBBBBBBBBBBBBBBB",
        ciphertext: "opaque_response_payload",
      }),
    ]);
  });

  it("rejects unknown protocol fields", async () => {
    const response = await api("/api/sessions", {
      method: "POST",
      body: {
        sessionId: randomId(),
        managerTokenHash: await hash("manager-token"),
        creatorPublicKey: "A".repeat(87),
        pairing: { id: randomId(), tokenHash: await hash("pairing-token") },
        typo: true,
      },
    });
    expect(response.status).toBe(400);
    expect(response.json.error).toBe("unknown_field");
  });

  it("rejects malformed JSON and unsafe cursors as protocol errors", async () => {
    const malformed = await SELF.fetch("https://notify.guru/api/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{",
    });
    expect(malformed.status).toBe(400);
    expect((await malformed.json<{ error: string }>()).error).toBe("invalid_json");

    const fixture = await createJoinedSession();
    const unsafeCursor = await api(`/api/sessions/${fixture.sessionId}/events?groupId=${fixture.groupId}&after=9007199254740992`, {
      token: fixture.groupToken,
    });
    expect(unsafeCursor.status).toBe(400);
    expect(unsafeCursor.json.error).toBe("invalid_query");
  });

  it("requires the exact manager and group capabilities", async () => {
    const fixture = await createJoinedSession();

    const managerResponse = await api(`/api/sessions/${fixture.sessionId}/responses?after=0`, {
      token: "wrong-token",
    });
    expect(managerResponse.status).toBe(401);
    expect(managerResponse.json.error).toBe("invalid_manager_token");

    const groupResponse = await api(`/api/sessions/${fixture.sessionId}/events?groupId=${fixture.groupId}&after=0`, {
      token: "wrong-token",
    });
    expect(groupResponse.status).toBe(401);
    expect(groupResponse.json.error).toBe("invalid_group_token");
  });

  it("registers an APNs token only for its exact device-group capability", async () => {
    const fixture = await createJoinedSession();
    const registered = await api(`/api/sessions/${fixture.sessionId}/push`, {
      method: "PUT",
      token: fixture.groupToken,
      body: {
        groupId: fixture.groupId,
        deviceToken: "aabbccdd",
        environment: "sandbox",
      },
    });
    expect(registered.status).toBe(200);
    expect(registered.json).toEqual({ registered: true, expiresAt: expect.any(Number) });

    const rejected = await api(`/api/sessions/${fixture.sessionId}/push`, {
      method: "PUT",
      token: "wrong-token",
      body: {
        groupId: fixture.groupId,
        deviceToken: "aabbccdd",
        environment: "sandbox",
      },
    });
    expect(rejected.status).toBe(401);
    expect(rejected.json.error).toBe("invalid_group_token");
  });

  it("consumes each pairing exactly once", async () => {
    const fixture = await createJoinedSession();
    const response = await join(fixture);
    expect(response.status).toBe(409);
    expect(response.json.error).toBe("pairing_consumed");
  });

  it("deallocates all session storage when its alarm fires", async () => {
    const fixture = await createJoinedSession();
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(fixture.sessionId));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE meta SET expires_at = 0 WHERE singleton = 1");
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    const response = await api(`/api/sessions/${fixture.sessionId}/responses?after=0`, {
      token: fixture.managerToken,
    });
    expect(response.status).toBe(404);
    expect(response.json.error).toBe("session_not_found");
  });

  it("deallocates all session storage on explicit close", async () => {
    const fixture = await createJoinedSession();
    const closed = await api(`/api/sessions/${fixture.sessionId}`, {
      method: "DELETE",
      token: fixture.managerToken,
    });
    expect(closed.status).toBe(204);

    const response = await api(`/api/sessions/${fixture.sessionId}/responses?after=0`, {
      token: fixture.managerToken,
    });
    expect(response.status).toBe(404);
  });

  it("redirects HTTP and instructs HTTPS clients to remain secure", async () => {
    const redirected = await SELF.fetch(new Request("http://notify.guru/join?pairing=test", {
      redirect: "manual",
    }));
    expect(redirected.status).toBe(301);
    expect(redirected.headers.get("location")).toBe("https://notify.guru/join?pairing=test");

    const secure = await SELF.fetch("https://notify.guru/api/health");
    expect(secure.headers.get("strict-transport-security")).toBe("max-age=15552000");
  });
});

async function createJoinedSession() {
  const fixture = {
    sessionId: randomId(),
    managerToken: "manager-token",
    pairingId: randomId(),
    pairingToken: "pairing-token",
    groupId: randomId(),
    groupToken: "group-token",
  };
  const created = await api("/api/sessions", {
    method: "POST",
    body: {
      sessionId: fixture.sessionId,
      managerTokenHash: await hash(fixture.managerToken),
      creatorPublicKey: "A".repeat(87),
      pairing: { id: fixture.pairingId, tokenHash: await hash(fixture.pairingToken) },
    },
  });
  expect(created.status).toBe(201);

  const joined = await join(fixture);
  expect(joined.status).toBe(201);
  return fixture;
}

async function join(fixture: {
  sessionId: string;
  pairingId: string;
  pairingToken: string;
  groupId: string;
  groupToken: string;
}) {
  return api(`/api/sessions/${fixture.sessionId}/join`, {
    method: "POST",
    body: {
      pairingId: fixture.pairingId,
      pairingToken: fixture.pairingToken,
      groupId: fixture.groupId,
      groupAccessTokenHash: await hash(fixture.groupToken),
      groupPublicKey: "B".repeat(87),
      proof: "C".repeat(43),
    },
  });
}

async function api(path: string, options: { method?: string; token?: string; body?: unknown } = {}) {
  const headers = new Headers();
  if (options.token !== undefined) {
    headers.set("authorization", `Bearer ${options.token}`);
  }
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
  }
  const response = await SELF.fetch(`https://notify.guru${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(await options.body),
  });
  const json = response.status === 204 ? undefined : await response.json<Record<string, any>>();
  return { status: response.status, json };
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomId(): string {
  return crypto.randomUUID().replaceAll("-", "_");
}
