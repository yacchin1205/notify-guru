import { env, reset, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

afterEach(reset);

describe("session relay", () => {
  it("rejects a creator key that is not a point on P-256", async () => {
    const response = await api("/api/sessions", {
      method: "POST",
      body: {
        sessionId: randomId(),
        managerTokenHash: await hash("manager-token"),
        creatorPublicKey: "A".repeat(87),
        pairing: { id: randomId(), tokenHash: await hash("pairing-token") },
      },
    });
    expect(response.status).toBe(400);
    expect(response.json.error).toBe("invalid_public_key");
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

    const session = await createSession();
    const unsafeCursor = await api(`/api/sessions/${session.id}/responses?after=9007199254740992`, {
      token: session.managerToken,
    });
    expect(unsafeCursor.status).toBe(400);
    expect(unsafeCursor.json.error).toBe("invalid_query");
  });

  it("requires the exact manager capability", async () => {
    const session = await createSession();
    const response = await api(`/api/sessions/${session.id}/responses?after=0`, { token: "wrong-token" });
    expect(response.status).toBe(401);
    expect(response.json.error).toBe("invalid_manager_token");
  });

  it("deallocates all session storage when its alarm fires", async () => {
    const session = await createSession();
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(session.id));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE meta SET expires_at = 0 WHERE singleton = 1");
    });
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    const response = await api(`/api/sessions/${session.id}/responses?after=0`, {
      token: session.managerToken,
    });
    expect(response.status).toBe(404);
    expect(response.json.error).toBe("session_not_found");
  });

  it("deallocates all session storage on explicit close", async () => {
    const session = await createSession();
    const closed = await api(`/api/sessions/${session.id}`, {
      method: "DELETE",
      token: session.managerToken,
    });
    expect(closed.status).toBe(204);

    const response = await api(`/api/sessions/${session.id}/responses?after=0`, {
      token: session.managerToken,
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

  it("associates only QR link paths with the iOS app", async () => {
    const response = await SELF.fetch("https://notify.guru/.well-known/apple-app-site-association");
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toEqual({
      applinks: {
        details: [{
          appIDs: ["TDW896YLJ7.guru.notify.app"],
          components: [{ "/": "/join" }, { "/": "/device" }],
        }],
      },
    });
  });
});

async function createSession(): Promise<{ id: string; managerToken: string }> {
  const id = randomId();
  const managerToken = "manager-token";
  const created = await api("/api/sessions", {
    method: "POST",
    body: {
      sessionId: id,
      managerTokenHash: await hash(managerToken),
      creatorPublicKey: await creatorPublicKey(),
      pairing: { id: randomId(), tokenHash: await hash("pairing-token") },
    },
  });
  expect(created.status).toBe(201);
  return { id, managerToken };
}

async function creatorPublicKey(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"],
  );
  const bytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function api(path: string, options: { method?: string; token?: string; body?: unknown } = {}) {
  const headers = new Headers();
  if (options.token !== undefined) headers.set("authorization", `Bearer ${options.token}`);
  if (options.body !== undefined) headers.set("content-type", "application/json");
  const response = await SELF.fetch(`https://notify.guru${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
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
