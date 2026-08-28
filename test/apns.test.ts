import { describe, expect, it, vi } from "vitest";
import { APNsClient, APNsTransportError } from "../src/apns";

describe("APNs client", () => {
  it("sends a generic alert with the default notification sound", async () => {
    const privateKey = await signingKey();
    let receivedURL = "";
    let receivedInit: RequestInit | undefined;
    const transport = (async (input: RequestInfo | URL, init?: RequestInit) => {
      receivedURL = String(input);
      receivedInit = init;
      return new Response(null, { status: 200 });
    }) as typeof fetch;
    const client = new APNsClient(
      {
        keyId: "ABCDEFGHIJ",
        teamId: "0123456789",
        privateKey,
        topic: "guru.notify.app",
      },
      transport,
    );

    await expect(client.send("aabbccdd", "sandbox", "notify")).resolves.toEqual({ outcome: "delivered" });
    expect(receivedURL).toBe("https://api.sandbox.push.apple.com/3/device/aabbccdd");
    expect(receivedInit?.headers).toMatchObject({
      "apns-push-type": "alert",
      "apns-priority": "10",
      "apns-topic": "guru.notify.app",
    });
    expect(JSON.parse(String(receivedInit?.body))).toEqual({
      aps: { alert: "A new notification is available.", sound: "default" },
    });
    const authorization = (receivedInit?.headers as Record<string, string>).authorization;
    expect(authorization.startsWith("bearer ")).toBe(true);
    expect(authorization.slice(7).split(".")).toHaveLength(3);
  });

  it("asks for a response without exposing the encrypted prompt", async () => {
    const privateKey = await signingKey();
    let body: unknown;
    const client = new APNsClient(
      { keyId: "REQUEST001", teamId: "REQUEST002", privateKey, topic: "guru.notify.app" },
      (async (_input: RequestInfo | URL, init?: RequestInit) => {
        body = JSON.parse(String(init?.body));
        return new Response(null, { status: 200 });
      }) as typeof fetch,
    );

    await client.send("aabb", "sandbox", "request");
    expect(body).toEqual({ aps: { alert: "Your input is requested.", sound: "default" } });
  });

  it("sets an absolute badge count and can update it without an alert", async () => {
    const privateKey = await signingKey();
    const bodies: unknown[] = [];
    const client = new APNsClient(
      { keyId: "BADGEKEY01", teamId: "BADGETEAM1", privateKey, topic: "guru.notify.app" },
      (async (_input: RequestInfo | URL, init?: RequestInit) => {
        bodies.push(JSON.parse(String(init?.body)));
        return new Response(null, { status: 200 });
      }) as typeof fetch,
    );

    await client.send("aabb", "sandbox", "notify", 3);
    await client.send("aabb", "sandbox", "badge", 2);

    expect(bodies).toEqual([
      { aps: { alert: "A new notification is available.", sound: "default", badge: 3 } },
      { aps: { badge: 2 } },
    ]);
  });

  it("reuses one provider token across APNs clients in the same Worker isolate", async () => {
    const privateKey = await signingKey();
    const authorizations: string[] = [];
    const transport = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      authorizations.push((init?.headers as Record<string, string>).authorization);
      return new Response(null, { status: 200 });
    }) as typeof fetch;
    const config = {
      keyId: "CACHEKEY01",
      teamId: "CACHETEA01",
      privateKey,
      topic: "guru.notify.app",
    };

    await Promise.all([
      new APNsClient(config, transport).send("aabb", "sandbox", "notify"),
      new APNsClient(config, transport).send("ccdd", "sandbox", "request"),
    ]);

    expect(authorizations).toHaveLength(2);
    expect(authorizations[0]).toBe(authorizations[1]);
  });

  it("refreshes a cached provider token before Apple's one-hour limit", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-08-27T00:00:00Z"));
      const privateKey = await signingKey();
      const authorizations: string[] = [];
      const transport = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        authorizations.push((init?.headers as Record<string, string>).authorization);
        return new Response(null, { status: 200 });
      }) as typeof fetch;
      const client = new APNsClient(
        { keyId: "REFRESH001", teamId: "REFRESH002", privateKey, topic: "guru.notify.app" },
        transport,
      );

      await client.send("aabb", "sandbox", "notify");
      vi.setSystemTime(new Date("2026-08-27T00:49:00Z"));
      await client.send("aabb", "sandbox", "notify");
      vi.setSystemTime(new Date("2026-08-27T00:51:00Z"));
      await client.send("aabb", "sandbox", "notify");

      expect(authorizations[0]).toBe(authorizations[1]);
      expect(authorizations[2]).not.toBe(authorizations[1]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("classifies invalid, permanent, and retryable provider responses", async () => {
    const privateKey = await signingKey();
    const invalid = new APNsClient(
      { keyId: "INVALID001", teamId: "INVALID002", privateKey, topic: "guru.notify.app" },
      (async () => Response.json({ reason: "Unregistered", timestamp: 1 }, { status: 410 })) as typeof fetch,
    );
    const providerFailure = new APNsClient(
      { keyId: "PERMANENT1", teamId: "PERMANENT2", privateKey, topic: "guru.notify.app" },
      (async () => Response.json({ reason: "BadTopic" }, { status: 400 })) as typeof fetch,
    );
    const retryable = new APNsClient(
      { keyId: "RETRYABLE1", teamId: "RETRYABLE2", privateKey, topic: "guru.notify.app" },
      (async () => Response.json({ reason: "ServiceUnavailable" }, { status: 503 })) as typeof fetch,
    );

    await expect(invalid.send("aabb", "production", "notify")).resolves.toEqual({
      outcome: "invalid-token",
      reason: "Unregistered",
    });
    await expect(providerFailure.send("aabb", "production", "notify")).resolves.toEqual({
      outcome: "permanent-failure",
      reason: "BadTopic",
    });
    await expect(retryable.send("aabb", "production", "request")).resolves.toEqual({
      outcome: "retry",
      reason: "ServiceUnavailable",
      minimumDelayMs: 15 * 60 * 1000,
    });
  });

  it("distinguishes retryable transport failures from configuration errors", async () => {
    const privateKey = await signingKey();
    const transportFailure = new APNsClient(
      { keyId: "NETWORK001", teamId: "NETWORK002", privateKey, topic: "guru.notify.app" },
      (async () => { throw new TypeError("network unavailable"); }) as typeof fetch,
    );
    await expect(transportFailure.send("aabb", "production", "notify")).rejects.toBeInstanceOf(APNsTransportError);

    const invalidConfiguration = new APNsClient(
      { keyId: "invalid", teamId: "NETWORK002", privateKey, topic: "guru.notify.app" },
    );
    await expect(invalidConfiguration.send("aabb", "production", "notify")).rejects.toThrow(
      "APNS_KEY_ID must be a 10-character uppercase identifier",
    );
  });
});

async function signingKey(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const encoded = btoa(binary);
  const lines = encoded.match(/.{1,64}/g);
  if (lines === null) {
    throw new Error("Generated PKCS#8 key was empty");
  }
  return `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`;
}
