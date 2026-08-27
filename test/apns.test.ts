import { describe, expect, it } from "vitest";
import { APNsClient } from "../src/apns";

describe("APNs client", () => {
  it("sends only a generic alert with token authentication", async () => {
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

    await expect(client.send("aabbccdd", "sandbox")).resolves.toBe("delivered");
    expect(receivedURL).toBe("https://api.sandbox.push.apple.com/3/device/aabbccdd");
    expect(receivedInit?.headers).toMatchObject({
      "apns-push-type": "alert",
      "apns-priority": "10",
      "apns-topic": "guru.notify.app",
    });
    expect(JSON.parse(String(receivedInit?.body))).toEqual({
      aps: { alert: "A new notification is available." },
    });
    const authorization = (receivedInit?.headers as Record<string, string>).authorization;
    expect(authorization.startsWith("bearer ")).toBe(true);
    expect(authorization.slice(7).split(".")).toHaveLength(3);
  });

  it("classifies invalid destination tokens without hiding provider errors", async () => {
    const privateKey = await signingKey();
    const invalid = new APNsClient(
      { keyId: "ABCDEFGHIJ", teamId: "0123456789", privateKey, topic: "guru.notify.app" },
      (async () => Response.json({ reason: "Unregistered", timestamp: 1 }, { status: 410 })) as typeof fetch,
    );
    const providerFailure = new APNsClient(
      { keyId: "ABCDEFGHIJ", teamId: "0123456789", privateKey, topic: "guru.notify.app" },
      (async () => Response.json({ reason: "InternalServerError" }, { status: 500 })) as typeof fetch,
    );

    await expect(invalid.send("aabb", "production")).resolves.toBe("invalid-token");
    await expect(providerFailure.send("aabb", "production")).rejects.toThrow(
      "APNs request failed (500): InternalServerError",
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
