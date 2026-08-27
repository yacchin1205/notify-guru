import { reset, SELF } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

afterEach(reset);

describe("persistent device groups", () => {
  it("requires inviter approval, rotates every membership change, and blocks removed devices", async () => {
    const first = await newDevice();
    const second = await newDevice();
    const group = await createGroup(first);
    const retained = {
      id: randomId(), managerToken: randomToken(), pairingId: randomId(), pairingToken: randomToken(),
    };
    expect((await api("/api/sessions", {
      method: "POST",
      body: {
        sessionId: retained.id,
        managerTokenHash: await hash(retained.managerToken),
        creatorPublicKey: group.generationPublicKey,
        pairing: { id: retained.pairingId, tokenHash: await hash(retained.pairingToken) },
      },
    })).status).toBe(201);
    expect((await api(`/api/sessions/${retained.id}/v2/join`, {
      method: "POST",
      body: {
        pairingId: retained.pairingId,
        pairingToken: retained.pairingToken,
        groupId: group.id,
        deviceId: first.id,
        deviceAccessToken: first.token,
        revision: 1,
        generation: 1,
        groupPublicKey: group.generationPublicKey,
        proof: randomToken(),
      },
    })).status).toBe(201);
    const retainedEvent = eventBody(group.id, 1);
    expect((await api(`/api/sessions/${retained.id}/v2/events`, {
      method: "POST", token: retained.managerToken, body: retainedEvent,
    })).status).toBe(201);
    const invitationId = randomId();
    const invitationToken = randomToken();

    const invited = await api(`/api/groups/${group.id}/invitations?deviceId=${first.id}`, {
      method: "POST",
      token: first.token,
      body: { invitationId, invitationTokenHash: await hash(invitationToken) },
    });
    expect(invited.status).toBe(201);

    const requested = await api(`/api/groups/${group.id}/join-requests`, {
      method: "POST",
      body: {
        invitationId,
        invitationToken,
        deviceId: second.id,
        deviceAccessTokenHash: await hash(second.token),
        deviceEncryptionPublicKey: second.encryptionPublicKey,
        deviceSigningPublicKey: second.signingPublicKey,
      },
    });
    expect(requested.status).toBe(201);

    const replayed = await api(`/api/groups/${group.id}/join-requests`, {
      method: "POST",
      body: {
        invitationId,
        invitationToken,
        deviceId: second.id,
        deviceAccessTokenHash: await hash(second.token),
        deviceEncryptionPublicKey: second.encryptionPublicKey,
        deviceSigningPublicKey: second.signingPublicKey,
      },
    });
    expect(replayed.status).toBe(409);
    expect(replayed.json.error).toBe("join_request_exists");

    const generation2 = await generateSigningKey();
    const packages2 = [keyPackage(2, first.id), keyPackage(2, second.id), keyPackage(1, second.id)];
    const approved = await transition(group, first, group.generationKey, generation2, {
      action: "add",
      targetDeviceId: second.id,
      revision: 2,
      previousGeneration: 1,
      generation: 2,
      packages: packages2,
      invitationId,
    });
    expect(approved.status).toBe(200);

    const secondState = await api(`/api/groups/${group.id}/state?deviceId=${second.id}&afterGeneration=0`, {
      token: second.token,
    });
    expect(secondState.status).toBe(200);
    expect(secondState.json).toEqual(expect.objectContaining({
      groupId: group.id,
      revision: 2,
      generation: 2,
      devices: expect.arrayContaining([
        expect.objectContaining({ deviceId: first.id }),
        expect.objectContaining({ deviceId: second.id }),
      ]),
      packages: expect.arrayContaining([
        expect.objectContaining({ generation: 1, deviceId: second.id }),
        expect.objectContaining({ generation: 2, deviceId: second.id }),
      ]),
    }));

    const inherited = await api(`/api/groups/${group.id}/sessions?deviceId=${second.id}`, { token: second.token });
    expect(inherited.status).toBe(200);
    expect(inherited.json.sessions).toEqual([
      expect.objectContaining({ sessionId: retained.id, creatorPublicKey: group.generationPublicKey }),
    ]);
    const retainedHistory = await api(
      `/api/sessions/${retained.id}/v2/events?groupId=${group.id}&deviceId=${second.id}&after=0`,
      { token: second.token },
    );
    expect(retainedHistory.status).toBe(200);
    expect(retainedHistory.json.events).toEqual([
      expect.objectContaining({ eventId: retainedEvent.eventId, generation: 1 }),
    ]);

    const generation3 = await generateSigningKey();
    const missingRemainingPackage = await transition(group, first, generation2, generation3, {
      action: "remove",
      targetDeviceId: first.id,
      revision: 3,
      previousGeneration: 2,
      generation: 3,
      packages: [],
    });
    expect(missingRemainingPackage.status).toBe(400);
    expect(missingRemainingPackage.json.error).toBe("invalid_package_set");

    const left = await transition(group, first, generation2, generation3, {
      action: "remove",
      targetDeviceId: first.id,
      revision: 3,
      previousGeneration: 2,
      generation: 3,
      packages: [keyPackage(3, second.id)],
    });
    expect(left.status).toBe(200);

    const blocked = await api(`/api/groups/${group.id}/state?deviceId=${first.id}`, { token: first.token });
    expect(blocked.status).toBe(403);
    expect(blocked.json.error).toBe("device_removed");

    const remaining = await api(`/api/groups/${group.id}/state?deviceId=${second.id}&afterGeneration=2`, {
      token: second.token,
    });
    expect(remaining.status).toBe(200);
    expect(remaining.json.devices).toEqual([expect.objectContaining({ deviceId: second.id })]);

    const generation4 = await generateSigningKey();
    const lastLeft = await transition(group, second, generation3, generation4, {
      action: "remove",
      targetDeviceId: second.id,
      revision: 4,
      previousGeneration: 3,
      generation: 4,
      packages: [],
    });
    expect(lastLeft.status).toBe(200);
    const nobodyRemains = await api(`/api/groups/${group.id}/state?deviceId=${second.id}`, { token: second.token });
    expect(nobodyRemains.status).toBe(403);
    expect(nobodyRemains.json.error).toBe("device_removed");

    const replacement = await createGroup(second);
    const replacementState = await api(`/api/groups/${replacement.id}/state?deviceId=${second.id}`, {
      token: second.token,
    });
    expect(replacementState.status).toBe(200);
    expect(replacementState.json.devices).toEqual([expect.objectContaining({ deviceId: second.id })]);
  });

  it("relays v2 payloads only at the current generation and authenticates each device", async () => {
    const device = await newDevice();
    const group = await createGroup(device);
    const session = {
      id: randomId(),
      managerToken: randomToken(),
      pairingId: randomId(),
      pairingToken: randomToken(),
    };
    const created = await api("/api/sessions", {
      method: "POST",
      body: {
        sessionId: session.id,
        managerTokenHash: await hash(session.managerToken),
        creatorPublicKey: group.generationPublicKey,
        pairing: { id: session.pairingId, tokenHash: await hash(session.pairingToken) },
      },
    });
    expect(created.status).toBe(201);

    const joined = await api(`/api/sessions/${session.id}/v2/join`, {
      method: "POST",
      body: {
        pairingId: session.pairingId,
        pairingToken: session.pairingToken,
        groupId: group.id,
        deviceId: device.id,
        deviceAccessToken: device.token,
        revision: 1,
        generation: 1,
        groupPublicKey: group.generationPublicKey,
        proof: randomToken(),
      },
    });
    expect(joined.status).toBe(201);

    const push = await api(`/api/sessions/${session.id}/v2/push`, {
      method: "PUT",
      token: device.token,
      body: {
        groupId: group.id,
        deviceId: device.id,
        deviceToken: "aabbccdd",
        environment: "sandbox",
      },
    });
    expect(push.status).toBe(200);

    const stale = await api(`/api/sessions/${session.id}/v2/events`, {
      method: "POST",
      token: session.managerToken,
      body: eventBody(group.id, 0),
    });
    expect(stale.status).toBe(409);
    expect(stale.json.error).toBe("stale_group_generation");

    const envelope = eventBody(group.id, 1);
    const sent = await api(`/api/sessions/${session.id}/v2/events`, {
      method: "POST",
      token: session.managerToken,
      body: envelope,
    });
    expect(sent.status).toBe(201);

    const events = await api(
      `/api/sessions/${session.id}/v2/events?groupId=${group.id}&deviceId=${device.id}&after=0`,
      { token: device.token },
    );
    expect(events.status).toBe(200);
    expect(events.json.events).toEqual([
      expect.objectContaining({ eventId: envelope.eventId, generation: 1, ciphertext: envelope.ciphertext }),
    ]);

    const denied = await api(
      `/api/sessions/${session.id}/v2/events?groupId=${group.id}&deviceId=${device.id}&after=0`,
      { token: randomToken() },
    );
    expect(denied.status).toBe(401);
    expect(denied.json.error).toBe("invalid_device_token");
  });
});

async function createGroup(device: Device) {
  const id = randomId();
  const generationKey = await generateSigningKey();
  const generationPublicKey = await publicKey(generationKey);
  const initialPackage = keyPackage(1, device.id);
  const packagesHash = await hashPackages([initialPackage]);
  const transcript = [
    "notify.guru/group-create/v1",
    id,
    device.id,
    device.encryptionPublicKey,
    device.signingPublicKey,
    generationPublicKey,
    packagesHash,
  ].join("\n");
  const created = await api("/api/groups", {
    method: "POST",
    body: {
      groupId: id,
      deviceId: device.id,
      deviceAccessTokenHash: await hash(device.token),
      deviceEncryptionPublicKey: device.encryptionPublicKey,
      deviceSigningPublicKey: device.signingPublicKey,
      generationPublicKey,
      package: initialPackage,
      deviceSignature: await sign(device.signingKey, transcript),
    },
  });
  expect(created.status).toBe(201);
  return { id, generationKey, generationPublicKey };
}

async function transition(
  group: { id: string },
  actor: Device,
  previousGenerationKey: CryptoKeyPair,
  nextGenerationKey: CryptoKeyPair,
  input: {
    action: "add" | "remove";
    targetDeviceId: string;
    revision: number;
    previousGeneration: number;
    generation: number;
    packages: KeyPackage[];
    invitationId?: string;
  },
) {
  const nextPublicKey = await publicKey(nextGenerationKey);
  const packagesHash = await hashPackages(input.packages);
  const transcript = [
    "notify.guru/group-transition/v1",
    group.id,
    String(input.revision),
    String(input.previousGeneration),
    String(input.generation),
    nextPublicKey,
    input.action,
    actor.id,
    input.targetDeviceId,
    packagesHash,
  ].join("\n");
  const body = {
    expectedRevision: input.revision - 1,
    nextGenerationPublicKey: nextPublicKey,
    packages: input.packages,
    groupSignature: await sign(previousGenerationKey, transcript),
    deviceSignature: await sign(actor.signingKey, transcript),
  };
  const path = input.action === "add"
    ? `/api/groups/${group.id}/join-requests/${input.invitationId}/approve?deviceId=${actor.id}`
    : `/api/groups/${group.id}/devices/${input.targetDeviceId}/remove?deviceId=${actor.id}`;
  return api(path, { method: "POST", token: actor.token, body });
}

interface Device {
  id: string;
  token: string;
  signingKey: CryptoKeyPair;
  signingPublicKey: string;
  encryptionPublicKey: string;
}

interface KeyPackage {
  generation: number;
  deviceId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

async function newDevice(): Promise<Device> {
  const signingKey = await generateSigningKey();
  return {
    id: randomId(),
    token: randomToken(),
    signingKey,
    signingPublicKey: await publicKey(signingKey),
    encryptionPublicKey: await publicKey(await signingKeyPairForEncryption()),
  };
}

async function generateSigningKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

async function signingKeyPairForEncryption(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
}

async function publicKey(pair: CryptoKeyPair): Promise<string> {
  return encode(await crypto.subtle.exportKey("raw", pair.publicKey));
}

async function sign(pair: CryptoKeyPair, transcript: string): Promise<string> {
  return encode(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    pair.privateKey,
    new TextEncoder().encode(transcript),
  ));
}

function keyPackage(generation: number, deviceId: string): KeyPackage {
  return {
    generation,
    deviceId,
    ephemeralPublicKey: "A".repeat(87),
    nonce: "A".repeat(16),
    ciphertext: randomToken(),
  };
}

async function hashPackages(packages: KeyPackage[]): Promise<string> {
  const canonical = [...packages]
    .sort((left, right) => left.generation - right.generation || left.deviceId.localeCompare(right.deviceId))
    .map((item) => [
      String(item.generation),
      item.deviceId,
      item.ephemeralPublicKey,
      item.nonce,
      item.ciphertext,
    ].join("\n"))
    .join("\n--\n");
  return hash(canonical);
}

function eventBody(groupId: string, generation: number) {
  return {
    eventId: randomId(),
    groupId,
    generation,
    nonce: "A".repeat(16),
    ciphertext: randomToken(),
  };
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
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const json = response.status === 204 ? undefined : await response.json<Record<string, any>>();
  return { status: response.status, json };
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encode(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function randomId(): string {
  return crypto.randomUUID().replaceAll("-", "_");
}

function randomToken(): string {
  return randomId() + randomId();
}
