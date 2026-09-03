import { env, reset, runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

afterEach(reset);

describe("devices and persistent groups", () => {
  it("registers a device and accepts push updates only with its signature", async () => {
    const device = await newDevice();
    const token = "ab".repeat(32);
    const transcript = ["notify.guru/device-push/v1", device.id, token, "sandbox"].join("\n");
    const updated = await api(`/api/devices/${device.id}/push`, {
      method: "PUT",
      body: { token, environment: "sandbox", signature: await sign(device.signingKey, transcript) },
    });
    expect(updated).toEqual({ status: 200, json: { updated: true } });

    const rejected = await api(`/api/devices/${device.id}/push`, {
      method: "PUT",
      body: {
        token,
        environment: "sandbox",
        signature: await sign(await generateSigningKey(), transcript),
      },
    });
    expect(rejected.status).toBe(401);
    expect(rejected.json.error).toBe("invalid_device_signature");
  });

  it("queues distinct request alerts and suppresses status alerts", async () => {
    const device = await newDevice();
    const group = await createGroup(device);
    const key = await registerKey(group.id, device, [device], true);
    const session = await createJoinedSession(group, device, key);

    expect((await postEvent(session, key.timestamp, "request")).status).toBe(201);
    expect((await postEvent(session, key.timestamp, "none")).status).toBe(201);
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(session.id));
    const { alarm, kinds } = await runInDurableObject(stub, async (_instance, state) => ({
      alarm: await state.storage.getAlarm(),
      kinds: Array.from(state.storage.sql.exec<{ notification_kind: string }>(
        "SELECT notification_kind FROM push_jobs_v3 ORDER BY event_id",
      )),
    }));
    expect(kinds).toEqual([{ notification_kind: "request" }]);
    expect(alarm).not.toBeNull();
    expect(alarm!).toBeLessThan(Date.now() + 5_000);

    expect((await postEvent(session, key.timestamp, "loud")).status).toBe(400);
  });

  it("alerts status updates only to devices that asked for attention", async () => {
    const device = await newDevice();
    const group = await createGroup(device);
    const key = await registerKey(group.id, device, [device], true);
    const session = await createJoinedSession(group, device, key);
    const stub = env.SESSIONS.get(env.SESSIONS.idFromName(session.id));
    const pushJobs = () => runInDurableObject(stub, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ event_id: string; notification_kind: string }>(
        "SELECT event_id, notification_kind FROM push_jobs_v3 ORDER BY event_id",
      )));

    expect((await postEvent(session, key.timestamp, "status")).status).toBe(201);
    expect(await pushJobs()).toEqual([]);
    const initial = await attentionEvents(session, device);
    expect(Object.keys(initial.json).sort()).toEqual(["attention", "events", "expiresAt"]);
    expect(initial.json.attention).toBe(false);

    const rejected = await setAttention(session, { ...device, token: randomToken() }, true);
    expect(rejected.status).toBe(401);
    expect(rejected.json.error).toBe("invalid_device_token");
    const enabled = await setAttention(session, device, true);
    expect(enabled).toEqual({ status: 200, json: { attention: true, expiresAt: expect.any(Number) } });
    expect((await attentionEvents(session, device)).json.attention).toBe(true);

    const first = await postEvent(session, key.timestamp, "status");
    expect(first.status).toBe(201);
    expect(await pushJobs()).toEqual([{ event_id: first.json.eventId, notification_kind: "status" }]);
    const second = await postEvent(session, key.timestamp, "status");
    expect(second.status).toBe(201);
    expect(await pushJobs()).toEqual([{ event_id: second.json.eventId, notification_kind: "status" }]);
    expect((await postEvent(session, key.timestamp, "none")).status).toBe(201);
    expect(await pushJobs()).toEqual([{ event_id: second.json.eventId, notification_kind: "status" }]);

    expect((await setAttention(session, device, false)).json.attention).toBe(false);
    expect(await pushJobs()).toEqual([]);
    expect((await postEvent(session, key.timestamp, "status")).status).toBe(201);
    expect(await pushJobs()).toEqual([]);

    const trackedStatus = await api(`/api/sessions/${session.id}/events`, {
      method: "POST",
      token: session.managerToken,
      body: {
        eventId: randomId(),
        itemId: randomId(),
        groupId: session.groupId,
        keyTimestamp: key.timestamp,
        nonce: "A".repeat(16),
        ciphertext: randomToken(),
        notificationKind: "status",
      },
    });
    expect(trackedStatus.status).toBe(400);
    expect(trackedStatus.json.error).toBe("invalid_field");
  });

  it("tracks opaque active items and invalidates them through ordinary responses", async () => {
    const device = await newDevice();
    const group = await createGroup(device);
    const key = await registerKey(group.id, device, [device], true);
    const session = await createJoinedSession(group, device, key);
    const itemId = randomId();

    const created = await postTrackedEvent(session, key.timestamp, itemId, "request");
    expect(created.status).toBe(201);
    expect((await postTrackedEvent(
      session,
      key.timestamp,
      itemId,
      "request",
      created.eventId,
      created.ciphertext,
    )).status).toBe(201);
    const conflictingRetry = await postTrackedEvent(
      session,
      key.timestamp,
      itemId,
      "request",
      created.eventId,
    );
    expect(conflictingRetry.status).toBe(409);
    expect(conflictingRetry.json.error).toBe("event_exists");
    const before = await trackedEvents(session, device);
    expect(before.json.activeItemIds).toEqual([itemId]);
    expect(before.json.events).toEqual([
      expect.objectContaining({ itemId }),
    ]);
    const registry = env.DEVICES.get(env.DEVICES.idFromName("registry"));
    expect(await runInDurableObject(registry, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM device_active_items_v1 WHERE device_id = ?",
        device.id,
      ))[0].count
    )).toBe(1);

    const trackedStatus = await api(`/api/sessions/${session.id}/events`, {
      method: "POST",
      token: session.managerToken,
      body: {
        eventId: randomId(),
        itemId: randomId(),
        groupId: session.groupId,
        keyTimestamp: key.timestamp,
        nonce: "A".repeat(16),
        ciphertext: randomToken(),
        notificationKind: "none",
      },
    });
    expect(trackedStatus.status).toBe(400);
    expect(trackedStatus.json.error).toBe("invalid_field");

    const response = (responseId: string) => api(`/api/sessions/${session.id}/responses`, {
      method: "POST",
      token: device.token,
      body: {
        responseId,
        itemId,
        groupId: group.id,
        deviceId: device.id,
        keyTimestamp: key.timestamp,
        nonce: "A".repeat(16),
        ciphertext: randomToken(),
      },
    });
    expect((await response(randomId())).status).toBe(201);
    expect((await trackedEvents(session, device)).json.activeItemIds).toEqual([]);
    expect(await runInDurableObject(registry, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM device_active_items_v1 WHERE device_id = ?",
        device.id,
      ))[0].count
    )).toBe(0);

    expect((await response(randomId())).status).toBe(201);
    const sessionStub = env.SESSIONS.get(env.SESSIONS.idFromName(session.id));
    expect(await runInDurableObject(sessionStub, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM session_responses_v3 WHERE item_id = ?",
        itemId,
      ))[0].count
    )).toBe(2);
  });

  it("stores version 4 attachment ciphertext in R2 and releases it after response acknowledgement", async () => {
    const device = await newDevice();
    const group = await createGroup(device);
    const key = await registerKey(group.id, device, [device], true);
    const session = await createJoinedSession(group, device, key, 4);
    const attachmentId = randomId();
    const responseId = randomId();
    const ciphertext = new TextEncoder().encode("opaque encrypted jpeg bytes");
    const reserved = await api(`/api/sessions/${session.id}/attachments`, {
      method: "POST",
      token: device.token,
      body: {
        attachmentId,
        responseId,
        groupId: group.id,
        deviceId: device.id,
        keyTimestamp: key.timestamp,
        ciphertextLength: ciphertext.byteLength,
        ciphertextSha256: await hash("opaque encrypted jpeg bytes"),
      },
    });
    expect(reserved).toEqual({
      status: 201,
      json: {
        attachmentId,
        uploadToken: expect.any(String),
        maxCiphertextBytes: 2 * 1024 * 1024,
        uploadExpiresAt: expect.any(Number),
      },
    });

    const uploaded = await SELF.fetch(`https://notify.guru/api/sessions/${session.id}/attachments/${attachmentId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${reserved.json.uploadToken}`,
        "content-type": "application/octet-stream",
      },
      body: ciphertext,
    });
    expect(uploaded.status).toBe(200);
    expect(await uploaded.json()).toEqual({ uploaded: true });

    const committed = await api(`/api/sessions/${session.id}/responses`, {
      method: "POST",
      token: device.token,
      body: {
        responseId,
        attachmentId,
        groupId: group.id,
        deviceId: device.id,
        keyTimestamp: key.timestamp,
        nonce: "A".repeat(16),
        ciphertext: randomToken(),
      },
    });
    expect(committed.status).toBe(201);

    const downloaded = await SELF.fetch(
      `https://notify.guru/api/sessions/${session.id}/attachments/${attachmentId}`,
      { headers: { authorization: `Bearer ${session.managerToken}` } },
    );
    expect(downloaded.status).toBe(200);
    expect(new Uint8Array(await downloaded.arrayBuffer())).toEqual(ciphertext);

    const received = await api(`/api/sessions/${session.id}/responses?after=0`, { token: session.managerToken });
    expect(received.json.responses).toEqual([
      expect.objectContaining({ responseId, attachmentId }),
    ]);
    const sequence = received.json.responses[0].sequence;
    expect((await api(`/api/sessions/${session.id}/responses?after=${sequence}`, {
      token: session.managerToken,
    })).status).toBe(200);
    expect((await SELF.fetch(
      `https://notify.guru/api/sessions/${session.id}/attachments/${attachmentId}`,
      { headers: { authorization: `Bearer ${session.managerToken}` } },
    )).status).toBe(404);
  });

  it("does not leave a claim behind when a version 3 device is rejected from a version 4 session group", async () => {
    const first = await newDevice();
    const second = await newDevice();
    const group = await createGroup(first);
    const key = await registerKey(group.id, first, [first], true);
    await createJoinedSession(group, first, key, 4);
    const request = await createDeviceRequest(second);
    const transcript = [
      "notify.guru/group-device-approve/v1", group.id, first.id, request.id,
    ].join("\n");
    const rejected = await api(
      `/api/groups/${group.id}/device-requests/${request.id}/approve?deviceId=${first.id}`,
      { method: "POST", token: first.token, body: { actorSignature: await sign(first.signingKey, transcript) } },
    );
    expect(rejected.status).toBe(409);
    expect(rejected.json.error).toBe("protocol_upgrade_required");

    const registry = env.DEVICES.get(env.DEVICES.idFromName("registry"));
    expect(await runInDurableObject(registry, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ claimed_group_id: string | null }>(
        "SELECT claimed_group_id FROM device_requests WHERE id = ?",
        request.id,
      ))[0].claimed_group_id
    )).toBeNull();
  });

  it("reverses device approval and binds group keys to their members", async () => {
    const first = await newDevice();
    const second = await newDevice();
    const group = await createGroup(first);
    const initialKey = await registerKey(group.id, first, [first], true);
    const session = await createJoinedSession(group, first, initialKey);

    const request = await createDeviceRequest(second);
    const unreadable = await api(`/api/device-requests/${request.id}?deviceId=${second.id}`, {
      token: await sign(
        first.signingKey,
        ["notify.guru/device-request-read/v1", request.id, second.id].join("\n"),
      ),
    });
    expect(unreadable.status).toBe(401);

    const approvalSignature = await sign(
      first.signingKey,
      ["notify.guru/group-device-approve/v1", group.id, first.id, request.id].join("\n"),
    );
    const approve = () => api(
      `/api/groups/${group.id}/device-requests/${request.id}/approve?deviceId=${first.id}`,
      { method: "POST", token: first.token, body: { actorSignature: approvalSignature } },
    );
    const approved = await approve();
    expect(approved.status).toBe(200);
    expect(approved.json).toEqual({ approved: true, deviceId: second.id, approvedByDeviceId: first.id });
    expect((await approve()).status).toBe(200);

    const requestStatus = await getDeviceRequest(second, request.id);
    expect(requestStatus).toEqual({ status: "approved", groupId: group.id, expiresAt: expect.any(Number) });

    const afterAddition = await groupState(group.id, first);
    expect(afterAddition.members.map((member: { deviceId: string }) => member.deviceId)).toEqual([first.id, second.id]);
    expect(afterAddition.keys).toEqual([
      expect.objectContaining({ timestamp: initialKey.timestamp, recreated: true, members: [first.id] }),
    ]);

    const oldKeyEvent = await postEvent(session, initialKey.timestamp);
    expect(oldKeyEvent.status).toBe(201);
    expect((await events(session, first)).json.events).toHaveLength(1);
    expect((await events(session, second)).json.events).toEqual([]);

    const sharedKey = await registerKey(group.id, first, [first, second], false);
    const sharedEvent = await postEvent(session, sharedKey.timestamp);
    expect(sharedEvent.status).toBe(201);
    expect((await events(session, first)).json.events).toHaveLength(2);
    expect((await events(session, second)).json.events).toEqual([
      expect.objectContaining({ eventId: sharedEvent.json.eventId, keyTimestamp: sharedKey.timestamp }),
    ]);

    const sharedItemID = randomId();
    expect((await postTrackedEvent(session, sharedKey.timestamp, sharedItemID, "request")).status).toBe(201);
    expect((await trackedEvents(session, first)).json.activeItemIds).toEqual([sharedItemID]);
    expect((await trackedEvents(session, second)).json.activeItemIds).toEqual([sharedItemID]);
    expect((await postTrackedResponse(session, second, sharedKey.timestamp, sharedItemID)).status).toBe(201);
    expect((await trackedEvents(session, first)).json.activeItemIds).toEqual([]);
    expect((await trackedEvents(session, second)).json.activeItemIds).toEqual([]);

    const removed = await api(`/api/groups/${group.id}/devices/${second.id}?deviceId=${first.id}`, {
      method: "DELETE",
      token: first.token,
      body: {
        actorSignature: await sign(
          first.signingKey,
          ["notify.guru/group-device-remove/v1", group.id, first.id, second.id].join("\n"),
        ),
      },
    });
    expect(removed).toEqual({ status: 200, json: { removed: true } });

    const unsafe = await postEvent(session, sharedKey.timestamp);
    expect(unsafe.status).toBe(409);
    expect(unsafe.json.error).toBe("group_key_unavailable");

    const missingBoundary = await registerKeyResponse(group.id, first, [first], false);
    expect(missingBoundary.status).toBe(409);
    expect(missingBoundary.json.error).toBe("recreated_required");

    const recreated = await registerKey(group.id, first, [first], true);
    expect((await postEvent(session, recreated.timestamp)).status).toBe(201);
    const removedState = await api(`/api/groups/${group.id}/state?deviceId=${second.id}`, { token: second.token });
    expect(removedState.status).toBe(403);
    expect(removedState.json.error).toBe("device_removed");
    const replayedApproval = await approve();
    expect(replayedApproval.status).toBe(409);
    expect(replayedApproval.json.error).toBe("device_request_used");
    expect((await groupState(group.id, first)).members.map((member: { deviceId: string }) => member.deviceId)).toEqual([
      first.id,
    ]);

    const repeatedRequest = await createDeviceRequest(second);
    const repeatedApproval = await api(
      `/api/groups/${group.id}/device-requests/${repeatedRequest.id}/approve?deviceId=${first.id}`,
      {
        method: "POST",
        token: first.token,
        body: {
          actorSignature: await sign(
            first.signingKey,
            ["notify.guru/group-device-approve/v1", group.id, first.id, repeatedRequest.id].join("\n"),
          ),
        },
      },
    );
    expect(repeatedApproval.status).toBe(200);
    expect((await groupState(group.id, first)).members.map((member: { deviceId: string }) => member.deviceId)).toEqual([
      first.id,
      second.id,
    ]);
    const preRemovalKeyAfterReaddition = await postEvent(session, sharedKey.timestamp);
    expect(preRemovalKeyAfterReaddition.status).toBe(409);
    expect(preRemovalKeyAfterReaddition.json.error).toBe("group_key_unavailable");
    const replacementSharedKey = await registerKey(group.id, first, [first, second], false);
    expect((await postEvent(session, replacementSharedKey.timestamp)).status).toBe(201);

    expect((await postTrackedEvent(session, replacementSharedKey.timestamp, randomId(), "notify")).status).toBe(201);
    const registry = env.DEVICES.get(env.DEVICES.idFromName("registry"));
    expect(await runInDurableObject(registry, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM device_active_items_v1 WHERE session_id = ?",
        session.id,
      ))[0].count
    )).toBe(2);

    expect((await groupState(group.id, first)).sessions).toHaveLength(1);
    expect((await api(`/api/sessions/${session.id}`, { method: "DELETE", token: session.managerToken })).status).toBe(204);
    expect((await groupState(group.id, first)).sessions).toEqual([]);
    expect(await runInDurableObject(registry, async (_instance, state) =>
      Array.from(state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM device_active_items_v1 WHERE session_id = ?",
        session.id,
      ))[0].count
    )).toBe(0);
  });

  it("rejects key records whose members or packages differ from active membership", async () => {
    const first = await newDevice();
    const second = await newDevice();
    const group = await createGroup(first);
    const key = await groupKey();

    const validMembers = [first.id];
    const validPackages = [keyPackage(first.id)];
    const forged = await api(`/api/groups/${group.id}/keys?deviceId=${first.id}`, {
      method: "POST",
      token: first.token,
      body: {
        publicKey: key.publicKey,
        recreated: true,
        members: validMembers,
        packages: validPackages,
        actorSignature: await sign(
          second.signingKey,
          groupKeyTranscript(group.id, first.id, key.publicKey, true, validMembers, validPackages),
        ),
      },
    });
    expect(forged.status).toBe(401);
    expect(forged.json.error).toBe("invalid_device_signature");

    const extraMember = await api(`/api/groups/${group.id}/keys?deviceId=${first.id}`, {
      method: "POST",
      token: first.token,
      body: {
        publicKey: key.publicKey,
        recreated: true,
        members: [first.id, second.id],
        packages: [keyPackage(first.id), keyPackage(second.id)],
        actorSignature: randomToken(),
      },
    });
    expect(extraMember.status).toBe(409);
    expect(extraMember.json.error).toBe("member_set_changed");

    const missingPackage = await api(`/api/groups/${group.id}/keys?deviceId=${first.id}`, {
      method: "POST",
      token: first.token,
      body: {
        publicKey: key.publicKey,
        recreated: true,
        members: [first.id],
        packages: [],
        actorSignature: randomToken(),
      },
    });
    expect(missingPackage.status).toBe(400);
    expect(missingPackage.json.error).toBe("invalid_field");
  });

  it("does not expose Durable Object RPC methods as HTTP routes", async () => {
    const device = await newDevice();
    const group = await createGroup(device);
    const response = await api(`/api/groups/${group.id}/current`, {
      headers: { "x-notify-guru-internal": "1" },
    });
    expect(response.status).toBe(404);
  });
});

interface Device {
  id: string;
  token: string;
  signingKey: CryptoKeyPair;
  encryptionPublicKey: string;
}

interface Group {
  id: string;
}

interface RegisteredKey {
  timestamp: number;
  publicKey: string;
}

interface JoinedSession {
  id: string;
  managerToken: string;
  groupId: string;
}

async function newDevice(): Promise<Device> {
  const signingKey = await generateSigningKey();
  const signingPublicKey = await publicKey(signingKey);
  const nonce = randomToken();
  const signature = await sign(
    signingKey,
    ["notify.guru/device-create/v1", signingPublicKey, nonce].join("\n"),
  );
  const created = await api("/api/devices", {
    method: "POST",
    body: { signingPublicKey, nonce, signature },
  });
  expect(created.status).toBe(201);
  const encryptionKey = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  return {
    id: created.json.deviceId,
    token: randomToken(),
    signingKey,
    encryptionPublicKey: await publicKey(encryptionKey),
  };
}

async function generateSigningKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

async function createGroup(device: Device): Promise<Group> {
  const id = randomId();
  const accessHash = await hash(device.token);
  const transcript = [
    "notify.guru/group-create/v2",
    id,
    device.id,
    accessHash,
    device.encryptionPublicKey,
  ].join("\n");
  const created = await api("/api/groups", {
    method: "POST",
    body: {
      groupId: id,
      deviceId: device.id,
      deviceAccessTokenHash: accessHash,
      deviceEncryptionPublicKey: device.encryptionPublicKey,
      deviceSignature: await sign(device.signingKey, transcript),
    },
  });
  expect(created).toEqual({ status: 201, json: { created: true, groupId: id } });
  return { id };
}

async function createDeviceRequest(device: Device): Promise<{ id: string; expiresAt: number }> {
  const id = randomId();
  const accessHash = await hash(device.token);
  const transcript = [
    "notify.guru/device-request/v1",
    id,
    device.id,
    accessHash,
    device.encryptionPublicKey,
  ].join("\n");
  const created = await api("/api/device-requests", {
    method: "POST",
    body: {
      requestId: id,
      deviceId: device.id,
      deviceAccessTokenHash: accessHash,
      deviceEncryptionPublicKey: device.encryptionPublicKey,
      deviceSignature: await sign(device.signingKey, transcript),
    },
  });
  expect(created.status).toBe(201);
  return { id, expiresAt: created.json.expiresAt };
}

async function getDeviceRequest(device: Device, requestId: string) {
  const signature = await sign(
    device.signingKey,
    ["notify.guru/device-request-read/v1", requestId, device.id].join("\n"),
  );
  return (await api(`/api/device-requests/${requestId}?deviceId=${device.id}`, { token: signature })).json;
}

async function registerKey(
  groupId: string,
  actor: Device,
  members: Device[],
  recreated: boolean,
): Promise<RegisteredKey> {
  const response = await registerKeyResponse(groupId, actor, members, recreated);
  expect(response.status).toBe(201);
  return { timestamp: response.json.timestamp, publicKey: response.publicKey };
}

async function registerKeyResponse(
  groupId: string,
  actor: Device,
  members: Device[],
  recreated: boolean,
) {
  const key = await groupKey();
  const memberIDs = members.map((member) => member.id);
  const packages = members.map((member) => keyPackage(member.id));
  const transcript = groupKeyTranscript(groupId, actor.id, key.publicKey, recreated, memberIDs, packages);
  const response = await api(`/api/groups/${groupId}/keys?deviceId=${actor.id}`, {
    method: "POST",
    token: actor.token,
    body: {
      publicKey: key.publicKey,
      recreated,
      members: memberIDs,
      packages,
      actorSignature: await sign(actor.signingKey, transcript),
    },
  });
  return { ...response, publicKey: key.publicKey };
}

async function createJoinedSession(
  group: Group,
  device: Device,
  key: RegisteredKey,
  protocolVersion = 3,
): Promise<JoinedSession> {
  const sessionId = randomId();
  const managerToken = randomToken();
  const pairingId = randomId();
  const pairingToken = randomToken();
  expect((await api("/api/sessions", {
    method: "POST",
    body: {
      sessionId,
      managerTokenHash: await hash(managerToken),
      creatorPublicKey: key.publicKey,
      ...(protocolVersion === 3 ? {} : { protocolVersion }),
      pairing: { id: pairingId, tokenHash: await hash(pairingToken) },
    },
  })).status).toBe(201);
  if (protocolVersion === 4) {
    expect((await api(`/api/groups/${group.id}/state?deviceId=${device.id}&protocolVersion=4`, {
      token: device.token,
    })).status).toBe(200);
  }
  expect((await api(`/api/sessions/${sessionId}/join`, {
    method: "POST",
    body: {
      pairingId,
      pairingToken,
      groupId: group.id,
      deviceId: device.id,
      deviceAccessToken: device.token,
      keyTimestamp: key.timestamp,
      groupPublicKey: key.publicKey,
      proof: randomToken(),
    },
  })).status).toBe(201);
  return { id: sessionId, managerToken, groupId: group.id };
}

async function postEvent(session: JoinedSession, keyTimestamp: number, notificationKind = "notify") {
  const eventId = randomId();
  const result = await api(`/api/sessions/${session.id}/events`, {
    method: "POST",
    token: session.managerToken,
    body: {
      eventId,
      groupId: session.groupId,
      keyTimestamp,
      nonce: "A".repeat(16),
      ciphertext: randomToken(),
      notificationKind,
    },
  });
  return { ...result, json: result.status === 201 ? { ...result.json, eventId } : result.json };
}

async function postTrackedEvent(
  session: JoinedSession,
  keyTimestamp: number,
  itemId: string,
  notificationKind: "notify" | "request",
  eventId = randomId(),
  ciphertext = randomToken(),
) {
  const result = await api(`/api/sessions/${session.id}/events`, {
    method: "POST",
    token: session.managerToken,
    body: {
      eventId,
      itemId,
      groupId: session.groupId,
      keyTimestamp,
      nonce: "A".repeat(16),
      ciphertext,
      notificationKind,
    },
  });
  return { ...result, eventId, ciphertext };
}

async function postTrackedResponse(
  session: JoinedSession,
  device: Device,
  keyTimestamp: number,
  itemId: string,
) {
  return api(`/api/sessions/${session.id}/responses`, {
    method: "POST",
    token: device.token,
    body: {
      responseId: randomId(),
      itemId,
      groupId: session.groupId,
      deviceId: device.id,
      keyTimestamp,
      nonce: "A".repeat(16),
      ciphertext: randomToken(),
    },
  });
}

async function events(session: JoinedSession, device: Device) {
  return api(
    `/api/sessions/${session.id}/events?groupId=${session.groupId}&deviceId=${device.id}&after=0`,
    { token: device.token },
  );
}

async function setAttention(session: JoinedSession, device: Device, attention: boolean) {
  return api(`/api/sessions/${session.id}/attention`, {
    method: "PUT",
    token: device.token,
    body: { groupId: session.groupId, deviceId: device.id, attention },
  });
}

async function attentionEvents(session: JoinedSession, device: Device) {
  return api(
    `/api/sessions/${session.id}/events?groupId=${session.groupId}&deviceId=${device.id}&after=0&includeAttention=1`,
    { token: device.token },
  );
}

async function trackedEvents(session: JoinedSession, device: Device) {
  return api(
    `/api/sessions/${session.id}/events?groupId=${session.groupId}&deviceId=${device.id}&after=0&includeActive=1`,
    { token: device.token },
  );
}

async function groupState(groupId: string, device: Device) {
  const result = await api(`/api/groups/${groupId}/state?deviceId=${device.id}`, { token: device.token });
  expect(result.status).toBe(200);
  return result.json;
}

async function groupKey(): Promise<{ publicKey: string }> {
  const key = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  return { publicKey: await publicKey(key) };
}

function keyPackage(deviceId: string) {
  return {
    deviceId,
    ephemeralPublicKey: "A".repeat(87),
    nonce: "A".repeat(16),
    ciphertext: randomToken(),
  };
}

function groupKeyTranscript(
  groupId: string,
  actorDeviceId: string,
  keyPublicKey: string,
  recreated: boolean,
  members: string[],
  packages: ReturnType<typeof keyPackage>[],
): string {
  const sortedMembers = [...members].sort();
  const packagesByDevice = new Map(packages.map((item) => [item.deviceId, item]));
  const lines = [
    "notify.guru/group-key-register/v1",
    groupId,
    actorDeviceId,
    keyPublicKey,
    recreated ? "1" : "0",
    String(sortedMembers.length),
    ...sortedMembers,
    String(packages.length),
  ];
  for (const deviceId of sortedMembers) {
    const item = packagesByDevice.get(deviceId);
    if (item === undefined) throw new Error("Test key package set is incomplete");
    lines.push(item.deviceId, item.ephemeralPublicKey, item.nonce, item.ciphertext);
  }
  return lines.join("\n");
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

async function api(
  path: string,
  options: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> } = {},
) {
  const headers = new Headers(options.headers);
  if (options.token !== undefined) headers.set("authorization", `Bearer ${options.token}`);
  if (options.body !== undefined) headers.set("content-type", "application/json");
  const response = await SELF.fetch(`https://notify.guru${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  return {
    status: response.status,
    json: response.status === 204 ? undefined : await response.json<Record<string, any>>(),
  };
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function encode(value: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function randomId(): string {
  return crypto.randomUUID().replaceAll("-", "_");
}

function randomToken(): string {
  return randomId() + randomId();
}
