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
    const { group, key } = await createV4Group(device);
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

  it("pauses v4 events after self-removal until a remaining device signs a fresh key", async () => {
    const first = await newDevice();
    const second = await newDevice();
    const initial = await createV4Group(first);
    const session = await createJoinedSession(initial.group, first, initial.key, 4);
    const request = await createV4DeviceRequest(second);
    const addition = await createSignedV4Transition(
      initial.group.id, first, initial.transition, [first, second],
      initial.continuityKey, false,
    );
    const approved = await api(
      `/api/groups/${initial.group.id}/device-requests/${request.id}/approve?deviceId=${first.id}`,
      {
        method: "POST", token: first.token,
        body: { transition: addition.transition, packages: addition.packages, approvalProof: randomToken() },
      },
    );
    expect(approved.status).toBe(200);
    const removedActorSession = await createJoinedSession(initial.group, second, {
      timestamp: addition.transition.timestamp,
      publicKey: addition.transition.publicKey,
      transitionHash: addition.transition.transitionHash,
      continuityKey: addition.continuityKey,
    }, 4);

    const invalidMarker = await createSignedV4Transition(
      initial.group.id, second, addition.transition, [first], addition.continuityKey, false,
    );
    const rejected = await api(`/api/groups/${initial.group.id}/devices/${second.id}?deviceId=${second.id}`, {
      method: "DELETE", token: second.token,
      body: { transition: invalidMarker.transition, packages: invalidMarker.packages },
    });
    expect(rejected.status).toBe(400);
    expect(rejected.json.error).toBe("invalid_self_removal");

    const marker = await createSignedV4Transition(
      initial.group.id, second, addition.transition, [first],
      addition.continuityKey, false, addition.continuityKey,
    );
    const removed = await api(`/api/groups/${initial.group.id}/devices/${second.id}?deviceId=${second.id}`, {
      method: "DELETE", token: second.token,
      body: { transition: marker.transition, packages: marker.packages },
    });
    expect(removed).toEqual({
      status: 200,
      json: { removed: true, transitionHash: marker.transition.transitionHash },
    });
    const paused = await postEvent(session, marker.transition.timestamp);
    expect(paused.status).toBe(409);
    expect(paused.json.error).toBe("group_key_unavailable");

    const recovery = await createSignedV4Transition(
      initial.group.id, first, marker.transition, [first], addition.continuityKey, true,
    );
    const recovered = await api(`/api/groups/${initial.group.id}/keys?deviceId=${first.id}`, {
      method: "POST", token: first.token,
      body: { transition: recovery.transition, packages: recovery.packages },
    });
    expect(recovered).toEqual({
      status: 201,
      json: { timestamp: recovery.transition.timestamp, transitionHash: recovery.transition.transitionHash },
    });
    const recoveredState = await api(
      `/api/groups/${initial.group.id}/state?deviceId=${first.id}&protocolVersion=4`,
      { token: first.token },
    );
    expect(recoveredState.status).toBe(200);
    expect(recoveredState.json.sessions.map((item: { sessionId: string }) => item.sessionId)).toEqual([session.id]);
    expect(recoveredState.json.sessions).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ sessionId: removedActorSession.id }),
    ]));
    expect((await postEvent(session, recovery.transition.timestamp)).status).toBe(201);
    const responseAt = (keyTimestamp: number) => api(`/api/sessions/${session.id}/responses`, {
      method: "POST", token: first.token,
      body: {
        responseId: randomId(), groupId: initial.group.id, deviceId: first.id, keyTimestamp,
        nonce: "A".repeat(16), ciphertext: randomToken(),
      },
    });
    const staleResponse = await responseAt(addition.transition.timestamp);
    expect(staleResponse.status).toBe(403);
    expect(staleResponse.json.error).toBe("key_not_available");
    expect((await responseAt(recovery.transition.timestamp)).status).toBe(201);
    expect((await api(`/api/groups/${initial.group.id}/state?deviceId=${second.id}&protocolVersion=4`, {
      token: second.token,
    })).status).toBe(403);
  });

  it("does not leave a claim behind when a version 3 device is rejected from a version 4 session group", async () => {
    const first = await newDevice();
    const second = await newDevice();
    const { group, key } = await createV4Group(first);
    await createJoinedSession(group, first, key, 4);
    const request = await createDeviceRequest(second);
    const packageValue = keyPackage(second.id);
    const rejected = await api(
      `/api/groups/${group.id}/device-requests/${request.id}/approve?deviceId=${first.id}`,
      {
        method: "POST", token: first.token, body: {
          transition: {
            transitionId: randomId(), previousHash: key.transitionHash, transitionHash: "a".repeat(64),
            timestamp: key.timestamp + 1, actorDeviceId: first.id, publicKey: key.publicKey, recreated: false,
            members: [{ deviceId: second.id, signingPublicKey: "A".repeat(87), encryptionPublicKey: second.encryptionPublicKey }],
            packageDigests: [{ deviceId: second.id, sha256: "b".repeat(64) }],
            actorSignature: randomToken(), continuitySignature: randomToken(),
          },
          packages: [packageValue], approvalProof: randomToken(),
        },
      },
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

  it("returns only sessions that a newly added device can authenticate", async () => {
    const device = await newDevice();
    const { group, key } = await createV4Group(device);
    const legacy = await createJoinedSession(group, device, key, 3);
    const current = await createJoinedSession(group, device, key, 4);

    const legacyState = await api(`/api/groups/${group.id}/state?deviceId=${device.id}`, {
      token: device.token,
    });
    expect(legacyState.status).toBe(200);
    expect(legacyState.json.sessions.map((session: { sessionId: string }) => session.sessionId)).toEqual([
      legacy.id,
    ]);

    const currentState = await api(
      `/api/groups/${group.id}/state?deviceId=${device.id}&protocolVersion=4`,
      { token: device.token },
    );
    expect(currentState.status).toBe(200);
    expect(currentState.json.sessions).toEqual([
      expect.objectContaining({ sessionId: current.id, groupId: group.id, protocolVersion: 4 }),
    ]);
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
  signingPublicKey: string;
  encryptionPublicKey: string;
}

interface Group {
  id: string;
}

interface RegisteredKey {
  timestamp: number;
  publicKey: string;
  transitionHash?: string;
  continuityKey?: CryptoKeyPair;
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
    signingPublicKey,
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

async function createV4Group(device: Device) {
  const id = randomId();
  const accessHash = await hash(device.token);
  const groupSigningKey = await generateSigningKey();
  const groupPublicKey = await publicKey(groupSigningKey);
  const packageValue = keyPackage(device.id);
  const transition = {
    transitionId: randomId(), previousHash: "0".repeat(64), timestamp: Date.now(),
    actorDeviceId: device.id, publicKey: groupPublicKey, recreated: true,
    members: [{
      deviceId: device.id, signingPublicKey: device.signingPublicKey,
      encryptionPublicKey: device.encryptionPublicKey,
    }],
    packageDigests: [{ deviceId: device.id, sha256: await keyPackageDigest(packageValue) }],
  };
  const transitionTranscript = groupTransitionTranscript(id, transition);
  const actorSignature = await sign(device.signingKey, transitionTranscript);
  const continuitySignature = await sign(groupSigningKey, transitionTranscript);
  const transitionHash = await hash(["notify.guru/group-transition-hash/v2", transitionTranscript].join("\n"));
  const signedTransition = { ...transition, actorSignature, continuitySignature, transitionHash };
  const transcript = [
    "notify.guru/group-create/v2", id, device.id, accessHash, device.encryptionPublicKey,
  ].join("\n");
  const created = await api("/api/groups", {
    method: "POST",
    body: {
      groupId: id, deviceId: device.id, deviceAccessTokenHash: accessHash,
      deviceEncryptionPublicKey: device.encryptionPublicKey,
      deviceSignature: await sign(device.signingKey, transcript), protocolVersion: 4,
      transition: signedTransition, packages: [packageValue],
    },
  });
  expect(created).toEqual({ status: 201, json: { created: true, groupId: id } });
  return {
    group: { id },
    key: { timestamp: transition.timestamp, publicKey: groupPublicKey, transitionHash, continuityKey: groupSigningKey },
    transition: signedTransition,
    continuityKey: groupSigningKey,
  };
}

async function createV4DeviceRequest(device: Device): Promise<{ id: string }> {
  const id = randomId();
  const accessHash = await hash(device.token);
  const transcript = [
    "notify.guru/device-request/v2", id, device.id, accessHash,
    device.encryptionPublicKey, "3,4",
  ].join("\n");
  const created = await api("/api/device-requests", {
    method: "POST",
    body: {
      requestId: id, deviceId: device.id, deviceAccessTokenHash: accessHash,
      deviceEncryptionPublicKey: device.encryptionPublicKey,
      deviceSignature: await sign(device.signingKey, transcript), protocolVersion: 4,
    },
  });
  expect(created.status).toBe(201);
  expect(created.json.requestHash).toMatch(/^[a-f0-9]{64}$/);
  return { id };
}

async function createSignedV4Transition(
  groupId: string,
  actor: Device,
  previous: any,
  members: Device[],
  previousContinuityKey: CryptoKeyPair,
  recreated: boolean,
  nextContinuityKey?: CryptoKeyPair,
) {
  const continuityKey = nextContinuityKey ?? await generateSigningKey();
  const packages = members.map((member) => keyPackage(member.id));
  const transition = {
    transitionId: randomId(), previousHash: previous.transitionHash,
    timestamp: previous.timestamp + 1, actorDeviceId: actor.id,
    publicKey: await publicKey(continuityKey), recreated,
    members: members.map((member) => ({
      deviceId: member.id, signingPublicKey: member.signingPublicKey,
      encryptionPublicKey: member.encryptionPublicKey,
    })),
    packageDigests: await Promise.all(packages.map(async (item) => ({
      deviceId: item.deviceId, sha256: await keyPackageDigest(item),
    }))),
  };
  const transcript = groupTransitionTranscript(groupId, transition);
  const actorSignature = await sign(actor.signingKey, transcript);
  const continuitySignature = await sign(previousContinuityKey, transcript);
  const transitionHash = await hash(["notify.guru/group-transition-hash/v2", transcript].join("\n"));
  return {
    transition: { ...transition, actorSignature, continuitySignature, transitionHash },
    packages,
    continuityKey,
  };
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
    expect(key.continuityKey).toBeDefined();
    expect((await api(`/api/groups/${group.id}/state?deviceId=${device.id}&protocolVersion=4`, {
      token: device.token,
    })).status).toBe(200);
  }
  const descriptorTranscript = [
    "notify.guru/session-descriptor/v1", sessionId, group.id, "4", key.publicKey,
    String(key.timestamp), key.transitionHash, device.id,
  ].join("\n");
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
      ...(protocolVersion === 4 ? {
        transitionHash: key.transitionHash,
        sessionDescriptor: {
          sessionId, groupId: group.id, protocolVersion: 4, creatorPublicKey: key.publicKey,
          keyTimestamp: key.timestamp, transitionHash: key.transitionHash, actorDeviceId: device.id,
          actorSignature: await sign(device.signingKey, descriptorTranscript),
          continuitySignature: await sign(key.continuityKey!, descriptorTranscript),
        },
      } : {}),
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

async function keyPackageDigest(value: ReturnType<typeof keyPackage>): Promise<string> {
  return hash([
    "notify.guru/group-key-package/v1", value.deviceId, value.ephemeralPublicKey,
    value.nonce, value.ciphertext,
  ].join("\n"));
}

function groupTransitionTranscript(
  groupId: string,
  transition: {
    transitionId: string; previousHash: string; timestamp: number; actorDeviceId: string;
    publicKey: string; recreated: boolean;
    members: Array<{ deviceId: string; signingPublicKey: string; encryptionPublicKey: string }>;
    packageDigests: Array<{ deviceId: string; sha256: string }>;
  },
): string {
  const members = [...transition.members].sort((a, b) => a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0);
  const digests = [...transition.packageDigests].sort((a, b) => a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0);
  const lines = [
    "notify.guru/group-transition/v1", groupId, transition.transitionId, transition.previousHash,
    String(transition.timestamp), transition.actorDeviceId, transition.publicKey,
    transition.recreated ? "1" : "0", String(members.length),
  ];
  for (const member of members) lines.push(member.deviceId, member.signingPublicKey, member.encryptionPublicKey);
  lines.push(String(digests.length));
  for (const digest of digests) lines.push(digest.deviceId, digest.sha256);
  return lines.join("\n");
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
