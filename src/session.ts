import { DurableObject } from "cloudflare:workers";
import type { DeviceRegistry, DevicePushTarget } from "./device";
import type { DeviceGroup, GroupCurrentState } from "./group";
import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  SHA256_HEX,
  bearerToken,
  booleanField,
  equalHex,
  expectKeys,
  integerField,
  integerQuery,
  json,
  readObject,
  sha256Hex,
  stringField,
} from "./http";
import { APNsClient, APNsTransportError, type APNsAlertKind, type APNsEnvironment } from "./apns";
import {
  randomIdentifier,
  validateP256KeyAgreementPublicKey,
  type SignedSessionDescriptor,
} from "./protocol";

const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const INITIALIZED_KEY = "initialized";
const MAX_PUSH_ATTEMPTS = 8;
const PUSH_RETRY_BASE_MS = 30_000;
const PUSH_RETRY_CAP_MS = 30 * 60 * 1000;
const PUSH_ALARM_FALLBACK_MS = 15 * 60 * 1000;
const NOTIFICATION_KIND = /^(none|status|notify|request)$/;
const ATTACHMENT_MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024;
const ATTACHMENT_UPLOAD_LIFETIME_MS = 10 * 60 * 1000;

type ItemKind = "notify" | "request";

interface SessionEnv {
  GROUPS: DurableObjectNamespace<DeviceGroup>;
  DEVICES: DurableObjectNamespace<DeviceRegistry>;
  ATTACHMENTS: R2Bucket;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  APNS_PRIVATE_KEY?: string;
}

interface MetaRow extends Record<string, SqlStorageValue> {
  session_id: string;
  manager_hash: string;
  creator_public_key: string;
  expires_at: number;
  protocol_version: number;
}

interface AttachmentRow extends Record<string, SqlStorageValue> {
  attachment_id: string;
  response_id: string;
  group_id: string;
  device_id: string;
  key_timestamp: number;
  object_key: string;
  upload_token_hash: string;
  ciphertext_length: number;
  ciphertext_sha256: string;
  state: "reserved" | "uploaded" | "committed";
  upload_expires_at: number;
}

interface GroupRow extends Record<string, SqlStorageValue> {
  sequence: number;
  id: string;
  pairing_id: string;
  initial_key_timestamp: number;
  initial_public_key: string;
  initial_transition_hash: string | null;
  join_proof: string;
  joined_at: number;
}

interface EventRow extends Record<string, SqlStorageValue> {
  sequence: number;
  event_id: string;
  item_id: string | null;
  group_id: string;
  key_timestamp: number;
  nonce: string;
  ciphertext: string;
  created_at: number;
}

interface ItemRow extends Record<string, SqlStorageValue> {
  item_id: string;
  notification_kind: ItemKind;
  invalidated_at: number | null;
}

interface ResponseRow extends Record<string, SqlStorageValue> {
  sequence: number;
  response_id: string;
  item_id: string | null;
  group_id: string;
  key_timestamp: number;
  nonce: string;
  ciphertext: string;
  created_at: number;
  attachment_id: string | null;
}

interface PushJobRow extends Record<string, SqlStorageValue> {
  event_id: string;
  item_id: string | null;
  device_id: string;
  attempt_count: number;
  next_attempt_at: number;
  notification_kind: APNsAlertKind;
}

export class Session extends DurableObject<SessionEnv> {
  private readonly state: DurableObjectState;
  private readonly apns: APNsClient;
  private readonly groups: DurableObjectNamespace<DeviceGroup>;
  private readonly devices: DurableObjectStub<DeviceRegistry>;
  private readonly attachments: R2Bucket;

  constructor(
    state: DurableObjectState,
    env: SessionEnv,
  ) {
    super(state, env);
    this.state = state;
    this.groups = env.GROUPS;
    this.devices = env.DEVICES.get(env.DEVICES.idFromName("registry"));
    this.attachments = env.ATTACHMENTS;
    this.apns = new APNsClient({
      keyId: env.APNS_KEY_ID,
      teamId: env.APNS_TEAM_ID,
      privateKey: env.APNS_PRIVATE_KEY,
      topic: "guru.notify.app",
    });
    this.state.blockConcurrencyWhile(async () => {
      if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) === true) this.createSchema();
    });
  }

  async fetch(request: Request): Promise<Response> {
    try {
      return await this.route(request);
    } catch (error) {
      if (error instanceof HttpError) {
        return json({ error: error.code, message: error.message }, error.status);
      }
      throw error;
    }
  }

  async alarm(): Promise<void> {
    if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) !== true) return;
    const meta = this.metaRow();
    if (Date.now() >= meta.expires_at) {
      await this.expireSession(meta.session_id);
      await this.state.storage.deleteAll();
      return;
    }
    const now = Date.now();
    await this.state.storage.setAlarm(Math.min(meta.expires_at, now + PUSH_ALARM_FALLBACK_MS));
    const jobs = Array.from(this.state.storage.sql.exec<PushJobRow>(
      `SELECT p.event_id, e.item_id, p.device_id, p.attempt_count, p.next_attempt_at, p.notification_kind
       FROM push_jobs_v3 p
       JOIN session_events_v3 e ON e.event_id = p.event_id
       WHERE p.next_attempt_at <= ?
       ORDER BY p.next_attempt_at, p.event_id LIMIT 100`,
      now,
    ));
    if (jobs.length === 0) {
      await this.scheduleNextAlarm(meta.expires_at);
      return;
    }
    const targets = await this.pushTargets([...new Set(jobs.map((job) => job.device_id))]);
    const targetsByDevice = new Map(targets.map((target) => [target.deviceId, target]));
    for (const job of jobs) {
      const target = targetsByDevice.get(job.device_id);
      if (target === undefined) {
        this.deletePushJob(job);
        continue;
      }
      try {
        const result = await this.apns.send(
          target.token,
          target.environment,
          job.notification_kind,
          job.item_id === null ? undefined : target.badgeCount,
          job.notification_kind === "status" ? meta.session_id : undefined,
        );
        switch (result.outcome) {
          case "delivered":
            this.deletePushJob(job);
            break;
          case "invalid-token":
            await this.clearPush(target);
            this.state.storage.sql.exec("DELETE FROM push_jobs_v3 WHERE device_id = ?", target.deviceId);
            break;
          case "permanent-failure":
            console.warn("APNs push discarded after a permanent provider response", { reason: result.reason });
            this.deletePushJob(job);
            break;
          case "retry":
            this.retryPushJob(job, result.reason, result.minimumDelayMs);
            break;
        }
      } catch (error) {
        if (error instanceof APNsTransportError) {
          this.retryPushJob(job, "transport", 0);
          continue;
        }
        throw error;
      }
    }
    await this.scheduleNextAlarm(this.metaRow().expires_at);
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/create") return this.create(request);

    const meta = await this.activeMeta();
    if (request.method === "POST" && url.pathname === "/pairings") {
      await this.requireManager(request, meta);
      return this.addPairing(request);
    }
    if (request.method === "POST" && url.pathname === "/join") return this.join(request, meta);
    if (request.method === "GET" && url.pathname === "/joins") {
      await this.requireManager(request, meta);
      return this.joins(meta);
    }
    if (request.method === "POST" && url.pathname === "/events") {
      await this.requireManager(request, meta);
      return this.addEvent(request, meta);
    }
    if (request.method === "GET" && url.pathname === "/events") return this.events(request, url, meta);
    if (request.method === "PUT" && url.pathname === "/attention") return this.setAttention(request, meta);
    if (request.method === "POST" && url.pathname === "/attachments") return this.reserveAttachment(request, meta);
    const attachmentMatch = /^\/attachments\/([^/]+)$/.exec(url.pathname);
    if (attachmentMatch !== null) {
      const attachmentId = stringField({ attachmentId: attachmentMatch[1] }, "attachmentId", IDENTIFIER, 64);
      if (request.method === "PUT") return this.uploadAttachment(request, meta, attachmentId);
      if (request.method === "GET") {
        await this.requireManager(request, meta);
        return this.downloadAttachment(attachmentId);
      }
    }
    if (request.method === "POST" && url.pathname === "/responses") return this.addResponse(request, meta);
    if (request.method === "GET" && url.pathname === "/responses") {
      await this.requireManager(request, meta);
      return this.responses(url, meta);
    }
    if (request.method === "DELETE" && url.pathname === "/") {
      await this.requireManager(request, meta);
      const groupIds = Array.from(this.state.storage.sql.exec<{ id: string }>(
        "SELECT id FROM session_groups_v3 ORDER BY sequence",
      )).map((row) => row.id);
      await this.expireSession(meta.session_id);
      await Promise.all(groupIds.map((groupId) => this.removeGroupSession(groupId, meta.session_id)));
      await this.state.storage.deleteAll();
      return new Response(null, { status: 204 });
    }
    throw new HttpError(404, "not_found", "Endpoint not found");
  }

  private async create(request: Request): Promise<Response> {
    if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) === true) {
      throw new HttpError(409, "session_exists", "Session already exists");
    }
    const body = await readObject(request);
    expectKeys(body, ["sessionId", "managerTokenHash", "creatorPublicKey", "pairing"], ["protocolVersion"]);
    const sessionId = stringField(body, "sessionId", IDENTIFIER, 64);
    const managerHash = stringField(body, "managerTokenHash", SHA256_HEX, 64);
    const creatorPublicKey = stringField(body, "creatorPublicKey", BASE64URL, 128);
    if (!(await validateP256KeyAgreementPublicKey(creatorPublicKey))) {
      throw new HttpError(400, "invalid_public_key", "Creator public key is not a P-256 key agreement key");
    }
    const protocolVersion = body.protocolVersion === undefined ? 3 : integerField(body, "protocolVersion");
    if (protocolVersion !== 3 && protocolVersion !== 4) {
      throw new HttpError(400, "unsupported_protocol", "Protocol version is not supported");
    }
    const pairing = pairingObject(body.pairing);
    const now = Date.now();
    const expiresAt = now + SESSION_LIFETIME_MS;
    this.createSchema();
    this.state.storage.sql.exec(
      `INSERT INTO meta (singleton, session_id, manager_hash, creator_public_key, expires_at, protocol_version)
       VALUES (1, ?, ?, ?, ?, ?)`,
      sessionId,
      managerHash,
      creatorPublicKey,
      expiresAt,
      protocolVersion,
    );
    this.state.storage.sql.exec(
      "INSERT INTO pairings (id, token_hash, created_at) VALUES (?, ?, ?)",
      pairing.id,
      pairing.tokenHash,
      now,
    );
    await this.state.storage.put(INITIALIZED_KEY, true);
    await this.state.storage.setAlarm(expiresAt);
    return json({ expiresAt }, 201);
  }

  private async addPairing(request: Request): Promise<Response> {
    const pairing = pairingObject(await readObject(request));
    this.state.storage.sql.exec(
      "INSERT INTO pairings (id, token_hash, created_at) VALUES (?, ?, ?)",
      pairing.id,
      pairing.tokenHash,
      Date.now(),
    );
    return json({ created: true }, 201);
  }

  private async join(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, [
      "pairingId",
      "pairingToken",
      "groupId",
      "deviceId",
      "deviceAccessToken",
      "keyTimestamp",
      "groupPublicKey",
      "proof",
    ], ["transitionHash", "sessionDescriptor"]);
    const pairingId = stringField(body, "pairingId", IDENTIFIER, 64);
    const pairingToken = stringField(body, "pairingToken", BASE64URL, 128);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const deviceAccessToken = stringField(body, "deviceAccessToken", BASE64URL, 128);
    const keyTimestamp = integerField(body, "keyTimestamp");
    const groupPublicKey = stringField(body, "groupPublicKey", BASE64URL, 128);
    const proof = stringField(body, "proof", BASE64URL, 128);
    const transitionHash = meta.protocol_version === 4
      ? stringField(body, "transitionHash", SHA256_HEX, 64)
      : null;
    const descriptor = meta.protocol_version === 4 ? sessionDescriptor(body.sessionDescriptor) : null;
    const pairing = this.unusedPairing(pairingId);
    if (!equalHex(pairing.token_hash, await sha256Hex(pairingToken))) {
      throw new HttpError(401, "invalid_pairing_token", "Pairing token is invalid");
    }
    await this.authorizeGroupDevice(groupId, deviceId, deviceAccessToken);
    if (!(await this.groupStub(groupId).supportsProtocolVersion(meta.protocol_version))) {
      throw new HttpError(409, "protocol_upgrade_required", "Every device in the group must support this session protocol");
    }
    const current = await this.groupCurrent(groupId);
    if (current.key === null || current.key.timestamp !== keyTimestamp || current.key.publicKey !== groupPublicKey
      || meta.protocol_version === 4 && current.key.transitionHash !== transitionHash) {
      throw new HttpError(409, "group_key_changed", "Device group key has changed");
    }
    if (descriptor !== null && (descriptor.sessionId !== meta.session_id || descriptor.groupId !== groupId
      || descriptor.creatorPublicKey !== meta.creator_public_key || descriptor.protocolVersion !== 4
      || descriptor.keyTimestamp !== keyTimestamp || descriptor.transitionHash !== transitionHash
      || descriptor.actorDeviceId !== deviceId)) {
      throw new HttpError(400, "invalid_session_descriptor", "Session descriptor does not match the authenticated join");
    }
    await this.putGroupSession(groupId, meta, meta.expires_at, descriptor);
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("UPDATE pairings SET consumed_at = ? WHERE id = ?", now, pairingId);
      this.state.storage.sql.exec(
        `INSERT INTO session_groups_v3
           (id, pairing_id, initial_key_timestamp, initial_public_key, initial_transition_hash, join_proof, joined_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        groupId,
        pairingId,
        keyTimestamp,
        groupPublicKey,
        transitionHash,
        proof,
        now,
      );
    });
    return json({ joined: true, expiresAt: meta.expires_at }, 201);
  }

  private async joins(meta: MetaRow): Promise<Response> {
    const rows = Array.from(this.state.storage.sql.exec<GroupRow>(
      `SELECT sequence, id, pairing_id, initial_key_timestamp, initial_public_key, initial_transition_hash, join_proof, joined_at
       FROM session_groups_v3 ORDER BY sequence`,
    ));
    const groups = await Promise.all(rows.map(async (row) => {
      const current = await this.groupCurrent(row.id);
      const transitions = meta.protocol_version === 4
        ? (await this.groupStub(row.id).getTransitionHistory()).filter((transition) => transition.timestamp >= row.initial_key_timestamp)
        : undefined;
      return {
        sequence: row.sequence,
        groupId: row.id,
        pairingId: row.pairing_id,
        initialKeyTimestamp: row.initial_key_timestamp,
        initialPublicKey: row.initial_public_key,
        ...(row.initial_transition_hash === null ? {} : { initialTransitionHash: row.initial_transition_hash }),
        proof: row.join_proof,
        joinedAt: row.joined_at,
        key: current.key,
        ...(transitions === undefined ? {} : { transitions }),
      };
    }));
    return json({ groups, expiresAt: meta.expires_at });
  }

  private async addEvent(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    const tracked = body.itemId !== undefined;
    expectKeys(body, tracked
      ? ["eventId", "itemId", "groupId", "keyTimestamp", "nonce", "ciphertext", "notificationKind"]
      : ["eventId", "groupId", "keyTimestamp", "nonce", "ciphertext", "notificationKind"]);
    const eventId = stringField(body, "eventId", IDENTIFIER, 64);
    const itemId = tracked ? stringField(body, "itemId", IDENTIFIER, 64) : null;
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const keyTimestamp = integerField(body, "keyTimestamp");
    const nonce = stringField(body, "nonce", BASE64URL, 32);
    const ciphertext = stringField(body, "ciphertext", BASE64URL, 350_000);
    const notificationKind = stringField(body, "notificationKind", NOTIFICATION_KIND, 16);
    if (tracked && (notificationKind === "none" || notificationKind === "status")) {
      throw new HttpError(400, "invalid_field", "Status events cannot contain an item ID");
    }
    this.requireGroup(groupId);
    if (itemId !== null) {
      const existing = this.eventById(eventId);
      if (existing !== null) {
        if (
          existing.item_id !== itemId || existing.group_id !== groupId ||
          existing.key_timestamp !== keyTimestamp || existing.nonce !== nonce || existing.ciphertext !== ciphertext
        ) {
          throw new HttpError(409, "event_exists", "Event ID is already used by another event");
        }
        const item = this.requiredItem(itemId);
        if (item.notification_kind !== notificationKind) {
          throw new HttpError(409, "item_kind_changed", "Session item notification kind changed between groups");
        }
        if (item.invalidated_at === null) {
          await this.devices.activateSessionItem(
            meta.session_id,
            groupId,
            itemId,
            this.eventRecipients(eventId),
          );
        }
        await this.scheduleNextAlarm(meta.expires_at);
        return json({ expiresAt: meta.expires_at }, 201);
      }
    }
    const recipients = await this.groupKeyRecipients(groupId, keyTimestamp, meta.protocol_version);
    const now = Date.now();
    const expiresAt = now + SESSION_LIFETIME_MS;
    await this.putGroupSession(groupId, meta, expiresAt);
    const attentive = this.attentiveDevices();
    let activeItem = false;
    this.state.storage.transactionSync(() => {
      if (itemId !== null) {
        activeItem = this.ensureItem(itemId, notificationKind as ItemKind, now);
      }
      this.state.storage.sql.exec(
        `INSERT INTO session_events_v3
           (event_id, item_id, group_id, key_timestamp, nonce, ciphertext, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        eventId,
        itemId,
        groupId,
        keyTimestamp,
        nonce,
        ciphertext,
        now,
      );
      for (const deviceId of recipients) {
        this.state.storage.sql.exec(
          "INSERT INTO session_event_recipients_v3 (event_id, device_id) VALUES (?, ?)",
          eventId,
          deviceId,
        );
        if (notificationKind === "none") continue;
        if (notificationKind === "status") {
          if (!attentive.has(deviceId)) continue;
          this.deleteStatusPushJobs(deviceId);
        } else if (itemId !== null && !activeItem) {
          continue;
        }
        this.state.storage.sql.exec(
          `INSERT INTO push_jobs_v3 (event_id, device_id, attempt_count, next_attempt_at, notification_kind)
           VALUES (?, ?, 0, ?, ?)`,
          eventId,
          deviceId,
          now,
          notificationKind,
        );
      }
      this.state.storage.sql.exec("UPDATE meta SET expires_at = ? WHERE singleton = 1", expiresAt);
    });
    if (activeItem && itemId !== null) {
      await this.devices.activateSessionItem(meta.session_id, groupId, itemId, recipients);
    }
    await this.scheduleNextAlarm(expiresAt);
    return json({ expiresAt }, 201);
  }

  private async events(request: Request, url: URL, meta: MetaRow): Promise<Response> {
    const groupId = queryIdentifier(url, "groupId");
    const deviceId = queryIdentifier(url, "deviceId");
    this.requireGroup(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    const after = integerQuery(url, "after");
    const includeActive = url.searchParams.get("includeActive") === "1";
    const includeAttention = url.searchParams.get("includeAttention") === "1";
    const events = Array.from(this.state.storage.sql.exec<EventRow>(
      `SELECT e.sequence, e.event_id, e.item_id, e.group_id, e.key_timestamp, e.nonce, e.ciphertext, e.created_at
       FROM session_events_v3 e
       JOIN session_event_recipients_v3 r ON r.event_id = e.event_id
       WHERE e.group_id = ? AND r.device_id = ? AND e.sequence > ?
       ORDER BY e.sequence LIMIT 100`,
      groupId,
      deviceId,
      after,
    )).map((row) => ({
      sequence: row.sequence,
      eventId: row.event_id,
      ...(includeActive ? { itemId: row.item_id } : {}),
      groupId: row.group_id,
      keyTimestamp: row.key_timestamp,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
    }));
    const result: Record<string, unknown> = { events };
    if (includeActive) {
      result.activeItemIds = Array.from(this.state.storage.sql.exec<{ item_id: string }>(
        `SELECT DISTINCT i.item_id
         FROM session_items_v1 i
         JOIN session_events_v3 e ON e.item_id = i.item_id
         JOIN session_event_recipients_v3 r ON r.event_id = e.event_id
         WHERE e.group_id = ? AND r.device_id = ? AND i.invalidated_at IS NULL
         ORDER BY i.item_id`,
        groupId,
        deviceId,
      )).map((row) => row.item_id);
    }
    if (includeAttention) result.attention = this.attentiveDevices().has(deviceId);
    result.expiresAt = meta.expires_at;
    return json(result);
  }

  // Attention is a per-device choice: a status alert on one phone says nothing
  // about whether the Mac in the same group wants to hear every step too.
  private async setAttention(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["groupId", "deviceId", "attention"]);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const attention = booleanField(body, "attention");
    this.requireGroup(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    if (attention) {
      this.state.storage.sql.exec(
        `INSERT INTO session_attention_v1 (device_id, created_at) VALUES (?, ?)
         ON CONFLICT(device_id) DO NOTHING`,
        deviceId,
        Date.now(),
      );
      return json({ attention, expiresAt: meta.expires_at });
    }
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("DELETE FROM session_attention_v1 WHERE device_id = ?", deviceId);
      this.deleteStatusPushJobs(deviceId);
    });
    await this.scheduleNextAlarm(meta.expires_at);
    return json({ attention, expiresAt: meta.expires_at });
  }

  private async reserveAttachment(request: Request, meta: MetaRow): Promise<Response> {
    this.requireV4(meta);
    const body = await readObject(request);
    expectKeys(body, [
      "attachmentId",
      "responseId",
      "groupId",
      "deviceId",
      "keyTimestamp",
      "ciphertextLength",
      "ciphertextSha256",
    ]);
    const attachmentId = stringField(body, "attachmentId", IDENTIFIER, 64);
    const responseId = stringField(body, "responseId", IDENTIFIER, 64);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const keyTimestamp = integerField(body, "keyTimestamp");
    const ciphertextLength = integerField(body, "ciphertextLength");
    const ciphertextSha256 = stringField(body, "ciphertextSha256", SHA256_HEX, 64);
    if (ciphertextLength === 0 || ciphertextLength > ATTACHMENT_MAX_CIPHERTEXT_BYTES) {
      throw new HttpError(413, "attachment_too_large", "Attachment ciphertext exceeds the current service limit");
    }
    this.requireGroup(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    await this.groupKeyDevice(groupId, keyTimestamp, deviceId);
    if (this.responseExists(responseId)) {
      throw new HttpError(409, "response_exists", "Response already exists");
    }

    const uploadToken = randomIdentifier();
    const uploadTokenHash = await sha256Hex(uploadToken);
    const uploadExpiresAt = Math.min(meta.expires_at, Date.now() + ATTACHMENT_UPLOAD_LIFETIME_MS);
    const existing = this.attachment(attachmentId) ?? this.attachmentByResponse(responseId);
    if (existing !== null) {
      if (
        existing.attachment_id !== attachmentId || existing.response_id !== responseId ||
        existing.group_id !== groupId || existing.device_id !== deviceId ||
        existing.key_timestamp !== keyTimestamp || existing.ciphertext_length !== ciphertextLength ||
        existing.ciphertext_sha256 !== ciphertextSha256 || existing.state !== "reserved"
      ) {
        throw new HttpError(409, "attachment_exists", "Attachment or response ID is already reserved");
      }
      this.state.storage.sql.exec(
        `UPDATE session_attachments_v4
         SET upload_token_hash = ?, upload_expires_at = ? WHERE attachment_id = ?`,
        uploadTokenHash,
        uploadExpiresAt,
        attachmentId,
      );
    } else {
      this.state.storage.sql.exec(
        `INSERT INTO session_attachments_v4
           (attachment_id, response_id, group_id, device_id, key_timestamp, object_key,
            upload_token_hash, ciphertext_length, ciphertext_sha256, state, upload_expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)`,
        attachmentId,
        responseId,
        groupId,
        deviceId,
        keyTimestamp,
        `v4/${randomIdentifier()}`,
        uploadTokenHash,
        ciphertextLength,
        ciphertextSha256,
        uploadExpiresAt,
        Date.now(),
      );
    }
    return json({ attachmentId, uploadToken, maxCiphertextBytes: ATTACHMENT_MAX_CIPHERTEXT_BYTES, uploadExpiresAt }, 201);
  }

  private async uploadAttachment(request: Request, meta: MetaRow, attachmentId: string): Promise<Response> {
    this.requireV4(meta);
    const row = this.requiredAttachment(attachmentId);
    const tokenHash = await sha256Hex(bearerToken(request));
    if (!equalHex(row.upload_token_hash, tokenHash)) {
      throw new HttpError(401, "invalid_upload_token", "Attachment upload token is invalid");
    }
    if (row.state !== "reserved") return json({ uploaded: true });
    if (Date.now() >= row.upload_expires_at) {
      throw new HttpError(410, "upload_expired", "Attachment upload reservation has expired");
    }
    if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/octet-stream") {
      throw new HttpError(415, "invalid_content_type", "Content-Type must be application/octet-stream");
    }
    const declaredLength = request.headers.get("content-length");
    if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) !== row.ciphertext_length)) {
      throw new HttpError(400, "attachment_length_mismatch", "Attachment ciphertext length does not match its reservation");
    }
    const ciphertext = await request.arrayBuffer();
    if (ciphertext.byteLength !== row.ciphertext_length || ciphertext.byteLength > ATTACHMENT_MAX_CIPHERTEXT_BYTES) {
      throw new HttpError(400, "attachment_length_mismatch", "Attachment ciphertext length does not match its reservation");
    }
    const digest = await sha256BytesHex(ciphertext);
    if (!equalHex(digest, row.ciphertext_sha256)) {
      throw new HttpError(400, "attachment_checksum_mismatch", "Attachment ciphertext checksum does not match its reservation");
    }
    await this.attachments.put(row.object_key, ciphertext, {
      httpMetadata: { contentType: "application/octet-stream" },
      sha256: row.ciphertext_sha256,
    });
    this.state.storage.sql.exec(
      "UPDATE session_attachments_v4 SET state = 'uploaded' WHERE attachment_id = ?",
      attachmentId,
    );
    return json({ uploaded: true });
  }

  private async downloadAttachment(attachmentId: string): Promise<Response> {
    const row = this.requiredAttachment(attachmentId);
    if (row.state !== "committed") {
      throw new HttpError(409, "attachment_not_committed", "Attachment is not attached to a response");
    }
    const object = await this.attachments.get(row.object_key);
    if (object === null) throw new HttpError(404, "attachment_not_found", "Attachment ciphertext was not found");
    if (object.size !== row.ciphertext_length) {
      throw new HttpError(500, "attachment_corrupt", "Stored attachment ciphertext has an unexpected length");
    }
    return new Response(object.body, {
      headers: {
        "cache-control": "no-store",
        "content-type": "application/octet-stream",
        "content-length": String(row.ciphertext_length),
        "x-content-type-options": "nosniff",
      },
    });
  }

  private async addResponse(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    const tracked = body.itemId !== undefined;
    const hasAttachment = body.attachmentId !== undefined;
    expectKeys(body, ["responseId", "groupId", "deviceId", "keyTimestamp", "nonce", "ciphertext"], ["itemId", "attachmentId"]);
    const responseId = stringField(body, "responseId", IDENTIFIER, 64);
    const itemId = tracked ? stringField(body, "itemId", IDENTIFIER, 64) : null;
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const keyTimestamp = integerField(body, "keyTimestamp");
    const nonce = stringField(body, "nonce", BASE64URL, 32);
    const ciphertext = stringField(body, "ciphertext", BASE64URL, 350_000);
    const attachmentId = hasAttachment ? stringField(body, "attachmentId", IDENTIFIER, 64) : null;
    if (hasAttachment) this.requireV4(meta);
    this.requireGroup(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    await this.groupKeyDevice(groupId, keyTimestamp, deviceId);
    if (this.responseExists(responseId)) {
      throw new HttpError(409, "response_exists", "Response already exists");
    }
    const attachment = attachmentId === null ? null : this.requiredAttachment(attachmentId);
    if (attachment !== null && (
      attachment.state !== "uploaded" || attachment.response_id !== responseId ||
      attachment.group_id !== groupId || attachment.device_id !== deviceId ||
      attachment.key_timestamp !== keyTimestamp
    )) {
      throw new HttpError(409, "attachment_mismatch", "Uploaded attachment does not match the response envelope");
    }
    if (itemId !== null) this.requireDeliveredItem(itemId, groupId, deviceId);
    if (itemId !== null) await this.devices.deactivateSessionItem(meta.session_id, itemId);
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(
        `INSERT INTO session_responses_v3
           (response_id, item_id, group_id, key_timestamp, nonce, ciphertext, created_at, attachment_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        responseId,
        itemId,
        groupId,
        keyTimestamp,
        nonce,
        ciphertext,
        now,
        attachmentId,
      );
      if (attachmentId !== null) {
        this.state.storage.sql.exec(
          "UPDATE session_attachments_v4 SET state = 'committed' WHERE attachment_id = ?",
          attachmentId,
        );
      }
      if (itemId !== null) {
        this.state.storage.sql.exec(
          "UPDATE session_items_v1 SET invalidated_at = COALESCE(invalidated_at, ?) WHERE item_id = ?",
          now,
          itemId,
        );
        this.state.storage.sql.exec(
          `INSERT INTO push_jobs_v3
             (event_id, device_id, attempt_count, next_attempt_at, notification_kind)
           SELECT e.event_id, r.device_id, 0, ?, 'badge'
           FROM session_events_v3 e
           JOIN session_event_recipients_v3 r ON r.event_id = e.event_id
           WHERE e.item_id = ?
           ON CONFLICT(event_id, device_id) DO UPDATE SET
             attempt_count = 0,
             next_attempt_at = excluded.next_attempt_at,
             notification_kind = 'badge'`,
          now,
          itemId,
        );
      }
    });
    if (itemId !== null) await this.scheduleNextAlarm(meta.expires_at);
    return json({ expiresAt: meta.expires_at }, 201);
  }

  private async responses(url: URL, meta: MetaRow): Promise<Response> {
    const after = integerQuery(url, "after");
    await this.releaseAcknowledgedAttachments(after);
    const responses = Array.from(this.state.storage.sql.exec<ResponseRow>(
      `SELECT sequence, response_id, item_id, group_id, key_timestamp, nonce, ciphertext, created_at, attachment_id
       FROM session_responses_v3 WHERE sequence > ? ORDER BY sequence LIMIT 100`,
      after,
    )).map((row) => ({
      sequence: row.sequence,
      responseId: row.response_id,
      itemId: row.item_id,
      groupId: row.group_id,
      keyTimestamp: row.key_timestamp,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
      ...(row.attachment_id === null ? {} : { attachmentId: row.attachment_id }),
    }));
    return json({ responses, expiresAt: meta.expires_at });
  }

  private async activeMeta(): Promise<MetaRow> {
    if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) !== true) {
      throw new HttpError(404, "session_not_found", "Session not found");
    }
    const meta = this.metaRow();
    if (Date.now() >= meta.expires_at) {
      await this.expireSession(meta.session_id);
      await this.state.storage.deleteAll();
      throw new HttpError(410, "session_expired", "Session has expired");
    }
    return meta;
  }

  private requireV4(meta: MetaRow): void {
    if (meta.protocol_version !== 4) {
      throw new HttpError(409, "protocol_mismatch", "Attachments require a protocol version 4 session");
    }
  }

  private attachment(attachmentId: string): AttachmentRow | null {
    const rows = Array.from(this.state.storage.sql.exec<AttachmentRow>(
      `SELECT attachment_id, response_id, group_id, device_id, key_timestamp, object_key,
              upload_token_hash, ciphertext_length, ciphertext_sha256, state, upload_expires_at
       FROM session_attachments_v4 WHERE attachment_id = ?`,
      attachmentId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private attachmentByResponse(responseId: string): AttachmentRow | null {
    const rows = Array.from(this.state.storage.sql.exec<AttachmentRow>(
      `SELECT attachment_id, response_id, group_id, device_id, key_timestamp, object_key,
              upload_token_hash, ciphertext_length, ciphertext_sha256, state, upload_expires_at
       FROM session_attachments_v4 WHERE response_id = ?`,
      responseId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private requiredAttachment(attachmentId: string): AttachmentRow {
    const row = this.attachment(attachmentId);
    if (row === null) throw new HttpError(404, "attachment_not_found", "Attachment was not found");
    return row;
  }

  private async releaseAcknowledgedAttachments(after: number): Promise<void> {
    if (after === 0) return;
    const rows = Array.from(this.state.storage.sql.exec<{ attachment_id: string; object_key: string }>(
      `SELECT a.attachment_id, a.object_key
       FROM session_attachments_v4 a
       JOIN session_responses_v3 r ON r.attachment_id = a.attachment_id
       WHERE a.state = 'committed' AND r.sequence <= ?`,
      after,
    ));
    if (rows.length === 0) return;
    await this.attachments.delete(rows.map((row) => row.object_key));
    this.state.storage.sql.exec(
      `DELETE FROM session_attachments_v4
       WHERE attachment_id IN (
         SELECT attachment_id FROM session_responses_v3
         WHERE attachment_id IS NOT NULL AND sequence <= ?
       )`,
      after,
    );
  }

  private metaRow(): MetaRow {
    const rows = Array.from(this.state.storage.sql.exec<MetaRow>(
      "SELECT session_id, manager_hash, creator_public_key, expires_at, protocol_version FROM meta WHERE singleton = 1",
    ));
    if (rows.length !== 1) throw new Error("Initialized session must contain exactly one meta row");
    return rows[0];
  }

  private unusedPairing(pairingId: string): { token_hash: string } {
    const rows = Array.from(this.state.storage.sql.exec<{ token_hash: string; consumed_at: number | null }>(
      "SELECT token_hash, consumed_at FROM pairings WHERE id = ?",
      pairingId,
    ));
    if (rows.length === 0) throw new HttpError(404, "pairing_not_found", "Pairing not found");
    if (rows[0].consumed_at !== null) {
      throw new HttpError(409, "pairing_consumed", "Pairing has already been consumed");
    }
    return rows[0];
  }

  private requireGroup(groupId: string): GroupRow {
    const rows = Array.from(this.state.storage.sql.exec<GroupRow>(
      `SELECT sequence, id, pairing_id, initial_key_timestamp, initial_public_key, initial_transition_hash, join_proof, joined_at
       FROM session_groups_v3 WHERE id = ?`,
      groupId,
    ));
    if (rows.length === 0) throw new HttpError(404, "group_not_found", "Device group not found");
    return rows[0];
  }

  private async requireManager(request: Request, meta: MetaRow): Promise<void> {
    if (!equalHex(meta.manager_hash, await sha256Hex(bearerToken(request)))) {
      throw new HttpError(401, "invalid_manager_token", "Manager token is invalid");
    }
  }

  private async authorizeGroupDevice(groupId: string, deviceId: string, token: string): Promise<void> {
    const result = await this.groupStub(groupId).authorizeDevice(deviceId, token);
    if (result === "device_removed") {
      throw new HttpError(403, "device_removed", "Device is not an active member of the group");
    }
    if (result === "invalid_token") {
      throw new HttpError(401, "invalid_device_token", "Device token is invalid");
    }
  }

  private async groupCurrent(groupId: string): Promise<GroupCurrentState> {
    const result = await this.groupStub(groupId).getCurrentState();
    if (result === null) throw new HttpError(404, "group_not_found", "Device group not found");
    if (result.groupId !== groupId) throw new Error("Device group returned another group ID");
    return result;
  }

  private async groupKeyRecipients(groupId: string, timestamp: number, protocolVersion = 3): Promise<string[]> {
    const result = await this.groupStub(groupId).getKeyRecipients(timestamp, protocolVersion);
    if (result.status === "unavailable") {
      throw new HttpError(409, "group_key_unavailable", "Group key is not valid for new events");
    }
    return result.deviceIds;
  }

  private async groupKeyDevice(groupId: string, timestamp: number, deviceId: string): Promise<void> {
    const meta = this.metaRow();
    const result = await this.groupStub(groupId).authorizeKeyForDevice(timestamp, deviceId, meta.protocol_version);
    if (result === "device_removed") {
      throw new HttpError(403, "device_removed", "Device is not an active member of the group");
    }
    if (result === "unavailable") {
      throw new HttpError(403, "key_not_available", "Group key was not shared with this device");
    }
  }

  private async putGroupSession(
    groupId: string, meta: MetaRow, expiresAt: number, descriptor: SignedSessionDescriptor | null = null,
  ): Promise<void> {
    await this.groupStub(groupId).storeSession(
      meta.session_id, meta.creator_public_key, expiresAt, meta.protocol_version, descriptor,
    );
  }

  private async removeGroupSession(groupId: string, sessionId: string): Promise<void> {
    await this.groupStub(groupId).removeSession(sessionId);
  }

  private groupStub(groupId: string): DurableObjectStub<DeviceGroup> {
    return this.groups.get(this.groups.idFromName(groupId));
  }

  private async pushTargets(deviceIds: string[]): Promise<DevicePushTarget[]> {
    return this.devices.getPushTargets(deviceIds);
  }

  private async clearPush(target: DevicePushTarget): Promise<void> {
    await this.devices.clearPushToken(target.deviceId, target.token);
  }

  private attentiveDevices(): Set<string> {
    return new Set(Array.from(this.state.storage.sql.exec<{ device_id: string }>(
      "SELECT device_id FROM session_attention_v1",
    )).map((row) => row.device_id));
  }

  // A status replaces the previous one, so an alert still waiting for the old
  // status has nothing left to announce.
  private deleteStatusPushJobs(deviceId: string): void {
    this.state.storage.sql.exec(
      "DELETE FROM push_jobs_v3 WHERE device_id = ? AND notification_kind = 'status'",
      deviceId,
    );
  }

  private ensureItem(itemId: string, notificationKind: ItemKind, createdAt: number): boolean {
    const rows = Array.from(this.state.storage.sql.exec<ItemRow>(
      "SELECT item_id, notification_kind, invalidated_at FROM session_items_v1 WHERE item_id = ?",
      itemId,
    ));
    if (rows.length === 0) {
      this.state.storage.sql.exec(
        `INSERT INTO session_items_v1 (item_id, notification_kind, created_at)
         VALUES (?, ?, ?)`,
        itemId,
        notificationKind,
        createdAt,
      );
      return true;
    }
    if (rows[0].notification_kind !== notificationKind) {
      throw new HttpError(409, "item_kind_changed", "Session item notification kind changed between groups");
    }
    return rows[0].invalidated_at === null;
  }

  private requireDeliveredItem(itemId: string, groupId: string, deviceId: string): void {
    const rows = Array.from(this.state.storage.sql.exec<{ item_id: string }>(
      `SELECT e.item_id
       FROM session_items_v1 i
       JOIN session_events_v3 e ON e.item_id = i.item_id
       JOIN session_event_recipients_v3 r ON r.event_id = e.event_id
       WHERE i.item_id = ? AND e.group_id = ? AND r.device_id = ?
       LIMIT 1`,
      itemId,
      groupId,
      deviceId,
    ));
    if (rows.length === 0) {
      throw new HttpError(404, "item_not_delivered", "Session item was not delivered to this device");
    }
  }

  private responseExists(responseId: string): boolean {
    const rows = Array.from(this.state.storage.sql.exec<{ found: number }>(
      "SELECT 1 AS found FROM session_responses_v3 WHERE response_id = ?",
      responseId,
    ));
    return rows.length !== 0;
  }

  private eventById(eventId: string): EventRow | null {
    const rows = Array.from(this.state.storage.sql.exec<EventRow>(
      `SELECT sequence, event_id, item_id, group_id, key_timestamp, nonce, ciphertext, created_at
       FROM session_events_v3 WHERE event_id = ?`,
      eventId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private eventRecipients(eventId: string): string[] {
    return Array.from(this.state.storage.sql.exec<{ device_id: string }>(
      "SELECT device_id FROM session_event_recipients_v3 WHERE event_id = ? ORDER BY device_id",
      eventId,
    )).map((row) => row.device_id);
  }

  private requiredItem(itemId: string): ItemRow {
    const rows = Array.from(this.state.storage.sql.exec<ItemRow>(
      "SELECT item_id, notification_kind, invalidated_at FROM session_items_v1 WHERE item_id = ?",
      itemId,
    ));
    if (rows.length !== 1) throw new Error("Tracked event must have exactly one session item");
    return rows[0];
  }

  private async expireSession(sessionId: string): Promise<void> {
    await this.devices.deactivateSession(sessionId);
    const objectKeys = Array.from(this.state.storage.sql.exec<{ object_key: string }>(
      "SELECT object_key FROM session_attachments_v4",
    )).map((row) => row.object_key);
    if (objectKeys.length > 0) await this.attachments.delete(objectKeys);
  }

  private createSchema(): void {
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        session_id TEXT NOT NULL,
        manager_hash TEXT NOT NULL,
        creator_public_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        protocol_version INTEGER NOT NULL DEFAULT 3 CHECK (protocol_version IN (3, 4))
      );
      CREATE TABLE IF NOT EXISTS pairings (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        consumed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS session_groups_v3 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(id),
        initial_key_timestamp INTEGER NOT NULL,
        initial_public_key TEXT NOT NULL,
        initial_transition_hash TEXT,
        join_proof TEXT NOT NULL,
        joined_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS session_events_v3 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        item_id TEXT,
        group_id TEXT NOT NULL REFERENCES session_groups_v3(id),
        key_timestamp INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS session_event_recipients_v3 (
        event_id TEXT NOT NULL REFERENCES session_events_v3(event_id),
        device_id TEXT NOT NULL,
        PRIMARY KEY (event_id, device_id)
      );
      CREATE TABLE IF NOT EXISTS session_responses_v3 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        response_id TEXT NOT NULL UNIQUE,
        item_id TEXT,
        group_id TEXT NOT NULL REFERENCES session_groups_v3(id),
        key_timestamp INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        attachment_id TEXT
      );
      CREATE TABLE IF NOT EXISTS session_attachments_v4 (
        attachment_id TEXT PRIMARY KEY,
        response_id TEXT NOT NULL UNIQUE,
        group_id TEXT NOT NULL REFERENCES session_groups_v3(id),
        device_id TEXT NOT NULL,
        key_timestamp INTEGER NOT NULL,
        object_key TEXT NOT NULL UNIQUE,
        upload_token_hash TEXT NOT NULL,
        ciphertext_length INTEGER NOT NULL,
        ciphertext_sha256 TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('reserved', 'uploaded', 'committed')),
        upload_expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS push_jobs_v3 (
        event_id TEXT NOT NULL REFERENCES session_events_v3(event_id),
        device_id TEXT NOT NULL,
        attempt_count INTEGER NOT NULL,
        next_attempt_at INTEGER NOT NULL,
        notification_kind TEXT NOT NULL DEFAULT 'notify',
        PRIMARY KEY (event_id, device_id)
      );
      CREATE INDEX IF NOT EXISTS push_jobs_v3_due
        ON push_jobs_v3(next_attempt_at, event_id);
      CREATE TABLE IF NOT EXISTS session_items_v1 (
        item_id TEXT PRIMARY KEY,
        notification_kind TEXT NOT NULL CHECK (notification_kind IN ('notify', 'request')),
        created_at INTEGER NOT NULL,
        invalidated_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS session_attention_v1 (
        device_id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
      );
    `);
    const groupColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(session_groups_v3)"));
    if (!groupColumns.some((column) => column.name === "initial_transition_hash")) {
      this.state.storage.sql.exec("ALTER TABLE session_groups_v3 ADD COLUMN initial_transition_hash TEXT");
    }
    const eventColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(session_events_v3)"));
    if (!eventColumns.some((column) => column.name === "item_id")) {
      this.state.storage.sql.exec("ALTER TABLE session_events_v3 ADD COLUMN item_id TEXT");
    }
    this.state.storage.sql.exec(
      `CREATE UNIQUE INDEX IF NOT EXISTS session_events_v3_group_item
       ON session_events_v3(group_id, item_id) WHERE item_id IS NOT NULL`,
    );
    const responseColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(session_responses_v3)"));
    if (!responseColumns.some((column) => column.name === "item_id")) {
      this.state.storage.sql.exec("ALTER TABLE session_responses_v3 ADD COLUMN item_id TEXT");
    }
    if (!responseColumns.some((column) => column.name === "attachment_id")) {
      this.state.storage.sql.exec("ALTER TABLE session_responses_v3 ADD COLUMN attachment_id TEXT");
    }
    const metaColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(meta)"));
    if (!metaColumns.some((column) => column.name === "protocol_version")) {
      this.state.storage.sql.exec("ALTER TABLE meta ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 3");
    }
    const pushColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(push_jobs_v3)"));
    if (!pushColumns.some((column) => column.name === "notification_kind")) {
      this.state.storage.sql.exec("ALTER TABLE push_jobs_v3 ADD COLUMN notification_kind TEXT NOT NULL DEFAULT 'notify'");
    }
  }

  private deletePushJob(job: PushJobRow): void {
    this.state.storage.sql.exec(
      "DELETE FROM push_jobs_v3 WHERE event_id = ? AND device_id = ?",
      job.event_id,
      job.device_id,
    );
  }

  private retryPushJob(job: PushJobRow, reason: string, minimumDelayMs: number): void {
    const attempt = job.attempt_count + 1;
    if (attempt >= MAX_PUSH_ATTEMPTS) {
      console.warn("APNs push discarded after exhausting retries", { reason, attempts: attempt });
      this.deletePushJob(job);
      return;
    }
    this.state.storage.sql.exec(
      `UPDATE push_jobs_v3 SET attempt_count = ?, next_attempt_at = ?
       WHERE event_id = ? AND device_id = ?`,
      attempt,
      Date.now() + pushRetryDelay(attempt, minimumDelayMs),
      job.event_id,
      job.device_id,
    );
  }

  private async scheduleNextAlarm(expiresAt: number): Promise<void> {
    const rows = Array.from(this.state.storage.sql.exec<{ count: number; next_attempt_at: number | null }>(
      "SELECT COUNT(*) AS count, MIN(next_attempt_at) AS next_attempt_at FROM push_jobs_v3",
    ));
    if (rows.length !== 1) throw new Error("Push queue aggregate must return exactly one row");
    if (rows[0].count === 0) {
      await this.state.storage.setAlarm(expiresAt);
      return;
    }
    if (rows[0].next_attempt_at === null) {
      throw new Error("Non-empty push queue must have a next attempt time");
    }
    await this.state.storage.setAlarm(
      Math.min(expiresAt, Math.max(Date.now() + 1_000, rows[0].next_attempt_at)),
    );
  }
}

function pairingObject(value: unknown): { id: string; tokenHash: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_field", "Invalid pairing object");
  }
  const pairing = value as Record<string, unknown>;
  expectKeys(pairing, ["id", "tokenHash"]);
  return {
    id: stringField(pairing, "id", IDENTIFIER, 64),
    tokenHash: stringField(pairing, "tokenHash", SHA256_HEX, 64),
  };
}

function sessionDescriptor(value: unknown): SignedSessionDescriptor {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_session_descriptor", "Version 4 join requires a signed session descriptor");
  }
  const object = value as Record<string, unknown>;
  expectKeys(object, [
    "sessionId", "groupId", "protocolVersion", "creatorPublicKey", "keyTimestamp", "transitionHash",
    "actorDeviceId", "actorSignature", "continuitySignature",
  ]);
  const protocolVersion = integerField(object, "protocolVersion");
  if (protocolVersion !== 4) throw new HttpError(400, "invalid_session_descriptor", "Invalid session descriptor protocol");
  return {
    sessionId: stringField(object, "sessionId", IDENTIFIER, 64),
    groupId: stringField(object, "groupId", IDENTIFIER, 64),
    protocolVersion,
    creatorPublicKey: stringField(object, "creatorPublicKey", BASE64URL, 128),
    keyTimestamp: integerField(object, "keyTimestamp"),
    transitionHash: stringField(object, "transitionHash", SHA256_HEX, 64),
    actorDeviceId: stringField(object, "actorDeviceId", IDENTIFIER, 64),
    actorSignature: stringField(object, "actorSignature", BASE64URL, 128),
    continuitySignature: stringField(object, "continuitySignature", BASE64URL, 128),
  };
}

function queryIdentifier(url: URL, name: string): string {
  return stringField({ [name]: url.searchParams.get(name) }, name, IDENTIFIER, 64);
}

function pushRetryDelay(attempt: number, minimumDelayMs: number): number {
  const exponential = Math.min(PUSH_RETRY_BASE_MS * 2 ** (attempt - 1), PUSH_RETRY_CAP_MS);
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  const jittered = exponential * (0.5 + random[0] / 2 ** 32);
  return minimumDelayMs + Math.floor(jittered);
}

async function sha256BytesHex(value: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
