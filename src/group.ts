import { DurableObject } from "cloudflare:workers";
import type { DeviceRegistry } from "./device";
import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  SHA256_HEX,
  bearerToken,
  equalHex,
  expectKeys,
  integerField,
  json,
  readObject,
  sha256Hex,
  stringField,
} from "./http";
import { verifyP256Signature } from "./protocol";

const PUBLIC_KEY = BASE64URL;

interface GroupEnv {
  DEVICES: DurableObjectNamespace<DeviceRegistry>;
}

interface MetaRow extends Record<string, SqlStorageValue> {
  group_id: string;
}

interface MemberRow extends Record<string, SqlStorageValue> {
  device_id: string;
  access_hash: string;
  encryption_public_key: string;
  request_id: string | null;
  added_at: number;
}

interface KeyRow extends Record<string, SqlStorageValue> {
  timestamp: number;
  public_key: string;
  recreated: number;
  created_by_device_id: string;
}

interface KeyMemberRow extends Record<string, SqlStorageValue> {
  key_timestamp: number;
  device_id: string;
}

interface PackageRow extends Record<string, SqlStorageValue> {
  key_timestamp: number;
  device_id: string;
  ephemeral_public_key: string;
  nonce: string;
  ciphertext: string;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  session_id: string;
  creator_public_key: string;
  expires_at: number;
}

interface KeyPackage {
  deviceId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

interface ClaimedRequest {
  requestId: string;
  deviceId: string;
  deviceAccessTokenHash: string;
  deviceEncryptionPublicKey: string;
}

export interface GroupCurrentState {
  groupId: string;
  members: string[];
  key: { timestamp: number; publicKey: string; members: string[] } | null;
}

export type GroupAuthorization = "authorized" | "device_removed" | "invalid_token";

export class DeviceGroup extends DurableObject<GroupEnv> {
  private readonly state: DurableObjectState;
  private readonly devices: DurableObjectStub<DeviceRegistry>;

  constructor(
    state: DurableObjectState,
    env: GroupEnv,
  ) {
    super(state, env);
    this.state = state;
    this.devices = env.DEVICES.get(env.DEVICES.idFromName("registry"));
    this.createSchema();
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

  async authorizeDevice(deviceId: string, token: string): Promise<GroupAuthorization> {
    const member = this.member(deviceId);
    if (member === null) return "device_removed";
    return equalHex(member.access_hash, await sha256Hex(token)) ? "authorized" : "invalid_token";
  }

  getCurrentState(): GroupCurrentState | null {
    const meta = this.meta();
    return meta === null ? null : this.current(meta);
  }

  getKeyRecipients(timestamp: number): { status: "ok"; deviceIds: string[] } | { status: "unavailable" } {
    const members = this.members().map((member) => member.device_id);
    const key = this.key(timestamp);
    if (key === null || !this.isUsableKey(key, members)) return { status: "unavailable" };
    return { status: "ok", deviceIds: this.keyMemberIds(timestamp) };
  }

  authorizeKeyForDevice(timestamp: number, deviceId: string): "authorized" | "device_removed" | "unavailable" {
    if (this.member(deviceId) === null) return "device_removed";
    return this.keyMemberIds(timestamp).includes(deviceId) ? "authorized" : "unavailable";
  }

  storeSession(sessionId: string, creatorPublicKey: string, expiresAt: number): void {
    this.state.storage.sql.exec(
      `INSERT INTO group_sessions_v3 (session_id, creator_public_key, expires_at)
       VALUES (?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET expires_at = excluded.expires_at`,
      sessionId,
      creatorPublicKey,
      expiresAt,
    );
  }

  removeSession(sessionId: string): void {
    this.state.storage.sql.exec("DELETE FROM group_sessions_v3 WHERE session_id = ?", sessionId);
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/create") return this.create(request);

    const meta = this.requiredMeta();
    if (request.method === "GET" && url.pathname === "/state") {
      const member = await this.requireMember(request);
      return this.groupState(meta, member.device_id);
    }
    if (request.method === "POST" && url.pathname === "/keys") {
      const member = await this.requireMember(request);
      return this.createKey(request, member);
    }
    const approveMatch = /^\/device-requests\/([^/]+)\/approve$/.exec(url.pathname);
    if (request.method === "POST" && approveMatch !== null) {
      const member = await this.requireMember(request);
      return this.approveDeviceRequest(request, meta, member, identifier(approveMatch[1], "requestId"));
    }
    const deviceMatch = /^\/devices\/([^/]+)$/.exec(url.pathname);
    if (request.method === "DELETE" && deviceMatch !== null) {
      const member = await this.requireMember(request);
      return this.removeDevice(request, meta, member, identifier(deviceMatch[1], "deviceId"));
    }

    throw new HttpError(404, "not_found", "Endpoint not found");
  }

  private async create(request: Request): Promise<Response> {
    if (this.meta() !== null) throw new HttpError(409, "group_exists", "Device group already exists");
    const body = await readObject(request);
    expectKeys(body, [
      "groupId",
      "deviceId",
      "deviceAccessTokenHash",
      "deviceEncryptionPublicKey",
      "deviceSignature",
    ]);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const accessHash = stringField(body, "deviceAccessTokenHash", SHA256_HEX, 64);
    const encryptionPublicKey = stringField(body, "deviceEncryptionPublicKey", PUBLIC_KEY, 128);
    const signature = stringField(body, "deviceSignature", BASE64URL, 128);
    const device = await this.registeredDevice(deviceId);
    const transcript = [
      "notify.guru/group-create/v2",
      groupId,
      deviceId,
      accessHash,
      encryptionPublicKey,
    ].join("\n");
    if (!(await verifyP256Signature(device.signingPublicKey, signature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Initial device signature is invalid");
    }
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("INSERT INTO group_meta_v3 (singleton, group_id) VALUES (1, ?)", groupId);
      this.state.storage.sql.exec(
        `INSERT INTO group_members_v3
           (device_id, access_hash, encryption_public_key, added_at)
         VALUES (?, ?, ?, ?)`,
        deviceId,
        accessHash,
        encryptionPublicKey,
        now,
      );
    });
    return json({ created: true, groupId }, 201);
  }

  private async approveDeviceRequest(
    request: Request,
    meta: MetaRow,
    actor: MemberRow,
    requestId: string,
  ): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["actorSignature"]);
    await this.requireManagementSignature(
      actor.device_id,
      stringField(body, "actorSignature", BASE64URL, 128),
      ["notify.guru/group-device-approve/v1", meta.group_id, actor.device_id, requestId].join("\n"),
    );
    const requestMember = this.memberByRequest(requestId);
    if (requestMember !== null) {
      await this.completeRequest(requestId, meta.group_id);
      return json({ approved: true, deviceId: requestMember.device_id, approvedByDeviceId: actor.device_id });
    }
    const claimed = await this.claimRequest(requestId, meta.group_id);
    if (this.member(claimed.deviceId) !== null) {
      throw new HttpError(409, "device_exists", "Device already belongs to the group");
    }
    this.state.storage.sql.exec(
      `INSERT INTO group_members_v3
         (device_id, access_hash, encryption_public_key, request_id, added_at)
       VALUES (?, ?, ?, ?, ?)`,
      claimed.deviceId,
      claimed.deviceAccessTokenHash,
      claimed.deviceEncryptionPublicKey,
      requestId,
      Date.now(),
    );
    await this.completeRequest(requestId, meta.group_id);
    return json({ approved: true, deviceId: claimed.deviceId, approvedByDeviceId: actor.device_id });
  }

  private async createKey(request: Request, actor: MemberRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["publicKey", "recreated", "members", "packages", "actorSignature"]);
    const publicKey = stringField(body, "publicKey", PUBLIC_KEY, 128);
    const recreated = booleanField(body, "recreated");
    const memberIds = identifierArray(body.members, "members");
    const packages = packageArray(body.packages);
    const actorSignature = stringField(body, "actorSignature", BASE64URL, 128);
    const activeMemberIds = this.members().map((member) => member.device_id);
    if (!sameStringSet(memberIds, activeMemberIds)) {
      throw new HttpError(409, "member_set_changed", "Key members do not match the active group members");
    }
    if (!sameStringSet(packages.map((item) => item.deviceId), activeMemberIds)) {
      throw new HttpError(400, "invalid_package_set", "Key packages must target every active member exactly once");
    }
    await this.requireManagementSignature(
      actor.device_id,
      actorSignature,
      groupKeyTranscript(this.requiredMeta().group_id, actor.device_id, publicKey, recreated, memberIds, packages),
    );
    const latest = this.keys().at(-1);
    if (!recreated && (latest === undefined || !this.isUsableKey(latest, activeMemberIds))) {
      throw new HttpError(409, "recreated_required", "A recreated key is required after membership removal");
    }
    const timestamp = Date.now();
    if (this.key(timestamp) !== null) {
      throw new HttpError(409, "key_timestamp_conflict", "Another key was accepted at the same timestamp");
    }
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(
        `INSERT INTO group_keys_v3
           (timestamp, public_key, recreated, created_by_device_id)
         VALUES (?, ?, ?, ?)`,
        timestamp,
        publicKey,
        recreated ? 1 : 0,
        actor.device_id,
      );
      for (const deviceId of memberIds) {
        this.state.storage.sql.exec(
          "INSERT INTO group_key_members_v3 (key_timestamp, device_id) VALUES (?, ?)",
          timestamp,
          deviceId,
        );
      }
      for (const keyPackage of packages) {
        this.state.storage.sql.exec(
          `INSERT INTO group_key_packages_v3
             (key_timestamp, device_id, ephemeral_public_key, nonce, ciphertext)
           VALUES (?, ?, ?, ?, ?)`,
          timestamp,
          keyPackage.deviceId,
          keyPackage.ephemeralPublicKey,
          keyPackage.nonce,
          keyPackage.ciphertext,
        );
      }
    });
    return json({ timestamp }, 201);
  }

  private async removeDevice(
    request: Request,
    meta: MetaRow,
    actor: MemberRow,
    deviceId: string,
  ): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["actorSignature"]);
    await this.requireManagementSignature(
      actor.device_id,
      stringField(body, "actorSignature", BASE64URL, 128),
      ["notify.guru/group-device-remove/v1", meta.group_id, actor.device_id, deviceId].join("\n"),
    );
    if (this.member(deviceId) === null) {
      throw new HttpError(404, "device_not_found", "Active device not found");
    }
    this.state.storage.sql.exec("DELETE FROM group_members_v3 WHERE device_id = ?", deviceId);
    await this.devices.deactivateGroupDevice(meta.group_id, deviceId);
    return json({ removed: true });
  }

  private groupState(meta: MetaRow, deviceId: string): Response {
    const members = this.members().map((member) => ({
      deviceId: member.device_id,
      encryptionPublicKey: member.encryption_public_key,
      addedAt: member.added_at,
    }));
    const keys = this.keys().map((key) => ({
      timestamp: key.timestamp,
      publicKey: key.public_key,
      recreated: key.recreated === 1,
      members: this.keyMemberIds(key.timestamp),
    }));
    const packages = Array.from(this.state.storage.sql.exec<PackageRow>(
      `SELECT key_timestamp, device_id, ephemeral_public_key, nonce, ciphertext
       FROM group_key_packages_v3 WHERE device_id = ? ORDER BY key_timestamp`,
      deviceId,
    )).map((item) => ({
      timestamp: item.key_timestamp,
      deviceId: item.device_id,
      ephemeralPublicKey: item.ephemeral_public_key,
      nonce: item.nonce,
      ciphertext: item.ciphertext,
    }));
    return json({ groupId: meta.group_id, members, keys, packages, sessions: this.sessionsJSON() });
  }

  private current(meta: MetaRow): GroupCurrentState {
    const members = this.members().map((member) => member.device_id);
    const currentKey = this.currentKey(members);
    return {
      groupId: meta.group_id,
      members,
      key: currentKey === null ? null : {
        timestamp: currentKey.timestamp,
        publicKey: currentKey.public_key,
        members: this.keyMemberIds(currentKey.timestamp),
      },
    };
  }

  private sessionsJSON(): Array<Record<string, unknown>> {
    return Array.from(this.state.storage.sql.exec<SessionRow>(
      `SELECT session_id, creator_public_key, expires_at
       FROM group_sessions_v3 WHERE expires_at > ? ORDER BY expires_at`,
      Date.now(),
    )).map((row) => ({
      sessionId: row.session_id,
      creatorPublicKey: row.creator_public_key,
      expiresAt: row.expires_at,
    }));
  }

  private async requireMember(request: Request): Promise<MemberRow> {
    const deviceId = identifier(new URL(request.url).searchParams.get("deviceId"), "deviceId");
    const member = this.member(deviceId);
    if (member === null) {
      throw new HttpError(403, "device_removed", "Device is not an active member of the group");
    }
    if (!equalHex(member.access_hash, await sha256Hex(bearerToken(request)))) {
      throw new HttpError(401, "invalid_device_token", "Device token is invalid");
    }
    return member;
  }

  private requiredMeta(): MetaRow {
    const meta = this.meta();
    if (meta === null) throw new HttpError(404, "group_not_found", "Device group not found");
    return meta;
  }

  private meta(): MetaRow | null {
    const rows = Array.from(this.state.storage.sql.exec<MetaRow>(
      "SELECT group_id FROM group_meta_v3 WHERE singleton = 1",
    ));
    if (rows.length > 1) throw new Error("Device group must contain at most one meta row");
    return rows.length === 0 ? null : rows[0];
  }

  private members(): MemberRow[] {
    return Array.from(this.state.storage.sql.exec<MemberRow>(
      `SELECT device_id, access_hash, encryption_public_key, request_id, added_at
       FROM group_members_v3 ORDER BY added_at, device_id`,
    ));
  }

  private member(deviceId: string): MemberRow | null {
    const rows = Array.from(this.state.storage.sql.exec<MemberRow>(
      `SELECT device_id, access_hash, encryption_public_key, request_id, added_at
       FROM group_members_v3 WHERE device_id = ?`,
      deviceId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private memberByRequest(requestId: string): MemberRow | null {
    const rows = Array.from(this.state.storage.sql.exec<MemberRow>(
      `SELECT device_id, access_hash, encryption_public_key, request_id, added_at
       FROM group_members_v3 WHERE request_id = ?`,
      requestId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private keys(): KeyRow[] {
    return Array.from(this.state.storage.sql.exec<KeyRow>(
      `SELECT timestamp, public_key, recreated, created_by_device_id
       FROM group_keys_v3 ORDER BY timestamp`,
    ));
  }

  private key(timestamp: number): KeyRow | null {
    const rows = Array.from(this.state.storage.sql.exec<KeyRow>(
      `SELECT timestamp, public_key, recreated, created_by_device_id
       FROM group_keys_v3 WHERE timestamp = ?`,
      timestamp,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private keyMemberIds(timestamp: number): string[] {
    return Array.from(this.state.storage.sql.exec<KeyMemberRow>(
      `SELECT key_timestamp, device_id FROM group_key_members_v3
       WHERE key_timestamp = ? ORDER BY device_id`,
      timestamp,
    )).map((row) => row.device_id);
  }

  private currentKey(activeMembers: string[]): KeyRow | null {
    const keys = this.keys();
    const recreated = keys.filter((key) => key.recreated === 1).at(-1);
    const cutoff = recreated?.timestamp ?? 0;
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      const key = keys[index];
      if (key.timestamp < cutoff) break;
      if (this.isUsableKey(key, activeMembers)) return key;
    }
    return null;
  }

  private isUsableKey(key: KeyRow, activeMembers: string[]): boolean {
    const recreated = this.keys().filter((item) => item.recreated === 1).at(-1);
    if (recreated !== undefined && key.timestamp < recreated.timestamp) return false;
    const active = new Set(activeMembers);
    return this.keyMemberIds(key.timestamp).every((deviceId) => active.has(deviceId));
  }

  private async registeredDevice(deviceId: string): Promise<{ signingPublicKey: string }> {
    const result = await this.devices.getRegisteredDevice(deviceId);
    if (result === null) throw new HttpError(404, "device_not_found", "Device not found");
    if (result.deviceId !== deviceId) throw new Error("Device registry returned another device");
    return { signingPublicKey: result.signingPublicKey };
  }

  private async requireManagementSignature(deviceId: string, signature: string, transcript: string): Promise<void> {
    const device = await this.registeredDevice(deviceId);
    if (!(await verifyP256Signature(device.signingPublicKey, signature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Group management signature is invalid");
    }
  }

  private async claimRequest(requestId: string, groupId: string): Promise<ClaimedRequest> {
    const result = await this.devices.claimDeviceRequest(requestId, groupId);
    switch (result.status) {
      case "claimed":
        return result;
      case "not_found":
        throw new HttpError(404, "device_request_not_found", "Device request not found");
      case "expired":
        throw new HttpError(410, "device_request_expired", "Device request has expired");
      case "used":
        throw new HttpError(409, "device_request_used", "Device request has already been approved");
      case "claimed_by_another_group":
        throw new HttpError(409, "device_request_claimed", "Device request is being approved by another group");
    }
  }

  private async completeRequest(requestId: string, groupId: string): Promise<void> {
    const result = await this.devices.completeDeviceRequest(requestId, groupId);
    if (result === "not_claimed") throw new Error("Device request was not claimed before completion");
    if (result === "used") throw new Error("Device request approval changed groups during completion");
  }

  private createSchema(): void {
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS group_meta_v3 (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        group_id TEXT NOT NULL UNIQUE
      );
      CREATE TABLE IF NOT EXISTS group_members_v3 (
        device_id TEXT PRIMARY KEY,
        access_hash TEXT NOT NULL,
        encryption_public_key TEXT NOT NULL,
        request_id TEXT UNIQUE,
        added_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS group_keys_v3 (
        timestamp INTEGER PRIMARY KEY,
        public_key TEXT NOT NULL,
        recreated INTEGER NOT NULL CHECK (recreated IN (0, 1)),
        created_by_device_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS group_key_members_v3 (
        key_timestamp INTEGER NOT NULL REFERENCES group_keys_v3(timestamp),
        device_id TEXT NOT NULL,
        PRIMARY KEY (key_timestamp, device_id)
      );
      CREATE TABLE IF NOT EXISTS group_key_packages_v3 (
        key_timestamp INTEGER NOT NULL REFERENCES group_keys_v3(timestamp),
        device_id TEXT NOT NULL,
        ephemeral_public_key TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        PRIMARY KEY (key_timestamp, device_id)
      );
      CREATE TABLE IF NOT EXISTS group_sessions_v3 (
        session_id TEXT PRIMARY KEY,
        creator_public_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
  }
}

function identifier(value: string | null, name: string): string {
  return stringField({ [name]: value }, name, IDENTIFIER, 64);
}

function booleanField(value: Record<string, unknown>, name: string): boolean {
  if (typeof value[name] !== "boolean") throw new HttpError(400, "invalid_field", `Invalid field: ${name}`);
  return value[name] as boolean;
}

function identifierArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) {
    throw new HttpError(400, "invalid_field", `Invalid field: ${name}`);
  }
  const result = value.map((item) => stringField({ [name]: item }, name, IDENTIFIER, 64));
  if (new Set(result).size !== result.length) {
    throw new HttpError(400, "invalid_field", `${name} must contain unique values`);
  }
  return result;
}

function packageArray(value: unknown): KeyPackage[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) {
    throw new HttpError(400, "invalid_field", "Invalid field: packages");
  }
  return value.map((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "invalid_field", "Invalid key package");
    }
    const object = item as Record<string, unknown>;
    expectKeys(object, ["deviceId", "ephemeralPublicKey", "nonce", "ciphertext"]);
    return {
      deviceId: stringField(object, "deviceId", IDENTIFIER, 64),
      ephemeralPublicKey: stringField(object, "ephemeralPublicKey", PUBLIC_KEY, 128),
      nonce: stringField(object, "nonce", BASE64URL, 32),
      ciphertext: stringField(object, "ciphertext", BASE64URL, 512),
    };
  });
}

function sameStringSet(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value) => right.includes(value));
}

function groupKeyTranscript(
  groupId: string,
  actorDeviceId: string,
  publicKey: string,
  recreated: boolean,
  members: string[],
  packages: KeyPackage[],
): string {
  const sortedMembers = [...members].sort();
  const packagesByDevice = new Map(packages.map((item) => [item.deviceId, item]));
  const sortedPackages = sortedMembers.map((deviceId) => {
    const item = packagesByDevice.get(deviceId);
    if (item === undefined) throw new Error("Validated key package set is incomplete");
    return item;
  });
  const lines = [
    "notify.guru/group-key-register/v1",
    groupId,
    actorDeviceId,
    publicKey,
    recreated ? "1" : "0",
    String(sortedMembers.length),
    ...sortedMembers,
    String(sortedPackages.length),
  ];
  for (const item of sortedPackages) {
    lines.push(item.deviceId, item.ephemeralPublicKey, item.nonce, item.ciphertext);
  }
  return lines.join("\n");
}
