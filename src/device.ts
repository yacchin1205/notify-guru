import { DurableObject } from "cloudflare:workers";
import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  SHA256_HEX,
  expectKeys,
  json,
  readObject,
  stringField,
} from "./http";
import { deviceRequestBindingHash, randomIdentifier, verifyP256Signature } from "./protocol";
import type { DeviceRequest, DeviceRequestCreation } from "./device-request";

const DEVICE_REQUEST_LIFETIME_MS = 10 * 60 * 1000;
const PUBLIC_KEY = BASE64URL;
const SIGNATURE = BASE64URL;

interface DeviceEnv {
  DEVICE_REQUESTS: DurableObjectNamespace<DeviceRequest>;
}

interface DeviceRow extends Record<string, SqlStorageValue> {
  id: string;
  signing_public_key: string;
  push_token: string | null;
  push_environment: string | null;
}

interface DevicePushRow extends DeviceRow {
  badge_count: number;
}

export interface DevicePushTarget {
  deviceId: string;
  token: string;
  environment: "sandbox" | "production";
  badgeCount: number;
}

export class DeviceRegistry extends DurableObject<DeviceEnv> {
  private readonly state: DurableObjectState;
  private readonly deviceRequests: DurableObjectNamespace<DeviceRequest>;

  constructor(state: DurableObjectState, env: DeviceEnv) {
    super(state, env);
    this.state = state;
    this.deviceRequests = env.DEVICE_REQUESTS;
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        signing_public_key TEXT NOT NULL UNIQUE,
        push_token TEXT,
        push_environment TEXT CHECK (push_environment IN ('sandbox', 'production')),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_active_items_v1 (
        device_id TEXT NOT NULL REFERENCES devices(id),
        session_id TEXT NOT NULL,
        group_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, session_id, item_id)
      );
      CREATE INDEX IF NOT EXISTS device_active_items_v1_session_item
        ON device_active_items_v1(session_id, item_id);
      CREATE INDEX IF NOT EXISTS device_active_items_v1_group_device
        ON device_active_items_v1(group_id, device_id);
      DROP TABLE IF EXISTS device_requests;
    `);
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

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/devices") {
      return this.createDevice(request);
    }
    const pushMatch = /^\/devices\/([^/]+)\/push$/.exec(url.pathname);
    if (request.method === "PUT" && pushMatch !== null) {
      return this.putPush(request, identifier(pushMatch[1], "deviceId"));
    }
    if (request.method === "POST" && url.pathname === "/device-requests") {
      return this.createDeviceRequest(request);
    }
    throw new HttpError(404, "not_found", "Endpoint not found");
  }

  getRegisteredDevice(deviceId: string): { deviceId: string; signingPublicKey: string } | null {
    const device = this.device(deviceId);
    return device === null ? null : { deviceId: device.id, signingPublicKey: device.signing_public_key };
  }

  getPushTargets(deviceIds: string[]): DevicePushTarget[] {
    return deviceIds.flatMap((deviceId) => {
      const device = this.pushDevice(deviceId);
      if (device.push_token === null || device.push_environment === null) return [];
      return [{
        deviceId,
        token: device.push_token,
        environment: device.push_environment as "sandbox" | "production",
        badgeCount: device.badge_count,
      }];
    });
  }

  activateSessionItem(sessionId: string, groupId: string, itemId: string, deviceIds: string[]): void {
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      for (const deviceId of deviceIds) {
        this.requiredDevice(deviceId);
        this.state.storage.sql.exec(
          `INSERT OR IGNORE INTO device_active_items_v1
             (device_id, session_id, group_id, item_id, created_at)
           VALUES (?, ?, ?, ?, ?)`,
          deviceId,
          sessionId,
          groupId,
          itemId,
          now,
        );
      }
    });
  }

  deactivateSessionItem(sessionId: string, itemId: string): void {
    this.state.storage.sql.exec(
      "DELETE FROM device_active_items_v1 WHERE session_id = ? AND item_id = ?",
      sessionId,
      itemId,
    );
  }

  deactivateSession(sessionId: string): void {
    this.state.storage.sql.exec("DELETE FROM device_active_items_v1 WHERE session_id = ?", sessionId);
  }

  deactivateGroupDevice(groupId: string, deviceId: string): void {
    this.state.storage.sql.exec(
      "DELETE FROM device_active_items_v1 WHERE group_id = ? AND device_id = ?",
      groupId,
      deviceId,
    );
  }

  clearPushToken(deviceId: string, token: string): void {
    this.state.storage.sql.exec(
      "UPDATE devices SET push_token = NULL, push_environment = NULL, updated_at = ? WHERE id = ? AND push_token = ?",
      Date.now(),
      deviceId,
      token,
    );
  }

  private async createDevice(request: Request): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["signingPublicKey", "nonce", "signature"]);
    const signingPublicKey = stringField(body, "signingPublicKey", PUBLIC_KEY, 128);
    const nonce = stringField(body, "nonce", BASE64URL, 128);
    const signature = stringField(body, "signature", SIGNATURE, 128);
    const transcript = ["notify.guru/device-create/v1", signingPublicKey, nonce].join("\n");
    if (!(await verifyP256Signature(signingPublicKey, signature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device signature is invalid");
    }
    if (this.deviceByPublicKey(signingPublicKey) !== null) {
      throw new HttpError(409, "device_exists", "This signing key is already registered");
    }
    let deviceId = randomIdentifier();
    while (this.device(deviceId) !== null) deviceId = randomIdentifier();
    const now = Date.now();
    this.state.storage.sql.exec(
      "INSERT INTO devices (id, signing_public_key, created_at, updated_at) VALUES (?, ?, ?, ?)",
      deviceId,
      signingPublicKey,
      now,
      now,
    );
    return json({ deviceId }, 201);
  }

  private async putPush(request: Request, deviceId: string): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["token", "environment", "signature"]);
    const token = stringField(body, "token", /^[a-f0-9]{64,256}$/, 256);
    const environment = stringField(body, "environment", /^(sandbox|production)$/, 10);
    const signature = stringField(body, "signature", SIGNATURE, 128);
    const device = this.requiredDevice(deviceId);
    const transcript = ["notify.guru/device-push/v1", deviceId, token, environment].join("\n");
    if (!(await verifyP256Signature(device.signing_public_key, signature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device signature is invalid");
    }
    this.state.storage.sql.exec(
      "UPDATE devices SET push_token = ?, push_environment = ?, updated_at = ? WHERE id = ?",
      token,
      environment,
      Date.now(),
      deviceId,
    );
    return json({ updated: true });
  }

  private async createDeviceRequest(request: Request): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, [
      "requestId",
      "deviceId",
      "deviceAccessTokenHash",
      "deviceEncryptionPublicKey",
      "deviceSignature",
    ], ["protocolVersion"]);
    const requestId = stringField(body, "requestId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const accessHash = stringField(body, "deviceAccessTokenHash", SHA256_HEX, 64);
    const encryptionPublicKey = stringField(body, "deviceEncryptionPublicKey", PUBLIC_KEY, 128);
    const deviceSignature = stringField(body, "deviceSignature", SIGNATURE, 128);
    const protocolVersion = body.protocolVersion === undefined ? 3 : integerProtocolVersion(body.protocolVersion);
    const device = this.requiredDevice(deviceId);
    const transcript = [
      protocolVersion === 4 ? "notify.guru/device-request/v2" : "notify.guru/device-request/v1",
      requestId,
      deviceId,
      accessHash,
      encryptionPublicKey,
      ...(protocolVersion === 4 ? ["3,4"] : []),
    ].join("\n");
    if (!(await verifyP256Signature(device.signing_public_key, deviceSignature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device request signature is invalid");
    }
    const expiresAt = Date.now() + DEVICE_REQUEST_LIFETIME_MS;
    const requestHash = await deviceRequestBindingHash({
      requestId,
      deviceId,
      signingPublicKey: device.signing_public_key,
      accessHash,
      encryptionPublicKey,
      protocolVersion,
    });
    const creation: DeviceRequestCreation = {
      requestId,
      deviceId,
      deviceAccessTokenHash: accessHash,
      deviceEncryptionPublicKey: encryptionPublicKey,
      deviceSigningPublicKey: device.signing_public_key,
      protocolVersion,
      expiresAt,
      requestHash,
    };
    await this.deviceRequestStub(requestId).create(creation);
    return json({ requestId, expiresAt, ...(protocolVersion === 4 ? { requestHash } : {}) }, 201);
  }

  private requiredDevice(deviceId: string): DeviceRow {
    const device = this.device(deviceId);
    if (device === null) throw new HttpError(404, "device_not_found", "Device not found");
    return device;
  }

  private device(deviceId: string): DeviceRow | null {
    const rows = Array.from(this.state.storage.sql.exec<DeviceRow>(
      "SELECT id, signing_public_key, push_token, push_environment FROM devices WHERE id = ?",
      deviceId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private pushDevice(deviceId: string): DevicePushRow {
    const rows = Array.from(this.state.storage.sql.exec<DevicePushRow>(
      `SELECT d.id, d.signing_public_key, d.push_token, d.push_environment,
              COUNT(a.item_id) AS badge_count
       FROM devices d
       LEFT JOIN device_active_items_v1 a ON a.device_id = d.id
       WHERE d.id = ?
       GROUP BY d.id, d.signing_public_key, d.push_token, d.push_environment`,
      deviceId,
    ));
    if (rows.length === 0) throw new HttpError(404, "device_not_found", "Device not found");
    return rows[0];
  }

  private deviceByPublicKey(publicKey: string): DeviceRow | null {
    const rows = Array.from(this.state.storage.sql.exec<DeviceRow>(
      "SELECT id, signing_public_key, push_token, push_environment FROM devices WHERE signing_public_key = ?",
      publicKey,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private deviceRequestStub(requestId: string): DurableObjectStub<DeviceRequest> {
    return this.deviceRequests.get(this.deviceRequests.idFromName(requestId));
  }
}

function integerProtocolVersion(value: unknown): number {
  if (value !== 4) throw new HttpError(400, "unsupported_protocol", "Device request protocol version is not supported");
  return value;
}

function identifier(value: string | null, name: string): string {
  return identifierValue(value, name);
}

function identifierValue(value: unknown, name: string): string {
  return stringField({ [name]: value }, name, IDENTIFIER, 64);
}
