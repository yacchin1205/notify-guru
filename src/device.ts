import { DurableObject } from "cloudflare:workers";
import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  SHA256_HEX,
  bearerToken,
  expectKeys,
  json,
  readObject,
  stringField,
} from "./http";
import { randomIdentifier, verifyP256Signature } from "./protocol";

const DEVICE_REQUEST_LIFETIME_MS = 10 * 60 * 1000;
const PUBLIC_KEY = BASE64URL;
const SIGNATURE = BASE64URL;

interface DeviceEnv {}

interface DeviceRow extends Record<string, SqlStorageValue> {
  id: string;
  signing_public_key: string;
  push_token: string | null;
  push_environment: string | null;
}

interface DeviceRequestRow extends Record<string, SqlStorageValue> {
  id: string;
  device_id: string;
  access_hash: string;
  encryption_public_key: string;
  expires_at: number;
  claimed_group_id: string | null;
  approved_group_id: string | null;
}

export type DeviceRequestClaim =
  | ({ status: "claimed" } & ClaimedDeviceRequest)
  | { status: "not_found" | "expired" | "used" | "claimed_by_another_group" };

export interface ClaimedDeviceRequest {
  requestId: string;
  deviceId: string;
  deviceAccessTokenHash: string;
  deviceEncryptionPublicKey: string;
}

export interface DevicePushTarget {
  deviceId: string;
  token: string;
  environment: "sandbox" | "production";
}

export class DeviceRegistry extends DurableObject<DeviceEnv> {
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState, env: DeviceEnv) {
    super(state, env);
    this.state = state;
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        signing_public_key TEXT NOT NULL UNIQUE,
        push_token TEXT,
        push_environment TEXT CHECK (push_environment IN ('sandbox', 'production')),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS device_requests (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id),
        access_hash TEXT NOT NULL,
        encryption_public_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        claimed_group_id TEXT,
        approved_group_id TEXT,
        created_at INTEGER NOT NULL,
        approved_at INTEGER
      );
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
    const requestMatch = /^\/device-requests\/([^/]+)$/.exec(url.pathname);
    if (request.method === "GET" && requestMatch !== null) {
      return this.deviceRequest(request, identifier(requestMatch[1], "requestId"));
    }

    throw new HttpError(404, "not_found", "Endpoint not found");
  }

  getRegisteredDevice(deviceId: string): { deviceId: string; signingPublicKey: string } | null {
    const device = this.device(deviceId);
    return device === null ? null : { deviceId: device.id, signingPublicKey: device.signing_public_key };
  }

  claimDeviceRequest(requestId: string, groupId: string): DeviceRequestClaim {
    const row = this.deviceRequestRow(requestId);
    if (row === null) return { status: "not_found" };
    if (Date.now() >= row.expires_at) return { status: "expired" };
    if (row.approved_group_id !== null) return { status: "used" };
    if (row.claimed_group_id !== null && row.claimed_group_id !== groupId) {
      return { status: "claimed_by_another_group" };
    }
    if (row.claimed_group_id === null) {
      this.state.storage.sql.exec("UPDATE device_requests SET claimed_group_id = ? WHERE id = ?", groupId, requestId);
    }
    return {
      status: "claimed",
      requestId: row.id,
      deviceId: row.device_id,
      deviceAccessTokenHash: row.access_hash,
      deviceEncryptionPublicKey: row.encryption_public_key,
    };
  }

  completeDeviceRequest(requestId: string, groupId: string): "approved" | "not_claimed" | "used" {
    const row = this.deviceRequestRow(requestId);
    if (row === null || row.claimed_group_id !== groupId) return "not_claimed";
    if (row.approved_group_id !== null && row.approved_group_id !== groupId) return "used";
    this.state.storage.sql.exec(
      "UPDATE device_requests SET approved_group_id = ?, approved_at = ? WHERE id = ?",
      groupId,
      Date.now(),
      requestId,
    );
    return "approved";
  }

  getPushTargets(deviceIds: string[]): DevicePushTarget[] {
    return deviceIds.flatMap((deviceId) => {
      const device = this.requiredDevice(deviceId);
      if (device.push_token === null || device.push_environment === null) return [];
      return [{
        deviceId,
        token: device.push_token,
        environment: device.push_environment as "sandbox" | "production",
      }];
    });
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
    ]);
    const requestId = stringField(body, "requestId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const accessHash = stringField(body, "deviceAccessTokenHash", SHA256_HEX, 64);
    const encryptionPublicKey = stringField(body, "deviceEncryptionPublicKey", PUBLIC_KEY, 128);
    const deviceSignature = stringField(body, "deviceSignature", SIGNATURE, 128);
    const device = this.requiredDevice(deviceId);
    const transcript = [
      "notify.guru/device-request/v1",
      requestId,
      deviceId,
      accessHash,
      encryptionPublicKey,
    ].join("\n");
    if (!(await verifyP256Signature(device.signing_public_key, deviceSignature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device request signature is invalid");
    }
    const expiresAt = Date.now() + DEVICE_REQUEST_LIFETIME_MS;
    this.state.storage.sql.exec(
      `INSERT INTO device_requests
         (id, device_id, access_hash, encryption_public_key, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      requestId,
      deviceId,
      accessHash,
      encryptionPublicKey,
      expiresAt,
      Date.now(),
    );
    return json({ requestId, expiresAt }, 201);
  }

  private async deviceRequest(request: Request, requestId: string): Promise<Response> {
    const row = this.requiredDeviceRequest(requestId);
    const deviceId = identifier(new URL(request.url).searchParams.get("deviceId"), "deviceId");
    if (deviceId !== row.device_id) {
      throw new HttpError(403, "wrong_device", "Device request belongs to another device");
    }
    const device = this.requiredDevice(deviceId);
    const transcript = ["notify.guru/device-request-read/v1", requestId, deviceId].join("\n");
    if (!(await verifyP256Signature(device.signing_public_key, bearerToken(request), transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device request signature is invalid");
    }
    if (row.approved_group_id !== null) {
      return json({ status: "approved", groupId: row.approved_group_id, expiresAt: row.expires_at });
    }
    if (Date.now() >= row.expires_at) {
      return json({ status: "expired", expiresAt: row.expires_at });
    }
    return json({ status: "waiting", expiresAt: row.expires_at });
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

  private deviceByPublicKey(publicKey: string): DeviceRow | null {
    const rows = Array.from(this.state.storage.sql.exec<DeviceRow>(
      "SELECT id, signing_public_key, push_token, push_environment FROM devices WHERE signing_public_key = ?",
      publicKey,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private requiredDeviceRequest(requestId: string): DeviceRequestRow {
    const row = this.deviceRequestRow(requestId);
    if (row === null) throw new HttpError(404, "device_request_not_found", "Device request not found");
    return row;
  }

  private deviceRequestRow(requestId: string): DeviceRequestRow | null {
    const rows = Array.from(this.state.storage.sql.exec<DeviceRequestRow>(
      `SELECT id, device_id, access_hash, encryption_public_key, expires_at,
              claimed_group_id, approved_group_id
       FROM device_requests WHERE id = ?`,
      requestId,
    ));
    return rows.length === 0 ? null : rows[0];
  }
}

function identifier(value: string | null, name: string): string {
  return identifierValue(value, name);
}

function identifierValue(value: unknown, name: string): string {
  return stringField({ [name]: value }, name, IDENTIFIER, 64);
}
