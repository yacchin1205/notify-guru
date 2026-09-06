import { DurableObject } from "cloudflare:workers";
import type {
  DeviceApprovalCommitResult,
  DeviceApprovalIntent,
  DeviceApprovalPreparation,
  DeviceGroup,
  DeviceRequestDescriptor,
} from "./group";
import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  bearerToken,
  json,
  readObject,
  stringField,
} from "./http";
import { verifyP256Signature } from "./protocol";

const APPROVAL_RETRY_DELAY_MS = 1_000;

interface DeviceRequestEnv {
  GROUPS: DurableObjectNamespace<DeviceGroup>;
}

export interface DeviceRequestCreation extends DeviceRequestDescriptor {
  expiresAt: number;
  requestHash: string;
}

interface RequestRow extends Record<string, SqlStorageValue> {
  request_id: string;
  device_id: string;
  access_hash: string;
  signing_public_key: string;
  encryption_public_key: string;
  protocol_version: number;
  expires_at: number;
  status: "waiting" | "approving" | "approved" | "expired";
  approval_group_id: string | null;
  approval_actor_device_id: string | null;
  approval_transition_hash: string | null;
  approval_proof: string | null;
  approval_intent_json: string | null;
}

export class DeviceRequest extends DurableObject<DeviceRequestEnv> {
  private readonly state: DurableObjectState;
  private readonly groups: DurableObjectNamespace<DeviceGroup>;

  constructor(state: DurableObjectState, env: DeviceRequestEnv) {
    super(state, env);
    this.state = state;
    this.groups = env.GROUPS;
    this.createSchema();
  }

  async create(creation: DeviceRequestCreation): Promise<{ expiresAt: number; requestHash: string }> {
    if (this.row() !== null) {
      throw new HttpError(409, "device_request_exists", "Device request already exists");
    }
    await this.state.storage.setAlarm(creation.expiresAt);
    this.state.storage.sql.exec(
      `INSERT INTO device_requests
         (singleton, request_id, device_id, access_hash, signing_public_key, encryption_public_key,
          protocol_version, expires_at, status)
       VALUES (1, ?, ?, ?, ?, ?, ?, ?, 'waiting')`,
      creation.requestId,
      creation.deviceId,
      creation.deviceAccessTokenHash,
      creation.deviceSigningPublicKey,
      creation.deviceEncryptionPublicKey,
      creation.protocolVersion,
      creation.expiresAt,
    );
    return { expiresAt: creation.expiresAt, requestHash: creation.requestHash };
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
    const row = this.row();
    if (row === null || row.status === "approved" || row.status === "expired") return;
    if (row.status === "waiting") {
      if (Date.now() >= row.expires_at) this.setExpired();
      else await this.state.storage.setAlarm(row.expires_at);
      return;
    }
    const result = await this.commitApproval(row);
    if (result.status === "rejected") await this.rejectApproval();
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const row = this.requiredRow();
    if (request.method === "GET" && url.pathname === "/") return this.requestState(request, row);

    const groupMatch = /^\/groups\/([^/]+)(\/approve)?$/.exec(url.pathname);
    if (groupMatch === null) throw new HttpError(404, "not_found", "Endpoint not found");
    const groupId = stringField({ groupId: groupMatch[1] }, "groupId", IDENTIFIER, 64);
    if (request.method === "GET" && groupMatch[2] === undefined) {
      return this.requestForGroup(request, row, groupId);
    }
    if (request.method === "POST" && groupMatch[2] === "/approve") {
      return this.approve(request, row, groupId);
    }
    throw new HttpError(404, "not_found", "Endpoint not found");
  }

  private async requestState(request: Request, initial: RequestRow): Promise<Response> {
    const deviceId = stringField(
      { deviceId: new URL(request.url).searchParams.get("deviceId") },
      "deviceId",
      IDENTIFIER,
      64,
    );
    if (deviceId !== initial.device_id) {
      throw new HttpError(403, "wrong_device", "Device request belongs to another device");
    }
    const transcript = ["notify.guru/device-request-read/v1", initial.request_id, deviceId].join("\n");
    if (!(await verifyP256Signature(initial.signing_public_key, bearerToken(request), transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device request signature is invalid");
    }
    let row = initial;
    if (row.status === "waiting" && Date.now() >= row.expires_at) {
      this.setExpired();
      row = this.requiredRow();
    }
    if (row.status === "approved") {
      if (row.approval_group_id === null || row.approval_transition_hash === null || row.approval_proof === null) {
        throw new Error("Approved DeviceRequest has no approval result");
      }
      return json({
        status: "approved",
        groupId: row.approval_group_id,
        expiresAt: row.expires_at,
        ...(row.protocol_version === 4 ? {
          transitionHash: row.approval_transition_hash,
          approvalProof: row.approval_proof,
        } : {}),
      });
    }
    return json({ status: row.status, expiresAt: row.expires_at });
  }

  private async requestForGroup(request: Request, initial: RequestRow, groupId: string): Promise<Response> {
    await this.authorizeGroup(request, groupId);
    let row = initial;
    if (row.status === "waiting" && Date.now() >= row.expires_at) {
      this.setExpired();
      row = this.requiredRow();
    }
    if (row.status === "expired") {
      throw new HttpError(410, "device_request_expired", "Device request has expired");
    }
    if (row.status === "approved") {
      throw new HttpError(409, "device_request_used", "Device request has already been approved");
    }
    if (row.status === "approving" && row.approval_group_id !== groupId) {
      throw new HttpError(409, "device_request_approving", "Device request is being approved by another group");
    }
    const descriptor = this.descriptor(row);
    return json({
      requestId: descriptor.requestId,
      deviceId: descriptor.deviceId,
      accessHash: descriptor.deviceAccessTokenHash,
      signingPublicKey: descriptor.deviceSigningPublicKey,
      encryptionPublicKey: descriptor.deviceEncryptionPublicKey,
      protocolVersion: descriptor.protocolVersion,
    });
  }

  private async approve(request: Request, initial: RequestRow, groupId: string): Promise<Response> {
    const actorDeviceId = stringField(
      { deviceId: new URL(request.url).searchParams.get("deviceId") },
      "deviceId",
      IDENTIFIER,
      64,
    );
    await this.authorizeGroup(request, groupId);
    let row = initial;
    if (row.status === "waiting" && Date.now() >= row.expires_at) {
      this.setExpired();
      row = this.requiredRow();
    }
    if (row.status === "expired") {
      throw new HttpError(410, "device_request_expired", "Device request has expired");
    }

    const body = await readObject(request);
    const preparation = await this.groupStub(groupId).prepareDeviceRequestApproval(
      this.descriptor(row),
      actorDeviceId,
      bearerToken(request),
      body,
    );
    if (preparation.status === "rejected") throw rejectionError(preparation);

    row = this.requiredRow();
    if (row.status === "approved") {
      this.requireSameApproval(row, preparation.intent);
      return this.approvedResponse(row);
    }
    if (row.status === "approving") {
      this.requireSameApproval(row, preparation.intent);
    } else {
      await this.state.storage.setAlarm(Date.now() + APPROVAL_RETRY_DELAY_MS);
      this.beginApproval(preparation.intent);
      row = this.requiredRow();
      this.requireSameApproval(row, preparation.intent);
      if (row.status === "approved") return this.approvedResponse(row);
    }

    const result = await this.commitApproval(row);
    if (result.status === "rejected") {
      await this.rejectApproval();
      throw rejectionError(result);
    }
    return this.approvedResponse(this.requiredRow());
  }

  private async commitApproval(row: RequestRow): Promise<DeviceApprovalCommitResult> {
    const intent = this.intent(row);
    const result = await this.groupStub(intent.groupId).commitDeviceRequestApproval(intent);
    if (result.status === "rejected") return result;
    this.state.storage.sql.exec(
      "UPDATE device_requests SET status = 'approved' WHERE singleton = 1 AND status = 'approving'",
    );
    await this.state.storage.deleteAlarm();
    return result;
  }

  private async rejectApproval(): Promise<void> {
    const row = this.requiredRow();
    if (row.status !== "approving") return;
    const nextState = Date.now() >= row.expires_at ? "expired" : "waiting";
    this.state.storage.sql.exec(
      `UPDATE device_requests
       SET status = ?, approval_group_id = NULL, approval_actor_device_id = NULL,
           approval_transition_hash = NULL, approval_proof = NULL, approval_intent_json = NULL
       WHERE singleton = 1 AND status = 'approving'`,
      nextState,
    );
    if (nextState === "waiting") await this.state.storage.setAlarm(row.expires_at);
    else await this.state.storage.deleteAlarm();
  }

  private async authorizeGroup(request: Request, groupId: string): Promise<void> {
    const deviceId = stringField(
      { deviceId: new URL(request.url).searchParams.get("deviceId") },
      "deviceId",
      IDENTIFIER,
      64,
    );
    const authorization = await this.groupStub(groupId).authorizeDevice(deviceId, bearerToken(request));
    if (authorization === "device_removed") {
      throw new HttpError(403, "device_removed", "Device is not an active member of the group");
    }
    if (authorization === "invalid_token") {
      throw new HttpError(401, "invalid_device_token", "Device token is invalid");
    }
  }

  private beginApproval(intent: DeviceApprovalIntent): void {
    this.state.storage.sql.exec(
      `UPDATE device_requests
       SET status = 'approving', approval_group_id = ?, approval_actor_device_id = ?,
           approval_transition_hash = ?, approval_proof = ?, approval_intent_json = ?
       WHERE singleton = 1 AND status = 'waiting'`,
      intent.groupId,
      intent.actorDeviceId,
      intent.transitionHash,
      intent.approvalProof,
      JSON.stringify(intent),
    );
  }

  private requireSameApproval(row: RequestRow, intent: DeviceApprovalIntent): void {
    if (row.approval_intent_json === null
      || row.approval_group_id !== intent.groupId
      || row.approval_actor_device_id !== intent.actorDeviceId
      || row.approval_transition_hash !== intent.transitionHash
      || row.approval_proof !== intent.approvalProof
      || row.approval_intent_json !== JSON.stringify(intent)) {
      throw new HttpError(409, "device_request_approving", "Device request is being approved by another Operation");
    }
  }

  private approvedResponse(row: RequestRow): Response {
    if (row.status !== "approved" || row.approval_group_id === null || row.approval_actor_device_id === null
      || row.approval_transition_hash === null) {
      throw new Error("DeviceRequest approval did not reach its terminal state");
    }
    return json({
      approved: true,
      deviceId: row.device_id,
      approvedByDeviceId: row.approval_actor_device_id,
      ...(row.protocol_version === 4 ? { transitionHash: row.approval_transition_hash } : {}),
    });
  }

  private descriptor(row: RequestRow): DeviceRequestDescriptor {
    return {
      requestId: row.request_id,
      deviceId: row.device_id,
      deviceAccessTokenHash: row.access_hash,
      deviceEncryptionPublicKey: row.encryption_public_key,
      deviceSigningPublicKey: row.signing_public_key,
      protocolVersion: row.protocol_version,
    };
  }

  private intent(row: RequestRow): DeviceApprovalIntent {
    if (row.status !== "approving" || row.approval_intent_json === null) {
      throw new Error("Approving DeviceRequest has no approval intent");
    }
    return JSON.parse(row.approval_intent_json) as DeviceApprovalIntent;
  }

  private setExpired(): void {
    this.state.storage.sql.exec(
      "UPDATE device_requests SET status = 'expired' WHERE singleton = 1 AND status = 'waiting'",
    );
  }

  private requiredRow(): RequestRow {
    const row = this.row();
    if (row === null) throw new HttpError(404, "device_request_not_found", "Device request not found");
    return row;
  }

  private row(): RequestRow | null {
    const rows = Array.from(this.state.storage.sql.exec<RequestRow>("SELECT * FROM device_requests WHERE singleton = 1"));
    return rows.length === 0 ? null : rows[0];
  }

  private groupStub(groupId: string): DurableObjectStub<DeviceGroup> {
    return this.groups.get(this.groups.idFromName(groupId));
  }

  private createSchema(): void {
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS device_requests (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        request_id TEXT NOT NULL UNIQUE,
        device_id TEXT NOT NULL,
        access_hash TEXT NOT NULL,
        signing_public_key TEXT NOT NULL,
        encryption_public_key TEXT NOT NULL,
        protocol_version INTEGER NOT NULL CHECK (protocol_version IN (3, 4)),
        expires_at INTEGER NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('waiting', 'approving', 'approved', 'expired')),
        approval_group_id TEXT,
        approval_actor_device_id TEXT,
        approval_transition_hash TEXT,
        approval_proof TEXT,
        approval_intent_json TEXT
      );
    `);
  }
}

function rejectionError(rejection: Extract<DeviceApprovalPreparation | DeviceApprovalCommitResult, { status: "rejected" }>): HttpError {
  return new HttpError(rejection.httpStatus, rejection.code, rejection.message);
}
