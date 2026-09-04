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
import {
  GENESIS_TRANSITION_HASH,
  type GroupTransitionContent,
  type SignedGroupTransition,
  type SignedSessionDescriptor,
  type TransitionMember,
  type TransitionPackageDigest,
  groupKeyPackageDigest,
  groupTransitionHash,
  groupTransitionTranscript,
  sessionDescriptorTranscript,
  validateP256KeyAgreementPublicKey,
  verifyP256Signature,
} from "./protocol";

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
  signing_public_key: string | null;
  request_id: string | null;
  added_at: number;
  supports_v4: number;
}

interface KeyRow extends Record<string, SqlStorageValue> {
  timestamp: number;
  public_key: string;
  recreated: number;
  created_by_device_id: string;
  transition_id: string | null;
  previous_hash: string | null;
  transition_hash: string | null;
  actor_signature: string | null;
  continuity_signature: string | null;
  members_json: string | null;
  package_digests_json: string | null;
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
  protocol_version: number;
  key_timestamp: number | null;
  transition_hash: string | null;
  actor_device_id: string | null;
  actor_signature: string | null;
  continuity_signature: string | null;
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
  deviceSigningPublicKey: string;
  protocolVersion: number;
}

export interface GroupCurrentState {
  groupId: string;
  members: string[];
  key: { timestamp: number; publicKey: string; members: string[]; transitionHash?: string } | null;
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

  supportsProtocolVersion(protocolVersion: number): boolean {
    return protocolVersion === 3 || protocolVersion === 4
      && this.getTransitionHistory().length > 0
      && this.members().every((member) => member.supports_v4 === 1 && member.signing_public_key !== null);
  }

  getKeyHistory(): Array<{ timestamp: number; publicKey: string }> {
    return this.keys().map((key) => ({ timestamp: key.timestamp, publicKey: key.public_key }));
  }

  getTransitionHistory(): SignedGroupTransition[] {
    return this.keys().flatMap((key) => {
      const transition = this.transition(key);
      return transition === null ? [] : [transition];
    });
  }

  getKeyRecipients(timestamp: number, protocolVersion = 3): { status: "ok"; deviceIds: string[] } | { status: "unavailable" } {
    const members = this.members().map((member) => member.device_id);
    const key = this.key(timestamp);
    if (protocolVersion === 4) {
      const latest = this.latestTransition();
      if (latest?.timestamp !== timestamp || this.transitionNeedsRecreation(latest)) return { status: "unavailable" };
    }
    if (key === null || !this.isUsableKey(key, members)) return { status: "unavailable" };
    return { status: "ok", deviceIds: this.keyMemberIds(timestamp) };
  }

  authorizeKeyForDevice(timestamp: number, deviceId: string, protocolVersion = 3): "authorized" | "device_removed" | "unavailable" {
    if (this.member(deviceId) === null) return "device_removed";
    if (protocolVersion === 4) {
      const latest = this.latestTransition();
      if (latest === null || latest.timestamp !== timestamp || this.transitionNeedsRecreation(latest)) return "unavailable";
    }
    return this.keyMemberIds(timestamp).includes(deviceId) ? "authorized" : "unavailable";
  }

  async storeSession(
    sessionId: string, creatorPublicKey: string, expiresAt: number, protocolVersion = 3,
    descriptor: SignedSessionDescriptor | null = null,
  ): Promise<void> {
    if (protocolVersion === 4 && descriptor !== null) await this.validateSessionDescriptor(descriptor);
    this.state.storage.sql.exec(
      `INSERT INTO group_sessions_v3
         (session_id, creator_public_key, expires_at, protocol_version, key_timestamp, transition_hash,
          actor_device_id, actor_signature, continuity_signature)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET expires_at = excluded.expires_at`,
      sessionId,
      creatorPublicKey,
      expiresAt,
      protocolVersion,
      descriptor?.keyTimestamp ?? null,
      descriptor?.transitionHash ?? null,
      descriptor?.actorDeviceId ?? null,
      descriptor?.actorSignature ?? null,
      descriptor?.continuitySignature ?? null,
    );
  }

  private async validateSessionDescriptor(descriptor: SignedSessionDescriptor): Promise<void> {
    const groupId = this.requiredMeta().group_id;
    if (descriptor.groupId !== groupId || descriptor.protocolVersion !== 4) {
      throw new HttpError(400, "invalid_session_descriptor", "Session descriptor targets another group or protocol");
    }
    if (!(await validateP256KeyAgreementPublicKey(descriptor.creatorPublicKey))) {
      throw new HttpError(400, "invalid_session_descriptor", "Session descriptor creator key is invalid");
    }
    const transition = this.getTransitionHistory().find((item) =>
      item.timestamp === descriptor.keyTimestamp && item.transitionHash === descriptor.transitionHash);
    const actor = transition?.members.find((member) => member.deviceId === descriptor.actorDeviceId);
    const currentActor = this.member(descriptor.actorDeviceId);
    if (transition === undefined || actor === undefined || currentActor === null
      || currentActor.signing_public_key !== actor.signingPublicKey
      || currentActor.encryption_public_key !== actor.encryptionPublicKey) {
      throw new HttpError(
        400,
        "invalid_session_descriptor",
        "Session descriptor is not anchored to a currently authorized device",
      );
    }
    const transcript = sessionDescriptorTranscript(descriptor);
    if (!(await verifyP256Signature(actor.signingPublicKey, descriptor.actorSignature, transcript))
      || !(await verifyP256Signature(transition.publicKey, descriptor.continuitySignature, transcript))) {
      throw new HttpError(401, "invalid_session_descriptor", "Session descriptor signature is invalid");
    }
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
      const protocolVersion = url.searchParams.get("protocolVersion") === "4" ? 4 : 3;
      if (protocolVersion === 4 && member.supports_v4 !== 1) {
        this.state.storage.sql.exec("UPDATE group_members_v3 SET supports_v4 = 1 WHERE device_id = ?", member.device_id);
      }
      return this.groupState(meta, member.device_id, protocolVersion);
    }
    if (request.method === "POST" && url.pathname === "/keys") {
      const member = await this.requireMember(request);
      return this.createKey(request, member);
    }
    const requestStateMatch = /^\/device-requests\/([^/]+)$/.exec(url.pathname);
    if (request.method === "GET" && requestStateMatch !== null) {
      await this.requireMember(request);
      return this.deviceRequestForApproval(identifier(requestStateMatch[1], "requestId"));
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
    ], ["protocolVersion", "transition", "packages"]);
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
    const protocolVersion = body.protocolVersion === 4 ? 4 : 3;
    const transition = protocolVersion === 4 ? signedTransition(body.transition) : null;
    const packages = protocolVersion === 4 ? packageArray(body.packages) : [];
    const member: TransitionMember = { deviceId, signingPublicKey: device.signingPublicKey, encryptionPublicKey };
    if (transition !== null) {
      await validateTransitionMaterial(groupId, transition, packages, null, [member], member);
    }
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("INSERT INTO group_meta_v3 (singleton, group_id) VALUES (1, ?)", groupId);
      this.state.storage.sql.exec(
        `INSERT INTO group_members_v3
           (device_id, access_hash, encryption_public_key, signing_public_key, added_at, supports_v4)
         VALUES (?, ?, ?, ?, ?, ?)`,
        deviceId,
        accessHash,
        encryptionPublicKey,
        device.signingPublicKey,
        now,
        protocolVersion === 4 ? 1 : 0,
      );
      if (transition !== null) this.insertTransition(transition, packages);
    });
    return json({ created: true, groupId }, 201);
  }

  private async deviceRequestForApproval(requestId: string): Promise<Response> {
    const request = await this.devices.getDeviceRequestForApproval(requestId);
    if (request === null) throw new HttpError(404, "device_request_not_found", "Device request is unavailable");
    return json({
      requestId: request.requestId,
      deviceId: request.deviceId,
      accessHash: request.deviceAccessTokenHash,
      signingPublicKey: request.deviceSigningPublicKey,
      encryptionPublicKey: request.deviceEncryptionPublicKey,
      protocolVersion: request.protocolVersion,
    });
  }

  private async approveDeviceRequest(
    request: Request,
    meta: MetaRow,
    actor: MemberRow,
    requestId: string,
  ): Promise<Response> {
    const body = await readObject(request);
    if (this.getTransitionHistory().length > 0) {
      expectKeys(body, ["transition", "packages", "approvalProof"]);
      const transition = signedTransition(body.transition);
      const packages = packageArray(body.packages);
      const approvalProof = stringField(body, "approvalProof", BASE64URL, 128);
      const existing = this.memberByRequest(requestId);
      if (existing !== null) {
        const latest = this.latestTransition();
        if (latest === null || transition.transitionHash !== latest.transitionHash) {
          throw new HttpError(409, "group_transition_changed", "Approved device transition no longer matches the group head");
        }
        await this.completeRequest(requestId, meta.group_id, latest.transitionHash, approvalProof);
        return json({
          approved: true,
          deviceId: existing.device_id,
          approvedByDeviceId: actor.device_id,
          transitionHash: latest.transitionHash,
        });
      }
      const currentTransition = this.latestTransition();
      if (currentTransition !== null && this.transitionNeedsRecreation(currentTransition)) {
        throw new HttpError(409, "recreated_required", "The pending device removal must be followed by a fresh group key");
      }
      const claimed = await this.claimRequest(requestId, meta.group_id);
      if (claimed.protocolVersion !== 4) {
        await this.devices.releaseDeviceRequestClaim(requestId, meta.group_id);
        throw new HttpError(409, "protocol_upgrade_required", "This device group requires version 4 device approval");
      }
      if (this.member(claimed.deviceId) !== null) {
        throw new HttpError(409, "device_exists", "Device already belongs to the group");
      }
      const expected = [
        ...this.transitionMembers(),
        {
          deviceId: claimed.deviceId,
          signingPublicKey: claimed.deviceSigningPublicKey,
          encryptionPublicKey: claimed.deviceEncryptionPublicKey,
        },
      ];
      const previous = this.latestTransition();
      await validateTransitionMaterial(
        meta.group_id,
        transition,
        packages,
        previous,
        expected,
        this.memberDescriptor(actor),
      );
      this.state.storage.transactionSync(() => {
        this.state.storage.sql.exec(
          `INSERT INTO group_members_v3
             (device_id, access_hash, encryption_public_key, signing_public_key, request_id, added_at, supports_v4)
           VALUES (?, ?, ?, ?, ?, ?, 1)`,
          claimed.deviceId,
          claimed.deviceAccessTokenHash,
          claimed.deviceEncryptionPublicKey,
          claimed.deviceSigningPublicKey,
          requestId,
          Date.now(),
        );
        this.insertTransition(transition, packages);
      });
      await this.completeRequest(requestId, meta.group_id, transition.transitionHash, approvalProof);
      return json({
        approved: true,
        deviceId: claimed.deviceId,
        approvedByDeviceId: actor.device_id,
        transitionHash: transition.transitionHash,
      });
    }
    expectKeys(body, ["actorSignature"]);
    await this.requireManagementSignature(
      actor.device_id,
      stringField(body, "actorSignature", BASE64URL, 128),
      ["notify.guru/group-device-approve/v1", meta.group_id, actor.device_id, requestId].join("\n"),
    );
    const requestMember = this.memberByRequest(requestId);
    if (requestMember !== null) {
      await this.completeRequest(requestId, meta.group_id, GENESIS_TRANSITION_HASH, "");
      return json({ approved: true, deviceId: requestMember.device_id, approvedByDeviceId: actor.device_id });
    }
    const claimed = await this.claimRequest(requestId, meta.group_id);
    if (claimed.protocolVersion < 4 && this.hasActiveV4Sessions()) {
      await this.devices.releaseDeviceRequestClaim(requestId, meta.group_id);
      throw new HttpError(409, "protocol_upgrade_required", "This device group has version 4 sessions");
    }
    if (this.member(claimed.deviceId) !== null) {
      throw new HttpError(409, "device_exists", "Device already belongs to the group");
    }
    this.state.storage.sql.exec(
      `INSERT INTO group_members_v3
         (device_id, access_hash, encryption_public_key, request_id, added_at, supports_v4)
       VALUES (?, ?, ?, ?, ?, ?)`,
      claimed.deviceId,
      claimed.deviceAccessTokenHash,
      claimed.deviceEncryptionPublicKey,
      requestId,
      Date.now(),
      claimed.protocolVersion >= 4 ? 1 : 0,
    );
    await this.completeRequest(requestId, meta.group_id, GENESIS_TRANSITION_HASH, "");
    return json({ approved: true, deviceId: claimed.deviceId, approvedByDeviceId: actor.device_id });
  }

  private async createKey(request: Request, actor: MemberRow): Promise<Response> {
    const body = await readObject(request);
    if (this.getTransitionHistory().length > 0) {
      expectKeys(body, ["transition", "packages"]);
      const transition = signedTransition(body.transition);
      const packages = packageArray(body.packages);
      const previous = this.latestTransition();
      if (previous !== null && this.transitionNeedsRecreation(previous)
        && (!transition.recreated || transition.publicKey === previous.publicKey)) {
        throw new HttpError(409, "recreated_required", "The pending device removal requires a new group key");
      }
      await validateTransitionMaterial(
        this.requiredMeta().group_id,
        transition,
        packages,
        previous,
        this.transitionMembers(),
        this.memberDescriptor(actor),
      );
      this.state.storage.transactionSync(() => this.insertTransition(transition, packages));
      return json({ timestamp: transition.timestamp, transitionHash: transition.transitionHash }, 201);
    }
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
    if (this.getTransitionHistory().length > 0) {
      const activeMembers = this.transitionMembers();
      const latest = this.latestTransition();
      if (activeMembers.length === 1 && deviceId === actor.device_id) {
        expectKeys(body, ["actorSignature", "headTransitionHash"]);
        if (latest === null) throw new Error("Version 4 group has no transition head");
        const headTransitionHash = stringField(body, "headTransitionHash", SHA256_HEX, 64);
        if (headTransitionHash !== latest.transitionHash) {
          throw new HttpError(409, "group_transition_changed", "Group transition head has changed");
        }
        await this.requireManagementSignature(
          actor.device_id,
          stringField(body, "actorSignature", BASE64URL, 128),
          ["notify.guru/group-abandon/v1", meta.group_id, actor.device_id, headTransitionHash].join("\n"),
        );
        this.state.storage.sql.exec("DELETE FROM group_members_v3 WHERE device_id = ?", deviceId);
        await this.devices.deactivateGroupDevice(meta.group_id, deviceId);
        return json({ removed: true, transitionHash: headTransitionHash });
      }
      expectKeys(body, ["transition", "packages"]);
      if (this.member(deviceId) === null) {
        throw new HttpError(404, "device_not_found", "Active device not found");
      }
      const expected = activeMembers.filter((member) => member.deviceId !== deviceId);
      if (expected.length === 0) throw new HttpError(409, "last_device", "The last device cannot leave its group");
      const transition = signedTransition(body.transition);
      const packages = packageArray(body.packages);
      const previous = this.latestTransition();
      if (previous === null) throw new Error("Version 4 group has no transition head");
      await validateTransitionMaterial(
        meta.group_id,
        transition,
        packages,
        previous,
        expected,
        this.memberDescriptor(actor),
      );
      if (deviceId === actor.device_id) {
        if (transition.recreated || transition.publicKey !== previous.publicKey) {
          throw new HttpError(400, "invalid_self_removal", "A leaving device may only sign a removal marker for the existing key");
        }
      } else if (!transition.recreated || transition.publicKey === previous.publicKey) {
        throw new HttpError(400, "recreated_required", "Removing another device must create a fresh group key");
      }
      this.state.storage.transactionSync(() => {
        this.state.storage.sql.exec("DELETE FROM group_members_v3 WHERE device_id = ?", deviceId);
        this.insertTransition(transition, packages);
      });
      await this.devices.deactivateGroupDevice(meta.group_id, deviceId);
      return json({ removed: true, transitionHash: transition.transitionHash });
    }
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

  private groupState(meta: MetaRow, deviceId: string, protocolVersion: number): Response {
    const members = this.members().map((member) => ({
      deviceId: member.device_id,
      encryptionPublicKey: member.encryption_public_key,
      addedAt: member.added_at,
      ...(protocolVersion === 4 ? { signingPublicKey: member.signing_public_key } : {}),
    }));
    const keys = protocolVersion === 4
      ? this.getTransitionHistory()
      : this.keys().map((key) => ({
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
    return json({
      groupId: meta.group_id,
      members,
      keys,
      packages,
      sessions: this.sessionsJSON(protocolVersion, meta.group_id),
    });
  }

  private current(meta: MetaRow): GroupCurrentState {
    const members = this.members().map((member) => member.device_id);
    const latest = this.latestTransition();
    const currentKey = latest !== null && this.transitionNeedsRecreation(latest) ? null : this.currentKey(members);
    return {
      groupId: meta.group_id,
      members,
      key: currentKey === null ? null : {
        timestamp: currentKey.timestamp,
        publicKey: currentKey.public_key,
        members: this.keyMemberIds(currentKey.timestamp),
        ...(currentKey.transition_hash === null ? {} : { transitionHash: currentKey.transition_hash }),
      },
    };
  }

  private sessionsJSON(protocolVersion: number, groupId: string): Array<Record<string, unknown>> {
    const currentMemberIds = new Set(this.members().map((member) => member.device_id));
    return Array.from(this.state.storage.sql.exec<SessionRow>(
      `SELECT session_id, creator_public_key, expires_at, protocol_version, key_timestamp, transition_hash,
              actor_device_id, actor_signature, continuity_signature
       FROM group_sessions_v3 WHERE expires_at > ? AND protocol_version = ? ORDER BY expires_at`,
      Date.now(),
      protocolVersion,
    )).filter((row) => protocolVersion !== 4
      || (row.actor_device_id !== null && currentMemberIds.has(row.actor_device_id))).map((row) => ({
      sessionId: row.session_id,
      creatorPublicKey: row.creator_public_key,
      expiresAt: row.expires_at,
      ...(protocolVersion === 4 ? { protocolVersion: row.protocol_version } : {}),
      ...(protocolVersion === 4 ? {
        groupId,
        keyTimestamp: row.key_timestamp,
        transitionHash: row.transition_hash,
        actorDeviceId: row.actor_device_id,
        actorSignature: row.actor_signature,
        continuitySignature: row.continuity_signature,
      } : {}),
    }));
  }

  private hasActiveV4Sessions(): boolean {
    return Array.from(this.state.storage.sql.exec<{ found: number }>(
      "SELECT 1 AS found FROM group_sessions_v3 WHERE expires_at > ? AND protocol_version = 4 LIMIT 1",
      Date.now(),
    )).length > 0;
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
      `SELECT device_id, access_hash, encryption_public_key, signing_public_key, request_id, added_at, supports_v4
       FROM group_members_v3 ORDER BY added_at, device_id`,
    ));
  }

  private member(deviceId: string): MemberRow | null {
    const rows = Array.from(this.state.storage.sql.exec<MemberRow>(
      `SELECT device_id, access_hash, encryption_public_key, signing_public_key, request_id, added_at, supports_v4
       FROM group_members_v3 WHERE device_id = ?`,
      deviceId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private memberByRequest(requestId: string): MemberRow | null {
    const rows = Array.from(this.state.storage.sql.exec<MemberRow>(
      `SELECT device_id, access_hash, encryption_public_key, signing_public_key, request_id, added_at, supports_v4
       FROM group_members_v3 WHERE request_id = ?`,
      requestId,
    ));
    return rows.length === 0 ? null : rows[0];
  }

  private keys(): KeyRow[] {
    return Array.from(this.state.storage.sql.exec<KeyRow>(
      `SELECT timestamp, public_key, recreated, created_by_device_id,
              transition_id, previous_hash, transition_hash, actor_signature,
              continuity_signature, members_json, package_digests_json
       FROM group_keys_v3 ORDER BY timestamp`,
    ));
  }

  private key(timestamp: number): KeyRow | null {
    const rows = Array.from(this.state.storage.sql.exec<KeyRow>(
      `SELECT timestamp, public_key, recreated, created_by_device_id,
              transition_id, previous_hash, transition_hash, actor_signature,
              continuity_signature, members_json, package_digests_json
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

  private memberDescriptor(member: MemberRow): TransitionMember {
    if (member.signing_public_key === null) {
      throw new HttpError(409, "protocol_upgrade_required", "Device group does not have an authenticated version 4 chain");
    }
    return {
      deviceId: member.device_id,
      signingPublicKey: member.signing_public_key,
      encryptionPublicKey: member.encryption_public_key,
    };
  }

  private transitionMembers(): TransitionMember[] {
    return this.members().map((member) => this.memberDescriptor(member));
  }

  private transition(key: KeyRow): SignedGroupTransition | null {
    if (key.transition_id === null || key.previous_hash === null || key.transition_hash === null
      || key.actor_signature === null || key.continuity_signature === null
      || key.members_json === null || key.package_digests_json === null) return null;
    return {
      transitionId: key.transition_id,
      previousHash: key.previous_hash,
      transitionHash: key.transition_hash,
      timestamp: key.timestamp,
      actorDeviceId: key.created_by_device_id,
      publicKey: key.public_key,
      recreated: key.recreated === 1,
      members: JSON.parse(key.members_json) as TransitionMember[],
      packageDigests: JSON.parse(key.package_digests_json) as TransitionPackageDigest[],
      actorSignature: key.actor_signature,
      continuitySignature: key.continuity_signature,
    };
  }

  private latestTransition(): SignedGroupTransition | null {
    const latest = this.keys().at(-1);
    return latest === undefined ? null : this.transition(latest);
  }

  private transitionNeedsRecreation(transition: SignedGroupTransition): boolean {
    if (transition.recreated) return false;
    const history = this.getTransitionHistory();
    const index = history.findIndex((item) => item.transitionHash === transition.transitionHash);
    if (index <= 0) return false;
    const currentMembers = new Set(transition.members.map((member) => member.deviceId));
    return history[index - 1].members.some((member) => !currentMembers.has(member.deviceId));
  }

  private insertTransition(transition: SignedGroupTransition, packages: KeyPackage[]): void {
    this.state.storage.sql.exec(
      `INSERT INTO group_keys_v3
         (timestamp, public_key, recreated, created_by_device_id, transition_id, previous_hash,
          transition_hash, actor_signature, continuity_signature, members_json, package_digests_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      transition.timestamp,
      transition.publicKey,
      transition.recreated ? 1 : 0,
      transition.actorDeviceId,
      transition.transitionId,
      transition.previousHash,
      transition.transitionHash,
      transition.actorSignature,
      transition.continuitySignature,
      JSON.stringify([...transition.members].sort((a, b) => canonicalCompare(a.deviceId, b.deviceId))),
      JSON.stringify([...transition.packageDigests].sort((a, b) => canonicalCompare(a.deviceId, b.deviceId))),
    );
    for (const member of transition.members) {
      this.state.storage.sql.exec(
        "INSERT INTO group_key_members_v3 (key_timestamp, device_id) VALUES (?, ?)",
        transition.timestamp,
        member.deviceId,
      );
    }
    for (const keyPackage of packages) {
      this.state.storage.sql.exec(
        `INSERT INTO group_key_packages_v3
           (key_timestamp, device_id, ephemeral_public_key, nonce, ciphertext)
         VALUES (?, ?, ?, ?, ?)`,
        transition.timestamp,
        keyPackage.deviceId,
        keyPackage.ephemeralPublicKey,
        keyPackage.nonce,
        keyPackage.ciphertext,
      );
    }
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

  private async completeRequest(
    requestId: string,
    groupId: string,
    transitionHash: string,
    approvalProof: string,
  ): Promise<void> {
    const result = await this.devices.completeDeviceRequest(requestId, groupId, transitionHash, approvalProof);
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
        signing_public_key TEXT,
        request_id TEXT UNIQUE,
        added_at INTEGER NOT NULL,
        supports_v4 INTEGER NOT NULL DEFAULT 0 CHECK (supports_v4 IN (0, 1))
      );
      CREATE TABLE IF NOT EXISTS group_keys_v3 (
        timestamp INTEGER PRIMARY KEY,
        public_key TEXT NOT NULL,
        recreated INTEGER NOT NULL CHECK (recreated IN (0, 1)),
        created_by_device_id TEXT NOT NULL,
        transition_id TEXT UNIQUE,
        previous_hash TEXT,
        transition_hash TEXT UNIQUE,
        actor_signature TEXT,
        continuity_signature TEXT,
        members_json TEXT,
        package_digests_json TEXT
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
        expires_at INTEGER NOT NULL,
        protocol_version INTEGER NOT NULL DEFAULT 3 CHECK (protocol_version IN (3, 4)),
        key_timestamp INTEGER,
        transition_hash TEXT,
        actor_device_id TEXT,
        actor_signature TEXT,
        continuity_signature TEXT
      );
    `);
    const memberColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(group_members_v3)"));
    if (!memberColumns.some((column) => column.name === "supports_v4")) {
      this.state.storage.sql.exec("ALTER TABLE group_members_v3 ADD COLUMN supports_v4 INTEGER NOT NULL DEFAULT 0");
    }
    if (!memberColumns.some((column) => column.name === "signing_public_key")) {
      this.state.storage.sql.exec("ALTER TABLE group_members_v3 ADD COLUMN signing_public_key TEXT");
    }
    const keyColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(group_keys_v3)"));
    for (const [name, declaration] of [
      ["transition_id", "TEXT"],
      ["previous_hash", "TEXT"],
      ["transition_hash", "TEXT"],
      ["actor_signature", "TEXT"],
      ["continuity_signature", "TEXT"],
      ["members_json", "TEXT"],
      ["package_digests_json", "TEXT"],
    ] as const) {
      if (!keyColumns.some((column) => column.name === name)) {
        this.state.storage.sql.exec(`ALTER TABLE group_keys_v3 ADD COLUMN ${name} ${declaration}`);
      }
    }
    const sessionColumns = Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(group_sessions_v3)"));
    if (!sessionColumns.some((column) => column.name === "protocol_version")) {
      this.state.storage.sql.exec("ALTER TABLE group_sessions_v3 ADD COLUMN protocol_version INTEGER NOT NULL DEFAULT 3");
    }
    for (const [name, declaration] of [
      ["key_timestamp", "INTEGER"],
      ["transition_hash", "TEXT"],
      ["actor_device_id", "TEXT"],
      ["actor_signature", "TEXT"],
      ["continuity_signature", "TEXT"],
    ] as const) {
      if (!sessionColumns.some((column) => column.name === name)) {
        this.state.storage.sql.exec(`ALTER TABLE group_sessions_v3 ADD COLUMN ${name} ${declaration}`);
      }
    }
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

function signedTransition(value: unknown): SignedGroupTransition {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_field", "Invalid group transition");
  }
  const object = value as Record<string, unknown>;
  expectKeys(object, [
    "transitionId",
    "previousHash",
    "transitionHash",
    "timestamp",
    "actorDeviceId",
    "publicKey",
    "recreated",
    "members",
    "packageDigests",
    "actorSignature",
    "continuitySignature",
  ]);
  const timestamp = integerField(object, "timestamp");
  if (timestamp <= 0) throw new HttpError(400, "invalid_field", "Transition timestamp must be positive");
  return {
    transitionId: stringField(object, "transitionId", IDENTIFIER, 64),
    previousHash: stringField(object, "previousHash", SHA256_HEX, 64),
    transitionHash: stringField(object, "transitionHash", SHA256_HEX, 64),
    timestamp,
    actorDeviceId: stringField(object, "actorDeviceId", IDENTIFIER, 64),
    publicKey: stringField(object, "publicKey", PUBLIC_KEY, 128),
    recreated: booleanField(object, "recreated"),
    members: transitionMemberArray(object.members),
    packageDigests: transitionPackageDigestArray(object.packageDigests),
    actorSignature: stringField(object, "actorSignature", BASE64URL, 128),
    continuitySignature: stringField(object, "continuitySignature", BASE64URL, 128),
  };
}

function transitionMemberArray(value: unknown): TransitionMember[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) {
    throw new HttpError(400, "invalid_field", "Invalid transition members");
  }
  const members = value.map((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "invalid_field", "Invalid transition member");
    }
    const object = item as Record<string, unknown>;
    expectKeys(object, ["deviceId", "signingPublicKey", "encryptionPublicKey"]);
    return {
      deviceId: stringField(object, "deviceId", IDENTIFIER, 64),
      signingPublicKey: stringField(object, "signingPublicKey", PUBLIC_KEY, 128),
      encryptionPublicKey: stringField(object, "encryptionPublicKey", PUBLIC_KEY, 128),
    };
  });
  if (new Set(members.map((member) => member.deviceId)).size !== members.length) {
    throw new HttpError(400, "invalid_field", "Transition members must be unique");
  }
  return members;
}

function transitionPackageDigestArray(value: unknown): TransitionPackageDigest[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) {
    throw new HttpError(400, "invalid_field", "Invalid transition package digests");
  }
  const result = value.map((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "invalid_field", "Invalid transition package digest");
    }
    const object = item as Record<string, unknown>;
    expectKeys(object, ["deviceId", "sha256"]);
    return {
      deviceId: stringField(object, "deviceId", IDENTIFIER, 64),
      sha256: stringField(object, "sha256", SHA256_HEX, 64),
    };
  });
  if (new Set(result.map((item) => item.deviceId)).size !== result.length) {
    throw new HttpError(400, "invalid_field", "Transition package digests must be unique");
  }
  return result;
}

async function validateTransitionMaterial(
  groupId: string,
  transition: SignedGroupTransition,
  packages: KeyPackage[],
  previous: SignedGroupTransition | null,
  expectedMembers: TransitionMember[],
  actor: TransitionMember,
): Promise<void> {
  const expectedPreviousHash = previous?.transitionHash ?? GENESIS_TRANSITION_HASH;
  if (transition.previousHash !== expectedPreviousHash) {
    throw new HttpError(409, "group_transition_changed", "Group transition head has changed");
  }
  if (previous !== null && transition.timestamp <= previous.timestamp) {
    throw new HttpError(409, "key_timestamp_conflict", "Transition timestamp must advance");
  }
  if (transition.actorDeviceId !== actor.deviceId) {
    throw new HttpError(400, "invalid_actor", "Transition actor does not match the authenticated device");
  }
  if (!sameMembers(transition.members, expectedMembers)) {
    throw new HttpError(409, "member_set_changed", "Transition members do not match the expected group members");
  }
  if (!sameStringSet(transition.packageDigests.map((item) => item.deviceId), expectedMembers.map((item) => item.deviceId))
    || !sameStringSet(packages.map((item) => item.deviceId), expectedMembers.map((item) => item.deviceId))) {
    throw new HttpError(400, "invalid_package_set", "Transition packages must target every resulting member exactly once");
  }
  const actualDigests = new Map<string, string>();
  for (const keyPackage of packages) actualDigests.set(keyPackage.deviceId, await groupKeyPackageDigest(keyPackage));
  for (const digest of transition.packageDigests) {
    if (actualDigests.get(digest.deviceId) !== digest.sha256) {
      throw new HttpError(400, "invalid_package_digest", "Transition package digest does not match its package");
    }
  }
  if (previous === null && !transition.recreated) {
    throw new HttpError(400, "recreated_required", "Genesis transition must create a fresh group key");
  }
  const transcript = groupTransitionTranscript(groupId, transition);
  if (!(await verifyP256Signature(actor.signingPublicKey, transition.actorSignature, transcript))) {
    throw new HttpError(401, "invalid_device_signature", "Transition actor signature is invalid");
  }
  const continuityPublicKey = previous?.publicKey ?? transition.publicKey;
  if (!(await verifyP256Signature(continuityPublicKey, transition.continuitySignature, transcript))) {
    throw new HttpError(401, "invalid_continuity_signature", "Group key continuity signature is invalid");
  }
  const expectedHash = await groupTransitionHash(
    groupId,
    transition,
    transition.actorSignature,
    transition.continuitySignature,
  );
  if (transition.transitionHash !== expectedHash) {
    throw new HttpError(400, "invalid_transition_hash", "Group transition hash is invalid");
  }
}

function sameMembers(left: TransitionMember[], right: TransitionMember[]): boolean {
  const normalized = (members: TransitionMember[]) => [...members]
    .sort((a, b) => canonicalCompare(a.deviceId, b.deviceId))
    .map((member) => `${member.deviceId}\n${member.signingPublicKey}\n${member.encryptionPublicKey}`);
  const leftValues = normalized(left);
  const rightValues = normalized(right);
  return leftValues.length === rightValues.length && leftValues.every((value, index) => value === rightValues[index]);
}

function canonicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
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
