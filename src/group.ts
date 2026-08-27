import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  SHA256_HEX,
  bearerToken,
  equalHex,
  expectKeys,
  integerField,
  integerQuery,
  json,
  readObject,
  sha256Hex,
  stringField,
} from "./http";

const INVITATION_LIFETIME_MS = 10 * 60 * 1000;
const INTERNAL_HEADER = "x-notify-guru-internal";
const PUBLIC_KEY = BASE64URL;
const SIGNATURE = BASE64URL;

interface MetaRow extends Record<string, SqlStorageValue> {
  group_id: string;
  revision: number;
  generation: number;
  generation_public_key: string;
}

interface DeviceRow extends Record<string, SqlStorageValue> {
  id: string;
  access_hash: string;
  encryption_public_key: string;
  signing_public_key: string;
  added_revision: number;
  removed_revision: number | null;
  added_at: number;
  removed_at: number | null;
}

interface InvitationRow extends Record<string, SqlStorageValue> {
  id: string;
  token_hash: string;
  inviter_device_id: string;
  expires_at: number;
  consumed_at: number | null;
}

interface JoinRequestRow extends Record<string, SqlStorageValue> {
  invitation_id: string;
  device_id: string;
  access_hash: string;
  encryption_public_key: string;
  signing_public_key: string;
  created_at: number;
  decided_at: number | null;
  decision: string | null;
}

interface PackageRow extends Record<string, SqlStorageValue> {
  generation: number;
  device_id: string;
  ephemeral_public_key: string;
  nonce: string;
  ciphertext: string;
}

interface TransitionRow extends Record<string, SqlStorageValue> {
  revision: number;
  previous_generation: number;
  generation: number;
  generation_public_key: string;
  action: string;
  actor_device_id: string;
  target_device_id: string;
  packages_hash: string;
  group_signature: string;
  device_signature: string;
  created_at: number;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  session_id: string;
  creator_public_key: string;
  expires_at: number;
}

interface KeyPackage {
  generation: number;
  deviceId: string;
  ephemeralPublicKey: string;
  nonce: string;
  ciphertext: string;
}

interface TransitionInput {
  expectedRevision: number;
  nextGenerationPublicKey: string;
  packages: KeyPackage[];
  groupSignature: string;
  deviceSignature: string;
}

export class DeviceGroup {
  constructor(private readonly state: DurableObjectState) {
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

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/create") {
      return this.create(request);
    }

    const meta = await this.meta();
    if (request.method === "GET" && url.pathname === "/state") {
      const device = await this.requireDevice(request);
      return this.groupState(meta, device.id, integerQuery(url, "afterGeneration"));
    }
    if (request.method === "POST" && url.pathname === "/invitations") {
      const device = await this.requireDevice(request);
      return this.createInvitation(request, device);
    }
    if (request.method === "POST" && url.pathname === "/join-requests") {
      return this.createJoinRequest(request);
    }
    const joinMatch = /^\/join-requests\/([^/]+)(?:\/(approve|reject))?$/.exec(url.pathname);
    if (joinMatch !== null) {
      const invitationId = identifier(joinMatch[1], "invitationId");
      if (request.method === "GET" && joinMatch[2] === undefined) {
        return this.joinRequest(request, invitationId);
      }
      if (request.method === "POST" && joinMatch[2] === "approve") {
        const device = await this.requireDevice(request);
        return this.approve(request, meta, device, invitationId);
      }
      if (request.method === "POST" && joinMatch[2] === "reject") {
        const device = await this.requireDevice(request);
        return this.reject(meta, device, invitationId);
      }
    }
    const removeMatch = /^\/devices\/([^/]+)\/remove$/.exec(url.pathname);
    if (request.method === "POST" && removeMatch !== null) {
      const device = await this.requireDevice(request);
      return this.remove(request, meta, device, identifier(removeMatch[1], "deviceId"));
    }
    if (request.method === "GET" && url.pathname === "/sessions") {
      await this.requireDevice(request);
      return this.sessions();
    }
    if (request.headers.get(INTERNAL_HEADER) === "1") {
      if (request.method === "POST" && url.pathname === "/authorize") {
        const device = await this.requireDevice(request);
        return json({ authorized: true, deviceId: device.id, revision: meta.revision, generation: meta.generation });
      }
      if (request.method === "GET" && url.pathname === "/current") {
        return this.current(meta, integerQuery(url, "afterGeneration"));
      }
      if (request.method === "PUT" && url.pathname === "/sessions") {
        return this.putSession(request);
      }
    }
    throw new HttpError(404, "not_found", "Endpoint not found");
  }

  private async create(request: Request): Promise<Response> {
    if (this.metaRow() !== null) {
      throw new HttpError(409, "group_exists", "Device group already exists");
    }
    const body = await readObject(request);
    expectKeys(body, [
      "groupId",
      "deviceId",
      "deviceAccessTokenHash",
      "deviceEncryptionPublicKey",
      "deviceSigningPublicKey",
      "generationPublicKey",
      "package",
      "deviceSignature",
    ]);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const accessHash = stringField(body, "deviceAccessTokenHash", SHA256_HEX, 64);
    const encryptionPublicKey = stringField(body, "deviceEncryptionPublicKey", PUBLIC_KEY, 128);
    const signingPublicKey = stringField(body, "deviceSigningPublicKey", PUBLIC_KEY, 128);
    const generationPublicKey = stringField(body, "generationPublicKey", PUBLIC_KEY, 128);
    const keyPackage = packageObject(body.package);
    const deviceSignature = stringField(body, "deviceSignature", SIGNATURE, 128);
    if (keyPackage.generation !== 1 || keyPackage.deviceId !== deviceId) {
      throw new HttpError(400, "invalid_package_set", "Initial package must target generation 1 and the initial device");
    }
    const packagesHash = await hashPackages([keyPackage]);
    const transcript = createTranscript(
      groupId,
      deviceId,
      encryptionPublicKey,
      signingPublicKey,
      generationPublicKey,
      packagesHash,
    );
    if (!(await verifySignature(signingPublicKey, deviceSignature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Initial device signature is invalid");
    }

    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(
        `INSERT INTO meta
           (singleton, group_id, revision, generation, generation_public_key)
         VALUES (1, ?, 1, 1, ?)`,
        groupId,
        generationPublicKey,
      );
      this.state.storage.sql.exec(
        `INSERT INTO devices
           (id, access_hash, encryption_public_key, signing_public_key, added_revision, added_at)
         VALUES (?, ?, ?, ?, 1, ?)`,
        deviceId,
        accessHash,
        encryptionPublicKey,
        signingPublicKey,
        now,
      );
      this.insertPackage(keyPackage);
    });
    return json({ created: true, revision: 1, generation: 1 }, 201);
  }

  private async createInvitation(request: Request, device: DeviceRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["invitationId", "invitationTokenHash"]);
    const invitationId = stringField(body, "invitationId", IDENTIFIER, 64);
    const tokenHash = stringField(body, "invitationTokenHash", SHA256_HEX, 64);
    const now = Date.now();
    const expiresAt = now + INVITATION_LIFETIME_MS;
    this.state.storage.sql.exec(
      "INSERT INTO invitations (id, token_hash, inviter_device_id, expires_at) VALUES (?, ?, ?, ?)",
      invitationId,
      tokenHash,
      device.id,
      expiresAt,
    );
    return json({ created: true, expiresAt }, 201);
  }

  private async createJoinRequest(request: Request): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, [
      "invitationId",
      "invitationToken",
      "deviceId",
      "deviceAccessTokenHash",
      "deviceEncryptionPublicKey",
      "deviceSigningPublicKey",
    ]);
    const invitationId = stringField(body, "invitationId", IDENTIFIER, 64);
    const invitationToken = stringField(body, "invitationToken", BASE64URL, 128);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const accessHash = stringField(body, "deviceAccessTokenHash", SHA256_HEX, 64);
    const encryptionPublicKey = stringField(body, "deviceEncryptionPublicKey", PUBLIC_KEY, 128);
    const signingPublicKey = stringField(body, "deviceSigningPublicKey", PUBLIC_KEY, 128);
    const invitation = this.invitation(invitationId);
    if (invitation.consumed_at !== null || Date.now() >= invitation.expires_at) {
      throw new HttpError(410, "invitation_expired", "Device invitation has expired");
    }
    if (!equalHex(invitation.token_hash, await sha256Hex(invitationToken))) {
      throw new HttpError(401, "invalid_invitation_token", "Device invitation token is invalid");
    }
    if (this.device(deviceId) !== null) {
      throw new HttpError(409, "device_exists", "Device already belongs to the group");
    }
    if (this.joinRequestRow(invitationId) !== null) {
      throw new HttpError(409, "join_request_exists", "This invitation already has a join request");
    }
    this.state.storage.sql.exec(
      `INSERT INTO join_requests
         (invitation_id, device_id, access_hash, encryption_public_key, signing_public_key, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      invitationId,
      deviceId,
      accessHash,
      encryptionPublicKey,
      signingPublicKey,
      Date.now(),
    );
    return json({ requested: true, expiresAt: invitation.expires_at }, 201);
  }

  private async joinRequest(request: Request, invitationId: string): Promise<Response> {
    const invitationToken = bearerToken(request);
    const invitation = this.invitation(invitationId);
    if (!equalHex(invitation.token_hash, await sha256Hex(invitationToken))) {
      throw new HttpError(401, "invalid_invitation_token", "Device invitation token is invalid");
    }
    const pending = this.joinRequestRow(invitationId);
    if (pending === null) {
      return json({ status: invitation.consumed_at === null ? "waiting" : "expired" });
    }
    if (pending.decision === "approved") {
      return json({ status: "approved" });
    }
    if (pending.decision === "rejected") {
      return json({ status: "rejected" });
    }
    if (Date.now() >= invitation.expires_at) {
      return json({ status: "expired" });
    }
    return json({ status: "pending" });
  }

  private async approve(
    request: Request,
    meta: MetaRow,
    actor: DeviceRow,
    invitationId: string,
  ): Promise<Response> {
    const invitation = this.invitation(invitationId);
    if (invitation.inviter_device_id !== actor.id) {
      throw new HttpError(403, "wrong_inviter", "Only the inviting device can approve this request");
    }
    if (invitation.consumed_at !== null || Date.now() >= invitation.expires_at) {
      throw new HttpError(410, "invitation_expired", "Device invitation has expired");
    }
    const pending = this.joinRequestRow(invitationId);
    if (pending === null || pending.decision !== null) {
      throw new HttpError(409, "join_request_unavailable", "Join request is not pending");
    }
    const input = transitionInput(await readObject(request));
    await this.applyTransition(meta, actor, "add", pending.device_id, input, pending, invitationId);
    return json({ approved: true, revision: meta.revision + 1, generation: meta.generation + 1 });
  }

  private reject(meta: MetaRow, actor: DeviceRow, invitationId: string): Response {
    const invitation = this.invitation(invitationId);
    if (invitation.inviter_device_id !== actor.id) {
      throw new HttpError(403, "wrong_inviter", "Only the inviting device can reject this request");
    }
    const pending = this.joinRequestRow(invitationId);
    if (pending === null || pending.decision !== null) {
      throw new HttpError(409, "join_request_unavailable", "Join request is not pending");
    }
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("UPDATE invitations SET consumed_at = ? WHERE id = ?", now, invitationId);
      this.state.storage.sql.exec(
        "UPDATE join_requests SET decided_at = ?, decision = 'rejected' WHERE invitation_id = ?",
        now,
        invitationId,
      );
    });
    return json({ rejected: true, revision: meta.revision });
  }

  private async remove(
    request: Request,
    meta: MetaRow,
    actor: DeviceRow,
    targetDeviceId: string,
  ): Promise<Response> {
    if (targetDeviceId === actor.id) {
      throw new HttpError(409, "cannot_remove_self", "A device cannot remove itself");
    }
    const target = this.device(targetDeviceId);
    if (target === null || target.removed_revision !== null) {
      throw new HttpError(404, "device_not_found", "Active device not found");
    }
    const input = transitionInput(await readObject(request));
    await this.applyTransition(meta, actor, "remove", targetDeviceId, input, null);
    return json({ removed: true, revision: meta.revision + 1, generation: meta.generation + 1 });
  }

  private async applyTransition(
    meta: MetaRow,
    actor: DeviceRow,
    action: "add" | "remove",
    targetDeviceId: string,
    input: TransitionInput,
    pending: JoinRequestRow | null,
    invitationId: string | null = null,
  ): Promise<void> {
    if (input.expectedRevision !== meta.revision) {
      throw new HttpError(409, "stale_group_revision", "Device group revision has changed");
    }
    const nextRevision = meta.revision + 1;
    const nextGeneration = meta.generation + 1;
    const activeDevices = this.activeDevices();
    const recipients = new Set(activeDevices.map((device) => device.id));
    if (action === "add") {
      recipients.add(targetDeviceId);
    } else {
      recipients.delete(targetDeviceId);
    }
    const currentPackages = input.packages.filter((item) => item.generation === nextGeneration);
    if (!sameSet(new Set(currentPackages.map((item) => item.deviceId)), recipients)) {
      throw new HttpError(400, "invalid_package_set", "Next generation packages must target every remaining device exactly once");
    }
    for (const item of input.packages) {
      if (item.generation === nextGeneration) {
        continue;
      }
      if (action !== "add" || item.deviceId !== targetDeviceId || item.generation < 1 || item.generation > meta.generation) {
        throw new HttpError(400, "invalid_package_set", "Historical packages may target only a newly approved device");
      }
    }
    const packageKeys = new Set(input.packages.map((item) => `${item.generation}:${item.deviceId}`));
    if (packageKeys.size !== input.packages.length) {
      throw new HttpError(400, "invalid_package_set", "Key package generation and device pairs must be unique");
    }
    const packagesHash = await hashPackages(input.packages);
    const transcript = transitionTranscript(
      meta.group_id,
      nextRevision,
      meta.generation,
      nextGeneration,
      input.nextGenerationPublicKey,
      action,
      actor.id,
      targetDeviceId,
      packagesHash,
    );
    if (!(await verifySignature(actor.signing_public_key, input.deviceSignature, transcript))) {
      throw new HttpError(401, "invalid_device_signature", "Device transition signature is invalid");
    }
    if (!(await verifySignature(meta.generation_public_key, input.groupSignature, transcript))) {
      throw new HttpError(401, "invalid_group_signature", "Group generation transition signature is invalid");
    }

    const now = Date.now();
    this.state.storage.transactionSync(() => {
      if (action === "add") {
        if (pending === null) {
          throw new Error("Add transition requires a pending device");
        }
        this.state.storage.sql.exec(
          `INSERT INTO devices
             (id, access_hash, encryption_public_key, signing_public_key, added_revision, added_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
          pending.device_id,
          pending.access_hash,
          pending.encryption_public_key,
          pending.signing_public_key,
          nextRevision,
          now,
        );
      } else {
        this.state.storage.sql.exec(
          "UPDATE devices SET removed_revision = ?, removed_at = ? WHERE id = ?",
          nextRevision,
          now,
          targetDeviceId,
        );
      }
      for (const keyPackage of input.packages) {
        this.insertPackage(keyPackage);
      }
      this.state.storage.sql.exec(
        `INSERT INTO transitions
           (revision, previous_generation, generation, generation_public_key, action,
            actor_device_id, target_device_id, packages_hash, group_signature, device_signature, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        nextRevision,
        meta.generation,
        nextGeneration,
        input.nextGenerationPublicKey,
        action,
        actor.id,
        targetDeviceId,
        packagesHash,
        input.groupSignature,
        input.deviceSignature,
        now,
      );
      this.state.storage.sql.exec(
        "UPDATE meta SET revision = ?, generation = ?, generation_public_key = ? WHERE singleton = 1",
        nextRevision,
        nextGeneration,
        input.nextGenerationPublicKey,
      );
      if (invitationId !== null) {
        this.state.storage.sql.exec(
          "UPDATE invitations SET consumed_at = ? WHERE id = ?",
          now,
          invitationId,
        );
        this.state.storage.sql.exec(
          "UPDATE join_requests SET decided_at = ?, decision = 'approved' WHERE invitation_id = ?",
          now,
          invitationId,
        );
      }
    });
  }

  private groupState(meta: MetaRow, deviceId: string, afterGeneration: number): Response {
    const devices = this.activeDevices().map((device) => ({
      deviceId: device.id,
      encryptionPublicKey: device.encryption_public_key,
      signingPublicKey: device.signing_public_key,
      addedAt: device.added_at,
    }));
    const packages = Array.from(
      this.state.storage.sql.exec<PackageRow>(
        `SELECT generation, device_id, ephemeral_public_key, nonce, ciphertext
         FROM key_packages WHERE device_id = ? AND generation > ? ORDER BY generation`,
        deviceId,
        afterGeneration,
      ),
    ).map(packageJSON);
    const pending = Array.from(
      this.state.storage.sql.exec<JoinRequestRow & InvitationRow>(
        `SELECT r.invitation_id, r.device_id, r.encryption_public_key, r.signing_public_key,
                r.created_at, i.expires_at
         FROM join_requests r JOIN invitations i ON i.id = r.invitation_id
         WHERE i.inviter_device_id = ? AND r.decision IS NULL AND i.consumed_at IS NULL AND i.expires_at > ?
         ORDER BY r.created_at`,
        deviceId,
        Date.now(),
      ),
    ).map((row) => ({
      invitationId: row.invitation_id,
      deviceId: row.device_id,
      encryptionPublicKey: row.encryption_public_key,
      signingPublicKey: row.signing_public_key,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
    }));
    const transitions = this.transitionsAfter(afterGeneration);
    return json({
      groupId: meta.group_id,
      revision: meta.revision,
      generation: meta.generation,
      generationPublicKey: meta.generation_public_key,
      devices,
      packages,
      pending,
      transitions,
    });
  }

  private current(meta: MetaRow, afterGeneration: number): Response {
    const transitions = this.transitionsAfter(afterGeneration);
    return json({
      groupId: meta.group_id,
      revision: meta.revision,
      generation: meta.generation,
      generationPublicKey: meta.generation_public_key,
      activeDeviceIds: this.activeDevices().map((device) => device.id),
      transitions,
    });
  }

  private transitionsAfter(afterGeneration: number): Array<Record<string, unknown>> {
    return Array.from(
      this.state.storage.sql.exec<TransitionRow>(
        `SELECT revision, previous_generation, generation, generation_public_key, action,
                actor_device_id, target_device_id, packages_hash, group_signature, device_signature, created_at
         FROM transitions WHERE generation > ? ORDER BY generation`,
        afterGeneration,
      ),
    ).map(transitionJSON);
  }

  private async putSession(request: Request): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["sessionId", "creatorPublicKey", "expiresAt"]);
    const sessionId = stringField(body, "sessionId", IDENTIFIER, 64);
    const creatorPublicKey = stringField(body, "creatorPublicKey", PUBLIC_KEY, 128);
    const expiresAt = integerField(body, "expiresAt");
    this.state.storage.sql.exec(
      `INSERT INTO sessions (session_id, creator_public_key, expires_at) VALUES (?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET expires_at = excluded.expires_at`,
      sessionId,
      creatorPublicKey,
      expiresAt,
    );
    return json({ stored: true });
  }

  private sessions(): Response {
    const rows = Array.from(
      this.state.storage.sql.exec<SessionRow>(
        "SELECT session_id, creator_public_key, expires_at FROM sessions WHERE expires_at > ? ORDER BY expires_at",
        Date.now(),
      ),
    ).map((row) => ({
      sessionId: row.session_id,
      creatorPublicKey: row.creator_public_key,
      expiresAt: row.expires_at,
    }));
    return json({ sessions: rows });
  }

  private async requireDevice(request: Request): Promise<DeviceRow> {
    const url = new URL(request.url);
    const deviceId = identifier(url.searchParams.get("deviceId"), "deviceId");
    const device = this.device(deviceId);
    if (device === null || device.removed_revision !== null) {
      throw new HttpError(403, "device_removed", "Device is not an active member of the group");
    }
    if (!equalHex(device.access_hash, await sha256Hex(bearerToken(request)))) {
      throw new HttpError(401, "invalid_device_token", "Device token is invalid");
    }
    return device;
  }

  private async meta(): Promise<MetaRow> {
    const row = this.metaRow();
    if (row === null) {
      throw new HttpError(404, "group_not_found", "Device group not found");
    }
    return row;
  }

  private metaRow(): MetaRow | null {
    const rows = Array.from(
      this.state.storage.sql.exec<MetaRow>(
        "SELECT group_id, revision, generation, generation_public_key FROM meta WHERE singleton = 1",
      ),
    );
    if (rows.length > 1) {
      throw new Error("Device group must contain at most one meta row");
    }
    return rows.length === 0 ? null : rows[0];
  }

  private activeDevices(): DeviceRow[] {
    return Array.from(
      this.state.storage.sql.exec<DeviceRow>(
        `SELECT id, access_hash, encryption_public_key, signing_public_key,
                added_revision, removed_revision, added_at, removed_at
         FROM devices WHERE removed_revision IS NULL ORDER BY added_revision, id`,
      ),
    );
  }

  private device(deviceId: string): DeviceRow | null {
    const rows = Array.from(
      this.state.storage.sql.exec<DeviceRow>(
        `SELECT id, access_hash, encryption_public_key, signing_public_key,
                added_revision, removed_revision, added_at, removed_at
         FROM devices WHERE id = ?`,
        deviceId,
      ),
    );
    return rows.length === 0 ? null : rows[0];
  }

  private invitation(invitationId: string): InvitationRow {
    const rows = Array.from(
      this.state.storage.sql.exec<InvitationRow>(
        "SELECT id, token_hash, inviter_device_id, expires_at, consumed_at FROM invitations WHERE id = ?",
        invitationId,
      ),
    );
    if (rows.length === 0) {
      throw new HttpError(404, "invitation_not_found", "Device invitation not found");
    }
    return rows[0];
  }

  private joinRequestRow(invitationId: string): JoinRequestRow | null {
    const rows = Array.from(
      this.state.storage.sql.exec<JoinRequestRow>(
        `SELECT invitation_id, device_id, access_hash, encryption_public_key, signing_public_key,
                created_at, decided_at, decision
         FROM join_requests WHERE invitation_id = ?`,
        invitationId,
      ),
    );
    return rows.length === 0 ? null : rows[0];
  }

  private insertPackage(keyPackage: KeyPackage): void {
    this.state.storage.sql.exec(
      `INSERT INTO key_packages
         (generation, device_id, ephemeral_public_key, nonce, ciphertext)
       VALUES (?, ?, ?, ?, ?)`,
      keyPackage.generation,
      keyPackage.deviceId,
      keyPackage.ephemeralPublicKey,
      keyPackage.nonce,
      keyPackage.ciphertext,
    );
  }

  private createSchema(): void {
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        group_id TEXT NOT NULL UNIQUE,
        revision INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        generation_public_key TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        access_hash TEXT NOT NULL,
        encryption_public_key TEXT NOT NULL,
        signing_public_key TEXT NOT NULL,
        added_revision INTEGER NOT NULL,
        removed_revision INTEGER,
        added_at INTEGER NOT NULL,
        removed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL,
        inviter_device_id TEXT NOT NULL REFERENCES devices(id),
        expires_at INTEGER NOT NULL,
        consumed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS join_requests (
        invitation_id TEXT PRIMARY KEY REFERENCES invitations(id),
        device_id TEXT NOT NULL,
        access_hash TEXT NOT NULL,
        encryption_public_key TEXT NOT NULL,
        signing_public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        decided_at INTEGER,
        decision TEXT CHECK (decision IN ('approved', 'rejected'))
      );
      CREATE TABLE IF NOT EXISTS key_packages (
        generation INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        ephemeral_public_key TEXT NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        PRIMARY KEY (generation, device_id)
      );
      CREATE TABLE IF NOT EXISTS transitions (
        revision INTEGER PRIMARY KEY,
        previous_generation INTEGER NOT NULL,
        generation INTEGER NOT NULL UNIQUE,
        generation_public_key TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('add', 'remove')),
        actor_device_id TEXT NOT NULL,
        target_device_id TEXT NOT NULL,
        packages_hash TEXT NOT NULL,
        group_signature TEXT NOT NULL,
        device_signature TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        creator_public_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
    `);
  }
}

function identifier(value: string | null, name: string): string {
  const object: Record<string, unknown> = { [name]: value };
  return stringField(object, name, IDENTIFIER, 64);
}

function transitionInput(body: Record<string, unknown>): TransitionInput {
  expectKeys(body, [
    "expectedRevision",
    "nextGenerationPublicKey",
    "packages",
    "groupSignature",
    "deviceSignature",
  ]);
  if (!Array.isArray(body.packages) || body.packages.length === 0 || body.packages.length > 256) {
    throw new HttpError(400, "invalid_field", "Invalid field: packages");
  }
  return {
    expectedRevision: integerField(body, "expectedRevision"),
    nextGenerationPublicKey: stringField(body, "nextGenerationPublicKey", PUBLIC_KEY, 128),
    packages: body.packages.map(packageObject),
    groupSignature: stringField(body, "groupSignature", SIGNATURE, 128),
    deviceSignature: stringField(body, "deviceSignature", SIGNATURE, 128),
  };
}

function packageObject(value: unknown): KeyPackage {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_field", "Invalid key package");
  }
  const object = value as Record<string, unknown>;
  expectKeys(object, ["generation", "deviceId", "ephemeralPublicKey", "nonce", "ciphertext"]);
  return {
    generation: integerField(object, "generation"),
    deviceId: stringField(object, "deviceId", IDENTIFIER, 64),
    ephemeralPublicKey: stringField(object, "ephemeralPublicKey", PUBLIC_KEY, 128),
    nonce: stringField(object, "nonce", BASE64URL, 32),
    ciphertext: stringField(object, "ciphertext", BASE64URL, 512),
  };
}

function packageJSON(row: PackageRow): KeyPackage {
  return {
    generation: row.generation,
    deviceId: row.device_id,
    ephemeralPublicKey: row.ephemeral_public_key,
    nonce: row.nonce,
    ciphertext: row.ciphertext,
  };
}

function transitionJSON(row: TransitionRow): Record<string, unknown> {
  return {
    revision: row.revision,
    previousGeneration: row.previous_generation,
    generation: row.generation,
    generationPublicKey: row.generation_public_key,
    action: row.action,
    actorDeviceId: row.actor_device_id,
    targetDeviceId: row.target_device_id,
    packagesHash: row.packages_hash,
    groupSignature: row.group_signature,
    deviceSignature: row.device_signature,
    createdAt: row.created_at,
  };
}

function createTranscript(
  groupId: string,
  deviceId: string,
  encryptionPublicKey: string,
  signingPublicKey: string,
  generationPublicKey: string,
  packagesHash: string,
): string {
  return [
    "notify.guru/group-create/v1",
    groupId,
    deviceId,
    encryptionPublicKey,
    signingPublicKey,
    generationPublicKey,
    packagesHash,
  ].join("\n");
}

export function transitionTranscript(
  groupId: string,
  revision: number,
  previousGeneration: number,
  generation: number,
  generationPublicKey: string,
  action: string,
  actorDeviceId: string,
  targetDeviceId: string,
  packagesHash: string,
): string {
  return [
    "notify.guru/group-transition/v1",
    groupId,
    String(revision),
    String(previousGeneration),
    String(generation),
    generationPublicKey,
    action,
    actorDeviceId,
    targetDeviceId,
    packagesHash,
  ].join("\n");
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
  return sha256Hex(canonical);
}

async function verifySignature(publicKey: string, signature: string, transcript: string): Promise<boolean> {
  let key: CryptoKey;
  let signatureBytes: Uint8Array;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      decodeBase64URL(publicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    signatureBytes = decodeBase64URL(signature);
  } catch {
    throw new HttpError(400, "invalid_signature_material", "P-256 public key or signature is invalid");
  }
  if (signatureBytes.length !== 64) {
    throw new HttpError(400, "invalid_signature_material", "P-256 signature must contain 64 bytes");
  }
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    signatureBytes,
    new TextEncoder().encode(transcript),
  );
}

function decodeBase64URL(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function sameSet(left: Set<string>, right: Set<string>): boolean {
  return left.size === right.size && Array.from(left).every((value) => right.has(value));
}
