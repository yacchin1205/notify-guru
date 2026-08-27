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
import { APNsClient, type APNsEnvironment } from "./apns";

const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const INITIALIZED_KEY = "initialized";
const MAX_PUSH_ATTEMPTS = 8;
const PUSH_RETRY_BASE_MS = 30_000;
const PUSH_RETRY_CAP_MS = 30 * 60 * 1000;
const PUSH_ALARM_FALLBACK_MS = 15 * 60 * 1000;

interface SessionEnv {
  GROUPS: DurableObjectNamespace;
  APNS_KEY_ID?: string;
  APNS_TEAM_ID?: string;
  APNS_PRIVATE_KEY?: string;
}

interface GroupV2Row extends Record<string, SqlStorageValue> {
  sequence: number;
  id: string;
  pairing_id: string;
  initial_revision: number;
  initial_generation: number;
  initial_public_key: string;
  join_proof: string;
  joined_at: number;
}

interface GroupCurrent {
  groupId: string;
  revision: number;
  generation: number;
  generationPublicKey: string;
  activeDeviceIds: string[];
  transitions: Array<Record<string, unknown>>;
}

interface MetaRow extends Record<string, SqlStorageValue> {
  session_id: string;
  manager_hash: string;
  creator_public_key: string;
  expires_at: number;
}

interface GroupRow extends Record<string, SqlStorageValue> {
  sequence: number;
  id: string;
  pairing_id: string;
  public_key: string;
  join_proof: string;
  joined_at: number;
}

interface EventRow extends Record<string, SqlStorageValue> {
  sequence: number;
  event_id: string;
  group_id: string;
  nonce: string;
  ciphertext: string;
  created_at: number;
}

interface EventV2Row extends EventRow {
  generation: number;
}

interface ResponseRow extends Record<string, SqlStorageValue> {
  sequence: number;
  response_id: string;
  group_id: string;
  nonce: string;
  ciphertext: string;
  created_at: number;
}

interface ResponseV2Row extends ResponseRow {
  generation: number;
}

interface PushJobRow extends Record<string, SqlStorageValue> {
  protocol: string;
  event_id: string;
  group_id: string;
  device_id: string;
  device_token: string;
  environment: APNsEnvironment;
  attempt_count: number;
  next_attempt_at: number;
}

export class Session {
  private readonly apns: APNsClient;
  private readonly groups: DurableObjectNamespace;

  constructor(
    private readonly state: DurableObjectState,
    env: SessionEnv,
  ) {
    this.groups = env.GROUPS;
    this.apns = new APNsClient({
      keyId: env.APNS_KEY_ID,
      teamId: env.APNS_TEAM_ID,
      privateKey: env.APNS_PRIVATE_KEY,
      topic: "guru.notify.app",
    });
    this.state.blockConcurrencyWhile(async () => {
      if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) === true) {
        this.createSchema();
      }
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
    const initialized = await this.state.storage.get<boolean>(INITIALIZED_KEY);
    if (initialized !== true) {
      return;
    }
    const initialMeta = Array.from(
      this.state.storage.sql.exec<{ expires_at: number }>("SELECT expires_at FROM meta WHERE singleton = 1"),
    );
    if (initialMeta.length !== 1) {
      throw new Error("Initialized session must contain exactly one meta row");
    }
    if (Date.now() >= initialMeta[0].expires_at) {
      await this.state.storage.deleteAll();
      return;
    }
    const now = Date.now();
    await this.state.storage.setAlarm(Math.min(initialMeta[0].expires_at, now + PUSH_ALARM_FALLBACK_MS));
    const jobs = Array.from(
      this.state.storage.sql.exec<PushJobRow>(
        `SELECT 'v1' AS protocol, event_id, group_id, '' AS device_id,
                device_token, environment, attempt_count, next_attempt_at
         FROM push_jobs WHERE next_attempt_at <= ?
         UNION ALL
         SELECT 'v2' AS protocol, event_id, group_id, device_id,
                device_token, environment, attempt_count, next_attempt_at
         FROM push_jobs_v2 WHERE next_attempt_at <= ?
         ORDER BY next_attempt_at, event_id LIMIT 100`,
        now,
        now,
      ),
    );
    if (jobs.length === 0) {
      await this.scheduleNextAlarm(initialMeta[0].expires_at);
      return;
    }
    const invalidTokens = new Set<string>();
    for (const job of jobs) {
      if (invalidTokens.has(job.device_token)) {
        continue;
      }
      try {
        const result = await this.apns.send(job.device_token, job.environment);
        switch (result.outcome) {
          case "delivered":
            this.deletePushJob(job);
            break;
          case "invalid-token":
            invalidTokens.add(job.device_token);
            this.deleteInvalidToken(job);
            break;
          case "permanent-failure":
            console.warn("APNs push discarded after a permanent provider response", { reason: result.reason });
            this.deletePushJob(job);
            break;
          case "retry":
            this.retryPushJob(job, result.reason, result.minimumDelayMs);
            break;
        }
      } catch {
        this.retryPushJob(job, "transport-or-provider-response", 0);
      }
    }

    const rows = Array.from(
      this.state.storage.sql.exec<{ expires_at: number }>("SELECT expires_at FROM meta WHERE singleton = 1"),
    );
    if (rows.length !== 1) {
      throw new Error("Initialized session must contain exactly one meta row");
    }
    await this.scheduleNextAlarm(rows[0].expires_at);
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/create") {
      return this.create(request);
    }

    const meta = await this.activeMeta();

    if (request.method === "POST" && url.pathname === "/pairings") {
      await this.requireManager(request, meta);
      return this.addPairing(request);
    }
    if (request.method === "POST" && url.pathname === "/join") {
      return this.join(request, meta);
    }
    if (request.method === "POST" && url.pathname === "/v2/join") {
      return this.joinV2(request, meta);
    }
    if (request.method === "GET" && url.pathname === "/joins") {
      await this.requireManager(request, meta);
      return this.joins(url, meta);
    }
    if (request.method === "GET" && url.pathname === "/v2/joins") {
      await this.requireManager(request, meta);
      return this.joinsV2(meta);
    }
    if (request.method === "POST" && url.pathname === "/events") {
      await this.requireManager(request, meta);
      return this.addEvent(request);
    }
    if (request.method === "POST" && url.pathname === "/v2/events") {
      await this.requireManager(request, meta);
      return this.addEventV2(request, meta);
    }
    if (request.method === "GET" && url.pathname === "/events") {
      return this.events(request, url, meta);
    }
    if (request.method === "GET" && url.pathname === "/v2/events") {
      return this.eventsV2(request, url, meta);
    }
    if (request.method === "PUT" && url.pathname === "/push") {
      return this.registerPush(request, meta);
    }
    if (request.method === "PUT" && url.pathname === "/v2/push") {
      return this.registerPushV2(request, meta);
    }
    if (request.method === "POST" && url.pathname === "/responses") {
      return this.addResponse(request, meta);
    }
    if (request.method === "POST" && url.pathname === "/v2/responses") {
      return this.addResponseV2(request, meta);
    }
    if (request.method === "GET" && url.pathname === "/responses") {
      await this.requireManager(request, meta);
      return this.responses(url, meta);
    }
    if (request.method === "GET" && url.pathname === "/v2/responses") {
      await this.requireManager(request, meta);
      return this.responsesV2(url, meta);
    }
    if (request.method === "DELETE" && url.pathname === "/") {
      await this.requireManager(request, meta);
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
    expectKeys(body, ["sessionId", "managerTokenHash", "creatorPublicKey", "pairing"]);
    const sessionId = stringField(body, "sessionId", IDENTIFIER, 64);
    const managerHash = stringField(body, "managerTokenHash", SHA256_HEX, 64);
    const creatorPublicKey = stringField(body, "creatorPublicKey", BASE64URL, 128);
    const pairing = this.pairingObject(body.pairing);
    const now = Date.now();
    const expiresAt = now + SESSION_LIFETIME_MS;

    this.createSchema();
    this.state.storage.sql.exec(
      `INSERT INTO meta
         (singleton, session_id, manager_hash, creator_public_key, expires_at)
       VALUES (1, ?, ?, ?, ?)`,
      sessionId,
      managerHash,
      creatorPublicKey,
      expiresAt,
    );
    this.state.storage.sql.exec(
      "INSERT INTO pairings (id, token_hash, created_at) VALUES (?, ?, ?)",
      pairing.id,
      pairing.tokenHash,
      now,
    );
    await this.state.storage.put(INITIALIZED_KEY, true);
    await this.scheduleExpiry(expiresAt);
    return json({ expiresAt }, 201);
  }

  private async addPairing(request: Request): Promise<Response> {
    const pairing = this.pairingObject(await readObject(request));
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
    expectKeys(body, ["pairingId", "pairingToken", "groupId", "groupAccessTokenHash", "groupPublicKey", "proof"]);
    const pairingId = stringField(body, "pairingId", IDENTIFIER, 64);
    const pairingToken = stringField(body, "pairingToken", BASE64URL, 128);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const groupAccessHash = stringField(body, "groupAccessTokenHash", SHA256_HEX, 64);
    const groupPublicKey = stringField(body, "groupPublicKey", BASE64URL, 128);
    const proof = stringField(body, "proof", BASE64URL, 128);

    const rows = Array.from(
      this.state.storage.sql.exec<{ token_hash: string; consumed_at: number | null }>(
        "SELECT token_hash, consumed_at FROM pairings WHERE id = ?",
        pairingId,
      ),
    );
    if (rows.length === 0) {
      throw new HttpError(404, "pairing_not_found", "Pairing not found");
    }
    if (rows[0].consumed_at !== null) {
      throw new HttpError(409, "pairing_consumed", "Pairing has already been consumed");
    }
    if (!equalHex(rows[0].token_hash, await sha256Hex(pairingToken))) {
      throw new HttpError(401, "invalid_pairing_token", "Pairing token is invalid");
    }

    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("UPDATE pairings SET consumed_at = ? WHERE id = ?", now, pairingId);
      this.state.storage.sql.exec(
        "INSERT INTO groups (id, pairing_id, access_hash, public_key, join_proof, joined_at) VALUES (?, ?, ?, ?, ?, ?)",
        groupId,
        pairingId,
        groupAccessHash,
        groupPublicKey,
        proof,
        now,
      );
    });
    return json({ joined: true, expiresAt: meta.expires_at }, 201);
  }

  private async joinV2(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, [
      "pairingId",
      "pairingToken",
      "groupId",
      "deviceId",
      "deviceAccessToken",
      "revision",
      "generation",
      "groupPublicKey",
      "proof",
    ]);
    const pairingId = stringField(body, "pairingId", IDENTIFIER, 64);
    const pairingToken = stringField(body, "pairingToken", BASE64URL, 128);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const deviceAccessToken = stringField(body, "deviceAccessToken", BASE64URL, 128);
    const revision = integerField(body, "revision");
    const generation = integerField(body, "generation");
    const groupPublicKey = stringField(body, "groupPublicKey", BASE64URL, 128);
    const proof = stringField(body, "proof", BASE64URL, 128);
    const pairing = this.unusedPairing(pairingId);
    if (!equalHex(pairing.token_hash, await sha256Hex(pairingToken))) {
      throw new HttpError(401, "invalid_pairing_token", "Pairing token is invalid");
    }

    await this.authorizeGroupDevice(groupId, deviceId, deviceAccessToken);
    const current = await this.groupCurrent(groupId, 0);
    if (
      current.revision !== revision
      || current.generation !== generation
      || current.generationPublicKey !== groupPublicKey
    ) {
      throw new HttpError(409, "stale_group_revision", "Device group revision has changed");
    }

    await this.groupRequest(groupId, "/sessions", {
      method: "PUT",
      body: JSON.stringify({
        sessionId: meta.session_id,
        creatorPublicKey: meta.creator_public_key,
        expiresAt: meta.expires_at,
      }),
    });
    const now = Date.now();
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("UPDATE pairings SET consumed_at = ? WHERE id = ?", now, pairingId);
      this.state.storage.sql.exec(
        `INSERT INTO groups_v2
           (id, pairing_id, initial_revision, initial_generation, initial_public_key, join_proof, joined_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        groupId,
        pairingId,
        revision,
        generation,
        groupPublicKey,
        proof,
        now,
      );
    });
    return json({ joined: true, expiresAt: meta.expires_at }, 201);
  }

  private joins(url: URL, meta: MetaRow): Response {
    const after = integerQuery(url, "after");
    const groups = Array.from(
      this.state.storage.sql.exec<GroupRow>(
        "SELECT sequence, id, pairing_id, public_key, join_proof, joined_at FROM groups WHERE sequence > ? ORDER BY sequence LIMIT 100",
        after,
      ),
    ).map((row) => ({
      sequence: row.sequence,
      groupId: row.id,
      pairingId: row.pairing_id,
      publicKey: row.public_key,
      proof: row.join_proof,
      joinedAt: row.joined_at,
    }));
    return json({ groups, expiresAt: meta.expires_at });
  }

  private async joinsV2(meta: MetaRow): Promise<Response> {
    const rows = Array.from(
      this.state.storage.sql.exec<GroupV2Row>(
        `SELECT sequence, id, pairing_id, initial_revision, initial_generation,
                initial_public_key, join_proof, joined_at
         FROM groups_v2 ORDER BY sequence`,
      ),
    );
    const groups = await Promise.all(rows.map(async (row) => {
      const current = await this.groupCurrent(row.id, row.initial_generation);
      return {
        sequence: row.sequence,
        groupId: row.id,
        pairingId: row.pairing_id,
        initialRevision: row.initial_revision,
        initialGeneration: row.initial_generation,
        initialPublicKey: row.initial_public_key,
        proof: row.join_proof,
        joinedAt: row.joined_at,
        currentRevision: current.revision,
        currentGeneration: current.generation,
        currentPublicKey: current.generationPublicKey,
        transitions: current.transitions,
      };
    }));
    return json({ groups, expiresAt: meta.expires_at });
  }

  private async addEvent(request: Request): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["eventId", "groupId", "nonce", "ciphertext"]);
    const eventId = stringField(body, "eventId", IDENTIFIER, 64);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const nonce = stringField(body, "nonce", BASE64URL, 32);
    const ciphertext = stringField(body, "ciphertext", BASE64URL, 350_000);
    this.requireGroup(groupId);

    const now = Date.now();
    const expiresAt = now + SESSION_LIFETIME_MS;
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(
        "INSERT INTO events (event_id, group_id, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)",
        eventId,
        groupId,
        nonce,
        ciphertext,
        now,
      );
      this.state.storage.sql.exec("UPDATE meta SET expires_at = ? WHERE singleton = 1", expiresAt);
      this.state.storage.sql.exec(
        `INSERT INTO push_jobs
           (event_id, group_id, device_token, environment, attempt_count, next_attempt_at)
         SELECT ?, group_id, device_token, environment, 0, ? FROM push_tokens WHERE group_id = ?`,
        eventId,
        now,
        groupId,
      );
    });
    const jobs = Array.from(
      this.state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM push_jobs WHERE event_id = ?",
        eventId,
      ),
    );
    if (jobs[0].count > 0) {
      await this.schedulePush(Date.now());
    } else {
      await this.scheduleExpiry(expiresAt);
    }
    return json({ expiresAt }, 201);
  }

  private async addEventV2(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["eventId", "groupId", "generation", "nonce", "ciphertext"]);
    const eventId = stringField(body, "eventId", IDENTIFIER, 64);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const generation = integerField(body, "generation");
    const nonce = stringField(body, "nonce", BASE64URL, 32);
    const ciphertext = stringField(body, "ciphertext", BASE64URL, 350_000);
    this.requireGroupV2(groupId);
    const current = await this.groupCurrent(groupId, generation);
    if (current.generation !== generation) {
      throw new HttpError(409, "stale_group_generation", "Device group generation has changed");
    }

    const now = Date.now();
    const expiresAt = now + SESSION_LIFETIME_MS;
    await this.groupRequest(groupId, "/sessions", {
      method: "PUT",
      body: JSON.stringify({
        sessionId: meta.session_id,
        creatorPublicKey: meta.creator_public_key,
        expiresAt,
      }),
    });
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec(
        `INSERT INTO events_v2
           (event_id, group_id, generation, nonce, ciphertext, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        eventId,
        groupId,
        generation,
        nonce,
        ciphertext,
        now,
      );
      this.state.storage.sql.exec("UPDATE meta SET expires_at = ? WHERE singleton = 1", expiresAt);
      for (const deviceId of current.activeDeviceIds) {
        this.state.storage.sql.exec(
          `INSERT INTO push_jobs_v2
             (event_id, group_id, device_id, device_token, environment, attempt_count, next_attempt_at)
           SELECT ?, group_id, device_id, device_token, environment, 0, ?
           FROM push_tokens_v2 WHERE group_id = ? AND device_id = ?`,
          eventId,
          now,
          groupId,
          deviceId,
        );
      }
    });
    const jobs = Array.from(
      this.state.storage.sql.exec<{ count: number }>(
        "SELECT COUNT(*) AS count FROM push_jobs_v2 WHERE event_id = ?",
        eventId,
      ),
    );
    if (jobs[0].count > 0) {
      await this.schedulePush(Date.now());
    } else {
      await this.scheduleExpiry(expiresAt);
    }
    return json({ expiresAt }, 201);
  }

  private async registerPush(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["groupId", "deviceToken", "environment"]);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceToken = stringField(body, "deviceToken", /^[a-f0-9]+$/, 512);
    if (deviceToken.length % 2 !== 0) {
      throw new HttpError(400, "invalid_field", "Invalid field: deviceToken");
    }
    const environment = stringField(body, "environment", /^(sandbox|production)$/, 10) as APNsEnvironment;
    await this.requireGroupAccess(request, groupId);
    this.state.storage.sql.exec(
      `INSERT INTO push_tokens (group_id, device_token, environment, registered_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET
         device_token = excluded.device_token,
         environment = excluded.environment,
         registered_at = excluded.registered_at`,
      groupId,
      deviceToken,
      environment,
      Date.now(),
    );
    return json({ registered: true, expiresAt: meta.expires_at });
  }

  private async registerPushV2(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["groupId", "deviceId", "deviceToken", "environment"]);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const deviceToken = stringField(body, "deviceToken", /^[a-f0-9]+$/, 512);
    if (deviceToken.length % 2 !== 0) {
      throw new HttpError(400, "invalid_field", "Invalid field: deviceToken");
    }
    const environment = stringField(body, "environment", /^(sandbox|production)$/, 10) as APNsEnvironment;
    this.requireGroupV2(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    this.state.storage.sql.exec(
      `INSERT INTO push_tokens_v2 (group_id, device_id, device_token, environment, registered_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(group_id, device_id) DO UPDATE SET
         device_token = excluded.device_token,
         environment = excluded.environment,
         registered_at = excluded.registered_at`,
      groupId,
      deviceId,
      deviceToken,
      environment,
      Date.now(),
    );
    return json({ registered: true, expiresAt: meta.expires_at });
  }

  private async events(request: Request, url: URL, meta: MetaRow): Promise<Response> {
    const groupId = this.groupIdQuery(url);
    await this.requireGroupAccess(request, groupId);
    const after = integerQuery(url, "after");
    const events = Array.from(
      this.state.storage.sql.exec<EventRow>(
        "SELECT sequence, event_id, group_id, nonce, ciphertext, created_at FROM events WHERE group_id = ? AND sequence > ? ORDER BY sequence LIMIT 100",
        groupId,
        after,
      ),
    ).map((row) => ({
      sequence: row.sequence,
      eventId: row.event_id,
      groupId: row.group_id,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
    }));
    return json({ events, expiresAt: meta.expires_at });
  }

  private async eventsV2(request: Request, url: URL, meta: MetaRow): Promise<Response> {
    const groupId = this.groupIdQuery(url);
    const deviceId = this.deviceIdQuery(url);
    this.requireGroupV2(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    const after = integerQuery(url, "after");
    const events = Array.from(
      this.state.storage.sql.exec<EventV2Row>(
        `SELECT sequence, event_id, group_id, generation, nonce, ciphertext, created_at
         FROM events_v2 WHERE group_id = ? AND sequence > ? ORDER BY sequence LIMIT 100`,
        groupId,
        after,
      ),
    ).map((row) => ({
      sequence: row.sequence,
      eventId: row.event_id,
      groupId: row.group_id,
      generation: row.generation,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
    }));
    return json({ events, expiresAt: meta.expires_at });
  }

  private async addResponse(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["responseId", "groupId", "nonce", "ciphertext"]);
    const responseId = stringField(body, "responseId", IDENTIFIER, 64);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const nonce = stringField(body, "nonce", BASE64URL, 32);
    const ciphertext = stringField(body, "ciphertext", BASE64URL, 350_000);
    await this.requireGroupAccess(request, groupId);

    this.state.storage.sql.exec(
      "INSERT INTO responses (response_id, group_id, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, ?)",
      responseId,
      groupId,
      nonce,
      ciphertext,
      Date.now(),
    );
    return json({ expiresAt: meta.expires_at }, 201);
  }

  private async addResponseV2(request: Request, meta: MetaRow): Promise<Response> {
    const body = await readObject(request);
    expectKeys(body, ["responseId", "groupId", "deviceId", "generation", "nonce", "ciphertext"]);
    const responseId = stringField(body, "responseId", IDENTIFIER, 64);
    const groupId = stringField(body, "groupId", IDENTIFIER, 64);
    const deviceId = stringField(body, "deviceId", IDENTIFIER, 64);
    const generation = integerField(body, "generation");
    const nonce = stringField(body, "nonce", BASE64URL, 32);
    const ciphertext = stringField(body, "ciphertext", BASE64URL, 350_000);
    const group = this.requireGroupV2(groupId);
    await this.authorizeGroupDevice(groupId, deviceId, bearerToken(request));
    const current = await this.groupCurrent(groupId, generation);
    if (generation < group.initial_generation || generation > current.generation) {
      throw new HttpError(400, "invalid_generation", "Response generation is outside this session's group history");
    }
    this.state.storage.sql.exec(
      `INSERT INTO responses_v2
         (response_id, group_id, generation, nonce, ciphertext, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      responseId,
      groupId,
      generation,
      nonce,
      ciphertext,
      Date.now(),
    );
    return json({ expiresAt: meta.expires_at }, 201);
  }

  private responses(url: URL, meta: MetaRow): Response {
    const after = integerQuery(url, "after");
    const responses = Array.from(
      this.state.storage.sql.exec<ResponseRow>(
        "SELECT sequence, response_id, group_id, nonce, ciphertext, created_at FROM responses WHERE sequence > ? ORDER BY sequence LIMIT 100",
        after,
      ),
    ).map((row) => ({
      sequence: row.sequence,
      responseId: row.response_id,
      groupId: row.group_id,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
    }));
    return json({ responses, expiresAt: meta.expires_at });
  }

  private responsesV2(url: URL, meta: MetaRow): Response {
    const after = integerQuery(url, "after");
    const responses = Array.from(
      this.state.storage.sql.exec<ResponseV2Row>(
        `SELECT sequence, response_id, group_id, generation, nonce, ciphertext, created_at
         FROM responses_v2 WHERE sequence > ? ORDER BY sequence LIMIT 100`,
        after,
      ),
    ).map((row) => ({
      sequence: row.sequence,
      responseId: row.response_id,
      groupId: row.group_id,
      generation: row.generation,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
      createdAt: row.created_at,
    }));
    return json({ responses, expiresAt: meta.expires_at });
  }

  private async activeMeta(): Promise<MetaRow> {
    if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) !== true) {
      throw new HttpError(404, "session_not_found", "Session not found");
    }
    const rows = Array.from(
      this.state.storage.sql.exec<MetaRow>(
        "SELECT session_id, manager_hash, creator_public_key, expires_at FROM meta WHERE singleton = 1",
      ),
    );
    if (rows.length !== 1) {
      throw new Error("Initialized session must contain exactly one meta row");
    }
    if (Date.now() >= rows[0].expires_at) {
      await this.state.storage.deleteAll();
      throw new HttpError(410, "session_expired", "Session has expired");
    }
    return rows[0];
  }

  private unusedPairing(pairingId: string): { token_hash: string } {
    const rows = Array.from(
      this.state.storage.sql.exec<{ token_hash: string; consumed_at: number | null }>(
        "SELECT token_hash, consumed_at FROM pairings WHERE id = ?",
        pairingId,
      ),
    );
    if (rows.length === 0) {
      throw new HttpError(404, "pairing_not_found", "Pairing not found");
    }
    if (rows[0].consumed_at !== null) {
      throw new HttpError(409, "pairing_consumed", "Pairing has already been consumed");
    }
    return rows[0];
  }

  private async authorizeGroupDevice(groupId: string, deviceId: string, token: string): Promise<void> {
    await this.groupRequest(groupId, `/authorize?deviceId=${encodeURIComponent(deviceId)}`, {
      method: "POST",
      token,
    });
  }

  private async groupCurrent(groupId: string, afterGeneration: number): Promise<GroupCurrent> {
    const body = await this.groupRequest(
      groupId,
      `/current?afterGeneration=${afterGeneration}`,
      { method: "GET" },
    );
    const parsedGroupId = stringField(body, "groupId", IDENTIFIER, 64);
    const revision = integerField(body, "revision");
    const generation = integerField(body, "generation");
    const generationPublicKey = stringField(body, "generationPublicKey", BASE64URL, 128);
    if (!Array.isArray(body.activeDeviceIds) || !Array.isArray(body.transitions)) {
      throw new Error("Device group returned malformed current state");
    }
    const activeDeviceIds = body.activeDeviceIds.map((value) =>
      stringField({ deviceId: value }, "deviceId", IDENTIFIER, 64));
    if (new Set(activeDeviceIds).size !== activeDeviceIds.length || parsedGroupId !== groupId) {
      throw new Error("Device group returned inconsistent current state");
    }
    const transitions = body.transitions.map((value) => {
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Device group returned a malformed generation transition");
      }
      return value as Record<string, unknown>;
    });
    return { groupId, revision, generation, generationPublicKey, activeDeviceIds, transitions };
  }

  private async groupRequest(
    groupId: string,
    path: string,
    options: { method: string; token?: string; body?: string },
  ): Promise<Record<string, unknown>> {
    const headers = new Headers({ "x-notify-guru-internal": "1" });
    if (options.token !== undefined) {
      headers.set("authorization", `Bearer ${options.token}`);
    }
    if (options.body !== undefined) {
      headers.set("content-type", "application/json");
    }
    const response = await this.groups.get(this.groups.idFromName(groupId)).fetch(
      new Request(`https://group.internal${path}`, {
        method: options.method,
        headers,
        body: options.body,
      }),
    );
    let body: unknown;
    try {
      body = await response.json();
    } catch (error) {
      throw new Error(`Device group returned non-JSON status ${response.status}`, { cause: error });
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      throw new Error("Device group returned a non-object response");
    }
    const object = body as Record<string, unknown>;
    if (!response.ok) {
      const code = typeof object.error === "string" ? object.error : "group_request_failed";
      const message = typeof object.message === "string" ? object.message : "Device group request failed";
      throw new HttpError(response.status, code, message);
    }
    return object;
  }

  private async requireManager(request: Request, meta: MetaRow): Promise<void> {
    if (!equalHex(meta.manager_hash, await sha256Hex(bearerToken(request)))) {
      throw new HttpError(401, "invalid_manager_token", "Manager token is invalid");
    }
  }

  private async requireGroupAccess(request: Request, groupId: string): Promise<void> {
    const rows = Array.from(
      this.state.storage.sql.exec<{ access_hash: string }>("SELECT access_hash FROM groups WHERE id = ?", groupId),
    );
    if (rows.length === 0) {
      throw new HttpError(404, "group_not_found", "Device group not found");
    }
    if (!equalHex(rows[0].access_hash, await sha256Hex(bearerToken(request)))) {
      throw new HttpError(401, "invalid_group_token", "Device group token is invalid");
    }
  }

  private requireGroup(groupId: string): void {
    const rows = Array.from(this.state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM groups WHERE id = ?", groupId));
    if (rows[0].count !== 1) {
      throw new HttpError(404, "group_not_found", "Device group not found");
    }
  }

  private requireGroupV2(groupId: string): GroupV2Row {
    const rows = Array.from(
      this.state.storage.sql.exec<GroupV2Row>(
        `SELECT sequence, id, pairing_id, initial_revision, initial_generation,
                initial_public_key, join_proof, joined_at
         FROM groups_v2 WHERE id = ?`,
        groupId,
      ),
    );
    if (rows.length === 0) {
      throw new HttpError(404, "group_not_found", "Device group not found");
    }
    return rows[0];
  }

  private groupIdQuery(url: URL): string {
    const value: Record<string, unknown> = { groupId: url.searchParams.get("groupId") };
    return stringField(value, "groupId", IDENTIFIER, 64);
  }

  private deviceIdQuery(url: URL): string {
    const value: Record<string, unknown> = { deviceId: url.searchParams.get("deviceId") };
    return stringField(value, "deviceId", IDENTIFIER, 64);
  }

  private pairingObject(value: unknown): { id: string; tokenHash: string } {
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

  private createSchema(): void {
    this.state.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        session_id TEXT NOT NULL,
        manager_hash TEXT NOT NULL,
        creator_public_key TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pairings (
        id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        consumed_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS groups (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(id),
        access_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        join_proof TEXT NOT NULL,
        joined_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        group_id TEXT NOT NULL REFERENCES groups(id),
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS responses (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        response_id TEXT NOT NULL UNIQUE,
        group_id TEXT NOT NULL REFERENCES groups(id),
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS push_tokens (
        group_id TEXT PRIMARY KEY REFERENCES groups(id),
        device_token TEXT NOT NULL,
        environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
        registered_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS push_jobs (
        event_id TEXT NOT NULL REFERENCES events(event_id),
        group_id TEXT NOT NULL REFERENCES groups(id),
        device_token TEXT NOT NULL,
        environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
        attempt_count INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (event_id, device_token)
      );
      CREATE TABLE IF NOT EXISTS groups_v2 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        pairing_id TEXT NOT NULL UNIQUE REFERENCES pairings(id),
        initial_revision INTEGER NOT NULL,
        initial_generation INTEGER NOT NULL,
        initial_public_key TEXT NOT NULL,
        join_proof TEXT NOT NULL,
        joined_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events_v2 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        group_id TEXT NOT NULL REFERENCES groups_v2(id),
        generation INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS responses_v2 (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        response_id TEXT NOT NULL UNIQUE,
        group_id TEXT NOT NULL REFERENCES groups_v2(id),
        generation INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS push_tokens_v2 (
        group_id TEXT NOT NULL REFERENCES groups_v2(id),
        device_id TEXT NOT NULL,
        device_token TEXT NOT NULL,
        environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
        registered_at INTEGER NOT NULL,
        PRIMARY KEY (group_id, device_id)
      );
      CREATE TABLE IF NOT EXISTS push_jobs_v2 (
        event_id TEXT NOT NULL REFERENCES events_v2(event_id),
        group_id TEXT NOT NULL REFERENCES groups_v2(id),
        device_id TEXT NOT NULL,
        device_token TEXT NOT NULL,
        environment TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
        attempt_count INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (event_id, device_token)
      );
    `);
    const metaColumns = new Set(
      Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(meta)"), (row) => row.name),
    );
    if (!metaColumns.has("session_id")) {
      this.state.storage.sql.exec("ALTER TABLE meta ADD COLUMN session_id TEXT NOT NULL DEFAULT ''");
    }
    const columns = new Set(
      Array.from(this.state.storage.sql.exec<{ name: string }>("PRAGMA table_info(push_jobs)"), (row) => row.name),
    );
    if (!columns.has("attempt_count")) {
      this.state.storage.sql.exec("ALTER TABLE push_jobs ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0");
    }
    if (!columns.has("next_attempt_at")) {
      this.state.storage.sql.exec("ALTER TABLE push_jobs ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0");
    }
    this.state.storage.sql.exec(
      "CREATE INDEX IF NOT EXISTS push_jobs_due ON push_jobs(next_attempt_at, event_id)",
    );
    this.state.storage.sql.exec(
      "CREATE INDEX IF NOT EXISTS push_jobs_v2_due ON push_jobs_v2(next_attempt_at, event_id)",
    );
  }

  private async scheduleExpiry(expiresAt: number): Promise<void> {
    await this.state.storage.setAlarm(expiresAt);
  }

  private async schedulePush(at: number): Promise<void> {
    await this.state.storage.setAlarm(at);
  }

  private deletePushJob(job: PushJobRow): void {
    const table = job.protocol === "v2" ? "push_jobs_v2" : "push_jobs";
    this.state.storage.sql.exec(
      `DELETE FROM ${table} WHERE event_id = ? AND device_token = ?`,
      job.event_id,
      job.device_token,
    );
  }

  private deleteInvalidToken(job: PushJobRow): void {
    this.state.storage.transactionSync(() => {
      this.state.storage.sql.exec("DELETE FROM push_tokens WHERE device_token = ?", job.device_token);
      this.state.storage.sql.exec("DELETE FROM push_tokens_v2 WHERE device_token = ?", job.device_token);
      this.state.storage.sql.exec("DELETE FROM push_jobs WHERE device_token = ?", job.device_token);
      this.state.storage.sql.exec("DELETE FROM push_jobs_v2 WHERE device_token = ?", job.device_token);
    });
  }

  private retryPushJob(job: PushJobRow, reason: string, minimumDelayMs: number): void {
    const attempt = job.attempt_count + 1;
    if (attempt >= MAX_PUSH_ATTEMPTS) {
      console.warn("APNs push discarded after exhausting retries", { reason, attempts: attempt });
      this.deletePushJob(job);
      return;
    }
    const nextAttemptAt = Date.now() + pushRetryDelay(attempt, minimumDelayMs);
    const table = job.protocol === "v2" ? "push_jobs_v2" : "push_jobs";
    this.state.storage.sql.exec(
      `UPDATE ${table} SET attempt_count = ?, next_attempt_at = ?
       WHERE event_id = ? AND device_token = ?`,
      attempt,
      nextAttemptAt,
      job.event_id,
      job.device_token,
    );
  }

  private async scheduleNextAlarm(expiresAt: number): Promise<void> {
    const rows = Array.from(
      this.state.storage.sql.exec<{ count: number; next_attempt_at: number | null }>(
        `SELECT COUNT(*) AS count, MIN(next_attempt_at) AS next_attempt_at FROM (
           SELECT next_attempt_at FROM push_jobs
           UNION ALL
           SELECT next_attempt_at FROM push_jobs_v2
         )`,
      ),
    );
    if (rows.length !== 1) {
      throw new Error("Push queue aggregate must return exactly one row");
    }
    if (rows[0].count === 0) {
      await this.scheduleExpiry(expiresAt);
      return;
    }
    if (rows[0].next_attempt_at === null) {
      throw new Error("Non-empty push queue must have a next attempt time");
    }
    await this.schedulePush(Math.min(expiresAt, Math.max(Date.now() + 1_000, rows[0].next_attempt_at)));
  }
}

function pushRetryDelay(attempt: number, minimumDelayMs: number): number {
  const exponential = Math.min(PUSH_RETRY_BASE_MS * 2 ** (attempt - 1), PUSH_RETRY_CAP_MS);
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  const jittered = exponential * (0.5 + random[0] / 2 ** 32);
  return minimumDelayMs + Math.floor(jittered);
}
