import {
  BASE64URL,
  HttpError,
  IDENTIFIER,
  SHA256_HEX,
  bearerToken,
  equalHex,
  expectKeys,
  integerQuery,
  json,
  readObject,
  sha256Hex,
  stringField,
} from "./http";

const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1000;
const INITIALIZED_KEY = "initialized";

interface MetaRow extends Record<string, SqlStorageValue> {
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

interface ResponseRow extends Record<string, SqlStorageValue> {
  sequence: number;
  response_id: string;
  group_id: string;
  nonce: string;
  ciphertext: string;
  created_at: number;
}

export class Session {
  constructor(private readonly state: DurableObjectState) {}

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
    await this.state.storage.deleteAll();
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
    if (request.method === "GET" && url.pathname === "/joins") {
      await this.requireManager(request, meta);
      return this.joins(url, meta);
    }
    if (request.method === "POST" && url.pathname === "/events") {
      await this.requireManager(request, meta);
      return this.addEvent(request);
    }
    if (request.method === "GET" && url.pathname === "/events") {
      return this.events(request, url, meta);
    }
    if (request.method === "POST" && url.pathname === "/responses") {
      return this.addResponse(request, meta);
    }
    if (request.method === "GET" && url.pathname === "/responses") {
      await this.requireManager(request, meta);
      return this.responses(url, meta);
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
    expectKeys(body, ["managerTokenHash", "creatorPublicKey", "pairing"]);
    const managerHash = stringField(body, "managerTokenHash", SHA256_HEX, 64);
    const creatorPublicKey = stringField(body, "creatorPublicKey", BASE64URL, 128);
    const pairing = this.pairingObject(body.pairing);
    const now = Date.now();
    const expiresAt = now + SESSION_LIFETIME_MS;

    this.createSchema();
    this.state.storage.sql.exec(
      "INSERT INTO meta (singleton, manager_hash, creator_public_key, expires_at) VALUES (1, ?, ?, ?)",
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
    await this.state.storage.setAlarm(expiresAt);
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
    });
    await this.state.storage.setAlarm(expiresAt);
    return json({ expiresAt }, 201);
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

  private async activeMeta(): Promise<MetaRow> {
    if ((await this.state.storage.get<boolean>(INITIALIZED_KEY)) !== true) {
      throw new HttpError(404, "session_not_found", "Session not found");
    }
    const rows = Array.from(
      this.state.storage.sql.exec<MetaRow>(
        "SELECT manager_hash, creator_public_key, expires_at FROM meta WHERE singleton = 1",
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

  private groupIdQuery(url: URL): string {
    const value: Record<string, unknown> = { groupId: url.searchParams.get("groupId") };
    return stringField(value, "groupId", IDENTIFIER, 64);
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
    `);
  }
}
