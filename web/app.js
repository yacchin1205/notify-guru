import { ApiError, getEvents, joinSession, postResponse } from "./api.js";
import { createIdentity, decryptEvent, deriveSessionKey, encryptResponse, hashToken, pairingProof, randomId, randomToken } from "./crypto.js";
import { deleteSession, getIdentity, getSession, listSessions, putIdentity, putSession } from "./db.js";
import { expiredSessionIDs } from "./expiry.js";

const cardsElement = document.querySelector("#cards");
const emptyElement = document.querySelector("#empty");
const messageElement = document.querySelector("#message");
const connectionElement = document.querySelector("#connection-state");
const cardTemplate = document.querySelector("#card-template");
let rendered = false;

window.addEventListener("unhandledrejection", (event) => {
  messageElement.textContent = `エラー: ${errorMessage(event.reason)}`;
  connectionElement.textContent = "同期エラー";
});

await initialize();

async function initialize() {
  if ("serviceWorker" in navigator) {
    await navigator.serviceWorker.register("/sw.js");
  }
  const identity = await identityOrCreate();
  await deleteExpiredLocalSessions();
  if (location.hash.length > 1) {
    await joinFromFragment(identity);
  }
  await syncAll();
  setInterval(syncAll, 2_000);
}

async function identityOrCreate() {
  const current = await getIdentity();
  if (current !== undefined) {
    return current;
  }
  const created = await createIdentity();
  await putIdentity(created);
  return created;
}

async function joinFromFragment(identity) {
  const parameters = new URLSearchParams(location.hash.slice(1));
  const required = ["v", "s", "p", "t", "a", "k"];
  for (const key of required) {
    if (parameters.getAll(key).length !== 1) {
      throw new Error(`Pairing URL must contain exactly one ${key}`);
    }
  }
  if (Array.from(parameters.keys()).length !== required.length || Array.from(parameters.keys()).some((key) => !required.includes(key))) {
    throw new Error("Pairing URL contains an unknown field");
  }
  if (parameters.get("v") !== "1") {
    throw new Error("Unsupported pairing protocol version");
  }

  const sessionId = parameters.get("s");
  const pairingId = parameters.get("p");
  const pairingToken = parameters.get("t");
  const authSecret = parameters.get("a");
  const creatorPublicKey = parameters.get("k");
  if (await getSession(sessionId) !== undefined) {
    throw new Error("This device group has already joined the session");
  }

  const groupAccessToken = randomToken();
  const proof = await pairingProof(authSecret, sessionId, pairingId, identity.groupId, identity.publicKey);
  const sharedKey = await deriveSessionKey(identity.keyPair.privateKey, creatorPublicKey, sessionId);
  const joined = await joinSession(sessionId, {
    pairingId,
    pairingToken,
    groupId: identity.groupId,
    groupAccessTokenHash: await hashToken(groupAccessToken),
    groupPublicKey: identity.publicKey,
    proof,
  });
  await putSession({
    sessionId,
    groupId: identity.groupId,
    groupAccessToken,
    sharedKey,
    cursor: 0,
    title: `Session ${sessionId.slice(0, 8)}`,
    status: "接続しました",
    notification: "",
    request: null,
    expiresAt: joined.expiresAt,
  });
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  messageElement.textContent = "セッションへ参加しました。";
}

async function syncAll() {
  connectionElement.textContent = "同期中";
  const expired = await deleteExpiredLocalSessions();
  if (expired) {
    await render();
    rendered = true;
  }
  const sessions = await listSessions();
  let changed = false;
  for (const session of sessions) {
    changed = (await syncSession(session)) || changed;
  }
  if (!rendered || changed) {
    await render();
    rendered = true;
  }
  connectionElement.textContent = "同期済み";
}

async function deleteExpiredLocalSessions() {
  const sessions = await listSessions();
  const expired = expiredSessionIDs(sessions, Date.now());
  for (const sessionID of expired) {
    await deleteSession(sessionID);
  }
  return expired.length > 0;
}

async function syncSession(session) {
  let result;
  try {
    result = await getEvents(session);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 410)) {
      await deleteSession(session.sessionId);
      return true;
    }
    throw error;
  }

  for (const envelope of result.events) {
    const event = await decryptEvent(session.sharedKey, session.sessionId, envelope);
    applyEvent(session, event);
    session.cursor = envelope.sequence;
  }
  session.expiresAt = result.expiresAt;
  await putSession(session);
  return result.events.length > 0;
}

function applyEvent(session, event) {
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("Decrypted event must be an object");
  }
  if (event.type === "notify") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "message", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.notification = stringValue(event.message, "message");
    return;
  }
  if (event.type === "status") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "status", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.status = stringValue(event.status, "status");
    return;
  }
  if (event.type === "request") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "requestId", "prompt", "options", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    if (!Array.isArray(event.options) || event.options.length < 2) {
      throw new Error("Request options must contain at least two choices");
    }
    for (const option of event.options) {
      requireExactKeys(option, ["id", "label"]);
      stringValue(option.id, "option.id");
      stringValue(option.label, "option.label");
    }
    session.request = event;
    return;
  }
  throw new Error(`Unsupported event type: ${String(event.type)}`);
}

async function render() {
  const sessions = await listSessions();
  cardsElement.replaceChildren();
  emptyElement.hidden = sessions.length !== 0;
  for (const session of sessions) {
    const card = cardTemplate.content.firstElementChild.cloneNode(true);
    card.querySelector(".session-title").textContent = session.title;
    card.querySelector(".expiry").textContent = expiryText(session.expiresAt);
    card.querySelector(".status").textContent = session.status;
    card.querySelector(".notification").textContent = session.notification;
    const requestElement = card.querySelector(".request");
    if (session.request !== null) {
      requestElement.hidden = false;
      requestElement.querySelector(".request-prompt").textContent = session.request.prompt;
      const optionsElement = requestElement.querySelector(".request-options");
      for (const option of session.request.options) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = option.label;
        button.addEventListener("click", () => respond(session.sessionId, option.id, button));
        optionsElement.append(button);
      }
    }
    cardsElement.append(card);
  }
}

async function respond(sessionId, optionId, button) {
  button.disabled = true;
  const session = await getSession(sessionId);
  if (session === undefined || session.request === null) {
    throw new Error("Request disappeared before response");
  }
  const responseId = randomId();
  const response = {
    id: responseId,
    requestId: session.request.requestId,
    optionId,
    createdAt: new Date().toISOString(),
  };
  const encrypted = await encryptResponse(session.sharedKey, session.sessionId, session.groupId, responseId, response);
  const posted = await postResponse(session, {
    responseId,
    groupId: session.groupId,
    ...encrypted,
  });
  session.request = null;
  session.status = "応答を送信しました";
  session.expiresAt = posted.expiresAt;
  await putSession(session);
  await render();
}

function requireExactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected an object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("Object fields do not match the protocol");
  }
}

function stringValue(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function expiryText(expiresAt) {
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) {
    return "失効確認中";
  }
  const hours = Math.max(1, Math.ceil(remaining / (60 * 60 * 1000)));
  return `残り約${hours}時間`;
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
