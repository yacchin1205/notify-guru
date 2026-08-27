import {
  ApiError,
  approveDeviceRequest,
  createDeviceGroup,
  createDeviceRequest,
  getDeviceRequest,
  getEvents,
  getGroupState,
  joinSession,
  postResponse,
  registerDevice,
  registerGroupKey,
  removeDevice,
} from "./api.js";
import {
  createDeviceIdentity,
  createGroupKey,
  createKeyPackage,
  decryptEvent,
  deriveSessionKey,
  deviceCreateTranscript,
  deviceRequestReadTranscript,
  deviceRequestTranscript,
  encryptResponse,
  groupCreateTranscript,
  groupDeviceApproveTranscript,
  groupDeviceRemoveTranscript,
  groupKeyRegisterTranscript,
  hashToken,
  openKeyPackage,
  pairingProof,
  randomId,
  randomToken,
  signDevice,
} from "./crypto.js";
import {
  deleteSession,
  detachDeviceGroup,
  getIdentity,
  getSession,
  listSessions,
  putIdentity,
  putSession,
  resetLocalData,
} from "./db.js";
import { expiredSessionIDs } from "./expiry.js";
import { latestGroupKeyMatchesMembers, nextGroupKeyIsRecreated, selectUsableGroupKey } from "./group-key-policy.js";
import { qrMatrix } from "./qr.js";

const cardsElement = document.querySelector("#cards");
const emptyElement = document.querySelector("#empty");
const messageElement = document.querySelector("#message");
const connectionElement = document.querySelector("#connection-state");
const cardTemplate = document.querySelector("#card-template");
const deviceSummaryElement = document.querySelector("#device-summary");
const deviceSummaryTitleElement = document.querySelector("#device-summary-title");
const deviceManagementElement = document.querySelector("#device-management");
const groupStatusElement = document.querySelector("#group-status");
const groupKeyTimeElement = document.querySelector("#group-key-time");
const groupDevicesElement = document.querySelector("#group-devices");
const requestQRElement = document.querySelector("#invitation-qr");
const requestSharingButton = document.querySelector("#request-device-sharing");
const shareRequestButton = document.querySelector("#share-invitation");
const leaveButton = document.querySelector("#leave-device-group");
const waitingElement = document.querySelector("#join-device");
const waitingStatusElement = document.querySelector("#join-device-status");
const startupErrorElement = document.querySelector("#startup-error");
const startupErrorMessageElement = document.querySelector("#startup-error-message");
const resetLocalDataActionsElement = document.querySelector("#reset-local-data-actions");
const resetLocalDataButton = document.querySelector("#reset-local-data");

class LegacyProtocolError extends Error {}

let identity;
let groupState;
let managingDevices = false;
let synchronizing = false;
let requestURL;

window.addEventListener("unhandledrejection", (event) => showError(event.reason));
document.querySelector("#open-device-management").addEventListener("click", () => setDeviceManagement(true));
document.querySelector("#close-device-management").addEventListener("click", () => setDeviceManagement(false));
requestSharingButton.addEventListener("click", () => beginDeviceRequest().catch(showError));
shareRequestButton.addEventListener("click", () => shareDeviceRequest().catch(showError));
leaveButton.addEventListener("click", () => leaveCurrentGroup().catch(showError));
resetLocalDataButton.addEventListener("click", () => resetCurrentDevice().catch((error) => showFatalError(error, true)));

initialize().catch(showFatalError);

async function initialize() {
  if ("serviceWorker" in navigator) await navigator.serviceWorker.register("/sw.js");
  identity = await identityOrCreate();
  await deleteExpiredLocalSessions();
  const scannedRequest = parseDeviceRequestFragment();
  if (scannedRequest !== null) {
    await approveScannedRequest(scannedRequest);
  } else {
    if (identity.group === null && identity.deviceRequest === null) await createSoloGroup();
    if (location.hash.length > 1) await joinFromFragment();
  }
  await syncAll();
  setInterval(() => syncAll().catch(showError), 2_000);
}

async function identityOrCreate() {
  const current = await getIdentity();
  if (current !== undefined) {
    if (current.protocolVersion !== 3) {
      throw new LegacyProtocolError("保存済みデータは旧プロトコルのため、このバージョンでは読み込めません。");
    }
    return current;
  }
  const created = await createDeviceIdentity();
  const nonce = randomToken();
  created.deviceId = await registerDevice({
    signingPublicKey: created.signingPublicKey,
    nonce,
    signature: await signDevice(created, deviceCreateTranscript(created.signingPublicKey, nonce)),
  });
  await putIdentity(created);
  return created;
}

async function createSoloGroup() {
  if (identity.group !== null || identity.deviceRequest !== null) throw new Error("Device already has an active destination");
  const groupId = randomId();
  const accessHash = await hashToken(identity.accessToken);
  await createDeviceGroup({
    groupId,
    deviceId: identity.deviceId,
    deviceAccessTokenHash: accessHash,
    deviceEncryptionPublicKey: identity.encryptionPublicKey,
    deviceSignature: await signDevice(identity, groupCreateTranscript(groupId, identity, accessHash)),
  });
  identity.group = { groupId, keys: {} };
  await putIdentity(identity);
  await syncGroup();
}

async function beginDeviceRequest() {
  if (identity.deviceRequest !== null) {
    showDeviceRequest(identity.deviceRequest);
    return;
  }
  if (identity.group !== null) {
    await syncGroup();
    const sessions = (await listSessions()).filter((session) => session.protocolVersion === 3 && session.groupId === identity.group.groupId);
    if ((groupState.members.length > 1 || sessions.length > 0)
      && !window.confirm("現在の端末共有とセッションを捨て、この端末を別の共有へ追加しますか？")) return;
    const groupId = identity.group.groupId;
    await removeDevice(identity, identity.deviceId, {
      actorSignature: await signDevice(
        identity,
        groupDeviceRemoveTranscript(identity.group.groupId, identity.deviceId, identity.deviceId),
      ),
    });
    identity.group = null;
    await detachDeviceGroup(identity, groupId);
    groupState = undefined;
  }
  const requestId = randomId();
  const accessHash = await hashToken(identity.accessToken);
  const created = await createDeviceRequest({
    requestId,
    deviceId: identity.deviceId,
    deviceAccessTokenHash: accessHash,
    deviceEncryptionPublicKey: identity.encryptionPublicKey,
    deviceSignature: await signDevice(identity, deviceRequestTranscript(requestId, identity, accessHash)),
  });
  identity.deviceRequest = created;
  await putIdentity(identity);
  showDeviceRequest(created);
  await renderGroup();
}

function showDeviceRequest(deviceRequest) {
  const link = new URL("/device", location.origin);
  link.hash = new URLSearchParams({ v: "2", r: deviceRequest.requestId }).toString();
  requestURL = link.toString();
  renderQR(requestURL);
  waitingElement.hidden = false;
  waitingStatusElement.textContent = "既存端末でQRコードを読み取ると、この端末が共有へ追加されます。";
}

async function approveScannedRequest(requestId) {
  if (identity.group === null || identity.deviceRequest !== null) {
    throw new Error("追加依頼を承認できる端末共有がありません");
  }
  await syncGroup();
  await ensureExactGroupKey();
  await approveDeviceRequest(identity, requestId, {
    actorSignature: await signDevice(
      identity,
      groupDeviceApproveTranscript(identity.group.groupId, identity.deviceId, requestId),
    ),
  });
  await syncGroup();
  await ensureExactGroupKey();
  history.replaceState(null, "", "/");
  messageElement.textContent = "端末を共有へ追加しました。";
}

async function pollDeviceRequest() {
  if (identity.deviceRequest === null) return;
  const requestId = identity.deviceRequest.requestId;
  const signature = await signDevice(identity, deviceRequestReadTranscript(requestId, identity.deviceId));
  const state = await getDeviceRequest(identity, requestId, signature);
  if (state.status === "waiting") {
    showDeviceRequest(identity.deviceRequest);
    return;
  }
  waitingElement.hidden = true;
  requestQRElement.replaceChildren();
  requestURL = undefined;
  identity.deviceRequest = null;
  if (state.status === "expired") {
    await putIdentity(identity);
    await createSoloGroup();
    messageElement.textContent = "端末追加依頼が失効したため、単独利用に戻りました。";
    return;
  }
  identity.group = { groupId: state.groupId, keys: {} };
  await putIdentity(identity);
  await syncGroup();
  await ensureExactGroupKey();
  messageElement.textContent = "端末共有へ追加されました。";
}

async function syncAll() {
  if (synchronizing) return;
  synchronizing = true;
  try {
    await deleteExpiredLocalSessions();
    await pollDeviceRequest();
    if (identity.group !== null) {
      await syncGroup();
      await ensureExactGroupKey();
      await inheritSessions();
      for (const session of await listSessions()) {
        if (session.protocolVersion !== 3) throw new Error("Stored session uses an unsupported protocol");
        if (session.groupId !== identity.group.groupId) continue;
        try {
          await syncSession(session);
        } catch (error) {
          if (error instanceof ApiError
            && ((error.status === 404 && error.code === "session_not_found")
              || (error.status === 410 && error.code === "session_expired"))) {
            await deleteSession(session.sessionId);
            continue;
          }
          throw error;
        }
      }
    }
    await renderGroup();
    await render();
    connectionElement.textContent = "接続中";
  } catch (error) {
    if (error instanceof ApiError && error.status === 403 && error.code === "device_removed" && identity.group !== null) {
      await recoverRemovedDevice();
      return;
    }
    throw error;
  } finally {
    synchronizing = false;
  }
}

async function syncGroup() {
  if (identity.group === null) throw new Error("Device group is unavailable");
  const state = await getGroupState(identity);
  validateGroupState(state);
  for (const keyPackage of state.packages) {
    const localKey = identity.group.keys[String(keyPackage.timestamp)];
    const keyRecord = state.keys.find((key) => key.timestamp === keyPackage.timestamp);
    if (keyRecord === undefined) throw new Error("Key package refers to an unknown group key");
    if (localKey === undefined) {
      identity.group.keys[String(keyPackage.timestamp)] = await openKeyPackage(identity, state.groupId, keyRecord, keyPackage);
    } else if (localKey.publicKey !== keyRecord.publicKey) {
      throw new Error("Stored group key conflicts with server metadata");
    }
  }
  groupState = state;
  await putIdentity(identity);
}

async function ensureExactGroupKey() {
  if (identity.group === null || groupState === undefined) throw new Error("Device group is not synchronized");
  const active = groupState.members.map((member) => member.deviceId).sort();
  if (latestGroupKeyMatchesMembers(groupState)) return;
  const recreated = nextGroupKeyIsRecreated(groupState);
  const groupKey = await createGroupKey();
  const packages = [];
  for (const member of groupState.members) packages.push(await createKeyPackage(groupState.groupId, groupKey, member));
  try {
    const registration = {
      publicKey: groupKey.publicKey,
      recreated,
      members: active,
      packages,
    };
    const timestamp = await registerGroupKey(identity, {
      ...registration,
      actorSignature: await signDevice(
        identity,
        groupKeyRegisterTranscript(identity.group.groupId, identity.deviceId, registration),
      ),
    });
    identity.group.keys[String(timestamp)] = { ...groupKey, timestamp };
    await putIdentity(identity);
  } catch (error) {
    if (!(error instanceof ApiError) || !["member_set_changed", "key_timestamp_conflict"].includes(error.code)) throw error;
  }
  await syncGroup();
}

async function currentLocalKey() {
  const keyRecord = selectUsableGroupKey(groupState);
  if (keyRecord === null) throw new Error("No usable group key is registered");
  const key = identity.group.keys[String(keyRecord.timestamp)];
  if (key === undefined || key.publicKey !== keyRecord.publicKey) throw new Error("Current group private key is unavailable");
  return key;
}

async function joinFromFragment() {
  const parameters = new URLSearchParams(location.hash.slice(1));
  requireFragmentFields(parameters, ["v", "s", "p", "t", "a", "k"]);
  if (parameters.get("v") !== "3") throw new Error("Unsupported pairing protocol version");
  if (identity.group === null) await createSoloGroup();
  await syncGroup();
  await ensureExactGroupKey();
  const sessionId = parameters.get("s");
  if (await getSession(sessionId) !== undefined) throw new Error("This device group has already joined the session");
  const groupKey = await currentLocalKey();
  const pairingId = parameters.get("p");
  const proof = await pairingProof(
    parameters.get("a"), sessionId, pairingId, identity.group.groupId, groupKey.timestamp, groupKey.publicKey,
  );
  const expiresAt = await joinSession(sessionId, {
    pairingId,
    pairingToken: parameters.get("t"),
    groupId: identity.group.groupId,
    deviceId: identity.deviceId,
    deviceAccessToken: identity.accessToken,
    keyTimestamp: groupKey.timestamp,
    groupPublicKey: groupKey.publicKey,
    proof,
  });
  await putSession(newSession(sessionId, identity.group.groupId, parameters.get("k"), expiresAt));
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  messageElement.textContent = "セッションへ参加しました。";
}

async function inheritSessions() {
  for (const remote of groupState.sessions) {
    if (await getSession(remote.sessionId) === undefined) {
      await putSession(newSession(remote.sessionId, groupState.groupId, remote.creatorPublicKey, remote.expiresAt));
    }
  }
}

async function syncSession(session) {
  const result = await getEvents(session, identity);
  for (const envelope of result.events) {
    validateEnvelope(envelope, session);
    const groupKey = identity.group.keys[String(envelope.keyTimestamp)];
    if (groupKey === undefined) throw new Error(`Private key for event timestamp ${envelope.keyTimestamp} is unavailable`);
    let key = session.keys[String(envelope.keyTimestamp)];
    if (key === undefined) {
      key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId);
      session.keys[String(envelope.keyTimestamp)] = key;
    }
    applyEvent(session, await decryptEvent(key, session.sessionId, envelope), envelope.keyTimestamp);
    session.cursor = envelope.sequence;
  }
  session.expiresAt = result.expiresAt;
  await putSession(session);
}

async function respond(sessionId, optionId, button) {
  button.disabled = true;
  const session = await getSession(sessionId);
  if (session === undefined || session.request === null) throw new Error("Request disappeared before response");
  const timestamp = session.requestKeyTimestamp;
  const key = session.keys[String(timestamp)];
  if (key === undefined) throw new Error("Response encryption key is unavailable");
  const responseId = randomId();
  const response = { id: responseId, requestId: session.request.requestId, optionId, createdAt: new Date().toISOString() };
  const encrypted = await encryptResponse(key, session.sessionId, session.groupId, timestamp, responseId, response);
  session.expiresAt = await postResponse(session, identity, {
    responseId,
    groupId: session.groupId,
    deviceId: identity.deviceId,
    keyTimestamp: timestamp,
    ...encrypted,
  });
  session.request = null;
  session.status = "応答を送信しました";
  await putSession(session);
  await render();
}

function applyEvent(session, event, keyTimestamp) {
  if (event === null || typeof event !== "object" || Array.isArray(event)) throw new Error("Decrypted event must be an object");
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
    if (!Array.isArray(event.options) || event.options.length < 2) throw new Error("Request options must contain at least two choices");
    for (const option of event.options) requireExactKeys(option, ["id", "label"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.request = event;
    session.requestKeyTimestamp = keyTimestamp;
    return;
  }
  throw new Error(`Unsupported event type: ${String(event.type)}`);
}

async function removeGroupDevice(deviceId) {
  if (!window.confirm("この端末との共有を解除しますか？")) return;
  await removeDevice(identity, deviceId, {
    actorSignature: await signDevice(
      identity,
      groupDeviceRemoveTranscript(identity.group.groupId, identity.deviceId, deviceId),
    ),
  });
  await syncGroup();
  await ensureExactGroupKey();
  await renderGroup();
}

async function leaveCurrentGroup() {
  if (groupState === undefined || groupState.members.length <= 1) throw new Error("単独利用中の端末は離脱できません");
  if (!window.confirm("この端末での共有をやめ、共有中のセッションと鍵を削除しますか？")) return;
  const groupId = identity.group.groupId;
  await removeDevice(identity, identity.deviceId, {
    actorSignature: await signDevice(
      identity,
      groupDeviceRemoveTranscript(identity.group.groupId, identity.deviceId, identity.deviceId),
    ),
  });
  identity.group = null;
  await detachDeviceGroup(identity, groupId);
  groupState = undefined;
  await createSoloGroup();
  setDeviceManagement(false);
  messageElement.textContent = "この端末は単独利用に戻りました。";
}

async function recoverRemovedDevice() {
  const groupId = identity.group.groupId;
  identity.group = null;
  await detachDeviceGroup(identity, groupId);
  groupState = undefined;
  await createSoloGroup();
  messageElement.textContent = "端末共有が解除されたため、この端末は単独利用に戻りました。";
  await renderGroup();
  await render();
  connectionElement.textContent = "接続中";
}

async function renderGroup() {
  const waiting = identity.deviceRequest !== null;
  waitingElement.hidden = !waiting;
  deviceSummaryElement.hidden = waiting || identity.group === null || managingDevices;
  deviceManagementElement.hidden = waiting || identity.group === null || !managingDevices;
  if (waiting) showDeviceRequest(identity.deviceRequest);
  if (identity.group === null || groupState === undefined) return;
  const sharing = groupState.members.length > 1;
  deviceSummaryTitleElement.textContent = sharing ? `${groupState.members.length}台で通知を共有中` : "この端末のみ";
  groupStatusElement.textContent = sharing ? `${groupState.members.length}台で通知を共有しています。` : "現在はこの端末だけで通知を受け取ります。";
  const current = selectUsableGroupKey(groupState);
  groupKeyTimeElement.textContent = current === null ? "利用可能な鍵なし" : `鍵 ${new Date(current.timestamp).toLocaleString()}`;
  leaveButton.hidden = !sharing;
  groupDevicesElement.replaceChildren();
  for (const member of groupState.members) {
    const row = document.createElement("div");
    row.className = "device-row";
    const label = document.createElement("span");
    label.textContent = member.deviceId === identity.deviceId ? `この端末 · ${member.deviceId.slice(0, 8)}` : `端末 · ${member.deviceId.slice(0, 8)}`;
    row.append(label);
    if (member.deviceId !== identity.deviceId) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "共有を解除";
      button.addEventListener("click", () => removeGroupDevice(member.deviceId).catch(showError));
      row.append(button);
    }
    groupDevicesElement.append(row);
  }
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
    if (session.request !== null) {
      const element = card.querySelector(".request");
      element.hidden = false;
      element.querySelector(".request-prompt").textContent = session.request.prompt;
      for (const option of session.request.options) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = option.label;
        button.addEventListener("click", () => respond(session.sessionId, option.id, button).catch(showError));
        element.querySelector(".request-options").append(button);
      }
    }
    cardsElement.append(card);
  }
}

function newSession(sessionId, groupId, creatorPublicKey, expiresAt) {
  return {
    protocolVersion: 3, sessionId, groupId, creatorPublicKey, keys: {}, cursor: 0,
    title: `Session ${sessionId.slice(0, 8)}`, status: "接続しました", notification: "",
    request: null, requestKeyTimestamp: null, expiresAt,
  };
}

function parseDeviceRequestFragment() {
  if (location.pathname !== "/device" || location.hash.length <= 1) return null;
  const parameters = new URLSearchParams(location.hash.slice(1));
  requireFragmentFields(parameters, ["v", "r"]);
  if (parameters.get("v") !== "2") throw new Error("Unsupported device request version");
  return parameters.get("r");
}

function validateGroupState(state) {
  for (const member of state.members) requireExactKeys(member, ["deviceId", "encryptionPublicKey", "addedAt"]);
  for (const key of state.keys) {
    requireExactKeys(key, ["timestamp", "publicKey", "recreated", "members"]);
    if (!Number.isSafeInteger(key.timestamp) || !Array.isArray(key.members) || typeof key.recreated !== "boolean") {
      throw new Error("Invalid group key metadata");
    }
  }
  for (const item of state.packages) requireExactKeys(item, ["timestamp", "deviceId", "ephemeralPublicKey", "nonce", "ciphertext"]);
  for (const session of state.sessions) requireExactKeys(session, ["sessionId", "creatorPublicKey", "expiresAt"]);
}

function validateEnvelope(envelope, session) {
  requireExactKeys(envelope, ["sequence", "eventId", "groupId", "keyTimestamp", "nonce", "ciphertext", "createdAt"]);
  if (envelope.groupId !== session.groupId || !Number.isSafeInteger(envelope.sequence) || !Number.isSafeInteger(envelope.keyTimestamp)) {
    throw new Error("Event envelope does not match the session");
  }
}

function requireFragmentFields(parameters, required) {
  for (const key of required) if (parameters.getAll(key).length !== 1) throw new Error(`Pairing URL must contain exactly one ${key}`);
  const actual = Array.from(parameters.keys());
  if (actual.length !== required.length || actual.some((key) => !required.includes(key))) throw new Error("Pairing URL contains an unknown field");
}

function requireExactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected an object");
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error("Object fields do not match the protocol");
}

function stringValue(value, field) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field} must be a non-empty string`);
  return value;
}

function setDeviceManagement(enabled) {
  managingDevices = enabled;
  document.body.classList.toggle("managing-devices", enabled);
  renderGroup().catch(showError);
}

async function shareDeviceRequest() {
  if (requestURL === undefined) throw new Error("有効な端末追加依頼がありません");
  if (navigator.share !== undefined) await navigator.share({ title: "notify.guru device request", url: requestURL });
  else {
    await navigator.clipboard.writeText(requestURL);
    messageElement.textContent = "端末追加依頼リンクをコピーしました。";
  }
}

function renderQR(value) {
  const quietZone = 4;
  const { size, modules } = qrMatrix(value);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${size + quietZone * 2} ${size + quietZone * 2}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "端末追加依頼QRコード");
  const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  background.setAttribute("width", "100%"); background.setAttribute("height", "100%"); background.setAttribute("fill", "white");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  const cells = [];
  for (let row = 0; row < size; row += 1) for (let column = 0; column < size; column += 1) {
    if (modules[row][column]) cells.push(`M${column + quietZone} ${row + quietZone}h1v1h-1z`);
  }
  path.setAttribute("d", cells.join("")); path.setAttribute("fill", "black");
  svg.append(background, path);
  requestQRElement.replaceChildren(svg);
}

async function deleteExpiredLocalSessions() {
  const sessions = await listSessions();
  const expired = expiredSessionIDs(sessions, Date.now());
  for (const sessionId of expired) await deleteSession(sessionId);
}

function expiryText(expiresAt) {
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) return "失効確認中";
  return `残り約${Math.max(1, Math.ceil(remaining / 3_600_000))}時間`;
}

function showError(error) {
  messageElement.textContent = `エラー: ${error instanceof Error ? error.message : String(error)}`;
  connectionElement.textContent = "同期エラー";
}

function showFatalError(error, resetAvailable = error instanceof LegacyProtocolError) {
  console.error(error);
  startupErrorMessageElement.textContent = error instanceof Error ? error.message : String(error);
  resetLocalDataActionsElement.hidden = !resetAvailable;
  startupErrorElement.hidden = false;
  connectionElement.textContent = "起動エラー";
}

async function resetCurrentDevice() {
  resetLocalDataButton.disabled = true;
  resetLocalDataButton.textContent = "リセット中…";
  try {
    await resetLocalData();
    location.replace("/");
  } catch (error) {
    resetLocalDataButton.disabled = false;
    resetLocalDataButton.textContent = "この端末のデータをリセット";
    throw error;
  }
}
