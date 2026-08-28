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
import { relativeTime } from "./relative-time.js";

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
let pendingDeviceRequest = null;
let sessionRenderSignature = "";

window.addEventListener("unhandledrejection", (event) => showError(event.reason));
document.querySelector("#open-device-management").addEventListener("click", () => setDeviceManagement(true));
document.querySelector("#close-device-management").addEventListener("click", () => setDeviceManagement(false));
requestSharingButton.addEventListener("click", () => beginDeviceRequest().catch(showError));
shareRequestButton.addEventListener("click", () => shareDeviceRequest().catch(showError));
leaveButton.addEventListener("click", () => leaveCurrentGroup().catch(showError));
resetLocalDataButton.addEventListener("click", () => resetCurrentDevice().catch((error) => showFatalError(error, true)));

initialize().catch(showFatalError);
setInterval(updateRelativeTimes, 1_000);

async function initialize() {
  if ("serviceWorker" in navigator) await navigator.serviceWorker.register("/sw.js");
  identity = await identityOrCreate();
  await migrateLocalSessions();
  await deleteExpiredLocalSessions();
  const scannedRequest = parseDeviceRequestFragment();
  if (scannedRequest !== null) {
    await approveScannedRequest(scannedRequest);
  } else {
    if (identity.group === null) await createSoloGroup();
    if (location.hash.length > 1) await joinFromFragment();
  }
  await syncAll();
  setInterval(() => syncAll().catch(showError), 2_000);
}

async function identityOrCreate() {
  const current = await getIdentity();
  if (current !== undefined) {
    if (current.protocolVersion !== 3) {
      throw new LegacyProtocolError("このブラウザに保存されているnotify.guruのデータを読み込めません。");
    }
    delete current.deviceRequest;
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
  if (identity.group !== null || pendingDeviceRequest !== null) throw new Error("Device already has an active destination");
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
  if (pendingDeviceRequest !== null) {
    showDeviceRequest(pendingDeviceRequest);
    return;
  }
  if (identity.group !== null) {
    await syncGroup();
    const sessions = (await listSessions()).filter((session) => session.protocolVersion === 3 && session.groupId === identity.group.groupId);
    if ((groupState.members.length > 1 || sessions.length > 0)
      && !window.confirm("このデバイスを現在のグループから除外し、表示中のセッションを削除して、別のグループへの追加を続けますか？")) return;
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
  pendingDeviceRequest = created;
  showDeviceRequest(created);
  setDeviceManagement(false);
}

function showDeviceRequest(deviceRequest) {
  const link = new URL("/device", location.origin);
  link.hash = new URLSearchParams({ v: "2", r: deviceRequest.requestId }).toString();
  requestURL = link.toString();
  renderQR(requestURL);
  waitingElement.hidden = false;
  waitingStatusElement.textContent = "追加先のグループに所属しているデバイスでこのQRコードを読み取ってください。";
}

async function approveScannedRequest(requestId) {
  if (identity.group === null || pendingDeviceRequest !== null) {
    throw new Error("このデバイスでは、別のデバイスをグループに追加できません");
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
  messageElement.textContent = "デバイスをグループへ追加しました。";
}

async function pollDeviceRequest() {
  if (pendingDeviceRequest === null) return;
  const requestId = pendingDeviceRequest.requestId;
  const signature = await signDevice(identity, deviceRequestReadTranscript(requestId, identity.deviceId));
  const state = await getDeviceRequest(identity, requestId, signature);
  if (state.status === "waiting") {
    showDeviceRequest(pendingDeviceRequest);
    return;
  }
  waitingElement.hidden = true;
  requestQRElement.replaceChildren();
  requestURL = undefined;
  pendingDeviceRequest = null;
  if (state.status === "expired") {
    await createSoloGroup();
    messageElement.textContent = "グループへの追加が時間切れになったため、このデバイスは単独利用に戻りました。";
    return;
  }
  identity.group = { groupId: state.groupId, keys: {} };
  await putIdentity(identity);
  await syncGroup();
  await ensureExactGroupKey();
  messageElement.textContent = "デバイスグループへ追加されました。";
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
  requireFragmentFields(parameters, ["v", "s", "p", "t", "a", "k", "c"]);
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
  await putSession(newSession(sessionId, identity.group.groupId, parameters.get("k"), expiresAt, colorValue(`#${parameters.get("c")}`)));
  history.replaceState(null, "", "/");
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
    applyEvent(
      session, await decryptEvent(key, session.sessionId, envelope), envelope.keyTimestamp, envelope.createdAt,
      envelope.itemId,
    );
    session.cursor = envelope.sequence;
    session.updatedAt = envelope.createdAt;
  }
  reconcileActiveItems(session, result.activeItemIds);
  session.expiresAt = result.expiresAt;
  await putSession(session);
}

async function respond(sessionId, optionId) {
  await sendRequestResponse(sessionId, "response", optionId);
}

async function dismissRequest(sessionId) {
  await sendRequestResponse(sessionId, "dismiss");
}

async function sendRequestResponse(sessionId, type, optionId) {
  const session = await getSession(sessionId);
  if (session === undefined || session.request === null) throw new Error("Request disappeared before response");
  const timestamp = session.requestKeyTimestamp;
  const key = session.keys[String(timestamp)];
  if (key === undefined) throw new Error("Response encryption key is unavailable");
  const responseId = randomId();
  const itemId = session.request.serverItemId;
  const response = type === "response"
    ? { id: responseId, type, requestId: session.request.requestId, optionId, createdAt: new Date().toISOString() }
    : itemId === null
      ? { id: responseId, type, requestId: session.request.requestId, createdAt: new Date().toISOString() }
      : { id: responseId, type, eventId: itemId, createdAt: new Date().toISOString() };
  const encrypted = await encryptResponse(key, session.sessionId, session.groupId, timestamp, responseId, response);
  session.expiresAt = await postResponse(session, identity, {
    responseId,
    groupId: session.groupId,
    deviceId: identity.deviceId,
    keyTimestamp: timestamp,
    ...(itemId === null ? {} : { itemId }),
    ...encrypted,
  });
  session.request = null;
  session.requestKeyTimestamp = null;
  session.status = type === "response" ? "応答を送信しました" : "リクエストを閉じました";
  await putSession(session);
  await render();
}

async function dismissNotification(sessionId, notificationId) {
  const session = await getSession(sessionId);
  if (session === undefined) throw new Error("Session disappeared before notification was dismissed");
  const index = session.notifications.findIndex((notification) => notification.id === notificationId);
  if (index === -1) throw new Error("Notification disappeared before it was dismissed");
  const notification = session.notifications[index];
  if (notification.serverItemId !== null) {
    const groupKey = await currentLocalKey();
    let key = session.keys[String(groupKey.timestamp)];
    if (key === undefined) {
      key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId);
      session.keys[String(groupKey.timestamp)] = key;
    }
    const responseId = randomId();
    const response = {
      id: responseId,
      type: "dismiss",
      eventId: notification.serverItemId,
      createdAt: new Date().toISOString(),
    };
    const encrypted = await encryptResponse(
      key, session.sessionId, session.groupId, groupKey.timestamp, responseId, response,
    );
    session.expiresAt = await postResponse(session, identity, {
      responseId,
      itemId: notification.serverItemId,
      groupId: session.groupId,
      deviceId: identity.deviceId,
      keyTimestamp: groupKey.timestamp,
      ...encrypted,
    });
  }
  session.notifications.splice(index, 1);
  await putSession(session);
  await render();
}

async function sendFeedback(sessionId, message) {
  const session = await getSession(sessionId);
  if (session === undefined) throw new Error("Session disappeared before feedback was sent");
  const text = message.trim();
  if (text.length === 0 || text.length > 20_000) throw new Error("メッセージは1文字以上20000文字以内で入力してください");
  const groupKey = await currentLocalKey();
  let key = session.keys[String(groupKey.timestamp)];
  if (key === undefined) {
    key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId);
    session.keys[String(groupKey.timestamp)] = key;
  }
  const responseId = randomId();
  const response = { id: responseId, type: "feedback", message: text, createdAt: new Date().toISOString() };
  const encrypted = await encryptResponse(key, session.sessionId, session.groupId, groupKey.timestamp, responseId, response);
  session.expiresAt = await postResponse(session, identity, {
    responseId,
    groupId: session.groupId,
    deviceId: identity.deviceId,
    keyTimestamp: groupKey.timestamp,
    ...encrypted,
  });
  await putSession(session);
  messageElement.textContent = "メッセージを送信しました。";
}

function applyEvent(session, event, keyTimestamp, createdAt, serverItemId) {
  if (event === null || typeof event !== "object" || Array.isArray(event)) throw new Error("Decrypted event must be an object");
  if (event.type === "notify") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "message", "color", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    const id = stringValue(event.id, "id");
    if (serverItemId !== null && serverItemId !== id) throw new Error("Notification ID does not match its server item ID");
    session.notifications.push({
      id,
      message: stringValue(event.message, "message"),
      createdAt,
      serverItemId,
    });
    session.color = colorValue(event.color);
    return;
  }
  if (event.type === "status") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "status", "color", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.status = stringValue(event.status, "status");
    session.color = colorValue(event.color);
    return;
  }
  if (event.type === "request") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "requestId", "prompt", "options", "color", "createdAt"]);
    if (!Array.isArray(event.options) || event.options.length < 2) throw new Error("Request options must contain at least two choices");
    for (const option of event.options) requireExactKeys(option, ["id", "label"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.color = colorValue(event.color);
    const requestId = stringValue(event.requestId, "requestId");
    if (serverItemId !== null && serverItemId !== requestId) throw new Error("Request ID does not match its server item ID");
    session.request = { ...event, createdAt, serverItemId };
    session.requestKeyTimestamp = keyTimestamp;
    return;
  }
  if (event.type === "close_request") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "requestId", "color", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.color = colorValue(event.color);
    if (session.request?.requestId === stringValue(event.requestId, "requestId")) {
      session.request = null;
      session.requestKeyTimestamp = null;
    }
    return;
  }
  if (event.type === "color") {
    requireExactKeys(event, ["id", "type", "sessionTitle", "color", "createdAt"]);
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    session.color = colorValue(event.color);
    return;
  }
  throw new Error(`Unsupported event type: ${String(event.type)}`);
}

function reconcileActiveItems(session, activeItemIds) {
  const active = new Set(activeItemIds);
  session.notifications = session.notifications.filter(
    (notification) => notification.serverItemId === null || active.has(notification.serverItemId),
  );
  if (session.request !== null && session.request.serverItemId !== null && !active.has(session.request.serverItemId)) {
    session.request = null;
    session.requestKeyTimestamp = null;
  }
}

async function removeGroupDevice(deviceId) {
  if (!window.confirm("このデバイスをグループから除外しますか？")) return;
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
  if (groupState === undefined || groupState.members.length <= 1) throw new Error("単独利用中のデバイスはグループから除外できません");
  if (!window.confirm("このデバイスをグループから除外しますか？このデバイスに表示されているセッションも削除されます。")) return;
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
  messageElement.textContent = "このデバイスは単独利用に戻りました。";
}

async function recoverRemovedDevice() {
  const groupId = identity.group.groupId;
  identity.group = null;
  await detachDeviceGroup(identity, groupId);
  groupState = undefined;
  await createSoloGroup();
  messageElement.textContent = "デバイスグループから除外されたため、このデバイスは単独利用に戻りました。";
  await renderGroup();
  await render();
  connectionElement.textContent = "接続中";
}

async function renderGroup() {
  const waiting = pendingDeviceRequest !== null;
  waitingElement.hidden = !waiting;
  deviceSummaryElement.hidden = waiting || identity.group === null || managingDevices;
  deviceManagementElement.hidden = waiting || identity.group === null || !managingDevices;
  if (waiting) showDeviceRequest(pendingDeviceRequest);
  if (identity.group === null || groupState === undefined) return;
  const sharing = groupState.members.length > 1;
  deviceSummaryTitleElement.textContent = sharing ? `${groupState.members.length}台で通知を共有中` : "共有なし";
  groupStatusElement.textContent = sharing ? `${groupState.members.length}台で通知を共有しています。` : "現在はこのデバイスだけで通知を受け取ります。";
  const current = selectUsableGroupKey(groupState);
  groupKeyTimeElement.textContent = current === null ? "利用可能な鍵なし" : `鍵 ${new Date(current.timestamp).toLocaleString()}`;
  leaveButton.hidden = !sharing;
  groupDevicesElement.replaceChildren();
  for (const member of groupState.members) {
    const row = document.createElement("div");
    row.className = "device-row";
    const label = document.createElement("span");
    label.textContent = member.deviceId === identity.deviceId ? `このデバイス · ${member.deviceId.slice(0, 8)}` : `デバイス · ${member.deviceId.slice(0, 8)}`;
    row.append(label);
    if (member.deviceId !== identity.deviceId) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "グループから除外";
      button.addEventListener("click", () => removeGroupDevice(member.deviceId).catch(showError));
      row.append(button);
    }
    groupDevicesElement.append(row);
  }
}

async function render() {
  const sessions = (await listSessions()).sort((left, right) => (right.updatedAt ?? 0) - (left.updatedAt ?? 0));
  const signature = JSON.stringify(sessions.map(({ keys: _keys, ...session }) => session));
  if (signature === sessionRenderSignature) return;
  sessionRenderSignature = signature;
  cardsElement.replaceChildren();
  emptyElement.hidden = sessions.length !== 0;
  for (const session of sessions) {
    const card = cardTemplate.content.firstElementChild.cloneNode(true);
    if (session.color !== null && session.color !== undefined) card.style.setProperty("--session-color", colorValue(session.color));
    card.querySelector(".session-title").textContent = session.title;
    card.querySelector(".expiry").textContent = expiryText(session.expiresAt);
    const sessionTime = card.querySelector(".session-time");
    setRelativeTime(sessionTime, session.updatedAt);
    const unresolvedCount = session.notifications.length + (session.request === null ? 0 : 1);
    const badge = card.querySelector(".unresolved-count");
    badge.hidden = unresolvedCount === 0;
    badge.textContent = String(unresolvedCount);
    badge.setAttribute("aria-label", `未対応項目: ${unresolvedCount}件`);
    card.querySelector(".status").textContent = session.status;
    const notifications = card.querySelector(".notifications");
    for (const notification of session.notifications) {
      const row = document.createElement("div");
      row.className = "notification";
      const content = document.createElement("div");
      content.className = "notification-content";
      const message = document.createElement("p");
      message.textContent = notification.message;
      const time = document.createElement("span");
      time.className = "relative-time";
      setRelativeTime(time, notification.createdAt);
      content.append(message, time);
      const dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.className = "dismiss-item";
      dismiss.textContent = "×";
      dismiss.setAttribute("aria-label", "通知を消す");
      dismiss.title = "通知を消す";
      dismiss.addEventListener("click", () => dismissNotification(session.sessionId, notification.id).catch(showError));
      row.append(content, dismiss);
      notifications.append(row);
    }
    if (session.request !== null) {
      const element = card.querySelector(".request");
      element.hidden = false;
      element.querySelector(".request-prompt").textContent = session.request.prompt;
      setRelativeTime(element.querySelector(".request-time"), session.request.createdAt);
      const dismiss = element.querySelector(".request-dismiss");
      dismiss.addEventListener("click", () => {
        dismiss.disabled = true;
        dismissRequest(session.sessionId).catch(showError).finally(() => { dismiss.disabled = false; });
      });
      for (const option of session.request.options) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = option.label;
        button.addEventListener("click", () => {
          button.disabled = true;
          respond(session.sessionId, option.id).catch(showError).finally(() => { button.disabled = false; });
        });
        element.querySelector(".request-options").append(button);
      }
    }
    const feedbackToggle = card.querySelector(".feedback-toggle");
    const feedbackForm = card.querySelector(".feedback-form");
    const feedbackMessage = card.querySelector(".feedback-message");
    feedbackToggle.addEventListener("click", () => {
      feedbackToggle.hidden = true;
      feedbackForm.hidden = false;
      feedbackMessage.focus();
    });
    card.querySelector(".feedback-cancel").addEventListener("click", () => {
      feedbackForm.reset();
      feedbackForm.hidden = true;
      feedbackToggle.hidden = false;
    });
    feedbackForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const submit = feedbackForm.querySelector('button[type="submit"]');
      submit.disabled = true;
      sendFeedback(session.sessionId, feedbackMessage.value).then(() => {
        feedbackForm.reset();
        feedbackForm.hidden = true;
        feedbackToggle.hidden = false;
      }).catch(showError).finally(() => { submit.disabled = false; });
    });
    cardsElement.append(card);
  }
}

function setRelativeTime(element, timestamp) {
  if (!Number.isSafeInteger(timestamp)) {
    element.hidden = true;
    return;
  }
  element.hidden = false;
  element.dataset.timestamp = String(timestamp);
  element.textContent = relativeTime(timestamp);
}

function updateRelativeTimes() {
  const now = Date.now();
  for (const element of document.querySelectorAll("[data-timestamp]")) {
    const timestamp = Number(element.dataset.timestamp);
    if (!Number.isSafeInteger(timestamp)) throw new Error("Relative time element has an invalid timestamp");
    element.textContent = relativeTime(timestamp, now);
  }
}

function newSession(sessionId, groupId, creatorPublicKey, expiresAt, color = null) {
  return {
    protocolVersion: 3, sessionId, groupId, creatorPublicKey, keys: {}, cursor: 0,
    title: `Session ${sessionId.slice(0, 8)}`, status: "接続しました", notifications: [],
    request: null, requestKeyTimestamp: null, color, updatedAt: Date.now(), expiresAt,
  };
}

async function migrateLocalSessions() {
  for (const session of await listSessions()) {
    if (Object.hasOwn(session, "notifications")) {
      if (!Array.isArray(session.notifications)) throw new Error("Stored session notifications must be an array");
      let changed = false;
      for (const notification of session.notifications) {
        if (!Object.hasOwn(notification, "createdAt")) {
          notification.createdAt = null;
          changed = true;
        }
        if (!Object.hasOwn(notification, "serverItemId")) {
          notification.serverItemId = null;
          changed = true;
        }
        requireExactKeys(notification, ["id", "message", "createdAt", "serverItemId"]);
        if (notification.createdAt !== null && !Number.isSafeInteger(notification.createdAt)) {
          throw new Error("Stored notification time must be integer milliseconds or null");
        }
        if (notification.serverItemId !== null && typeof notification.serverItemId !== "string") {
          throw new Error("Stored notification server item ID must be a string or null");
        }
        stringValue(notification.id, "notification id");
        stringValue(notification.message, "notification message");
      }
      if (session.request !== null) {
        if (!Object.hasOwn(session.request, "createdAt") || typeof session.request.createdAt === "string") {
          session.request.createdAt = null;
          changed = true;
        }
        if (!Object.hasOwn(session.request, "serverItemId")) {
          session.request.serverItemId = null;
          changed = true;
        }
        if (session.request.createdAt !== null && !Number.isSafeInteger(session.request.createdAt)) {
          throw new Error("Stored request time must be integer milliseconds or null");
        }
        if (session.request.serverItemId !== null && typeof session.request.serverItemId !== "string") {
          throw new Error("Stored request server item ID must be a string or null");
        }
      }
      if (changed) await putSession(session);
      continue;
    }
    if (typeof session.notification !== "string") throw new Error("Stored session notification is invalid");
    session.notifications = session.notification === "" ? [] : [{
      id: `legacy:${session.sessionId}`,
      message: session.notification,
      createdAt: null,
      serverItemId: null,
    }];
    delete session.notification;
    await putSession(session);
  }
}

function colorValue(value) {
  if (typeof value !== "string" || !/^#[0-9a-fA-F]{6}$/.test(value)) throw new Error("Session color must be #rrggbb");
  return value.toLowerCase();
}

function parseDeviceRequestFragment() {
  if (location.pathname !== "/device" || location.hash.length <= 1) return null;
  const parameters = new URLSearchParams(location.hash.slice(1));
  requireFragmentFields(parameters, ["v", "r"]);
  if (parameters.get("v") !== "2") throw new Error("このグループ追加用リンクは使用できません");
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
  requireExactKeys(envelope, ["sequence", "eventId", "itemId", "groupId", "keyTimestamp", "nonce", "ciphertext", "createdAt"]);
  if (envelope.itemId !== null && typeof envelope.itemId !== "string") {
    throw new Error("Event envelope itemId must be a string or null");
  }
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
  if (requestURL === undefined) throw new Error("有効な追加用リンクがありません");
  if (navigator.share !== undefined) await navigator.share({ title: "notify.guru device group", url: requestURL });
  else {
    await navigator.clipboard.writeText(requestURL);
    messageElement.textContent = "追加用リンクをコピーしました。";
  }
}

function renderQR(value) {
  const quietZone = 4;
  const { size, modules } = qrMatrix(value);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${size + quietZone * 2} ${size + quietZone * 2}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "このデバイスをグループに追加するQRコード");
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
    resetLocalDataButton.textContent = "このデバイスのデータをリセット";
    throw error;
  }
}
