import {
  ApiError,
  approveDeviceRequest,
  createDeviceGroup,
  createDeviceRequest,
  getDeviceRequestForApproval,
  getDeviceRequest,
  getEvents,
  getGroupState,
  joinSession,
  postResponse,
  reserveAttachment,
  registerGroupKey,
  registerDevice,
  removeDevice,
  uploadAttachment,
} from "./api.js";
import {
  authenticatedInheritedSessions,
  createDeviceIdentity,
  createGroupTransition,
  createSessionDescriptor,
  createGroupKey,
  createKeyPackage,
  decryptEvent,
  deriveSessionKey,
  deviceApprovalProof,
  deviceCreateTranscript,
  deviceRequestBindingHash,
  deviceRequestReadTranscript,
  deviceRequestTranscript,
  encryptResponse,
  encryptAttachment,
  groupCreateTranscript,
  hashToken,
  openKeyPackage,
  pairingProof,
  randomId,
  randomToken,
  signDevice,
  validateGroupTransitions,
  verifyDeviceApprovalProof,
  verifyKeyPackageDigest,
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
    if (current.protocolVersion !== 3 && current.protocolVersion !== 4) {
      throw new LegacyProtocolError("このブラウザに保存されているnotify.guruのデータを読み込めません。");
    }
    current.protocolVersion = 4;
    if (current.group !== null && (current.group.rootTransitionHash === undefined || current.group.headTransitionHash === undefined)) {
      throw new LegacyProtocolError("このブラウザのデバイスグループは、安全なv4鍵履歴を持っていません。ローカルデータを消去して再設定してください。");
    }
    delete current.deviceRequest;
    await putIdentity(current);
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
  const groupKey = await createGroupKey();
  const member = {
    deviceId: identity.deviceId,
    signingPublicKey: identity.signingPublicKey,
    encryptionPublicKey: identity.encryptionPublicKey,
  };
  const packages = [await createKeyPackage(groupId, groupKey, member)];
  const transition = await createGroupTransition(groupId, identity, groupKey, null, [member], packages, true);
  await createDeviceGroup({
    groupId,
    deviceId: identity.deviceId,
    deviceAccessTokenHash: accessHash,
    deviceEncryptionPublicKey: identity.encryptionPublicKey,
    deviceSignature: await signDevice(identity, groupCreateTranscript(groupId, identity, accessHash)),
    protocolVersion: 4,
    transition,
    packages,
  });
  identity.group = {
    groupId,
    rootTransitionHash: transition.transitionHash,
    headTransitionHash: transition.transitionHash,
    keys: {
      [String(transition.timestamp)]: { ...groupKey, timestamp: transition.timestamp, transitionHash: transition.transitionHash },
    },
  };
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
    const sessions = (await listSessions()).filter((session) => (session.protocolVersion === 3 || session.protocolVersion === 4) && session.groupId === identity.group.groupId);
    if ((groupState.members.length > 1 || sessions.length > 0)
      && !window.confirm("このデバイスを現在のグループから除外し、表示中のセッションを削除して、別のグループへの追加を続けますか？")) return;
    const groupId = identity.group.groupId;
    if (groupState.members.length === 1) {
      await removeDevice(identity, identity.deviceId, {
        actorSignature: await signDevice(identity, groupAbandonTranscript(
          identity.group.groupId, identity.deviceId, identity.group.headTransitionHash,
        )),
        headTransitionHash: identity.group.headTransitionHash,
      });
    } else {
      const remaining = groupState.members.filter((member) => member.deviceId !== identity.deviceId);
      const update = await createSelfRemovalTransition(remaining);
      await removeDevice(identity, identity.deviceId, { transition: update.transition, packages: update.packages });
    }
    identity.group = null;
    await detachDeviceGroup(identity, groupId);
    groupState = undefined;
  }
  const requestId = randomId();
  const authSecret = randomToken();
  const accessHash = await hashToken(identity.accessToken);
  const created = await createDeviceRequest({
    requestId,
    deviceId: identity.deviceId,
    deviceAccessTokenHash: accessHash,
    deviceEncryptionPublicKey: identity.encryptionPublicKey,
    deviceSignature: await signDevice(identity, deviceRequestTranscript(requestId, identity, accessHash, 4)),
    protocolVersion: 4,
  });
  const expectedRequestHash = await deviceRequestBindingHash({
    requestId,
    deviceId: identity.deviceId,
    signingPublicKey: identity.signingPublicKey,
    accessHash,
    encryptionPublicKey: identity.encryptionPublicKey,
    protocolVersion: 4,
  });
  if (created.requestHash !== expectedRequestHash) throw new Error("Relay changed the device request binding");
  pendingDeviceRequest = { ...created, authSecret };
  showDeviceRequest(pendingDeviceRequest);
  setDeviceManagement(false);
}

function showDeviceRequest(deviceRequest) {
  const link = new URL("/device", location.origin);
  link.hash = new URLSearchParams({
    v: "3", r: deviceRequest.requestId, a: deviceRequest.authSecret, h: deviceRequest.requestHash,
  }).toString();
  requestURL = link.toString();
  renderQR(requestURL);
  waitingElement.hidden = false;
  waitingStatusElement.textContent = "追加先のグループに所属しているデバイスでこのQRコードを読み取ってください。";
}

async function approveScannedRequest(scannedRequest) {
  if (identity.group === null || pendingDeviceRequest !== null) {
    throw new Error("このデバイスでは、別のデバイスをグループに追加できません");
  }
  await syncGroup();
  await ensureExactGroupKey();
  const requested = await getDeviceRequestForApproval(identity, scannedRequest.requestId);
  if (await deviceRequestBindingHash(requested) !== scannedRequest.requestHash) {
    throw new Error("追加用リンクと端末要求の内容が一致しません");
  }
  if (requested.protocolVersion !== 4) throw new Error("この端末要求は安全なv4追加方式に対応していません");
  if (groupState.members.some((member) => member.deviceId === requested.deviceId)) {
    throw new Error("この端末はすでにグループへ追加されています");
  }
  const members = [...groupState.members, {
    deviceId: requested.deviceId,
    signingPublicKey: requested.signingPublicKey,
    encryptionPublicKey: requested.encryptionPublicKey,
  }];
  const update = await createMembershipTransition(members, false);
  const approvalProof = await deviceApprovalProof(
    scannedRequest.authSecret,
    scannedRequest.requestId,
    identity.group.groupId,
    update.transition.transitionHash,
  );
  await approveDeviceRequest(identity, scannedRequest.requestId, {
    transition: update.transition,
    packages: update.packages,
    approvalProof,
  });
  identity.group.keys[String(update.transition.timestamp)] = {
    ...update.groupKey,
    timestamp: update.transition.timestamp,
    transitionHash: update.transition.transitionHash,
  };
  identity.group.headTransitionHash = update.transition.transitionHash;
  await putIdentity(identity);
  await syncGroup();
  await ensureExactGroupKey();
  history.replaceState(null, "", "/");
  messageElement.textContent = "デバイスをグループへ追加しました。";
}

async function pollDeviceRequest() {
  if (pendingDeviceRequest === null) return;
  const pending = pendingDeviceRequest;
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
  if (!await verifyDeviceApprovalProof(
    pending.authSecret,
    requestId,
    state.groupId,
    state.transitionHash,
    state.approvalProof,
  )) throw new Error("Device approval proof is invalid");
  identity.group = {
    groupId: state.groupId,
    pendingTransitionHash: state.transitionHash,
    keys: {},
  };
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
        if (session.protocolVersion !== 3 && session.protocolVersion !== 4) throw new Error("Stored session uses an unsupported protocol");
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
  const trustedHash = identity.group.headTransitionHash ?? identity.group.pendingTransitionHash;
  if (trustedHash === undefined) throw new Error("Device group has no authenticated transition anchor");
  const head = await validateGroupTransitions(state.groupId, state.keys, trustedHash);
  if (!sameTransitionMembers(head.members, state.members)) throw new Error("Relay changed the active group member set");
  for (const keyPackage of state.packages) {
    const localKey = identity.group.keys[String(keyPackage.timestamp)];
    const keyRecord = state.keys.find((key) => key.timestamp === keyPackage.timestamp);
    if (keyRecord === undefined) throw new Error("Key package refers to an unknown group key");
    await verifyKeyPackageDigest(keyPackage, keyRecord);
    if (localKey === undefined) {
      identity.group.keys[String(keyPackage.timestamp)] = {
        ...await openKeyPackage(identity, state.groupId, keyRecord, keyPackage),
        transitionHash: keyRecord.transitionHash,
      };
    } else if (localKey.publicKey !== keyRecord.publicKey || localKey.transitionHash !== keyRecord.transitionHash) {
      throw new Error("Stored group key conflicts with server metadata");
    }
  }
  identity.group.rootTransitionHash ??= state.keys[0].transitionHash;
  identity.group.headTransitionHash = head.transitionHash;
  delete identity.group.pendingTransitionHash;
  groupState = state;
  await putIdentity(identity);
}

async function ensureExactGroupKey() {
  if (identity.group === null || groupState === undefined) throw new Error("Device group is not synchronized");
  const head = groupState.keys.at(-1);
  if (head === undefined || !sameTransitionMembers(head.members, groupState.members)) {
    throw new Error("Device group key does not match its authenticated members");
  }
  if (!transitionNeedsRecreation(groupState.keys)) return;
  const update = await createMembershipTransition(groupState.members, true);
  try {
    await registerGroupKey(identity, { transition: update.transition, packages: update.packages });
    identity.group.keys[String(update.transition.timestamp)] = {
      ...update.groupKey,
      timestamp: update.transition.timestamp,
      transitionHash: update.transition.transitionHash,
    };
    identity.group.headTransitionHash = update.transition.transitionHash;
    await putIdentity(identity);
  } catch (error) {
    if (!(error instanceof ApiError && (error.code === "group_transition_changed" || error.code === "key_timestamp_conflict"))) {
      throw error;
    }
  }
  await syncGroup();
}

async function currentLocalKey() {
  const keyRecord = groupState?.keys.at(-1) ?? null;
  if (keyRecord === null) throw new Error("No usable group key is registered");
  const key = identity.group.keys[String(keyRecord.timestamp)];
  if (key === undefined || key.publicKey !== keyRecord.publicKey) throw new Error("Current group private key is unavailable");
  if (key.transitionHash !== keyRecord.transitionHash) throw new Error("Current group key transition is not authenticated");
  return key;
}

async function joinFromFragment() {
  const parameters = new URLSearchParams(location.hash.slice(1));
  requireFragmentFields(parameters, ["v", "s", "p", "t", "a", "k", "c"]);
  const protocolVersion = Number(parameters.get("v"));
  if (protocolVersion !== 3 && protocolVersion !== 4) throw new Error("Unsupported pairing protocol version");
  if (identity.group === null) await createSoloGroup();
  await syncGroup();
  await ensureExactGroupKey();
  const sessionId = parameters.get("s");
  if (await getSession(sessionId) !== undefined) throw new Error("This device group has already joined the session");
  const groupKey = await currentLocalKey();
  const pairingId = parameters.get("p");
  const proof = await pairingProof(
    parameters.get("a"), protocolVersion, sessionId, pairingId, identity.group.groupId,
    groupKey.timestamp, groupKey.publicKey, groupKey.transitionHash,
  );
  const creatorPublicKey = parameters.get("k");
  const sessionDescriptor = protocolVersion === 4
    ? await createSessionDescriptor(
      identity, groupKey, sessionId, identity.group.groupId, creatorPublicKey,
    )
    : undefined;
  const expiresAt = await joinSession(sessionId, {
    pairingId,
    pairingToken: parameters.get("t"),
    groupId: identity.group.groupId,
    deviceId: identity.deviceId,
    deviceAccessToken: identity.accessToken,
    keyTimestamp: groupKey.timestamp,
    groupPublicKey: groupKey.publicKey,
    transitionHash: groupKey.transitionHash,
    proof,
    ...(sessionDescriptor === undefined ? {} : { sessionDescriptor }),
  });
  await putSession(newSession(protocolVersion, sessionId, identity.group.groupId, creatorPublicKey, expiresAt, colorValue(`#${parameters.get("c")}`)));
  history.replaceState(null, "", "/");
  messageElement.textContent = "セッションへ参加しました。";
}

async function inheritSessions() {
  const localSessionIds = new Set((await listSessions()).map((session) => session.sessionId));
  const candidates = groupState.sessions.filter((remote) => !localSessionIds.has(remote.sessionId));
  for (const remote of await authenticatedInheritedSessions(candidates, groupState.groupId, groupState.keys)) {
    await putSession(newSession(remote.protocolVersion, remote.sessionId, groupState.groupId, remote.creatorPublicKey, remote.expiresAt));
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
      key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId, session.protocolVersion);
      session.keys[String(envelope.keyTimestamp)] = key;
    }
    applyEvent(
      session, await decryptEvent(key, session.protocolVersion, session.sessionId, envelope), envelope.keyTimestamp, envelope.createdAt,
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
  const groupKey = await currentLocalKey();
  const timestamp = groupKey.timestamp;
  let key = session.keys[String(timestamp)];
  if (key === undefined) {
    key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId, session.protocolVersion);
    session.keys[String(timestamp)] = key;
  }
  const responseId = randomId();
  const itemId = session.request.serverItemId;
  const response = type === "response"
    ? { id: responseId, type, requestId: session.request.requestId, optionId, createdAt: new Date().toISOString() }
    : itemId === null
      ? { id: responseId, type, requestId: session.request.requestId, createdAt: new Date().toISOString() }
      : { id: responseId, type, eventId: itemId, createdAt: new Date().toISOString() };
  const encrypted = await encryptResponse(key, session.protocolVersion, session.sessionId, session.groupId, timestamp, responseId, response);
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
      key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId, session.protocolVersion);
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
      key, session.protocolVersion, session.sessionId, session.groupId, groupKey.timestamp, responseId, response,
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

async function sendFeedback(sessionId, message, imageFile) {
  const session = await getSession(sessionId);
  if (session === undefined) throw new Error("Session disappeared before feedback was sent");
  const text = message.trim();
  if (new TextEncoder().encode(text).byteLength > 20_000) throw new Error("メッセージは20000バイト以内で入力してください");
  if (session.protocolVersion === 3 && imageFile !== undefined) throw new Error("このセッションには写真を添付できません");
  if (text.length === 0 && imageFile === undefined) throw new Error("メッセージまたは写真を指定してください");
  const groupKey = await currentLocalKey();
  let key = session.keys[String(groupKey.timestamp)];
  if (key === undefined) {
    key = await deriveSessionKey(groupKey, session.creatorPublicKey, session.sessionId, session.groupId, session.protocolVersion);
    session.keys[String(groupKey.timestamp)] = key;
  }
  const responseId = randomId();
  let attachment;
  if (imageFile !== undefined) {
    const attachmentId = randomId();
    const jpeg = await normalizedJPEG(imageFile);
    const encryptedAttachment = await encryptAttachment(
      groupKey, session.creatorPublicKey, session.sessionId, session.groupId, responseId, attachmentId, jpeg,
    );
    const reservation = await reserveAttachment(session, identity, {
      attachmentId,
      responseId,
      groupId: session.groupId,
      deviceId: identity.deviceId,
      keyTimestamp: groupKey.timestamp,
      ciphertextLength: encryptedAttachment.manifest.ciphertextLength,
      ciphertextSha256: encryptedAttachment.manifest.ciphertextSha256,
    });
    if (encryptedAttachment.ciphertext.byteLength > reservation.maxCiphertextBytes) {
      throw new Error("写真が現在の添付サイズ上限を超えています");
    }
    await uploadAttachment(session, attachmentId, reservation.uploadToken, encryptedAttachment.ciphertext);
    attachment = encryptedAttachment.manifest;
  }
  const response = {
    id: responseId,
    type: "feedback",
    ...(text.length === 0 ? {} : { message: text }),
    ...(attachment === undefined ? {} : { attachment }),
    createdAt: new Date().toISOString(),
  };
  const encrypted = await encryptResponse(
    key, session.protocolVersion, session.sessionId, session.groupId, groupKey.timestamp, responseId, response,
  );
  session.expiresAt = await postResponse(session, identity, {
    responseId,
    ...(attachment === undefined ? {} : { attachmentId: attachment.id }),
    groupId: session.groupId,
    deviceId: identity.deviceId,
    keyTimestamp: groupKey.timestamp,
    ...encrypted,
  });
  await putSession(session);
  messageElement.textContent = "メッセージを送信しました。";
}

async function normalizedJPEG(file) {
  if (!file.type.startsWith("image/")) throw new Error("画像ファイルを選択してください");
  const bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
  try {
    const scale = Math.min(1, 2048 / Math.max(bitmap.width, bitmap.height));
    let width = Math.max(1, Math.round(bitmap.width * scale));
    let height = Math.max(1, Math.round(bitmap.height * scale));
    let quality = 0.82;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext("2d", { alpha: false });
      if (context === null) throw new Error("写真を変換できません");
      context.drawImage(bitmap, 0, 0, width, height);
      const blob = await new Promise((resolve, reject) => canvas.toBlob(
        (value) => value === null ? reject(new Error("写真をJPEGへ変換できません")) : resolve(value),
        "image/jpeg",
        quality,
      ));
      if (blob.size <= 1024 * 1024 || (blob.size <= 2 * 1024 * 1024 - 16 && attempt === 9)) {
        return { bytes: new Uint8Array(await blob.arrayBuffer()), width, height };
      }
      if (quality > 0.55) {
        quality -= 0.09;
      } else {
        width = Math.max(1, Math.round(width * 0.82));
        height = Math.max(1, Math.round(height * 0.82));
      }
    }
    throw new Error("写真を添付サイズ上限まで縮小できません");
  } finally {
    bitmap.close();
  }
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
  const remaining = groupState.members.filter((member) => member.deviceId !== deviceId);
  const update = await createMembershipTransition(remaining, true);
  await removeDevice(identity, deviceId, { transition: update.transition, packages: update.packages });
  identity.group.keys[String(update.transition.timestamp)] = {
    ...update.groupKey,
    timestamp: update.transition.timestamp,
    transitionHash: update.transition.transitionHash,
  };
  identity.group.headTransitionHash = update.transition.transitionHash;
  await putIdentity(identity);
  await syncGroup();
  await ensureExactGroupKey();
  await renderGroup();
}

async function leaveCurrentGroup() {
  if (groupState === undefined || groupState.members.length <= 1) throw new Error("単独利用中のデバイスはグループから除外できません");
  if (!window.confirm("このデバイスをグループから除外しますか？このデバイスに表示されているセッションも削除されます。")) return;
  const groupId = identity.group.groupId;
  const remaining = groupState.members.filter((member) => member.deviceId !== identity.deviceId);
  const update = await createSelfRemovalTransition(remaining);
  await removeDevice(identity, identity.deviceId, { transition: update.transition, packages: update.packages });
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
  const current = groupState.keys.at(-1) ?? null;
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
    const feedbackImage = card.querySelector(".feedback-image");
    const feedbackPreview = card.querySelector(".feedback-preview");
    const feedbackSubmit = feedbackForm.querySelector('button[type="submit"]');
    let feedbackPreviewURL;
    const updateFeedbackSubmit = () => {
      feedbackSubmit.disabled = feedbackMessage.value.trim().length === 0 && feedbackImage.files.length === 0;
    };
    const updateFeedbackPreview = () => {
      if (feedbackPreviewURL !== undefined) URL.revokeObjectURL(feedbackPreviewURL);
      const file = feedbackImage.files[0];
      feedbackPreviewURL = file === undefined ? undefined : URL.createObjectURL(file);
      feedbackPreview.hidden = feedbackPreviewURL === undefined;
      if (feedbackPreviewURL === undefined) feedbackPreview.removeAttribute("src");
      else feedbackPreview.src = feedbackPreviewURL;
    };
    if (session.protocolVersion !== 4) feedbackImage.closest("label").hidden = true;
    feedbackToggle.addEventListener("click", () => {
      feedbackToggle.hidden = true;
      feedbackForm.hidden = false;
      updateFeedbackSubmit();
      feedbackMessage.focus();
    });
    feedbackMessage.addEventListener("input", updateFeedbackSubmit);
    feedbackImage.addEventListener("change", () => {
      updateFeedbackPreview();
      updateFeedbackSubmit();
    });
    card.querySelector(".feedback-cancel").addEventListener("click", () => {
      feedbackForm.reset();
      updateFeedbackPreview();
      updateFeedbackSubmit();
      feedbackForm.hidden = true;
      feedbackToggle.hidden = false;
    });
    feedbackForm.addEventListener("submit", (event) => {
      event.preventDefault();
      feedbackSubmit.disabled = true;
      sendFeedback(session.sessionId, feedbackMessage.value, feedbackImage.files[0]).then(() => {
        feedbackForm.reset();
        updateFeedbackPreview();
        feedbackForm.hidden = true;
        feedbackToggle.hidden = false;
      }).catch(showError).finally(updateFeedbackSubmit);
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

function newSession(protocolVersion, sessionId, groupId, creatorPublicKey, expiresAt, color = null) {
  return {
    protocolVersion, sessionId, groupId, creatorPublicKey, keys: {}, cursor: 0,
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
  requireFragmentFields(parameters, ["v", "r", "a", "h"]);
  if (parameters.get("v") !== "3") throw new Error("このグループ追加用リンクは使用できません");
  const requestId = parameters.get("r");
  const authSecret = parameters.get("a");
  const requestHash = parameters.get("h");
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(requestId)
    || !/^[A-Za-z0-9_-]{43}$/.test(authSecret)
    || !/^[a-f0-9]{64}$/.test(requestHash)) {
    throw new Error("グループ追加用リンクが不正です");
  }
  return { requestId, authSecret, requestHash };
}

function validateGroupState(state) {
  for (const member of state.members) {
    requireExactKeys(member, ["deviceId", "signingPublicKey", "encryptionPublicKey", "addedAt"]);
  }
  for (const key of state.keys) {
    requireExactKeys(key, [
      "transitionId", "previousHash", "transitionHash", "timestamp", "actorDeviceId", "publicKey",
      "recreated", "members", "packageDigests", "actorSignature", "continuitySignature",
    ]);
    if (!Number.isSafeInteger(key.timestamp) || key.timestamp <= 0 || !Array.isArray(key.members)
      || !Array.isArray(key.packageDigests) || typeof key.recreated !== "boolean") {
      throw new Error("Invalid group key metadata");
    }
    for (const member of key.members) {
      requireExactKeys(member, ["deviceId", "signingPublicKey", "encryptionPublicKey"]);
    }
    for (const digest of key.packageDigests) requireExactKeys(digest, ["deviceId", "sha256"]);
  }
  for (const item of state.packages) requireExactKeys(item, ["timestamp", "deviceId", "ephemeralPublicKey", "nonce", "ciphertext"]);
  for (const session of state.sessions) {
    requireExactKeys(session, [
      "sessionId", "groupId", "creatorPublicKey", "expiresAt", "protocolVersion", "keyTimestamp", "transitionHash",
      "actorDeviceId", "actorSignature", "continuitySignature",
    ]);
    if (session.protocolVersion !== 3 && session.protocolVersion !== 4) throw new Error("Unsupported session protocol version");
  }
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

async function createMembershipTransition(members, recreated) {
  if (identity.group === null || groupState === undefined) throw new Error("Device group is not synchronized");
  const previous = groupState.keys.at(-1);
  if (previous === undefined || previous.transitionHash !== identity.group.headTransitionHash) {
    throw new Error("Device group transition head is not synchronized");
  }
  const groupKey = await createGroupKey();
  const packages = await Promise.all(members.map((member) => createKeyPackage(
    identity.group.groupId, groupKey, member,
  )));
  const transition = await createGroupTransition(
    identity.group.groupId, identity, groupKey, previous, members, packages, recreated,
  );
  return { groupKey, packages, transition };
}

async function createSelfRemovalTransition(members) {
  if (identity.group === null || groupState === undefined) throw new Error("Device group is not synchronized");
  const previous = groupState.keys.at(-1);
  if (previous === undefined || previous.transitionHash !== identity.group.headTransitionHash) {
    throw new Error("Device group transition head is not synchronized");
  }
  const groupKey = await currentLocalKey();
  const packages = await Promise.all(members.map((member) => createKeyPackage(
    identity.group.groupId, groupKey, member,
  )));
  const transition = await createGroupTransition(
    identity.group.groupId, identity, groupKey, previous, members, packages, false,
  );
  return { groupKey, packages, transition };
}

function transitionNeedsRecreation(transitions) {
  if (transitions.length < 2) return false;
  const previous = transitions.at(-2);
  const head = transitions.at(-1);
  if (head.recreated) return false;
  const current = new Set(head.members.map((member) => member.deviceId));
  return previous.members.some((member) => !current.has(member.deviceId));
}

function sameTransitionMembers(left, right) {
  const normalize = (members) => [...members]
    .sort((a, b) => a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0)
    .map((member) => `${member.deviceId}\n${member.signingPublicKey}\n${member.encryptionPublicKey}`);
  const leftValues = normalize(left);
  const rightValues = normalize(right);
  return leftValues.length === rightValues.length
    && leftValues.every((value, index) => value === rightValues[index]);
}

function groupAbandonTranscript(groupId, actorDeviceId, headTransitionHash) {
  return ["notify.guru/group-abandon/v1", groupId, actorDeviceId, headTransitionHash].join("\n");
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
