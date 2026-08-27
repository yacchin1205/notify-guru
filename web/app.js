import {
  ApiError,
  approveJoin,
  createDeviceGroup,
  createInvitation,
  getEvents,
  getGroupSessions,
  getGroupState,
  getJoinRequest,
  getLegacyEvents,
  joinSession,
  postLegacyResponse,
  postResponse,
  rejectJoin,
  removeDevice,
  submitJoinRequest,
} from "./api.js";
import {
  createDeviceIdentity,
  createGeneration,
  createKeyPackage,
  decryptEvent,
  decryptLegacyEvent,
  deriveSessionKey,
  encryptLegacyResponse,
  encryptResponse,
  groupCreateTranscript,
  hashPackages,
  hashToken,
  openKeyPackage,
  pairingProof,
  randomId,
  randomToken,
  signDevice,
  signGeneration,
  transitionTranscript,
  verificationCode,
  verifySignature,
} from "./crypto.js";
import { deleteSession, detachDeviceGroup, getIdentity, getSession, listSessions, putIdentity, putSession } from "./db.js";
import { expiredInvitationIDs, expiredSessionIDs } from "./expiry.js";
import { qrMatrix } from "./qr.js";

const cardsElement = document.querySelector("#cards");
const emptyElement = document.querySelector("#empty");
const messageElement = document.querySelector("#message");
const connectionElement = document.querySelector("#connection-state");
const cardTemplate = document.querySelector("#card-template");
const deviceSummaryElement = document.querySelector("#device-summary");
const deviceSummaryTitleElement = document.querySelector("#device-summary-title");
const deviceManagementElement = document.querySelector("#device-management");
const openDeviceManagementButton = document.querySelector("#open-device-management");
const closeDeviceManagementButton = document.querySelector("#close-device-management");
const groupStatusElement = document.querySelector("#group-status");
const groupDevicesElement = document.querySelector("#group-devices");
const pendingDevicesElement = document.querySelector("#pending-devices");
const invitationElement = document.querySelector("#invitation");
const invitationQRElement = document.querySelector("#invitation-qr");
const shareInvitationButton = document.querySelector("#share-invitation");
const joinDeviceElement = document.querySelector("#join-device");
const joinDeviceStatusElement = document.querySelector("#join-device-status");
const verificationCodeElement = document.querySelector("#verification-code");
const inviteDeviceButton = document.querySelector("#invite-device");
const leaveDeviceGroupButton = document.querySelector("#leave-device-group");

let identity;
let groupState;
let rendered = false;
let synchronizing = false;
let managingDevices = false;
let outboundInvitationURL;

window.addEventListener("unhandledrejection", (event) => showError(event.reason));
inviteDeviceButton.addEventListener("click", () => createDeviceInvitation().catch(showError));
leaveDeviceGroupButton.addEventListener("click", () => leaveCurrentGroup().catch(showError));
openDeviceManagementButton.addEventListener("click", () => setDeviceManagement(true));
closeDeviceManagementButton.addEventListener("click", () => setDeviceManagement(false));
shareInvitationButton.addEventListener("click", () => shareDeviceInvitation().catch(showError));

await initialize();

async function initialize() {
  if ("serviceWorker" in navigator) await navigator.serviceWorker.register("/sw.js");
  identity = await identityOrCreate();
  await deleteExpiredLocalSessions();

  let handledDeviceInvitation = false;
  try {
    const deviceInvitation = parseDeviceInvitation();
    if (deviceInvitation !== null) {
      handledDeviceInvitation = true;
      await beginDeviceJoin(deviceInvitation);
    }
  } catch (error) {
    showError(error);
    history.replaceState(null, "", "/");
  }
  if (!handledDeviceInvitation) {
    if (identity.group === null && identity.pendingInvitation === undefined) await createInitialGroup();
    if (location.hash.length > 1) await joinFromFragment();
  }

  await syncAll();
  setInterval(() => syncAll().catch(showError), 2_000);
}

async function identityOrCreate() {
  const current = await getIdentity();
  if (current?.protocolVersion === 2) return current;
  const created = await createDeviceIdentity();
  await putIdentity(created);
  return created;
}

async function createInitialGroup() {
  if (identity.group !== null || identity.pendingInvitation !== undefined) {
    throw new Error("この端末にはすでにデバイスグループがあります");
  }
  const groupId = randomId();
  const generation = await createGeneration(1);
  const keyPackage = await createKeyPackage(groupId, generation, deviceDescriptor(identity));
  const packagesHash = await hashPackages([keyPackage]);
  const transcript = groupCreateTranscript(groupId, identity, generation, packagesHash);
  await createDeviceGroup({
    groupId,
    deviceId: identity.deviceId,
    deviceAccessTokenHash: await hashToken(identity.accessToken),
    deviceEncryptionPublicKey: identity.encryptionPublicKey,
    deviceSigningPublicKey: identity.signingPublicKey,
    generationPublicKey: generation.publicKey,
    package: keyPackage,
    deviceSignature: await signDevice(identity, transcript),
  });
  identity.group = {
    groupId,
    revision: 1,
    generation: 1,
    publicKey: generation.publicKey,
    generations: { "1": generation },
  };
  await putIdentity(identity);
}

async function beginDeviceJoin(invitation) {
  if (identity.group !== null && identity.group.groupId !== invitation.groupId) {
    if (!(await switchFromStandaloneGroup())) return;
  }
  if (identity.group?.groupId === invitation.groupId && identity.pendingInvitation === undefined) {
    throw new Error("この端末はすでに同じ端末共有に参加しています");
  }
  if (identity.pendingInvitation === undefined) {
    await submitJoinRequest(invitation, identity);
    identity.pendingInvitation = invitation;
    identity.group = {
      groupId: invitation.groupId,
      revision: invitation.revision,
      generation: invitation.generation,
      publicKey: invitation.publicKey,
      generations: {},
    };
    await putIdentity(identity);
  } else if (
    identity.pendingInvitation.groupId !== invitation.groupId
    || identity.pendingInvitation.invitationId !== invitation.invitationId
  ) {
    throw new Error("別の端末追加がすでに進行中です");
  }
  joinDeviceElement.hidden = false;
  const code = await verificationCode(invitation, deviceDescriptor(identity));
  verificationCodeElement.textContent = code;
  joinDeviceStatusElement.textContent = "既存端末に同じ確認コードが表示されていることを確認し、承認してください。";
}

async function switchFromStandaloneGroup() {
  await syncGroup();
  if (groupState.devices.length !== 1 || groupState.devices[0].deviceId !== identity.deviceId) {
    throw new Error("別の端末との共有をやめてから、この招待を開いてください");
  }
  const sessions = (await listSessions()).filter(
    (session) => session.protocolVersion === 2 && session.groupId === identity.group.groupId,
  );
  if (sessions.length > 0 && !window.confirm("現在この端末にあるセッションと鍵を消して、別の端末との共有を開始しますか？")) {
    history.replaceState(null, "", "/");
    return false;
  }
  const groupId = identity.group.groupId;
  const transition = await buildTransition("remove", identity.deviceId);
  await removeDevice(identity, identity.deviceId, transition.body);
  identity.group = null;
  identity.pendingInvitation = undefined;
  identity.invitations = {};
  await detachDeviceGroup(identity, groupId);
  clearGroupPresentation();
  return true;
}

async function joinFromFragment() {
  const parameters = new URLSearchParams(location.hash.slice(1));
  const required = ["v", "s", "p", "t", "a", "k"];
  requireFragmentFields(parameters, required);
  if (parameters.get("v") !== "2") throw new Error("Unsupported pairing protocol version");
  if (identity.group === null) {
    await createInitialGroup();
  }
  await syncGroup();

  const sessionId = parameters.get("s");
  const pairingId = parameters.get("p");
  const pairingToken = parameters.get("t");
  const authSecret = parameters.get("a");
  const creatorPublicKey = parameters.get("k");
  if (await getSession(sessionId) !== undefined) throw new Error("This device group has already joined the session");
  const group = identity.group;
  const proof = await pairingProof(
    authSecret, sessionId, pairingId, group.groupId, group.revision, group.generation, group.publicKey,
  );
  const joined = await joinSession(sessionId, {
    pairingId,
    pairingToken,
    groupId: group.groupId,
    deviceId: identity.deviceId,
    deviceAccessToken: identity.accessToken,
    revision: group.revision,
    generation: group.generation,
    groupPublicKey: group.publicKey,
    proof,
  });
  const session = newSession(sessionId, creatorPublicKey, joined.expiresAt);
  await populateSessionKeys(session);
  await putSession(session);
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  messageElement.textContent = "セッションへ参加しました。";
}

async function syncAll() {
  if (synchronizing) return;
  synchronizing = true;
  try {
    connectionElement.textContent = "同期中";
    if (identity.group === null && identity.pendingInvitation === undefined) await createInitialGroup();
    if (identity.pendingInvitation !== undefined) await pollDeviceJoin();
    if (identity.group !== null && identity.pendingInvitation === undefined) {
      await syncGroup();
      await inheritSessions();
    }
    const expired = await deleteExpiredLocalSessions();
    const sessions = await listSessions();
    let changed = expired;
    for (const session of sessions) changed = (await syncSession(session)) || changed;
    if (!rendered || changed) {
      await render();
      rendered = true;
    }
    await renderGroup();
    connectionElement.textContent = "同期済み";
  } catch (error) {
    if (error instanceof ApiError && error.status === 403 && error.code === "device_removed" && identity.group !== null) {
      await detachRemovedDevice();
      await render();
      rendered = true;
      await renderGroup();
      connectionElement.textContent = "同期済み";
      return;
    }
    throw error;
  } finally {
    synchronizing = false;
  }
}

async function detachRemovedDevice() {
  const groupId = identity.group.groupId;
  identity.group = null;
  identity.pendingInvitation = undefined;
  identity.invitations = {};
  await detachDeviceGroup(identity, groupId);
  clearGroupPresentation();
  await createInitialGroup();
  messageElement.textContent = "この端末での共有が解除され、単独利用に戻りました。";
  rendered = false;
}

function clearGroupPresentation() {
  groupState = undefined;
  outboundInvitationURL = undefined;
  managingDevices = false;
  document.body.classList.remove("managing-devices");
  invitationElement.hidden = true;
  invitationQRElement.replaceChildren();
  joinDeviceElement.hidden = true;
  verificationCodeElement.textContent = "";
}

async function pollDeviceJoin() {
  const status = await getJoinRequest(identity.pendingInvitation);
  joinDeviceElement.hidden = false;
  if (status === "rejected" || status === "expired") {
    joinDeviceStatusElement.textContent = status === "rejected" ? "端末追加は拒否されました。" : "端末追加の有効期限が切れました。";
    const groupId = identity.group.groupId;
    identity.pendingInvitation = undefined;
    identity.group = null;
    await detachDeviceGroup(identity, groupId);
    clearGroupPresentation();
    await createInitialGroup();
    messageElement.textContent = status === "rejected" ? "端末共有は承認されませんでした。" : "端末招待の有効期限が切れました。";
    history.replaceState(null, "", "/");
    return;
  }
  if (status !== "approved") return;
  await syncGroup();
  identity.pendingInvitation = undefined;
  await putIdentity(identity);
  verificationCodeElement.textContent = "";
  joinDeviceElement.hidden = true;
  messageElement.textContent = "この端末でも通知を受け取れるようになりました。";
  history.replaceState(null, "", "/");
}

async function syncGroup() {
  const group = identity.group;
  const state = await getGroupState(identity, identity.pendingInvitation === undefined ? group.generation : 0);
  let revision = group.revision;
  let generation = group.generation;
  let publicKey = group.publicKey;
  const publicKeys = { [String(generation)]: publicKey };

  for (const transition of state.transitions) {
    validateTransitionShape(transition);
    if (transition.generation <= generation) continue;
    if (
      transition.revision !== revision + 1
      || transition.previousGeneration !== generation
      || transition.generation !== generation + 1
    ) throw new Error("Device group transition chain is discontinuous");
    const transcript = transitionTranscript(group.groupId, transition);
    if (!(await verifySignature(publicKey, transition.groupSignature, transcript))) {
      throw new Error("Device group transition signature is invalid");
    }
    revision = transition.revision;
    generation = transition.generation;
    publicKey = transition.generationPublicKey;
    publicKeys[String(generation)] = publicKey;
  }
  if (revision !== state.revision || generation !== state.generation || publicKey !== state.generationPublicKey) {
    throw new Error("Device group current state does not match its signed chain");
  }

  for (const keyPackage of state.packages) {
    if (group.generations[String(keyPackage.generation)] !== undefined) continue;
    const expected = keyPackage.generation > group.generation ? publicKeys[String(keyPackage.generation)] : undefined;
    group.generations[String(keyPackage.generation)] = await openKeyPackage(
      identity, group.groupId, expected, keyPackage,
    );
  }
  if (group.generations[String(generation)] === undefined) {
    throw new Error(`Current generation ${generation} key package is missing`);
  }
  group.revision = revision;
  group.generation = generation;
  group.publicKey = publicKey;
  groupState = state;
  pruneExpiredInvitations();
  const activeInvitation = latestInvitation();
  if (state.pending.length === 0 && activeInvitation !== undefined) {
    showInvitation(activeInvitation);
  } else {
    hideInvitation();
  }
  await putIdentity(identity);

  for (const session of await listSessions()) {
    if (session.protocolVersion === 2) {
      await populateSessionKeys(session);
      await putSession(session);
    }
  }
}

async function inheritSessions() {
  for (const remote of await getGroupSessions(identity)) {
    if (await getSession(remote.sessionId) !== undefined) continue;
    const session = newSession(remote.sessionId, remote.creatorPublicKey, remote.expiresAt);
    await populateSessionKeys(session);
    await putSession(session);
  }
}

async function populateSessionKeys(session) {
  session.keys ??= {};
  for (const generation of Object.values(identity.group.generations)) {
    const key = String(generation.generation);
    if (session.keys[key] === undefined) {
      session.keys[key] = await deriveSessionKey(
        generation, session.creatorPublicKey, session.sessionId, identity.group.groupId,
      );
    }
  }
}

async function syncSession(session) {
  let result;
  try {
    result = session.protocolVersion === 2 ? await getEvents(session, identity) : await getLegacyEvents(session);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 410)) {
      await deleteSession(session.sessionId);
      return true;
    }
    throw error;
  }
  for (const envelope of result.events) {
    let event;
    if (session.protocolVersion === 2) {
      const key = session.keys[String(envelope.generation)];
      if (key === undefined) throw new Error(`Session key for generation ${envelope.generation} is missing`);
      event = await decryptEvent(key, session.sessionId, envelope);
    } else {
      event = await decryptLegacyEvent(session.sharedKey, session.sessionId, envelope);
    }
    applyEvent(session, event, envelope.generation);
    session.cursor = envelope.sequence;
  }
  session.expiresAt = result.expiresAt;
  await putSession(session);
  return result.events.length > 0;
}

async function createDeviceInvitation() {
  await syncGroup();
  if (groupState.pending.length > 0) throw new Error("端末の承認を完了してから、新しい招待を作成してください");
  pruneExpiredInvitations();
  const existing = latestInvitation();
  if (existing !== undefined) {
    showInvitation(existing);
    await putIdentity(identity);
    await renderGroup();
    return;
  }
  const invitationId = randomId();
  const invitationToken = randomToken();
  const expires = await createInvitation(identity, invitationId, await hashToken(invitationToken));
  const invitation = {
    groupId: identity.group.groupId,
    invitationId,
    invitationToken,
    revision: identity.group.revision,
    generation: identity.group.generation,
    publicKey: identity.group.publicKey,
    expiresAt: expires.expiresAt,
  };
  identity.invitations[invitationId] = invitation;
  await putIdentity(identity);
  showInvitation(invitation);
  await renderGroup();
}

function showInvitation(invitation) {
  const link = new URL("/device", location.origin);
  link.hash = new URLSearchParams({
    v: "1", g: invitation.groupId, i: invitation.invitationId, t: invitation.invitationToken,
    r: String(invitation.revision), n: String(invitation.generation), k: invitation.publicKey,
  }).toString();
  outboundInvitationURL = link.toString();
  renderInvitationQR(outboundInvitationURL);
  invitationElement.hidden = false;
}

function hideInvitation() {
  outboundInvitationURL = undefined;
  invitationElement.hidden = true;
  invitationQRElement.replaceChildren();
}

function pruneExpiredInvitations() {
  for (const invitationId of expiredInvitationIDs(identity.invitations, Date.now())) {
    delete identity.invitations[invitationId];
  }
}

function latestInvitation() {
  return Object.values(identity.invitations).sort((left, right) => right.expiresAt - left.expiresAt)[0];
}

async function shareDeviceInvitation() {
  if (outboundInvitationURL === undefined) throw new Error("有効な端末招待がありません");
  if (navigator.share !== undefined) {
    await navigator.share({ title: "notify.guru device invitation", url: outboundInvitationURL });
    return;
  }
  await navigator.clipboard.writeText(outboundInvitationURL);
  messageElement.textContent = "招待リンクをコピーしました。";
}

function renderInvitationQR(value) {
  const quietZone = 4;
  const { size, modules } = qrMatrix(value);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${size + quietZone * 2} ${size + quietZone * 2}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "デバイス招待QRコード");
  const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  background.setAttribute("width", "100%");
  background.setAttribute("height", "100%");
  background.setAttribute("fill", "white");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  const cells = [];
  for (let row = 0; row < size; row += 1) {
    for (let column = 0; column < size; column += 1) {
      if (modules[row][column]) cells.push(`M${column + quietZone} ${row + quietZone}h1v1h-1z`);
    }
  }
  path.setAttribute("d", cells.join(""));
  path.setAttribute("fill", "black");
  svg.append(background, path);
  invitationQRElement.replaceChildren(svg);
}

async function approvePending(invitationId) {
  const pending = groupState.pending.find((item) => item.invitationId === invitationId);
  const invitation = identity.invitations[invitationId];
  if (pending === undefined || invitation === undefined) throw new Error("Pending invitation details are unavailable");
  const transition = await buildTransition("add", pending.deviceId, pending);
  await approveJoin(identity, invitationId, transition.body);
  identity.group.generations[String(transition.next.generation)] = transition.next;
  identity.group.revision += 1;
  identity.group.generation = transition.next.generation;
  identity.group.publicKey = transition.next.publicKey;
  delete identity.invitations[invitationId];
  hideInvitation();
  await putIdentity(identity);
  messageElement.textContent = "別の端末でも通知を受け取れるようになりました。";
  await syncAll();
}

async function rejectPending(invitationId) {
  await rejectJoin(identity, invitationId);
  delete identity.invitations[invitationId];
  hideInvitation();
  await putIdentity(identity);
  messageElement.textContent = "端末の追加を拒否しました。";
  await syncAll();
}

async function removeGroupDevice(deviceId) {
  if (!window.confirm("この端末との共有を解除しますか？解除後、その端末は新しい通知を受け取れません。")) return;
  const transition = await buildTransition("remove", deviceId);
  await removeDevice(identity, deviceId, transition.body);
  identity.group.generations[String(transition.next.generation)] = transition.next;
  identity.group.revision += 1;
  identity.group.generation = transition.next.generation;
  identity.group.publicKey = transition.next.publicKey;
  await putIdentity(identity);
  await syncAll();
}

async function leaveCurrentGroup() {
  await syncGroup();
  if (identity.group === null || groupState === undefined) throw new Error("端末情報が同期されていません");
  if (groupState.devices.length <= 1) throw new Error("この端末はすでに単独で利用されています");
  if (!window.confirm("この端末での共有をやめますか？共有中のセッションと鍵はこの端末から削除されます。")) return;

  leaveDeviceGroupButton.disabled = true;
  try {
    const groupId = identity.group.groupId;
    const transition = await buildTransition("remove", identity.deviceId);
    await removeDevice(identity, identity.deviceId, transition.body);
    identity.group = null;
    identity.pendingInvitation = undefined;
    identity.invitations = {};
    await detachDeviceGroup(identity, groupId);
    clearGroupPresentation();
    await createInitialGroup();
    setDeviceManagement(false);
    messageElement.textContent = "この端末は単独利用に戻りました。";
    rendered = false;
    await syncAll();
  } finally {
    leaveDeviceGroupButton.disabled = false;
  }
}

async function buildTransition(action, targetDeviceId, pending) {
  if (groupState === undefined) throw new Error("Device group state has not been synchronized");
  const current = identity.group.generations[String(identity.group.generation)];
  if (current === undefined) throw new Error("Current generation private key is unavailable");
  const next = await createGeneration(identity.group.generation + 1);
  const devices = groupState.devices.map(deviceDescriptor);
  if (action === "add") devices.push(deviceDescriptor(pending));
  const recipients = devices.filter((device) => action !== "remove" || device.deviceId !== targetDeviceId);
  const packages = [];
  for (const recipient of recipients) packages.push(await createKeyPackage(identity.group.groupId, next, recipient));
  if (action === "add") {
    for (const previous of Object.values(identity.group.generations)) {
      packages.push(await createKeyPackage(identity.group.groupId, previous, deviceDescriptor(pending)));
    }
  }
  const packagesHash = await hashPackages(packages);
  const signed = {
    revision: identity.group.revision + 1,
    previousGeneration: identity.group.generation,
    generation: next.generation,
    generationPublicKey: next.publicKey,
    action,
    actorDeviceId: identity.deviceId,
    targetDeviceId,
    packagesHash,
  };
  const transcript = transitionTranscript(identity.group.groupId, signed);
  return {
    next,
    body: {
      expectedRevision: identity.group.revision,
      nextGenerationPublicKey: next.publicKey,
      packages,
      groupSignature: await signGeneration(current, transcript),
      deviceSignature: await signDevice(identity, transcript),
    },
  };
}

async function renderGroup() {
  if (identity.pendingInvitation !== undefined) {
    managingDevices = false;
    document.body.classList.remove("managing-devices");
    deviceSummaryElement.hidden = true;
    deviceManagementElement.hidden = true;
    return;
  }
  deviceSummaryElement.hidden = identity.group === null || managingDevices;
  deviceManagementElement.hidden = identity.group === null || !managingDevices;
  if (identity.group === null || groupState === undefined) return;
  const sharing = groupState.devices.length > 1;
  deviceSummaryTitleElement.textContent = sharing ? `${groupState.devices.length}台で通知を共有中` : "この端末のみ";
  groupStatusElement.textContent = sharing ? `${groupState.devices.length}台で通知を共有しています。` : "現在はこの端末だけで通知を受け取ります。";
  leaveDeviceGroupButton.hidden = !sharing;

  groupDevicesElement.replaceChildren();
  for (const device of groupState.devices) {
    const row = document.createElement("div");
    row.className = "device-row";
    const label = document.createElement("span");
    label.textContent = device.deviceId === identity.deviceId ? `この端末 · ${device.deviceId.slice(0, 8)}` : `端末 · ${device.deviceId.slice(0, 8)}`;
    row.append(label);
    if (device.deviceId !== identity.deviceId) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = "共有を解除";
      button.addEventListener("click", () => removeGroupDevice(device.deviceId).catch(showError));
      row.append(button);
    }
    groupDevicesElement.append(row);
  }

  pendingDevicesElement.replaceChildren();
  for (const pending of groupState.pending) {
    const invitation = identity.invitations[pending.invitationId];
    if (invitation === undefined) throw new Error("Server returned an invitation this device did not create");
    const section = document.createElement("section");
    const code = await verificationCode(invitation, pending);
    section.append(textParagraph("両方の端末に同じ確認コードが表示されていることを確認してください。"));
    const codeElement = textParagraph(code);
    codeElement.className = "verification-code";
    section.append(codeElement);
    const approve = document.createElement("button");
    approve.type = "button";
    approve.textContent = "承認";
    approve.addEventListener("click", () => approvePending(pending.invitationId).catch(showError));
    const reject = document.createElement("button");
    reject.type = "button";
    reject.textContent = "拒否";
    reject.addEventListener("click", () => rejectPending(pending.invitationId).catch(showError));
    section.append(approve, " ", reject);
    pendingDevicesElement.append(section);
  }
  const approving = groupState.pending.length > 0;
  inviteDeviceButton.hidden = approving || outboundInvitationURL !== undefined;
  if (approving) hideInvitation();
}

function setDeviceManagement(enabled) {
  managingDevices = enabled;
  document.body.classList.toggle("managing-devices", enabled);
  renderGroup().catch(showError);
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
        button.addEventListener("click", () => respond(session.sessionId, option.id, button).catch(showError));
        optionsElement.append(button);
      }
    }
    cardsElement.append(card);
  }
}

async function respond(sessionId, optionId, button) {
  button.disabled = true;
  const session = await getSession(sessionId);
  if (session === undefined || session.request === null) throw new Error("Request disappeared before response");
  const responseId = randomId();
  const response = { id: responseId, requestId: session.request.requestId, optionId, createdAt: new Date().toISOString() };
  let posted;
  if (session.protocolVersion === 2) {
    const generation = session.requestGeneration;
    const key = session.keys[String(generation)];
    const encrypted = await encryptResponse(key, session.sessionId, identity.group.groupId, generation, responseId, response);
    posted = await postResponse(session, identity, {
      responseId,
      groupId: identity.group.groupId,
      deviceId: identity.deviceId,
      generation,
      ...encrypted,
    });
  } else {
    const encrypted = await encryptLegacyResponse(session.sharedKey, session.sessionId, session.groupId, responseId, response);
    posted = await postLegacyResponse(session, { responseId, groupId: session.groupId, ...encrypted });
  }
  session.request = null;
  session.status = "応答を送信しました";
  session.expiresAt = posted.expiresAt;
  await putSession(session);
  await render();
}

function applyEvent(session, event, generation) {
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
    session.title = stringValue(event.sessionTitle, "sessionTitle");
    if (!Array.isArray(event.options) || event.options.length < 2) throw new Error("Request options must contain at least two choices");
    for (const option of event.options) {
      requireExactKeys(option, ["id", "label"]);
      stringValue(option.id, "option.id");
      stringValue(option.label, "option.label");
    }
    session.request = event;
    if (session.protocolVersion === 2) session.requestGeneration = generation;
    return;
  }
  throw new Error(`Unsupported event type: ${String(event.type)}`);
}

function newSession(sessionId, creatorPublicKey, expiresAt) {
  return {
    protocolVersion: 2,
    sessionId,
    creatorPublicKey,
    keys: {},
    cursor: 0,
    title: `Session ${sessionId.slice(0, 8)}`,
    status: "接続しました",
    notification: "",
    request: null,
    requestGeneration: null,
    expiresAt,
  };
}

function parseDeviceInvitation() {
  if (location.pathname !== "/device" || location.hash.length <= 1) return null;
  const parameters = new URLSearchParams(location.hash.slice(1));
  const required = ["v", "g", "i", "t", "r", "n", "k"];
  requireFragmentFields(parameters, required);
  if (parameters.get("v") !== "1") throw new Error("Unsupported device invitation version");
  const revision = Number(parameters.get("r"));
  const generation = Number(parameters.get("n"));
  if (!Number.isSafeInteger(revision) || revision < 1 || !Number.isSafeInteger(generation) || generation < 1) {
    throw new Error("Device invitation contains an invalid group revision");
  }
  return {
    groupId: parameters.get("g"), invitationId: parameters.get("i"), invitationToken: parameters.get("t"),
    revision, generation, publicKey: parameters.get("k"),
  };
}

function requireFragmentFields(parameters, required) {
  for (const key of required) if (parameters.getAll(key).length !== 1) throw new Error(`Pairing URL must contain exactly one ${key}`);
  const actual = Array.from(parameters.keys());
  if (actual.length !== required.length || actual.some((key) => !required.includes(key))) throw new Error("Pairing URL contains an unknown field");
}

function validateTransitionShape(value) {
  requireExactKeys(value, [
    "revision", "previousGeneration", "generation", "generationPublicKey", "action", "actorDeviceId",
    "targetDeviceId", "packagesHash", "groupSignature", "deviceSignature", "createdAt",
  ]);
  if (!["add", "remove"].includes(value.action)) throw new Error("Unknown device group transition action");
}

function deviceDescriptor(value) {
  return {
    deviceId: value.deviceId,
    encryptionPublicKey: value.encryptionPublicKey,
    signingPublicKey: value.signingPublicKey,
  };
}

async function deleteExpiredLocalSessions() {
  const sessions = await listSessions();
  const expired = expiredSessionIDs(sessions, Date.now());
  for (const sessionID of expired) await deleteSession(sessionID);
  return expired.length > 0;
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

function textParagraph(text) {
  const element = document.createElement("p");
  element.textContent = text;
  return element;
}

function expiryText(expiresAt) {
  const remaining = expiresAt - Date.now();
  if (remaining <= 0) return "失効確認中";
  return `残り約${Math.max(1, Math.ceil(remaining / (60 * 60 * 1000)))}時間`;
}

function showError(error) {
  messageElement.textContent = `エラー: ${error instanceof Error ? error.message : String(error)}`;
  connectionElement.textContent = "同期エラー";
}
