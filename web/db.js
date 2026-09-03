const DB_NAME = "notify.guru";
const DB_VERSION = 1;
let databasePromise;

export async function getIdentity() {
  return read("identity", "device-group");
}

export async function putIdentity(identity) {
  await write("identity", identity, "device-group");
}

export async function getSession(sessionId) {
  return read("sessions", sessionId);
}

export async function putSession(session) {
  await write("sessions", session);
}

export async function deleteSession(sessionId) {
  const database = await openDatabase();
  const transaction = database.transaction("sessions", "readwrite");
  transaction.objectStore("sessions").delete(sessionId);
  await complete(transaction);
}

export async function detachDeviceGroup(identity, groupId) {
  const database = await openDatabase();
  const transaction = database.transaction(["identity", "sessions"], "readwrite");
  transaction.objectStore("identity").put(identity, "device-group");
  const sessions = transaction.objectStore("sessions");
  const cursorRequest = sessions.openCursor();
  cursorRequest.onsuccess = () => {
    const cursor = cursorRequest.result;
    if (cursor === null) return;
    if ((cursor.value.protocolVersion === 3 || cursor.value.protocolVersion === 4) && cursor.value.groupId === groupId) cursor.delete();
    cursor.continue();
  };
  await complete(transaction);
}

export async function listSessions() {
  const database = await openDatabase();
  const transaction = database.transaction("sessions", "readonly");
  const result = await request(transaction.objectStore("sessions").getAll());
  await complete(transaction);
  return result;
}

export async function resetLocalData() {
  const opening = databasePromise;
  databasePromise = undefined;
  if (opening !== undefined) {
    const database = await opening;
    database.close();
  }
  await new Promise((resolve, reject) => {
    const deletion = indexedDB.deleteDatabase(DB_NAME);
    deletion.onsuccess = () => resolve();
    deletion.onerror = () => reject(deletion.error ?? new Error("ブラウザ内データを削除できませんでした"));
    deletion.onblocked = () => reject(new Error("別のタブでnotify.guruが開かれています。ほかのタブを閉じて再試行してください。"));
  });
}

async function read(storeName, key) {
  const database = await openDatabase();
  const transaction = database.transaction(storeName, "readonly");
  const result = await request(transaction.objectStore(storeName).get(key));
  await complete(transaction);
  return result;
}

async function write(storeName, value, key) {
  const database = await openDatabase();
  const transaction = database.transaction(storeName, "readwrite");
  if (key === undefined) {
    transaction.objectStore(storeName).put(value);
  } else {
    transaction.objectStore(storeName).put(value, key);
  }
  await complete(transaction);
}

function openDatabase() {
  if (databasePromise !== undefined) return databasePromise;
  const opening = new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, DB_VERSION);
    open.onupgradeneeded = () => {
      const database = open.result;
      database.createObjectStore("identity");
      database.createObjectStore("sessions", { keyPath: "sessionId" });
    };
    open.onsuccess = () => {
      const database = open.result;
      database.onversionchange = () => {
        database.close();
        if (databasePromise === opening) databasePromise = undefined;
      };
      resolve(database);
    };
    open.onerror = () => {
      if (databasePromise === opening) databasePromise = undefined;
      reject(open.error ?? new Error("ブラウザ内データを開けませんでした"));
    };
  });
  databasePromise = opening;
  return opening;
}

function request(operation) {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(operation.error);
  });
}

function complete(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}
