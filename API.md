# notify.guru v4 API

This document defines the client-visible Objects and Operations of protocol v4. Each Operation defines the state changes a caller can establish or observe and the conditions under which it may continue them.

## 1. Scope

- `protocolVersion` is `4` wherever it appears.
- The relay never receives plaintext event, response, attachment-manifest, or
  session-title data.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## 2. Objects

An Object is a client-visible entity with its own stable identifier and state that changes across API operations. Immutable records, credentials, relationships identified only by other Objects, and operation identifiers are not Objects.

### 2.1 Device

A `Device` is identified by `deviceId` and represents one registered client installation. Its state defines its public identity and notification delivery configuration.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | register | `registered` |

#### 2.1.1 DeviceRequest

A `DeviceRequest` is identified by `requestId` and is created by a Device seeking membership in a Group. Once an approval has been selected, the DeviceRequest remains associated with that approval until the corresponding Group membership is established or the approval is rejected without changing the Group.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | create | `waiting` |
| `waiting` | select an approval | `approving` |
| `approving` | establish Group membership | `approved` |
| `approving` | reject before Group membership is established | `waiting` |
| `waiting` | expire | `expired` |
| `approving` | reject after expiration | `expired` |

### 2.2 Group

A `Group` is identified by `groupId` and represents a set of Devices that act together as one participant in Sessions. Its state defines the current members and whether a group key version is currently accepted by the API.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | create | `active` |
| `active (membership M, usable group key K)` | add a Device, remove another Device, or replace the group key | `active (membership M′, usable group key K′)` |
| `active (membership M, usable group key K)` | remove self while members remain | `active (membership M′, no usable group key)` |
| `active (membership M, no usable group key)` | establish the group key | `active (membership M, usable group key K′)` |

### 2.3 Session

A `Session` is identified by `sessionId` and defines a time-limited scope that Groups may join. A Session exists only while it is `open`; closing or expiration removes the Session and makes its child Objects and associated records no longer observable.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | create | `open` |
| `open` | close | — |
| `open` | expire | — |

#### 2.3.1 SessionPairing

A `SessionPairing` is identified by `sessionId` and `pairingId` and is issued for a Group to join the Session. Once a join has started, it is bound to that Group, the calling Device, and the submitted Group state; only the same join may be retried and complete it.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | issue | `available` |
| `available` | start a join | `joining` |
| `joining` | complete the same join | `consumed` |

#### 2.3.2 SessionItem

A `SessionItem` is identified by `sessionId` and `itemId` and represents an actionable item created by a Session event. Acceptance of a matching response makes the item inactive.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | create | `active` |
| `active` | accept response | `inactive` |

#### 2.3.3 SessionAttachment

A `SessionAttachment` is identified by `sessionId` and `attachmentId` and represents encrypted data associated with a Session response. It becomes available only when the associated response is accepted.

State transitions:

| From | Operation | To |
| --- | --- | --- |
| — | reserve | `reserved` |
| `reserved` | upload | `uploaded` |
| `reserved` | expire or end Session | `unavailable` |
| `uploaded` | accept response | `available` |
| `uploaded` | end Session | `unavailable` |
| `available` | acknowledge or end Session | `unavailable` |

## 3. Authentication

Authentication establishes the caller identity or capability presented to an Operation. Authorization determines whether that authenticated identity or capability may perform the Operation against the current Object state.

### 3.1 Tokens

| Token | Scope |
| --- | --- |
| `sessionToken` | The credential established for the process that creates one Session. It authorizes mutation and observation while that Session exists in `open` state. |
| `groupToken` | Access by one Device to one Group. Every current member has a distinct token with the same authority. |
| `pairingToken` | One join started through an `available` SessionPairing, including continuation or observation of that same join while the Pairing is `joining` or `consumed`. It grants no other Session access. |
| `attachmentUploadToken` | The `reserved` to `uploaded` change of one SessionAttachment. It grants no other Session or Group access. |

The Session-creating process retains its `sessionToken`; the protocol does not transfer or recover it, and does not disclose it to participating Groups. Group membership changes therefore do not replace or invalidate it.

Removing a Device from a Group invalidates that Device's `groupToken` for the Group. A `pairingToken` can select at most one join; once selected, it may only continue or observe that same join. An `attachmentUploadToken` can authorize at most one upload; reuse may only observe the result of that same upload. Removal of the Session or expiration of the upload reservation makes its corresponding token unusable.

### 3.2 Device signatures

A registered Device authenticates an Operation by signing the Operation and its security-relevant inputs with the private key corresponding to the public key in that Device's state. Where a `groupToken` already authenticates the caller, an additional Device signature authenticates the submitted Group state as originating from that same Device; it does not grant access to the Group. A signature by the current group key proves continuity from an existing Group state, not caller identity; for the initial Group state, the initial group-key signature proves possession of that key.

A signature made with a not-yet-registered key is not Device authentication; an Operation may use it only as proof of possession when registering the key. A valid Device signature authenticates its signed content but does not by itself establish that the request is newer than another valid request.

### 3.3 Client-verifiable proofs

Some Operations carry a proof that the Worker preserves but cannot verify because its secret is shared directly between clients. Such a proof neither authenticates the caller to the Worker nor authorizes the Operation; the Operation states exactly what the receiving client can verify.

## 4. Operations

Each endpoint below is one Operation at the client–Worker boundary. An Operation states which changes are established together and which accepted intermediate states remain when a later change cannot be completed. Repetition does not apply an already established state change twice.

`Encryption` describes application-layer end-to-end encryption, independently of HTTPS transport encryption and signatures.

### `GET /api/health`

Authentication: none. Authorization: none.

Encryption: none; this Operation carries no end-to-end encrypted payload.

Reports whether the Worker can accept an Operation. It does not observe or change an Object.

### `POST /api/devices`

Authentication: none. Authorization: none.

Encryption: none; this Operation carries public identity material, not an end-to-end encrypted payload.

The caller MUST sign this registration with the private key corresponding to the public key being registered. The Worker verifies that signature against the submitted public key, without treating it as an existing Device identity.

Registers a Device after the caller demonstrates control of its public identity. Success creates exactly one `registered` Device and returns its stable identity; rejection creates no Device.

### `PUT /api/devices/:deviceId/push`

Authentication: the signature of the registered Device named by `deviceId`. Authorization: only that Device may replace its notification destination, and the replacement MUST be based on the current notification configuration.

Encryption: none; the notification destination is not an end-to-end encrypted payload.

The signature MUST be bound to this Device, the replacement notification destination, and the current notification configuration on which the replacement is based.

Replaces the notification delivery destination of a registered Device after the caller demonstrates control of that Device. The Device identity and lifecycle state do not change, and future delivery attempts use only the replacement destination.

Replaying an earlier valid replacement MUST NOT overwrite a later accepted replacement.

### `POST /api/device-requests`

Authentication: the signature of the registered Device named by the request. Authorization: a Device may create a DeviceRequest only for itself.

Encryption: none; this Operation carries public membership material, not an end-to-end encrypted payload.

The signature MUST be bound to the DeviceRequest being created and the Device state proposed for Group membership.

A registered Device creates a DeviceRequest in `waiting` state. The DeviceRequest is not yet associated with a Group and expires without changing either the Device or a Group.

### `GET /api/device-requests/:requestId`

Authentication: the signature of a registered Device. Authorization: the DeviceRequest MUST belong to that Device.

Encryption: none; the response carries DeviceRequest state and public membership material.

The signature MUST be bound to this read of the named DeviceRequest.

The requesting Device observes its DeviceRequest as `waiting`, `approving`, `approved`, or `expired`. The Operation does not change the DeviceRequest.

### `GET /api/groups/:groupId/device-requests/:requestId`

Authentication: a `groupToken` for the named Group. Authorization: its Device MUST be a current member of the Group and the DeviceRequest MUST be `waiting`, or MUST be `approving` an Operation by that Group.

Encryption: none; the response carries the requesting Device's public membership material.

A current member of a Group observes the DeviceRequest membership material available to that Group. Reading a `waiting` DeviceRequest neither selects that Group nor changes either Object.

Before approval, the caller MUST verify the returned DeviceRequest against the binding carried by the DeviceRequest link. Possession of `requestId` alone does not authenticate the DeviceRequest contents.

### `POST /api/groups/:groupId/device-requests/:requestId/approve`

Authentication: a `groupToken` for the named Group. Authorization: its Device MUST be a current member of the Group and the DeviceRequest MUST be `waiting`, or MUST already be `approving` this same Operation.

Encryption: the request carries the resulting group key encrypted separately for each resulting member. Each package key is derived from that member's Device encryption public key: existing members' keys come from `GET /api/groups/:groupId/state`, and the joining Device's key comes from `GET /api/groups/:groupId/device-requests/:requestId`.

The complete resulting Group state MUST be signed by the approving Device and by the current group key. The approval MUST also include a proof, verifiable by the requesting Device using the secret carried by its DeviceRequest link, that binds the DeviceRequest and Group to that resulting Group state.

A current member of a Group approves a `waiting` DeviceRequest. The accepted approval first changes the DeviceRequest to `approving`, thereby selecting one complete approval by one Group; competing approval by another Group cannot also succeed.

The DeviceRequest remains `approving` while the selected Group change is completed or recovered. A successful response is returned only after the DeviceRequest is `approved` and the new Group state includes everything required for the added Device to act as a current member.

If the selected Group change can no longer be applied, rejection returns the DeviceRequest to `waiting`, or to `expired` once its lifetime has elapsed, without applying that Group change. Once the Group has accepted the selected change, retry or recovery MUST complete the DeviceRequest as `approved` rather than make it available for another approval.

### `POST /api/groups`

Authentication: the signature of a registered Device. Authorization: the authenticated Device MUST be the sole initial member of the new Group.

Encryption: the request carries the initial group key encrypted for the initial Device. Its package key is derived from the Device encryption public key supplied by that Device in this Operation.

The Device authentication signature MUST bind the new Group and that Device's initial membership credentials. Separately, the initial membership, initial group key, and key material supplied to the member MUST be signed by that Device and by the initial group key.

A registered Device creates a Group. Success creates the Group in `active` state with that Device as its sole current member and with a Group state usable by that member.

### `GET /api/groups/:groupId/state`

Authentication: a `groupToken` for the named Group. Authorization: its Device MUST be a current member of the Group.

Encryption: the response carries the public Group key history and, for each retained generation made available to the calling Device, its private-key material in a per-Device encrypted package. The package key is derived from the Device encryption public key established by `POST /api/groups` or `POST /api/groups/:groupId/device-requests/:requestId/approve`; the matching private key remains on that Device.

A current member observes one coherent Group state: its current membership, complete Group key transition history, whether that history establishes a currently usable key, and Sessions in which the Group currently participates. The Operation does not change the Group.

The response includes every retained generation of the Group key.

### `POST /api/groups/:groupId/keys`

Authentication: a `groupToken` for the named Group. Authorization: its Device MUST be a current member of the Group and the proposed change MUST start from the current Group state.

Encryption: the request carries the replacement group key encrypted separately for each current member. Each package key is derived from the member's Device encryption public key returned by `GET /api/groups/:groupId/state`.

The complete resulting Group state MUST be signed by that Device and by the current group key. Both signatures MUST bind the resulting membership, group key, and key material supplied to each member.

A current member replaces the current group key without changing membership. Success makes the replacement usable by the current membership as one Group state change; rejection leaves the previous Group state current.

### `DELETE /api/groups/:groupId/devices/:deviceId`

Authentication: a `groupToken` for the named Group. Authorization: its Device and the Device being removed MUST both be current members of the Group.

Encryption: removing another Device carries the resulting group key encrypted separately for each remaining member, using Device encryption public keys from `GET /api/groups/:groupId/state`. Self-removal creates no replacement group key; while members remain, it re-encrypts the current group key for them using those same public keys. Abandonment by the sole member carries no encrypted package.

When the calling Device removes another Device, the complete resulting Group state MUST be signed by the calling Device and by the current group key. Both signatures MUST bind the removed Device, the resulting membership, the resulting group key, and the key material supplied to each remaining member. When the calling Device removes itself, it MUST instead sign a resulting membership that excludes it without establishing a resulting group key.

A current member removes itself or another Device from the Group. Success removes the Device from the membership and immediately prevents it from performing later Operations as a Group member.

Removing another Device also establishes a group key that excludes it in the same Group state change. After self-removal, the remaining membership cannot perform new Session Operations until a remaining Device establishes a new group key; no Operation may continue using the old key as though removal had not occurred.

Any Session participation that is no longer valid under the resulting Group state becomes unavailable in that same observable result. Rejection leaves membership, group key, and Session availability unchanged.

### `POST /api/sessions`

Authentication: none. Authorization: none.

Encryption: none; the request carries the Session creator public key, while its private key remains with the creating process.

The calling process creates a Session in `open` state and retains the `sessionToken` established by the Operation. The Operation also issues the first SessionPairing in `available` state; both Objects become observable together, or neither is created.

The Session expires after its defined period of inactivity. Expiration removes the Session and makes its child Objects, associated records, and Group participation no longer observable.

### `POST /api/sessions/:sessionId/pairings`

Authentication: the `sessionToken` for the named Session. Authorization: the Session MUST be `open`.

Encryption: none; the request registers a client-generated pairing identifier and token verifier, while the pairing capability and its authentication secret remain with the Session-creating process.

The Session-creating process issues a new SessionPairing for its `open` Session. Success creates exactly one `available` SessionPairing without changing existing Pairings or joined Groups; rejection creates none.

### `POST /api/sessions/:sessionId/join`

Authentication: a `groupToken` for the joining Group and the `pairingToken` for the named SessionPairing. Authorization: the `groupToken`'s Device MUST be a current member of the Group, the Session MUST be `open`, and the SessionPairing MUST be `available`, or MUST be `joining` or `consumed` for this same join.

Encryption: none; this Operation carries no encrypted content. It binds the Session creator public key from the pairing link to the current Group public key obtained through `GET /api/groups/:groupId/state`, which are the public inputs for later Session payload encryption.

The Group's participation in the Session MUST be signed by the calling Device and by the current group key, binding the Session and Group to the current Group state. The Operation MUST also record a proof, verifiable by the Session client using the secret carried by the pairing link, that binds the Session and SessionPairing, the Group, and the joined group key and Group state.

A current member of a Group uses an `available` SessionPairing to join an `open` Session. The accepted join first changes the SessionPairing to `joining` and establishes the Group's participation in the Session, then adds the Session to the Group, and finally changes the SessionPairing to `consumed`.

Each established change remains in place if a later change cannot be completed. The caller receives success only after all three changes have been established; otherwise it may repeat the same join to continue from the first incomplete change.

While the SessionPairing is `joining` or `consumed`, a request with a different Group, calling Device, or submitted Group state MUST be rejected. Repeating the same join does not duplicate an established change, consume the Pairing again, or restore participation made unavailable by a later transition.

### `GET /api/sessions/:sessionId`

Authentication: the `sessionToken` for the named Session. Authorization: the Session MUST exist in `open` state.

Encryption: none; the response carries Group public keys. The Session-creating process combines them with its locally held Session private key to derive the keys used for encrypted Session payloads.

The Session-creating process observes its Session's current state, including the Groups whose participation has been established and the Group state currently usable for each one. The Operation does not change the Session or another Object.

### `POST /api/sessions/:sessionId/events`

Authentication: the `sessionToken` for the named Session. Authorization: the Session MUST be `open`, the target Group MUST be joined, and its current Group state MUST be usable by the Session.

Encryption: the request carries the Event payload encrypted with a key derived from the locally held Session private key and the target Group public key returned by `GET /api/sessions/:sessionId`. The derivation and authenticated encryption bind the Session, Group, group-key version, and Event identity.

The Session-creating process records one immutable Event for a currently joined Group. The Event is accepted only against the Group state currently usable by that `open` Session.

When the Event introduces an actionable item, success also creates the corresponding SessionItem in `active` state. Recording the Event, creating the SessionItem, scheduling its notification behavior, and extending the Session lifetime are one observable result.

### `GET /api/sessions/:sessionId/events`

Authentication: a `groupToken` for a Group joined to the named Session. Authorization: its Device MUST be a current member of that Group, the Session MUST be `open`, and the Group's current state MUST be usable by the Session.

Encryption: the response carries encrypted Event payloads. The Device derives each decryption key from its locally held Group private key and the Session creator public key returned by `GET /api/groups/:groupId/state`; when the private key is not already held locally, the Device recovers it from its package in that same response.

A current member of a joined Group observes a coherent sequence of Events addressed to that Group together with the current SessionItem and attention state relevant to that Device. The Operation changes no Object and does not extend the Session lifetime.

### `PUT /api/sessions/:sessionId/attention`

Authentication: a `groupToken` for a Group joined to the named Session. Authorization: its Device MUST be a current member of that Group, the Session MUST be `open`, the Group's current state MUST be usable by the Session, and the change MUST be based on that Device's current attention state.

Encryption: none; attention is Device-specific control state and carries no end-to-end encrypted payload.

A current member of a joined Group changes whether its Device is attending to an `open` Session. The change affects no other Device; disabling attention also removes outstanding status-notification behavior for that Device in the same result and does not extend the Session lifetime.

Replaying an earlier valid attention change MUST NOT overwrite a later accepted change.

### `POST /api/sessions/:sessionId/attachments`

Authentication: a `groupToken` for a Group joined to the named Session. Authorization: its Device MUST be a current member of that Group, the Session MUST be `open`, and the Group's current state MUST be usable by the Session.

Encryption: none; the request carries attachment identifiers, ciphertext length, and ciphertext digest, but not attachment content or its encrypted manifest.

Reserves a SessionAttachment for one not-yet-recorded Response from a current member of a joined Group. Success creates the SessionAttachment in `reserved` state and fixes the Response and Group with which it may become available.

### `PUT /api/sessions/:sessionId/attachments/:attachmentId`

Authentication: the `attachmentUploadToken` for the named SessionAttachment. Authorization: the SessionAttachment MUST be `reserved`, or `uploaded` by this same token with no later state change; the token MUST be unexpired and the Session MUST be `open`.

Encryption: the request body is attachment ciphertext encrypted with an attachment-specific key derived from the Device's locally held Group private key and the Session creator public key returned by `GET /api/groups/:groupId/state`. The key derivation and authenticated encryption bind the Session, Group, group-key version, Response, and SessionAttachment.

Uploads the encrypted content of a `reserved` SessionAttachment. Success changes it to `uploaded`; rejection leaves it `reserved` and makes no rejected content available.

Repeating a successful upload while the SessionAttachment remains `uploaded` observes the same result and performs no further write. Once the SessionAttachment advances to another state, the upload token cannot change or restore it.

### `POST /api/sessions/:sessionId/responses`

Authentication: a `groupToken` for a Group joined to the named Session. Authorization: its Device MUST be a current member of that Group, the Session MUST be `open`, and the Group's current state MUST be usable by the Session.

Encryption: the request carries the Response payload, including the ordered `attachments` manifest array, encrypted with a key derived from the Device's locally held Group private key and the Session creator public key returned by `GET /api/groups/:groupId/state`. The derivation and authenticated encryption bind the Session, Group, group-key version, and Response identity.

Records one immutable Response from a current member of a joined Group in an `open` Session. The Response is accepted only against the Group state currently usable by that Session.

If the Response addresses an `active` SessionItem, success also changes that item to `inactive`. The ordered `attachmentIds` array contains zero to five distinct IDs. Each referenced SessionAttachment must match the Response, Group, Device, and key version and be `uploaded`; success changes all referenced attachments to `available`; the Response and all applicable child-Object changes become observable together.

### `GET /api/sessions/:sessionId/responses`

Authentication: the `sessionToken` for the named Session. Authorization: the Session MUST be `open`.

Encryption: the response carries encrypted Response payloads. The Session-creating process derives each decryption key from its locally held Session private key and the responding Group public key returned by `GET /api/sessions/:sessionId`.

The Session-creating process observes a coherent sequence of Responses to its `open` Session. The Operation does not select, aggregate, acknowledge, or otherwise change a Response or another Object.

### `GET /api/sessions/:sessionId/attachments/:attachmentId`

Authentication: the `sessionToken` for the named Session. Authorization: the SessionAttachment MUST be `available` in that Session.

Encryption: the response body remains attachment ciphertext. The Session-creating process derives its attachment-specific key from the locally held Session private key and the responding Group public key returned by `GET /api/sessions/:sessionId`; the encrypted Response supplies the bound Response and SessionAttachment identities.

The Session-creating process obtains the encrypted content of an `available` SessionAttachment. The Operation does not change the SessionAttachment.

### `DELETE /api/sessions/:sessionId/attachments/:attachmentId`

Authentication: the `sessionToken` for the named Session. Authorization: the SessionAttachment MUST be `available` in that Session, or already `unavailable` because this acknowledgement succeeded.

Encryption: none; this Operation identifies the SessionAttachment but carries no encrypted payload.

The Session-creating process acknowledges that an `available` SessionAttachment is no longer required. Success changes it to `unavailable`; repetition observes the same terminal result and cannot make it available again.

### `DELETE /api/sessions/:sessionId`

Authentication: the `sessionToken` for the named Session. Authorization: the Session MUST exist in `open` state.

Encryption: none; this Operation carries no end-to-end encrypted payload.

The Session-creating process closes its `open` Session. Success removes the Session; its child Objects and associated records are no longer observable, and no Group state reports participation in it.

Once the Session has been removed, later access observes that it does not exist rather than a retained `closed` state.
