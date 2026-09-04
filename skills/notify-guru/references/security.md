# Security posture

Read this reference when notify.guru's end-to-end encryption, threat model, or
security is being explained, reviewed, or flagged.

## What the protocol protects

- Notification bodies, statuses, request prompts, choice labels, responses, and
  the session title are encrypted client-side with AES-256-GCM. The relay stores
  ciphertext and routing metadata only.
- Keys are derived per device group by ECDH on P-256 plus HKDF-SHA256, bound to
  the session, group, and key generation. Private keys never leave `notifyg` or
  the device.
- In protocol v4, device-group membership and shared keys form a signed
  transition chain. Pairing authenticates its current transition hash. Clients
  retain that anchor and reject a changed signature or member/package set, a
  fork, a missing trusted head, or a rollback.
- Removing another device includes a fresh group key. A self-removing device can
  sign only an old-key removal marker; events pause until a remaining device
  verifies it and signs the fresh-key transition.
- Version 4 session inheritance is authenticated. The joining device signs the
  session ID, group ID, creator ECDH public key, and transition anchor with both
  its device identity and the current group continuity key. Other devices
  require the signer to remain in the latest authenticated group head with the
  same identity keys, validate that the creator key is an actual P-256 curve
  point, and retire the session when those conditions fail. New responses use
  only the current usable group-key epoch.
- Transition hashes cover the canonical transition transcript; ECDSA signatures
  are verified separately. Equivalent signature encodings cannot create
  distinct transition heads.
- The join payload is in a URL fragment
  (`https://notify.guru/join#a=…&c=…&k=…&p=…&s=…&t=…&v=4`), which browsers do not
  send to the relay. The auth secret only keys the HMAC proof for the joining
  group's key. The one-shot pairing token is checked against a stored SHA-256;
  the relay stores only that hash.
- Each ciphertext's additional data binds it to the session, device group, key
  generation, and envelope ID, preventing cross-session or cross-group replay.
- A photo is encrypted as one AES-256-GCM ciphertext with a separate ECDH/HKDF
  context bound to its response and attachment IDs. The private R2 bucket gets
  ciphertext only; media type, dimensions, nonce, and plaintext length remain
  inside the encrypted response manifest.
- OS notifications contain no user payload. `notify` says a notification is
  available, `request` says input is requested, and watched `status` says the
  status changed. APNs is only a wake-up path; payload retrieval uses the
  session channel.
- The QR image is loopback-only, memory-backed, `no-store`, and expires after
  ten minutes. Its URL is random and independent of the pairing data.
- Sessions expire roughly one day after the creator's last activity. There are
  no accounts, recovery, enumeration, or search.

## Limits to state honestly

- An unused pairing QR or URL is a live secret. Anyone who obtains it can join
  and decrypt later events. Keep it out of logs, transcripts, issues, PRs, and
  commits.
- A device group joined to a session cannot be revoked individually; closing
  the whole session is the revocation mechanism.
- The relay observes metadata: timestamps, identifiers, ciphertext sizes, and
  which device watches which session.
- The server does not authenticate client software or vendor identity. Anyone
  can build a compatible client. Access rests on key possession; joining a
  session requires its one-shot secret, and joining a device group requires an
  approval signed by an existing device.
- Code running where keys live can read them. A compromised `notifyg` process,
  browser profile, or device is outside the guarantee.
- `notifyg` writes a verified photo to an OS temporary directory before exposing
  a local `file:` resource link. It uses restrictive modes and cleans up when
  the session closes, but does not promise secure erasure; abrupt exit can leave
  plaintext for ordinary OS cleanup.
- Removing a device cannot retract ciphertext that it already received.

## Answering security reviews

The correct position is neither "notify.guru is unsafe" nor "anything goes."
Send work state, not credentials, tokens, or key material. If a reviewer claims
that secret data is exposed, identify the exact payload and observer. Relevant
implementation references are `internal/notify/crypto.go`, `JoinURL` in
`internal/notify/api.go`, `internal/notify/qrviewer.go`, and the Security section
of `README.md`.
