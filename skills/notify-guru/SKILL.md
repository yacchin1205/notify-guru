---
name: notify-guru
description: Use the notify.guru MCP server (notifyg mcp) to keep a person informed about a long-running agent task on their phone, tablet, or browser — pairing a device group, sending silent status updates and notifications, and asking the person a question with choices. Use whenever the mcp__notify-guru__* tools are available and the user wants to follow, be notified about, or approve steps of a task, and whenever notify.guru's end-to-end encryption is being explained, reviewed, or flagged.
---

# notify.guru MCP

notify.guru links one agent session to one or more device groups. Payloads after
pairing are end-to-end encrypted between `notifyg` and the devices. A session
expires about one day after its creator's last activity, and its management keys
exist only in the `notifyg` process.

When explaining or reviewing encryption, the threat model, or a security
finding, read [references/security.md](references/security.md) completely before
answering.

## Session lifecycle

```text
session_create
session_wait_for_device
status / notify / request
responses_wait
request_close
```

One session identifies this agent and the work the person is following.
`session_create` returns that running session with `reused: true`; it does not
create another. Calling it is the safe way to recover a forgotten `session_id`.

- For another device group on the same work, use `session_pairing_create`.
- For a later phase of the same work, keep the session and send `status`.
- For genuinely separate work, call `session_close` first only when the user has
  explicitly requested immediate removal of the current session.
- Do not close on ordinary process exit. Let the session expire so unread items
  do not disappear from the person's device.

`unknown local session` means this `notifyg` process lost the in-memory keys;
create and pair a new session. `request is not open` means it was already
closed; do not close it defensively.

## Pairing

`session_create` and `session_pairing_create` provide:

- `qr_image_url`: a loopback PNG held in memory. This is the default when the
  browser and `notifyg` run on the same machine.
- `pairing_url`: the live one-shot secret. Use it only for containers, remote
  hosts, or SSH where loopback is not reachable.

Never render or reconstruct the QR code yourself. Give the person
`qr_image_url` alone on its own line and ask them to open it in a browser, or
open it with the system browser and then wait. Do not say that the QR is visible
or pairing is complete before the person has acted.

Keep `pairing_url` out of shared logs, transcripts, issues, PRs, and commits.
Anyone who gets an unused pairing secret can join. A pairing is consumed by the
first device group that uses it.

Call `session_wait_for_device` before sending any event. Only
`device_group_count >= 1` proves that pairing succeeded. Use modest waits of
about 60–120 seconds so the user can regain control. A timeout is reported as a
tool error and is not a failed pairing; retry if still appropriate.

The QR image expires after ten minutes or when `notifyg` exits. If it returns
404, create another pairing. Adding a device to an already joined device group
happens inside the app and requires approval from an existing device; it does
not use a session pairing.

## Choose the event type

```text
The person's decision is required to continue   -> request
The task has returned to the person's hands     -> notify
Everything else                                 -> status
```

Write titles and payloads in the language the person is using. A card has no
conversation context, so make each request and terminal notification stand on
its own.

### status

`status` is current state, not a history. It silently replaces the previous
status and leaves no item to clear. A device explicitly watching the session
may raise a generic OS alert, but the agent cannot assume anyone is watching.

### notify

Use `notify` for a finished, failed, aborted, or blocked work unit. It raises a
generic OS alert on native clients and leaves an outstanding item until someone
dismisses it. One terminal notification per work unit is normally enough.

A browser PWA has no push; its badge is visible only while the page is open.
Relay acceptance is not proof that a device or person received the event.

### request

Use `request` only when a choice is required to proceed. It returns a
`request_id` and `{id, label}` choices; retain the mapping because answers carry
the option ID, not the label.

After sending, call `responses_wait`. It returns every unhanded response from
every device group in arrival order; do not silently choose among conflicting
answers. A `dismiss` is not consent. After acting on an answer, call
`request_close` so the item clears everywhere.

If the wait returns nothing and the decision is still required, wait again or
notify that work is blocked and stop. Do not answer for the person. An open
request remains on the badge until closed, dismissed, or expired.

Response types are:

- `response`: a selected `optionId` and `requestId`.
- `dismiss`: a cleared request or notification, not an answer.
- `feedback`: an unprompted message, optional photo, or both.

## Read every result completely

Every send (`status`, `notify`, `session_color`, `request`, and
`request_close`) can hand over responses that arrived earlier. Responses are
delivered once. Inspect the complete result before making another call, act on
everything returned, or at minimum tell the user what arrived.

A photo is not necessarily nested in structured `responses`. After verification
and decryption, it arrives as a separate `resource_link` content block with a
local `file:` URI. That block can piggyback on any send or on `responses_wait`.
Preserve and surface every content block; never forward only `text`, `image`, or
structured fields while silently dropping other content types. A result with no
text can contain the only handed-over attachment link.

Text limits are measured in bytes, so Japanese and emoji use more than one byte.
Use the limits declared by each MCP tool. Keep credentials, tokens, and key
material out of notification payloads, as with any other output channel.
