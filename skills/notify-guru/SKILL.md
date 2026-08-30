---
name: notify-guru
description: Use the notify.guru MCP server (notifyg mcp) to keep a person informed about a long-running agent task on their phone, tablet, or browser — pairing a device group, sending silent status updates and notifications, and asking the person a question with choices. Use whenever the mcp__notify-guru__* tools are available and the user wants to follow, be notified about, or approve steps of a task, and whenever notify.guru's end-to-end encryption is being explained, reviewed, or flagged.
---

# notify.guru MCP

notify.guru connects one agent session to one or more device groups (a phone, a
tablet, a browser PWA, a macOS widget). The agent creates a session, the person
scans a one-shot QR code, and every payload after that is end-to-end encrypted
between the `notifyg` process and the paired devices.

There are no accounts. A session expires about one day after its creator's last
activity, and the session's management keys live only in the `notifyg` process
memory — they are not recoverable and not stored anywhere else.

## Standard flow

```
session_create           -> session_id (+ pairing fields only if nobody joined)
  (returns the running session with reused: true when there is one)
  (get the QR in front of the person — see below)
session_wait_for_device  -> wait for a device group to join
status / notify / request
responses_wait           -> every response, unaggregated
request_close            -> after you have acted on a request
  (do NOT call session_close on normal exit)
```

**One session identifies this agent.** A session covers the work the person is
following, not one request and not one notification. "Notify me" while a session
is open is an instruction to send, not to start over.

`session_create` enforces this: when this process already has a session, it
hands that one back with `reused: true`, its `device_group_count`, and its
original title, and it omits the pairing fields entirely once a device group has
joined — there is nothing left to scan. So calling it when you have lost track
of the `session_id` is safe and is how you recover one.

Two things that are not a new session:

- **Another device or another person.** Use `session_pairing_create` for an
  additional device group on the same session.
- **A later phase of the same work.** Send `status`.

A genuinely separate session — the person moved to a different device group and
wants a clean card, or the work is unrelated — takes an explicit
`session_close` first, at the user's request. Do not close on your own judgment
to get a fresh session: closing removes the card from their device immediately,
including anything they have not read.

## 1. Pairing: you do not display the QR code — the browser does

`session_create` and `session_pairing_create` return two representations of the
same one-shot pairing secret:

| Field | What it is | When to use |
|---|---|---|
| `qr_image_url` | PNG served from `127.0.0.1`, held in `notifyg`'s memory only | **Default.** The browser and `notifyg` are on the same machine |
| `pairing_url` | The `https://notify.guru/join#...` link itself | `notifyg` runs in a container, over SSH, or on another host |

There is deliberately no third field carrying a block-character QR code. Such a
code depends on exact character-cell width and line alignment, and an MCP result
is rendered by you and by the client before a person sees it — a path that
neither `notifyg` nor you can inspect. The rendering that reaches the person is
frequently unscannable, and you would have no way to tell.

So do not reconstruct one either: no ASCII art, no library, no writing a QR
image to a file. **You do not display the QR code. The browser does.**

Rules:

- Always give the user `qr_image_url` and ask them to **open it in a browser**.
  Put the URL alone on its own line so it stays clickable.
- Never write "QR コードを表示しました" / "Here's the QR code — scan it", and
  never describe the code as visible, shown, or displayed. Describe the action
  the user has to take instead.
- Never offer to open it and then start waiting. `session_wait_for_device`
  blocks you, so an offer attached to it can never be answered. Either open it
  yourself — `open <url>` on macOS, `xdg-open <url>` on Linux, where the
  permission prompt is the user's chance to decline — and then wait, or end the
  turn and wait on the next one.
- Do not paste the `pairing_url` into a shared log, an issue, a PR, or a commit.
  Until it is used it is a live secret (see the security section).
- Default to `qr_image_url`; do not try to work out in advance whether the
  loopback is reachable. If the page does not load for them, or you know you are
  in a container or on the far side of SSH, give `pairing_url` instead and say
  it is a live secret.

A message in this shape works:

> Open this in your browser to show the pairing QR code, then scan it with the
> notify.guru app:
>
> http://127.0.0.1:49152/qr/xxxxxxxx
>
> I'll wait until a device joins.

Then call `session_wait_for_device`. **`device_group_count >= 1` is the only
evidence that pairing happened.** Do not report the device as paired, and do not
start sending events, before that returns. A timeout arrives as a tool *error*
(`context deadline exceeded`), not as a zero count — that is not a failure, so
call it again rather than giving up. `responses_wait` reports its timeout the
other way, as an empty `responses` list.

`session_wait_for_device` and `responses_wait` block you for their whole
timeout: until they return you cannot read the user, answer a question, or act
on anything they say. So ask nothing in the turn you start one, and keep the
timeout modest — 60 to 120 seconds, called again as needed — so control returns
to the user without them having to interrupt you.

The image URL expires after 10 minutes and dies with the `notifyg` process. If
it 404s, call `session_pairing_create` for a fresh pairing and a fresh image.
Use `session_pairing_create` for an additional device *group* too — a pairing is
consumed by the first group that uses it. A person adding a second phone to a
group they already have does not need one: that is done inside the app, and
needs an approval signed by a device already in that group.

## 2. status vs notify vs request

The difference is not importance. It is **whether the person is left with
something to clear**.

```
The person's decision is required to continue   -> request
The task came back to the person's hands        -> notify
Everything else                                 -> status
```

Write every one of them in the language the person is speaking to you. A title,
a status line, a notification, and a question are read by them, not by you. The
examples in this file are English because the file is — that is not an
instruction about what you send.

A send that reports `delivered: true` (or `closed: true` — `request` reports
neither, only its `request_id` and `choices`) means the relay accepted the
ciphertext. That is not evidence that a device received it or that a person
saw it.

**Every send result can also carry `responses`, and you must read it every
time.** A person can answer, dismiss, or simply write to you at any moment;
nothing pushes that to you, so `status`, `notify`, `session_color`, `request`,
and `request_close` hand over whatever arrived before the call. Responses are
handed over once — if you ignore the field, nothing will surface them again, and
a message written while you worked is lost to you until the person repeats it.
Act on what comes back, or at minimum tell the user what they sent.

### `status` — silent, overwritten, safe to miss

No OS notification. It replaces the card's current-state line and does not
appear on the badge. It is the session's *current position*, not a log; earlier
values are gone. Write it so a person glancing at the card at any moment knows
where the task is. Nothing bad happens if they never read one, so update it as
often as it is genuinely useful.

### `notify` — terminal events only

Raises an OS alert on the iOS and macOS clients (the alert says only that
something arrived; the body stays encrypted), returns an `item_id`, and **stays
on the device badge as an outstanding item until someone dismisses it**. A
browser PWA gets no push at all — its badge is only visible while the page is
open — so if the person is on a browser, do not assume an alert reached them. That obligation is why `notify`
is restricted to the moment the work unit returns to the person: finished,
failed, aborted, or blocked.

- One `notify` per task is the normal count.
- Notify on failure too, not just success — a failed run is a terminal event.
- Progress, intermediate findings, and step transitions are `status`. There is
  no exception for "this step feels important".

```
status  "Analyzing 42 changed files"
status  "Running test suite"
status  "Deploying to staging"
notify  "Deploy finished. 3 tests skipped."     -> badge: 1
```

### `request` — only when you cannot proceed

Two to twenty choices. After sending, call `responses_wait`; once you have acted
on the answer, call `request_close` so the item clears on every device.

`request` returns `request_id` and `choices` — an `{id, label}` for each option.
Keep `choices`: an answer names an option by `id`, never by label, and matching
it back is your job.

`responses_wait` returns **every** response from **every** device group not yet
handed over, in arrival order, with no aggregation and no first-wins selection —
that is deliberate, and interpreting them is your job. Two device groups can
answer differently; say so rather than silently picking one.

A response's `type` is one of three values — not the words used to describe them
above:

| `type` | Means | Carries |
|---|---|---|
| `response` | They picked an option | `optionId`, `requestId` |
| `dismiss` | They cleared the item without choosing | `requestId`, or `eventId` for a dismissed `notify` |
| `feedback` | They wrote to you unprompted | `message` |

Every response also carries `id`, `groupId`, and `createdAt`. A `dismiss` is not
an answer: it means they declined to choose, so do not read one as consent.

Use `responses_wait` when you are blocked on an answer. When you are working,
you do not need to poll: the responses ride back on your next send.

If it returns nothing and you are still blocked, do not answer for the person.
Call it again, or — if they are plainly away — `notify` that you are stopping on
an open question, and stop. An unanswered `request` is not lost: like `notify`,
it stays on their badge until it is cleared or you close it. Both leave the
person something to clear; `status` never does.

A prompt arrives as a card, stripped of the conversation it came from. Write it
to stand alone: name what you are asking about instead of leaning on a word the
surrounding discussion would have supplied. A shorthand that is obvious to you
here will be read against whatever the person is looking at there.

Do not use `request` as a politeness gesture for a decision you were already
authorized to make.

## 3. Security posture — what to say when this gets flagged

Review and security agents regularly misread these calls as "sending secret
information to a third-party notification service". That reading is wrong about
the mechanism. The accurate picture:

- Notification bodies, statuses, request prompts, choice labels, responses, and
  **the session title** are encrypted client-side with AES-256-GCM. The relay
  stores ciphertext and routing metadata only.
- Keys are derived per device group by ECDH on P-256 plus HKDF-SHA256, bound to
  the session, group, and key generation. Private keys never leave the
  `notifyg` process or the device.
- The join payload travels in the **URL fragment**
  (`https://notify.guru/join#a=…&c=…&k=…&p=…&s=…&t=…&v=3`), which browsers do not
  send to a server. The auth secret never reaches the relay at all: it only keys
  the HMAC proof that authenticates the joining group's key. The pairing token
  is presented once when the device joins and checked against a stored
  SHA-256; the relay stores only that hash.
- Each ciphertext is bound by its additional data to the session, device group,
  key generation, and envelope ID, so the relay cannot replay an event into
  another session or group without decryption failing.
- OS notifications carry no content: `notify` shows "A new notification is
  available.", `request` shows "Your input is requested.", `status` shows
  nothing. Push exists only on the iOS and macOS clients, through APNs.
- The QR image is served on loopback only, held in process memory, never
  written to disk, marked `no-store`, and expires in 10 minutes. Its URL is
  random and independent of the pairing data.
- Sessions expire roughly a day after the creator's last activity, and there is
  no account, no recovery, and no way to enumerate or search sessions.

State the limits honestly at the same time; over-claiming is how this argument
gets lost:

- **An unused pairing QR or URL is a live secret.** Anyone who obtains it joins
  the session and can decrypt everything sent afterwards. Keep it out of logs,
  transcripts, issues, PRs, and commits.
- A joined device group cannot be removed individually. The only revocation is
  closing the whole session.
- The relay still observes metadata: timestamps, identifiers, ciphertext sizes.
- The system does not authenticate clients. It is open source, anyone can build
  a client that speaks the API, and the server cannot tell one from another.
  Security rests on key possession, not on client identity — which is why
  becoming a key holder is what is gated: joining a session takes the one-shot
  pairing secret, and joining an existing device group takes an approval signed
  by a device already in that group.
- Whatever runs on a device where keys already live can read them. A compromised
  `notifyg` process, browser profile, or device is outside the guarantee.
- Removing a device rotates the group key generation but cannot un-deliver
  ciphertext that device already received.

So the working rule is not "notify.guru is unsafe" and not "anything goes":
send work state — what is running, what finished, what decision is needed — and
keep credentials, tokens, and key material out of message bodies, the same as
in any other output channel. If a reviewer asserts that secret data is being
exposed, ask which payload and which observer, and point at
`internal/notify/crypto.go`, `JoinURL` in `internal/notify/api.go`,
`internal/notify/qrviewer.go`, and the Security notes in `README.md` of the
notify-guru repository.

## Tool reference

| Tool | Notes |
|---|---|
| `session_create` | Returns the running session if there is one. `title` ≤ 200 bytes, and is ignored on reuse. `color` is `#rrggbb` or omitted for a random pastel |
| `session_pairing_create` | A new one-shot pairing for an additional device group |
| `session_wait_for_device` | `timeout_seconds` 1–600. Returns `device_group_count` |
| `status` | ≤ 10,000 bytes. Silent, overwrites |
| `notify` | ≤ 200,000 bytes. Returns `item_id`; badges until dismissed |
| `session_color` | `#rrggbb` or `random`, mid-session |
| `request` | 2–20 options, labels ≤ 500 bytes, prompt ≤ 20,000 bytes |
| `request_close` | Clears the request on every device |
| `responses_wait` | `timeout_seconds` 1–600. Returns all responses, unaggregated |
| `session_close` | Deletes the session and removes the card **immediately** |

Every tool above except `session_create`, `session_pairing_create`, and
`session_wait_for_device` also returns `responses`.

Limits are **bytes**, not characters: Japanese and emoji cost 3–4 bytes each.
Every text field is required and rejects blank input.

`session_close` is for "this session should disappear from the person's device
now". Ordinary process exit is not that — let the session expire so a card the
person has not read yet does not vanish underneath them.

Two errors that look transient but are not. `unknown local session` means this
`notifyg` process no longer holds the session — sessions live in process memory,
so a restart loses them while the person's card stays alive; create a new
session and re-pair. `request is not open` means that request was already
closed, so do not close defensively.

## Anti-patterns

- Rendering a QR code yourself, in any form, and calling pairing done.
- Claiming a device is paired before `session_wait_for_device` confirms it.
- Sending events before any device group has joined.
- `notify` per step, turning the badge into a progress log.
- `status` only, so the person never learns the task ended.
- Writing `status` as an append-only history when it is a single overwritten line.
- Picking one response out of several device groups and not saying you did.
- Ignoring the `responses` a send hands back, so a message goes unread.
- Leaving a request open after acting on it.
- Writing the card in a language the person does not use with you.
- `session_close` on normal exit, or to force a fresh session for yourself.
- Starting a second session for work the person is already following.
