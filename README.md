# notify.guru

notify.guru connects a short-lived Agent or CLI session to one or more device groups. The sender displays a one-shot QR code, a PWA or iOS device scans it, and subsequent notifications, status updates, questions, and responses are end-to-end encrypted.

There are no user accounts and no recovery flow. A session expires one day after its creator's last activity. The relay stores ciphertext and routing metadata, but does not receive application payloads in plaintext. The web client must still trust the JavaScript served by notify.guru.

The PWA is available at [notify.guru](https://notify.guru).

## Install

Download the archive for your operating system and architecture from [GitHub Releases](https://github.com/yacchin1205/notify-guru/releases), extract it, and place `notifyg` or `notifyg.exe` on your `PATH`.

To build from source instead:

```sh
git clone https://github.com/yacchin1205/notify-guru.git
cd notify-guru
go build -o notifyg ./cmd/notifyg
```

## Interactive CLI

Start a session:

```sh
notifyg --title "Deployment"
```

The CLI prints a terminal QR code, its pairing URL, and a `QR image` URL such as `http://127.0.0.1:49152/qr/...`. Open the local URL in a browser to display a full-size QR image without creating a file, then scan it with the receiving device. The CLI reports when a new device group starts receiving the session.

The terminal QR code depends on the cell geometry of a terminal, so it is drawn only when `notifyg` writes to one; redirected or piped output gets the two URLs alone. Pass `--no-terminal-qr` to suppress it on a terminal as well, when the block characters are noise, when the terminal is too narrow to render them, or when the screen is being shared or recorded. The pairing URL is still printed either way and remains a temporary secret.

Session cards use a randomly selected pastel color by default. Pass `--color '#a1b2c3'` to choose an exact color at startup.

The PWA and iOS app prepare a single-device cryptographic group automatically. To receive the same notifications on another device, open device management, create a 10-minute invitation, and approve it on a device already in the group. The invitation authenticates the exact device request and the accepted signed group transition without revealing its approval secret to the relay. Invitation QR codes and links disappear as soon as approval is pending. A device can stop sharing only while two or more devices are connected; it then returns automatically to single-device use. Different people should join the Agent session as separate device groups instead of sharing one group.

Available commands:

```text
join
pair
notify Deployment completed
status Waiting for approval
color #d9f2d0
request Continue deployment? | Continue | Stop
close-request REQUEST_ID
responses
close
quit
```

- `pair` creates another one-shot QR code for an additional device group.
- `color` changes the card color during the session; use `color random` to select another pastel color.
- `status` updates the card silently, unless the device is watching the session: long-press a card on iOS or macOS to watch it, and every status update then shows a generic status-updated alert, collapsed to the latest one. `notify` returns the item ID used to identify a later dismissal and shows a generic new-notification alert, while `request` shows a generic input-requested alert. Encrypted event content is not included in any OS alert.
- `close-request` ends the identified request on connected devices.
- Each local QR image remains available for 10 minutes or until `notifyg` exits. It is held only in process memory, and the response prevents browser caching.
- `responses` retrieves every choice response, request dismissal, and free-form message without selecting or aggregating them.
- `close` immediately deletes the session and removes its card from connected browsers.
- `quit` only exits the CLI. The session remains until its normal expiry, but its creator keys are lost with the process.

Use `--base-url` before the optional mode argument when connecting to a development deployment:

```sh
notifyg --base-url http://localhost:8787 --title "Local session"
```

## MCP server

Run the same binary as a stdio MCP server:

```sh
notifyg mcp
```

A typical MCP client configuration is:

```json
{
  "mcpServers": {
    "notify-guru": {
      "command": "/absolute/path/to/notifyg",
      "args": ["mcp"]
    }
  }
}
```

The server exposes tools to create and pair sessions, wait for a device group, send notifications and status updates, change card colors, ask and close multiple-choice questions, receive choices, dismissals, free-form messages, and photos, and close sessions.

A session identifies the agent, so one MCP process runs one session: `session_create` returns the session already running instead of starting another, and omits the pairing fields once a device group has joined. Add a device group with `session_pairing_create`; start a separate session by closing the running one first.

Nothing pushes a response to the agent, so every send also hands over the responses received before it: `status`, `notify`, `session_color`, `request`, and `request_close` return them alongside their own result. Each response is handed over once, whether by a send or by `responses_wait`.

Protocol version 4 lets the PWA, iOS app, or macOS app send feedback containing text, one JPEG photo, or both. On iOS, a photo can be taken with the camera or selected through the system photo picker; the picker gives the app only the item the person chooses rather than requiring full-library access. On macOS, an image can be pasted from the clipboard with Command-V or the explicit Paste button. The app reads the clipboard only in response to that action. The native clients fix orientation, limit the long edge to 2048 pixels, and normally compress toward 1 MiB. The current service policy rejects attachment ciphertext over 2 MiB; that value is returned by the reservation API and is not encoded as a permanent protocol limit.

Photos use a separate ECDH/HKDF context and full-file AES-256-GCM encryption. A private R2 bucket receives only the ciphertext; the encrypted response carries the media type, dimensions, nonce, plaintext length, ciphertext length, and checksum. `notifyg` checks the manifest, checksum, GCM tag, and JPEG dimensions before writing plaintext. MCP returns the verified photo as a `file:` resource link.

Verified plaintext is written below the operating system's temporary directory, with a `0700` directory and `0600` file where those modes apply. It is removed when the local session is closed or replaced. This is ordinary temporary-file cleanup, not secure erasure: a crash can leave the file until the operating system cleans its temporary storage.

`session_create` and `session_pairing_create` return `qr_image_url` and `pairing_url`. They do not return a terminal QR code: an MCP result is rendered by an agent before a person sees it, and neither `notifyg` nor the agent can check that block characters survived that rendering intact. Ask the person to open `qr_image_url` in a browser.

The image URL is reachable only from the same machine as the `notifyg` process. When MCP runs in a container, on a remote host, or across SSH without port forwarding, use the pairing URL instead.

## Security notes

- Treat an unused pairing QR code or URL as a temporary secret.
- Local QR images use an opaque, independently generated loopback URL. The URL contains no pairing data and expires after 10 minutes, but anyone who can view the image can use the underlying one-shot pairing secret.
- Session management keys exist only in the CLI process memory and are not recoverable.
- The relay can observe metadata such as timestamps, identifiers, and ciphertext sizes.
- Attachment objects in R2 are ciphertext only. They are removed after `notifyg` has advanced past the response and polls again, or when the session expires; an uploaded attachment that is never committed can remain until session expiry.
- Compromise of the served web application, the browser profile, or the CLI process is outside the end-to-end encryption guarantee.
- Each app installation or browser profile belongs to at most one device group. Version 4 authenticates its membership and key history as a signed transition chain anchored during pairing. Sessions carry a device-and-group-signed descriptor whose creator key must be an actual P-256 ECDH public key and whose signer must still be a current member; clients revalidate those conditions on synchronization and retire a locally stored session when either fails. This prevents the relay from keeping a removed device's Agent key as a future response destination. New responses use only the current usable key epoch. Adding a device creates a new transition; removing another device rotates the key immediately. A device leaving by itself signs only its removal marker, after which events pause until a remaining device verifies it and creates the fresh key. Removal cannot revoke ciphertext already received by that device.

See [CONCEPT.md](CONCEPT.md) for the product model and [DESIGN.md](DESIGN.md) for design rationale.

## Releases

GoReleaser builds archives for Linux, macOS, and Windows on amd64 and arm64. Pushing a semantic version tag creates a GitHub Release with those archives and `checksums.txt`:

```sh
git tag v2026.8.0
git push origin v2026.8.0
```
