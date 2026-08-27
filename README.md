# notify.guru

notify.guru connects a short-lived Agent or CLI session to one or more browsers. The sender displays a one-shot QR code, a browser scans it, and subsequent notifications, status updates, questions, and responses are end-to-end encrypted.

There are no user accounts and no recovery flow. A session expires one day after its creator's last activity. The relay stores ciphertext and routing metadata, but does not receive application payloads in plaintext. The web client must still trust the JavaScript served by notify.guru.

The PWA is available at [notify.guru](https://notify.guru).

## Install

Download the archive for your operating system and architecture from [GitHub Releases](https://github.com/yacchin1205/notify-guru/releases), extract it, and place `notify` or `notify.exe` on your `PATH`.

To build from source instead:

```sh
git clone https://github.com/yacchin1205/notify-guru.git
cd notify-guru
go build -o notify ./cmd/notify
```

## Interactive CLI

Start a session:

```sh
notify --title "Deployment"
```

The CLI prints a QR code and its pairing URL. Open notify.guru on the receiving device, scan the QR code, then enter `join` in the CLI to refresh the joined devices.

Available commands:

```text
join
pair
notify Deployment completed
status Waiting for approval
request Continue deployment? | Continue | Stop
responses
close
quit
```

- `pair` creates another one-shot QR code for an additional browser.
- `responses` retrieves every response without selecting or aggregating them.
- `close` immediately deletes the session and removes its card from connected browsers.
- `quit` only exits the CLI. The session remains until its normal expiry, but its creator keys are lost with the process.

Use `--base-url` before the optional mode argument when connecting to a development deployment:

```sh
notify --base-url http://localhost:8787 --title "Local session"
```

## MCP server

Run the same binary as a stdio MCP server:

```sh
notify mcp
```

A typical MCP client configuration is:

```json
{
  "mcpServers": {
    "notify-guru": {
      "command": "/absolute/path/to/notify",
      "args": ["mcp"]
    }
  }
}
```

The server exposes tools to create and pair sessions, wait for a browser, send notifications and status updates, ask multiple-choice questions, receive responses, and close sessions. One MCP process can manage multiple independent notification sessions.

## Security notes

- Treat an unused pairing QR code or URL as a temporary secret.
- Session management keys exist only in the CLI process memory and are not recoverable.
- The relay can observe metadata such as timestamps, identifiers, and ciphertext sizes.
- Compromise of the served web application, the browser profile, or the CLI process is outside the end-to-end encryption guarantee.
- A browser profile currently acts as one independent device group. Cross-device group key sharing and approval are not implemented yet.

See [CONCEPT.md](CONCEPT.md) for the product model and [DESIGN.md](DESIGN.md) for design rationale.

## Releases

GoReleaser builds archives for Linux, macOS, and Windows on amd64 and arm64. Pushing a semantic version tag creates a GitHub Release with those archives and `checksums.txt`:

```sh
git tag v0.1.0
git push origin v0.1.0
```
