# MiniDrive Protocol

All control traffic travels over a single TCP connection as length-prefixed JSON messages. Every frame begins with a
32-bit unsigned payload length in network byte order, followed by UTF-8 encoded JSON. Responses always include the
request id (when supplied), a status discriminator (`OK`, `ERROR`, `CONTINUE`), an error code, a human readable
message, and an optional payload object.

## Core Commands

### `AUTHENTICATE`

```json
{ "cmd": "AUTHENTICATE", "id": "req-1", "payload": { "public": false, "username": "alice", "password": "...", "register": false } }
```

Successful responses carry the resolved identity and indicate whether a new account was created.

### `UPLOAD_*`

1. `UPLOAD_INIT` negotiates a resumable upload. The client sends file size, desired chunk size, and the root hash.
   The server replies with a `TransferDescriptor` (unique id, chunk size, hash) and the number of bytes already stored.
2. `UPLOAD_CHUNK` streams base64 encoded chunks together with the byte offset and per-chunk hash.
3. `UPLOAD_COMMIT` finalises the transfer, triggering hash verification and atomically moving the staged file into place.

### `DOWNLOAD_*`

1. `DOWNLOAD_INIT` returns a `TransferDescriptor` and file metadata. The descriptor id is ephemeral and scoped to the
   download session.
2. `DOWNLOAD_CHUNK` requests the next block (`offset`, `max_bytes`). Responses contain base64 data, chunk hash, and a
   `done` flag.

### `SYNC_ENUMERATE`

Enumerates the subtree rooted at the supplied path. The payload contains an `entries` array with relative paths,
directory flags, file sizes, modification timestamps, and optional content hashes.

### `SYNC_APPLY`

Accepts a `SyncPlan` made up of diff entries. Currently only `DELETE_REMOTE` actions are applied server-side; uploads
are driven by the client via the standard `UPLOAD_*` pipeline. The server guarantees deletions remain scoped to the
authenticated user root.

## Error Handling

Errors are returned with `status: "ERROR"` and a structured `error` code. Notable codes:

| Code | Meaning |
| --- | --- |
| `invalid_command` | Command not recognised |
| `invalid_payload` | Malformed or semantically invalid payload |
| `authentication_failed` | Username/password rejected |
| `busy` | Session already active for the requested identity |
| `resume_state_invalid` | Resumable transfer metadata no longer valid |
| `permission_denied` | Operation would escape the user root |

## Transfer Framing

- Upload/download bodies are base64 encoded to keep control and data on the same stream.
- Every chunk response echoes the transfer id, byte offset, byte count, hash (BLAKE2b), and a `done` boolean.
- Clients rate-limit transfers locally and keep a JSON state file (`~/.minidrive/transfers.json`) to resume interrupted
  work after reconnecting.
