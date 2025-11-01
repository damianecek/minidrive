## Phase 0 — Environment & Build

- [x] Validate build toolchain: confirm CMake ≥ 3.22, compliant C++20 compiler, libsodium, Asio, nlohmann/json, spdlog availability.
  - [x] Run `cmake -S . -B build` and verify `client` and `server` link against fetched dependencies.
  - [x] Document environment bootstrap steps in `README.md`.

## Phase 1 — Shared Protocol & Utilities

- [x] Finalize JSON schema, command set, and 32-bit length framing in `shared/`.
  - [x] Author `ErrorCodes.hpp` mapping authentication, traversal, conflict, and sync errors to structured responses.
  - [x] Implement serialization helpers for request/response payloads including file metadata and sync diffs.
  - [x] Integrate libsodium helpers for password hashing (salted) and chunk/file hashing; add focused utility tests.

## Phase 2 — Server Core

- [x] Implement Asio-based server accept loop with thread pool and graceful SIGTERM shutdown.
  - [x] Build session manager enforcing single session per identity (public/private) with informative rejection messaging.
  - [x] Create authenticated user store under `--root`, persisting salted hashes and provisioning directories.
  - [x] Implement command handlers for LIST, STAT, MKDIR, RMDIR, MOVE, COPY, DELETE, UPLOAD_INIT/CHUNK/COMMIT, and download preparation.
  - [x] Harden filesystem executor against traversal, sanitize absolute paths, ensure atomic writes.
  - [x] Persist resumable upload metadata, implement timeout-based cleanup for abandoned partial files.

## Phase 3 — Client Shell & Operations

- [x] Develop CLI parsing for `[username@]<host>:<port>` and `--log`, prompt for credentials, warn when in public mode.
  - [x] Implement interactive shell with HELP/EXIT local commands, history, and SIGINT cleanup.
  - [x] Implement remote command wrappers mirroring server API with status handling, retries, and user feedback.
  - [x] Build local file manager for path resolution, staging uploads, and pre-transfer hash validation.

## Phase 4 — Transfer Engine & Resumability

- [x] Define shared chunked transfer framing with size, offset, hash metadata.
  - [x] Implement resumable upload flow: `.part` handling, resume negotiation, timeout invalidation, integrity verification.
  - [x] Implement resumable download flow with local state persistence and resume prompt on startup.
  - [x] Add progress reporting and optional bandwidth throttling hooks.

## Phase 5 — Synchronization & Advanced Commands

- [x] Implement client sync engine: local tree scan, hash diffing, plan generation for create/update/delete per requirements.
  - [x] Extend server to process batch sync commands, deletions, and conflict resolution policy.
  - [x] Support directory-aware commands (recursive LIST, nested MKDIR/RMDIR safeguards).
  - [x] Add optional multi-session support once single-session flow is stable.

## Phase 6 — Observability, Testing & Release

- [x] Integrate structured logging (spdlog) across client/server for connections, commands, and errors.
  - [x] Extend automated tests to cover auth/register, resumable transfers, and sync setup (`tests/unit/server_components.cpp`).
  - [x] Add stress-style resume validations for TransferRegistry edge cases.
  - [x] Refresh README with logging/sync usage notes and runtime guidance.
  - [x] Provide sample configs/run scripts (see `data/` and README run instructions).
