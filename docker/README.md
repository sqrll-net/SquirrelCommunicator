# Docker and `.env` File Configuration

This document explains how to properly configure the environment variables required to run the connected services:
1. **C++ Backend** (REST CROWCPP & UWebSockets)
2. **Go Voice Service** (SquirrelCommunicatorVoice)

## Dockerfiles

| File | Purpose | Build time |
|---|---|---|
| `Dockerfile.release` | Downloads pre-built binary from GitHub Releases (recommended) | ~10 seconds |
| `Dockerfile` | Compiles from source inside container (for development/debugging) | ~10 minutes |

`docker-compose.yml` uses `Dockerfile.release` by default.

## Configuration INI (repo vs. baked-in)

The backend reads its runtime settings from `Assets/Config/BackendSettings.ini`.

The pre-built release tarball ships with a **snapshot** of that file baked in at
release-build time. To avoid running with stale settings, **both** Dockerfiles
replace that snapshot with the **latest config from the repository** at image
build time — regardless of whether the image uses the pre-built GitHub binary
or is compiled locally:

1. `Dockerfile.release` shallow-clones the repository (no submodules) and copies
   `ProjectServer/Assets/Config/BackendSettings.ini` over the baked-in copy.
2. `Dockerfile` already clones the repository to compile from it; it additionally
   copies `ProjectServer/Assets/Config/BackendSettings.ini` from that checkout
   over the build output, so the source is always the repo file, not any
   snapshot embedded elsewhere.

In both cases the copy runs **once per image build** and is cached in the image
layer — there is **no network access at container runtime** and no dependency on
GitHub when the container starts. If the copy fails for any reason, the image
build still succeeds and keeps the previously available config, so the image can
always start.

### Refreshing the config

Config is fetched at **build time**, so to pick up the latest repo config you
rebuild the image. Because Docker caches the fetch layer, force a refresh with:

```bash
docker compose build --no-cache backend
docker compose up -d backend
```

or bump the cache-bust argument (`Dockerfile.release`):

```bash
docker compose build --build-arg CONFIG_CACHE_BUST="$(date +%s)" backend
docker compose up -d backend
```

For the source-build `Dockerfile`, use `CACHE_BUST` instead:

```bash
docker compose build --build-arg CACHE_BUST="$(date +%s)" backend
docker compose up -d backend
```

## Configuration Files

### `.env.backend` (backend container env)

- Database is separate for data safety. It could be added to services but its management would be complicated
- Brevo key can be generated at 'https://app.brevo.com/settings/keys/api'

```
# Version of the backend release to deploy
BACKEND_VERSION=1.0.9

# Database connections env vars
SQRLL_COMM_DB_HOST=127.0.0.1
SQRLL_COMM_DB_PORT=3306
SQRLL_COMM_DB_DBNAME=sqrllapitest
SQRLL_COMM_DB_USER=commapisqrllusertest
SQRLL_COMM_DB_PASSWORD=

# Brevo API key
SQRLL_COMM_MAIL_API_KEY=
```

### `.env.sentry` (Sentry crash reporting)

All Sentry configuration lives in this single gitignored file. It is split into
**runtime** values (read by the backend container at startup) and **upload**
values (read by `sentry-cli` when uploading debug symbols).

The backend loads this file via `env_file` in `docker-compose.yml` (with
`required: false`), so Sentry stays **optional** — if the file is missing the
backend simply logs a warning and continues.

```
# --- Runtime (backend container) ---
# Public ingest endpoint for this project. It is safe to keep here (it is also
# embedded in the shipped client binaries), but it is NOT the auth token.
SENTRY_DSN=

# Which Sentry environment this deployment belongs to
# (production / staging / development). Defaults to "production" if unset.
SENTRY_ENVIRONMENT=production

# Optional: override the crashpad database directory (minidumps, pending reports).
# Defaults to ".sentry-native" in the working directory (/app inside the image).
# SENTRY_DB_PATH=/app/.sentry-native

# --- Upload (sentry-cli debug symbol upload) ---
# Auth token from Sentry (Organization -> Settings -> Auth Tokens). PRIVATE.
SENTRY_AUTH_TOKEN=

# Your Sentry organization slug.
SENTRY_ORG=

# Your Sentry project slug.
SENTRY_PROJECT=
```

> [!NOTE]
> Because the whole file is loaded into the backend container via `env_file`,
> the upload values (`SENTRY_AUTH_TOKEN` / `SENTRY_ORG` / `SENTRY_PROJECT`) are
> also present in the container's environment — the backend simply ignores them.
> If you'd rather keep the token off the host entirely, leave the upload block
> empty here and upload symbols from CI only (GitHub Secrets).

### `.env.voice` (voice service container env)

- SQRLL_VOICE_API_KEY - It is backend password to do not allow random calls to create random rooms.

```
# Address for voice service
SQRLL_VOICE_ADDRESS=127.0.0.1

# The port the Go service runs on for Voice and Backend app server
SQRLL_VOICE_PORT=8082

# The main password for communicating with the backend (Change this!)
SQRLL_VOICE_API_KEY=

# Domain for frontend
SQRLL_VOICE_ALLOWED_DOMAINS=sqrll.net
```

### `.env.image` (image service container env)

```
# Address for image service
SQRLL_IMAGE_SERVICE_URL=127.0.0.1

# The port the Go service runs on
SQRLL_IMAGE_PORT=8083

# The main password for communicating with the backend (Change this!)
SQRLL_IMAGE_API_KEY=

# API key for gifs, get one on https://partner.klipy.com/api-keys
SQRLL_KLIPY_API_KEY=

# Image service settings itself
MAX_DISK_GB=100
MAX_RAM_MB=1024
MAX_UPLOAD_MB=8
```

> [!WARNING]
> The backend and the image service must be configured with the **same**
> `SQRLL_IMAGE_API_KEY`. If they differ, the backend cannot issue per-session
> API keys (the image service answers `403`), the client receives no key, and
> every GIF / upload request fails with `401 Unauthorized`. After changing the
> key, recreate **both** containers so they read the new value:
>
> ```bash
> docker compose up -d --force-recreate backend image_service
> ```

### `.env.encryptionpass` (Encryption password file)

```
# Message encryption key (used instead of MessageEncryptionKeyFile from ini config).
SQRLL_MESSAGE_ENCRYPTION_KEY=
```

### Apache config for redirecting page
##### Apache config is recommended for safe ussage with follwoing config
##### Content for like 

```
        # Go image service (HTTP) — media upload/download + GIFs (port 8083)
        ProxyPass        /api/image  http://localhost:8083/api/image
        ProxyPassReverse /api/image  http://localhost:8083/api/image

        ProxyPass        /api/gifs   http://localhost:8083/api/gifs
        ProxyPassReverse /api/gifs   http://localhost:8083/api/gifs

        # C++ backend REST (/api/v1/*)
        ProxyPass        /api  http://localhost:8080/api
        ProxyPassReverse /api  http://localhost:8080/api
        
        RewriteEngine On

        # GO voice service (HTTP + WebSocket) — rooms, gifs, files, voice, screenshare
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule ^/voice-ws/(.*) ws://localhost:8082/$1 [P,L]
        ProxyPass        /voice-ws  http://localhost:8082
        ProxyPassReverse /voice-ws  http://localhost:8082

        # WebSocket of C++ server
        RewriteCond %{HTTP:Upgrade} =websocket [NC]
        RewriteRule /ws/(.*) ws://localhost:8081/$1 [P,L]
        ProxyPass        /ws  http://localhost:8081
        ProxyPassReverse /ws  http://localhost:8081
```

## Sentry Crash Reporting

The backend ships with `sentry-native` (Crashpad backend) compiled in. When a
`SENTRY_DSN` is present, unhandled crashes (`SIGSEGV`, `std::terminate`, `std::bad_alloc`, …)
are captured as minidumps and uploaded to Sentry automatically.

### Two different values — do not confuse them

| Variable | Secret? | Purpose |
|---|---|---|
| `SENTRY_DSN` | Public-ish | Ingest endpoint that tells the running server *where* to send crash events. Set in `.env.sentry`. |
| `SENTRY_AUTH_TOKEN` | **PRIVATE** | Used by `sentry-cli` to *upload debug symbols*. Set in `.env.sentry` (gitignored) or GitHub Secrets for CI. |

### Runtime variables (container)

Set these in `.env.sentry`:

- `SENTRY_DSN` — required to enable crash reporting. If empty, the server runs normally but does not report crashes.
- `SENTRY_ENVIRONMENT` — optional label (`production`, `staging`, `development`). Defaults to `production`.
- `SENTRY_DB_PATH` — optional crashpad database directory. Defaults to `.sentry-native` in the working directory.

### Upload variables (debug symbols)

Used by `sentry-cli` to upload debug symbols so crashes are symbolicated (stack
traces show source lines instead of raw addresses):

- `SENTRY_AUTH_TOKEN` — an auth token from Sentry (Organization → Settings → Auth Tokens).
- `SENTRY_ORG` — your Sentry organization slug.
- `SENTRY_PROJECT` — your Sentry project slug.

These are **private**. They are stored in two places depending on how you build:

- **GitHub Actions (CI):** stored in GitHub Secrets and read by
  `.github/workflows/release.yml`.
- **Local / self-hosted builds:** stored in `docker/.env.sentry` (gitignored) and
  read by [`docker/UploadSentrySymbols.sh`](UploadSentrySymbols.sh).

If any of these are missing, the upload is skipped — the workflow / script still
completes successfully.

### Verifying crash reporting works

All `sentry-native` diagnostics are routed into the application log (both the
console and `communicator.log`) prefixed with `Sentry:`. After starting the
container, look for:

- `Sentry initialized (release: …, environment: …, database: …, dsn: set)` — Sentry
  is on and a DSN was found. If instead you see `SENTRY_DSN is not set`, crash
  reporting is disabled and you must set `SENTRY_DSN` in `.env.sentry`.
- `Sentry: …` `WARN`/`ERROR` lines — these reveal why events are not arriving
  (e.g. `crashpad_handler` not found, an invalid DSN, or network/transport
  failures). The handler must be executable and located next to `communicatorsrv`.
- `Sentry: removed N stale crashpad lock file(s).` — the startup cleanup removed
  lock files left behind by a previous handler that was killed mid-upload. This
  is expected after a crash-induced container restart and is what allows the
  pending minidump from that crash to be uploaded.

### Why crash reports can go missing in Docker

Two things happen when the server crashes inside a container and none of them
produce a visible error by default:

1. **The handler is killed mid-upload.** The server runs as PID 1. When it
   crashes, the container is stopped and the `crashpad_handler` child process is
   `SIGKILL`ed before it can finish uploading the minidump.
2. **Stale lock files block the next upload.** crashpad guards each pending report
   with a `<uuid>.lock` file created with `O_CREAT|O_EXCL`. The killed handler
   leaves those files behind, so on the next start the new handler hits
   `open …/pending/<uuid>.lock: File exists (17)` and silently skips the report.

The backend now mitigates both:

- It waits for the upload to finish before the process exits
  (`sentry_options_set_crashpad_wait_for_upload`), keeping the container alive
  until the handler completes.
- It removes stale `.lock` files at startup, so any minidump still pending from a
  previous crash is uploaded on the next start.

The crashpad database is also kept on a named Docker volume
(`sqrll_sentry:/app/.sentry-native`) so minidumps survive `docker compose down`
and `up`, not just in-place restarts.

### Disabling Sentry at build time

Local builds that do not need crash reporting (or lack `libcurl`/`zlib` dev headers)
can disable it at CMake configure time:

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSQRLL_ENABLE_SENTRY=OFF
```
