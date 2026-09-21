# Google Authentication Setup

This document covers how to configure Google OAuth login, both for the **backend**
and for the **frontend** client. It is split into two parts:

1. [Backend setup](#backend-setup) — the `SQRLL_GOOGLE_CLIENT_ID` environment variable.
2. [Frontend requirements](#frontend-requirements) — what the client must do to keep Google login working.

---

## Backend setup

### Overview

The backend verifies Google ID tokens server-side via
`https://oauth2.googleapis.com/tokeninfo` and then creates (or logs in) the user
account. See the official Google docs for the flow:

* Frontend: <https://developers.google.com/identity/gsi/web/guides/overview>
* Backend: <https://developers.google.com/identity/gsi/web/guides/verify-google-id-token>

### Prerequisites

1. Create a project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the Google Identity (OAuth) APIs.
3. Create an **OAuth 2.0 Client ID** for a Web application (the "Clients" section
   of the Credentials page).
4. Note the **Client ID** value (it looks like
   `1234567890-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com`).

### Required environment variable

Set the client ID in the backend environment:

```bash
export SQRLL_GOOGLE_CLIENT_ID="<your-client-id>.apps.googleusercontent.com"
```

> [!IMPORTANT]
> This variable is **required** and is used to validate the ID token's `aud`
> (audience) claim. Google login **fails closed** (returns `401`) when the
> variable is missing or does not match the token's audience. This prevents a
> valid Google token issued for *any other* Google project from being accepted.

---

## Frontend requirements

> [!WARNING]
> **Read this section before deploying the backend change.** If the frontend and
> backend are not configured with the *same* Google OAuth Client ID, every Google
> login will fail with `401 Unauthorized`.

### 1. What is the "audience" (`aud`)?

When Google issues an ID token (a signed JWT), that token contains a set of
standard claims. One of them is **`aud`** — the *audience* — which is the
**OAuth Client ID** of the application the token was issued **to**.

In practice:

* The frontend calls Google with a `client_id`.
* Google mints an ID token whose `aud` is set to that exact `client_id`.
* The backend now checks that this `aud` equals the backend's own configured
  `SQRLL_GOOGLE_CLIENT_ID`.

If the two client IDs differ, the token was issued for a *different* application
and is rejected.

### 2. Why does the backend validate it?

Without this check, the backend would accept **any** valid Google ID token — even
one minted for an attacker's own Google Cloud project. That would let anyone sign
in as any Google account they control, because the token looks legitimate even
though it was not requested for *your* application.

Validating `aud` pins Google login to **your** application's Client ID, so only
tokens actually issued for your app are accepted.

> **Note:** this is a server-side security fix. It does **not** change the user
> experience; it only requires that the frontend and backend share the same
> Client ID.

### 3. What the frontend MUST do

There are exactly three requirements:

1. **Use the same Client ID.**
   The `client_id` used when initializing Google sign-in **must be byte-for-byte
   identical** to the backend's `SQRLL_GOOGLE_CLIENT_ID`. Do not use a separate
   client ID for web vs. mobile, dev vs. prod, or a stale/hardcoded value.

2. **Send the ID token — not the access token.**
   The request body field is `google_token`, and it must contain the **ID token**
   (JWT), which is the value that carries the `aud` claim.
   * Google Identity Services (GIS): this is `response.credential`.
   * Legacy `gapi.auth2`: this is `authResponse.id_token`.
     Sending an *access token* will be rejected (its `aud` is a scope/resource,
     not the Client ID).

3. **Handle the new `401` response.**
   The endpoint `POST /api/v1/integrate/google` returns:
   * `401 Unauthorized` with message `"Google integration - invalid token audience."`
     when the `aud` check fails (client ID mismatch or backend env var unset).
   * `400 Bad Request` with message `"Google integration - E-Mail not verified."`
     when the Google account's email is not verified.
     Treat a `401` as a **configuration error** (client/backend ID mismatch), not a
     user error.

### 4. Example (Google Identity Services)

```html
<!-- Load the GIS client library -->
<script src="https://accounts.google.com/gsi/client" async defer></script>
<script>
  // MUST match the backend's SQRLL_GOOGLE_CLIENT_ID exactly.
  const GOOGLE_CLIENT_ID = "1234567890-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com";

  function handleCredentialResponse(response) {
    // response.credential is the ID token (JWT) — this carries the 'aud' claim.
    fetch("/api/v1/integrate/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ google_token: response.credential }),
    })
      .then(async (res) => {
        if (res.status === 401) {
          // Configuration error: the frontend client ID does not match
          // the backend's SQRLL_GOOGLE_CLIENT_ID (or it is unset).
          console.error("Google sign-in failed: token audience mismatch.");
          return;
        }
        const data = await res.json();
        // ... continue login flow
      })
      .catch((err) => console.error("Google sign-in request failed", err));
  }

  window.onload = function () {
    google.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: handleCredentialResponse,
    });

    // Either render a button or trigger One Tap:
    google.accounts.id.renderButton(
      document.getElementById("googleSignInButton"),
      { theme: "outline", size: "large" }
    );
    // google.accounts.id.prompt();
  };
</script>
```

### 5. Troubleshooting — common `401` causes

| Symptom | Likely cause | Fix |
|---|---|---|
| `401` on every Google login | Backend `SQRLL_GOOGLE_CLIENT_ID` is unset | Set the env var and restart the backend. |
| `401` after a frontend change | Frontend `client_id` differs from the backend env var | Make both values identical (trim whitespace/newlines). |
| `401` intermittently | Multiple environments (dev/staging/prod) with different client IDs | Use one Client ID per backend environment, or align them. |
| `400` "E-Mail not verified" | The Google account has no verified email | User must verify their Google email, or use an account with a verified email. |
| Backend logs `token audience validation failed (expected '…', got '…')` | Client ID mismatch confirmed | Compare the logged `expected` vs `got` values and align config. |

### 6. Coordination checklist (frontend + backend + ops)

- [ ] Backend has `SQRLL_GOOGLE_CLIENT_ID` set to the exact OAuth Client ID.
- [ ] Frontend uses the **same** Client ID string in `google.accounts.id.initialize`.
- [ ] Frontend sends `response.credential` (the ID token) as `google_token`.
- [ ] Frontend handles the `401` response gracefully and surfaces it as a config error.
- [ ] The Client ID is **not** hardcoded in both places independently — ideally it is
  injected via the frontend build/env so it cannot drift from the backend.