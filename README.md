# Innogen Pharma Universal SSO Provider (FastAPI)

Centralized SSO/IdP service for Innogen Pharma apps, built with FastAPI + Postgres. Supports email-first routing, Google OAuth for `@innogen-pharma.com`, and cPanel mailbox + app-password for `@innogen-pharma.ph`. Issues an SSO device cookie and exposes a session verification endpoint for other apps.

## Features

- Email-first flow (`/api/v1/auth/method`)
  - `@innogen-pharma.com` → Google OAuth
  - `@innogen-pharma.ph` → cPanel mailbox check + local app password (stored in Postgres)
  - Apple OAuth endpoints exist (requires Apple config)
- Shared SSO session cookie
  - Cookie: `device_token` (HTTP-only)
  - Stored as hash in DB with user-agent + IP binding and expiry
- `GET /api/v1/verify-session` for apps to check authentication state
- CORS configured for `*.innogen-pharma.com`, `*.innogen-pharma.ph`, and `*.innogen.local` (regex-based)

## Repository Layout

- `main.py` — FastAPI app, OAuth flows, auth endpoints, cookie session issuance, CORS
- `models.py` — SQLAlchemy async models and DB init
- `cpanel_service.py` — cPanel UAPI mailbox checks
- `docker-compose.yml` — Postgres + API stack
- `static/` — static assets (e.g. `favicon.png`)
- `static_site/` — optional demo/template assets (if present)

## Quick Start (Docker)

From the project directory:

```bash
docker compose up -d --build
```

Health check:

```bash
curl http://127.0.0.1:8520/health
```

## Environment Variables

Set these via `.env` (recommended) and/or `docker-compose.yml`.

### Required

- `JWT_SECRET`  
  Used to sign OAuth state.

- `DATABASE_URL` (already set in `docker-compose.yml`)  
  Example:
  `postgresql+asyncpg://postgres:postgres@db:5432/innogen_sso`

### Google OAuth (required for `@innogen-pharma.com`)

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI`  
  Recommended:
  `https://sso.innogen-pharma.com/api/v1/oauth/google/callback`

Google Cloud Console settings:
- Authorized redirect URI must match `GOOGLE_REDIRECT_URI` exactly.

### Apple OAuth (optional)

- `APPLE_CLIENT_ID`
- `APPLE_TEAM_ID`
- `APPLE_KEY_ID`
- `APPLE_PRIVATE_KEY` (PEM, can be stored with `\n` escaped newlines)
- `APPLE_REDIRECT_URI`

### cPanel UAPI (required for mailbox checks on `@innogen-pharma.ph`)

- `CPANEL_HOST` (e.g. `cpanel.innogen-pharma.ph`)
- `CPANEL_PORT` (default `2083`)
- `CPANEL_USERNAME`
- `CPANEL_PASSWORD` or `CPANEL_API_TOKEN`
- `CPANEL_VERIFY_TLS` (default `true`)
- `CPANEL_ACCESS_MODE` (default `auto`)

### Cookie Settings

- `SSO_COOKIE_NAME` (default `device_token`)
- `SSO_COOKIE_SECURE` (default `true`)
- `SSO_COOKIE_SAMESITE` (default `none`)
- `SSO_COOKIE_MAX_AGE_SECONDS` (default `2592000`)

## API Endpoints

### Core

- `GET /health`
- `GET /api/v1/auth/method?email=...`
- `GET /api/v1/verify-session`

### cPanel + App Password (`@innogen-pharma.ph`)

- `GET /api/v1/cpanel/mailbox-exists?email=...`
- `GET /api/v1/auth/password/status?email=...`
- `POST /api/v1/auth/password/create`
- `POST /api/v1/auth/password/login`

### Google OAuth (`@innogen-pharma.com`)

- `GET /api/v1/oauth/google/start?email=...&return_to=...`
- `GET /api/v1/oauth/google/callback?code=...&state=...`

### Apple OAuth

- `GET /api/v1/oauth/apple/start?email=...&return_to=...`
- `GET|POST /api/v1/oauth/apple/callback`

## How Other Apps Integrate

### 1) Add a “Continue with InnoGen” button

Your app redirects the user to the SSO service. Include a `return_to` URL where SSO should send the user after successful login.

```html
<button id="continueWithInnogen" type="button">
  <img src="https://sso.innogen-pharma.com/static/favicon.png" alt="InnoGen" />
  Continue with InnoGen
</button>

<script>
  const SSO_BASE = "https://sso.innogen-pharma.com";
  const returnTo = window.location.origin + "/sso-callback.html";
  document.getElementById("continueWithInnogen").addEventListener("click", () => {
    window.location.href = `${SSO_BASE}/api/v1/oauth/google/start?email=${encodeURIComponent("user@innogen-pharma.com")}&return_to=${encodeURIComponent(returnTo)}`;
  });
</script>
```

Recommended UX: collect email first, call `/api/v1/auth/method`, then send user to the correct provider (Google vs password vs Apple).

### 2) On your callback page, verify session

```html
<script>
  const SSO_BASE = "https://sso.innogen-pharma.com";

  fetch(`${SSO_BASE}/api/v1/verify-session`, {
    method: "GET",
    credentials: "include"
  })
    .then(r => r.json())
    .then(data => {
      if (!data.authenticated) {
        window.location.href = "/login.html";
        return;
      }
      console.log("SSO user:", data.user);
    });
</script>
```

## Reverse Proxy (Nginx)

If you publish the API container to the host at port `8520`, proxy to loopback:

```nginx
location / {
  proxy_pass http://127.0.0.1:8520;
  proxy_http_version 1.1;

  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Troubleshooting

### Nginx shows 502 Bad Gateway

- Confirm API is reachable on host:
  ```bash
  curl -i http://127.0.0.1:8520/health
  ```
- If you used `proxy_pass http://host.docker.internal:8520;` on Linux, switch to `127.0.0.1`.

### API crashes on startup: `InvalidPasswordError` (Postgres)

This means `DATABASE_URL` password does not match the existing DB’s password.

Fix options:
- Keep data: change DB user password to match `DATABASE_URL`
- Reset DB: `docker compose down -v` (destroys volume/data)

### Google callback fails (400 from token endpoint)

Most common causes:
- `redirect_uri_mismatch`: `GOOGLE_REDIRECT_URI` does not exactly match the URI registered in Google Cloud Console
- expired/reused auth code (`invalid_grant`)
- incorrect client secret (`invalid_client`)

### “Failed to fetch” in browser

Usually indicates network-layer failure:
- reverse proxy returning 502
- TLS/DNS issues
- CORS blocking (check DevTools console and verify `Access-Control-Allow-Origin` headers)

## Security Notes

- Never commit secrets (`JWT_SECRET`, OAuth secrets, cPanel credentials) to GitHub.
- If secrets were ever pasted/shared, rotate them immediately.
- For production, remove `--reload` from Uvicorn in `Dockerfile` and run with a process manager strategy suitable for your environment.

## License

### Copyright (c) 2026 Benedic Cater / InnoGen Pharmaceuticals Inc.

### All Rights Reserved.

This repository and its contents, including all code, assets, and data, are the sole property of the author. This code is made public for portfolio review and demonstration purposes only.

### Restrictions:
- You may not copy, modify, or distribute this code.
- You may not use the "InnoGen" name, branding, or logos for any purpose.
- Use of the data contained within this repository for commercial or personal projects is strictly prohibited.

For inquiries or permission requests, please contact the author.
