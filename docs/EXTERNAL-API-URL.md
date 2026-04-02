# External users / “localhost” API errors

## 1. Node listens on all interfaces

`server.js` uses `HOST` (default `0.0.0.0`) so port `PORT` accepts connections from other machines, not only `127.0.0.1`.

In `.env`:

```env
HOST=0.0.0.0
PORT=3000
```

If you use **Nginx → `proxy_pass http://127.0.0.1:3000`**, browsers still talk to **443/80 on your domain**; you only need to open **3000** on the firewall if you hit Node directly.

## 2. Browser on your real domain

If pages are served as `https://your-domain.com/...`, relative requests like `fetch('/api/...')` already go to **that domain**. No `localhost` is involved.

## 3. WebView / hybrid app (page origin is `localhost` or `file://`)

Then relative `/api/...` points at the **phone or dev machine**, not your server.

**Option A — set before other scripts:**

```html
<script>window.__API_BASE__ = 'https://your-domain.com';</script>
```

**Option B — meta tag in `<head>`:**

```html
<meta name="api-base" content="https://your-domain.com">
```

`admin.html`, `owner.html`, and `user.html` read these and prefix API calls.

**Option C — server env (good behind Nginx + correct `Host` / `X-Forwarded-*`):**

```env
PUBLIC_API_URL=https://your-domain.com
```

`GET /api/public-config` returns `{ "apiBase": "...", "publicUrl": "..." }` for native apps to read once.

## 4. CORS

Default CORS allows all origins unless `CORS_ORIGINS` is set to a comma-separated list. For a locked-down setup:

```env
CORS_ORIGINS=https://your-domain.com,https://www.your-domain.com
```

Use `CORS_ORIGINS=*` only if you need any origin (less secure).
