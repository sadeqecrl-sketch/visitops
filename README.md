# VisitOps — Netlify setup guide (no Supabase)

> **Easiest start:** upload the `public/` folder to any static host (Netlify Drop) and open it: *easy mode*, no settings (see `DEPLOY.md`, `docs/EASY-MODE.md`). The rest of this README describes the optional *server mode* (Netlify functions).
>
> **For the IT department:** start with `docs/README.md` (architecture, code map, API, data model, security, operations, testing). Administrators also see it in the app under **Governance → IT Documentation**.
>
> **Quick start:** see `DEPLOY.md` (10 minutes, Dropbox optional). Settings template: `.env.example`. After deploying run `npm run check https://YOUR-SITE.netlify.app`.

Everything runs on Netlify:
- **Sign-in:** a Netlify Function checks passwords (stored only as salted scrypt hashes) and issues a signed, HttpOnly, Secure, SameSite=Lax session cookie.
- **Data:** stored in **Netlify Blobs** (Netlify's built-in storage; nothing extra to create). Saves use compare-and-set, so two people saving at once never overwrite each other.
- **Backups:** a nightly Netlify scheduled function copies all data to **Dropbox** (kept 30 days).
- **Permissions:** enforced on the server for every request (admin / MIS / leader / member / monitor).

## Files
| Path | Purpose |
|---|---|
| `public/index.html` | The application (only `public/` is published as web pages) |
| `netlify/functions/api.mjs` | Server API: login, users, visits, review, restore, backup |
| `netlify/functions/dropbox-backup.mjs` | Nightly backup, 20:00 UTC (02:00 Bangladesh) |
| `netlify/lib/*.mjs` | Storage, password/session security, Dropbox backup, webhooks |
| `package.json` | One dependency: `@netlify/blobs` (pinned) |
| `netlify.toml` | Deploy settings + security headers (CSP, HSTS, no framing) |

## One-time setup (about 20 minutes)

### 1. Dropbox app (for backups)
1. dropbox.com/developers/apps → **Create app** → *Scoped access* → **App folder** → name it (e.g. `VisitOpsBackup`).
2. **Permissions** tab: tick `files.content.write`, `files.content.read`, `files.metadata.read` → **Submit**.
3. **Settings** tab: copy **App key** and **App secret**.
4. Open in a browser (replace `APP_KEY`), approve, copy the code shown:
   `https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&response_type=code&token_access_type=offline`
5. In a terminal, once (replace the three values):
   ```
   curl https://api.dropbox.com/oauth2/token -d code=THE_CODE -d grant_type=authorization_code -u APP_KEY:APP_SECRET
   ```
   Copy `refresh_token` from the answer. Treat it like a password.

### 2. Put the project on Netlify
Functions and the nightly job need a Git (or Netlify CLI) deploy. Loose drag-and-drop of files will not run them.
1. Create a **private** GitHub repository and upload everything in this folder.
2. Netlify → **Add new site → Import an existing project** → pick the repo. Build command: empty. Publish directory: `public` (already in `netlify.toml`).

### 3. Environment variables
Netlify → **Site configuration → Environment variables** (mark all as *Secret*):
| Variable | Value |
|---|---|
| `SESSION_SECRET` | A long random string, at least 32 characters (e.g. run `openssl rand -base64 48`). Changing it later signs everyone out. |
| `SETUP_CODE` | A secret code (6+ characters) that lets you create the first administrator in the browser (see step 4). Remove it after setup. |
| `ADMIN_EMAIL` | Optional alternative to the setup screen: your email, created as the first administrator |
| `ADMIN_INITIAL_PASSWORD` | Optional, with `ADMIN_EMAIL`: the first administrator's password. Used once. |
| `DROPBOX_APP_KEY` | from step 1 |
| `DROPBOX_APP_SECRET` | from step 1 |
| `DROPBOX_REFRESH_TOKEN` | from step 1 |
| `ALLOWED_EMAIL_DOMAINS` | optional. Only these email domains can sign in, e.g. `company.com, partner.org`. Empty = any domain. `ADMIN_EMAIL` is always exempt. |
| `ALLOWED_IPS` | optional. Only these networks can use the app, e.g. `203.0.113.7, 198.51.100.0/24` (IPv4 CIDR or exact IPv4/IPv6). Empty = anywhere. |
| `MIN_PASSWORD_LENGTH` | optional, default `6` (allowed 4–64) |
| `FORCE_PASSWORD_CHANGE` | optional, set `true` to make new/reset accounts choose their own password at first sign-in. Default: off. |
| `DROPBOX_FOLDER` | optional, default `/backups` (inside the Dropbox app folder) |
| `BACKUP_RETENTION_DAYS` | optional, default `30` |

Then **Deploys → Trigger deploy** so the variables take effect.

### 4. First sign-in (create your administrator)
**Easiest:** set `SETUP_CODE`, redeploy, open the site. While no account exists you will see **Create administrator account**: enter the setup code, your email, name and your own password. The screen disappears once the first administrator exists; then delete `SETUP_CODE`. Wrong codes are limited to 5 tries, then a 15-minute pause.

**Alternative (old way):**
1. Open your site, sign in with `ADMIN_EMAIL` and `ADMIN_INITIAL_PASSWORD`.
2. Optionally change your password with **Change password** (top right). It is only forced if `FORCE_PASSWORD_CHANGE=true`.
3. **Delete `ADMIN_INITIAL_PASSWORD` from Netlify** (it is no longer needed) and redeploy.
4. Create a **second administrator** (Admin Control → Users & roles) so one lost account never locks you out.

### 5. Set up the organisation (as administrator)
1. **Departments** → add departments.
2. **Teams & Members** → create each team (this also creates its leader entry), then add members.
3. **Admin Control → Users & roles → Create user**: email, display name, role, linked member entry.
   - Team Leader → the leader entry of their team; Team Member → their own member entry.
   - Administrator / MIS Officer / Cross-team Monitor → no link needed.
4. Type a password for them, or leave it empty and the system shows a **one-time 8-character password**. Give it to them privately (not by group chat). They can change it any time.
5. Test backup: **Admin Control → Dropbox → Back up to Dropbox now**, then confirm a file appears in Dropbox → Apps → your app → backups. Check **Netlify → Logs → Functions** the next morning to confirm the nightly run.

## Team testing
See `DEPLOY.md` → "Testing with your team": test guide on the dashboard, **Load sample data**, and the **Test as** role menu (test mode only).

## Test mode (no sign-in)
Set `OPEN_ACCESS=true` and redeploy to skip sign-in: every visitor is a full administrator and a red banner is shown. **Never leave it on with real client data.** `ALLOWED_IPS` still applies. Remove the variable and redeploy to switch it off.

## Easy sign-in
- Sign in with the **email or a short username** (defaults to the part before the `@`; set another when creating the user).
- **Keep me signed in for 30 days** tick box (off by default; use only on private devices). Otherwise sessions last 8 hours and the app signs out after 30 minutes idle.
- Passwords need only 6 characters (change with `MIN_PASSWORD_LENGTH`); obvious ones such as `password1` or `qwerty` are still refused.
- Accounts still lock for 15 minutes after 5 wrong passwords.

## Restricting who can sign in (server-side)
Set `ALLOWED_EMAIL_DOMAINS` and/or `ALLOWED_IPS` (table above), then redeploy.
- **Domain rule:** applied when signing in, on every later request, and when an administrator creates a user. An existing user outside the list is locked out immediately and sees the normal "Incorrect username or password" message. The login page shows the allowed domains.
- **IP rule:** applied to every request (even before sign-in). Others see "Sign-in is not allowed from this network." The address comes from Netlify's own `x-nf-client-connection-ip` header, which visitors cannot fake. If the address is unknown the request is refused.
- Staff on mobile data or home internet have changing IPs, so use the IP rule only if everyone uses a fixed office/VPN address.
- **Locked yourself out?** Clear the variable in Netlify and redeploy. `ADMIN_EMAIL` is exempt from the domain rule only, not the IP rule.
- The nightly backup does not go through this rule, so it keeps working.

## Webhooks (notify other services)
Administrators: **Admin Control → Webhooks**. Add an `https://` URL, tick the events, and (optionally) your own signing secret. If you leave the secret empty one is generated and shown **once**.
- **Events:** visit created, updated, completed, approved, returned.
- **Request:** HTTPS `POST` with JSON `{ "id", "event", "createdAt", "data": { …visit, teamName, assigneeName } }`. Headers: `X-VisitOps-Event` and `X-VisitOps-Signature: sha256=<HMAC-SHA256 of the raw body using your secret>`.
- **Verify in the receiver** (Node example): `crypto.createHmac('sha256', secret).update(rawBody).digest('hex')` and compare with the header using a constant-time comparison.
- **Safety:** only `https://` domain names are accepted (no IP addresses, localhost or internal names), redirects are not followed, each call times out after 5 seconds, and a failing webhook never blocks saving a visit. The last result is shown in the table; use **Send test** to check a new URL.
- **Privacy:** the message contains client names, contacts and notes. Only connect services you trust. The signing secret is stored on the server only.
- Works with Zapier, Make, n8n, Slack workflow webhooks, etc. Pointing it at a *Netlify build hook* will trigger a site rebuild on every selected event, which is rarely what you want.
- Limits: up to 10 webhooks; delivery is attempted once (no automatic retry), so make the receiver quick and reliable.

## Standard practices built in
- Passwords: salted scrypt hashes, minimum 6 characters (configurable), optional forced change for temporary passwords.
- Account lock for 15 minutes after 5 wrong passwords; sessions last 8 hours; the app also signs out after 30 minutes idle.
- Changing a role, disabling, resetting or deleting a user ends their sessions immediately.
- The last active administrator cannot be demoted, disabled or deleted; you cannot change your own role.
- Every request is permission-checked on the server; CSRF protection (SameSite=Lax cookie + custom header + origin check).
- Security headers via `netlify.toml`; no scripts or data from other websites.

## Operating practice
- **Joiners/leavers:** create on joining; on leaving, **Disable** (instant) and later Delete.
- **Forgotten password:** there is no email reset by design; an administrator uses **Reset password** and shares the new temporary password.
- **Access review:** review Users & roles monthly.
- **Backups:** nightly to Dropbox. Once a quarter, test a restore (download a file from Dropbox → *Restore JSON backup*) on a test site.
- **MFA:** turn on two-step verification for your Netlify, GitHub and Dropbox accounts (they control this system).
- **Rotating secrets:** if `SESSION_SECRET` or the Dropbox token leaks, replace it in Netlify and redeploy.

## Limits to know
- Netlify Blobs suits small and medium teams (thousands of visits). If you grow to tens of thousands of visits or many simultaneous users, move to a database.
- The scheduled backup runs only on the published production deploy and is subject to your Netlify plan's limits.
- Local testing needs the Netlify CLI (`netlify dev`) because storage is provided by Netlify.

## Troubleshooting
| Symptom | Fix |
|---|---|
| "The server functions are not available" | Site was not deployed from Git/CLI, or `netlify/functions` is missing from the repo |
| "Server is not configured (SESSION_SECRET)" | Add `SESSION_SECRET` (32+ characters) and redeploy |
| "Sign-in is not allowed from this network" | `ALLOWED_IPS` does not include your current address; update or clear it and redeploy |
| Cannot sign in as first admin | `ADMIN_EMAIL` / `ADMIN_INITIAL_PASSWORD` missing at deploy time, or an account already exists (use Reset password from another admin) |
| Page opens but data never loads / "Server error" | Run `npm run check https://YOUR-SITE`; it reports storage and `SESSION_SECRET` problems in plain words. Also read Netlify > Logs > Functions. |
| Build fails at "npm install" | `@netlify/blobs` version in `package.json` must exist; it is `>=8.2.0` |
| Signed out when opening a link from WhatsApp/email | Fixed: cookie is `SameSite=Lax`. Redeploy and sign in again. |
| "Account temporarily locked" | Wait 15 minutes, or an administrator resets the password |
| Leader/member sees no data | Account is not linked to the right member entry (Users & roles) |
| "Backup failed" | Check the Dropbox variables and the Netlify function log; recreate the refresh token if revoked |
