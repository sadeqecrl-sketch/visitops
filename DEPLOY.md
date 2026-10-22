# Deploy VisitOps

## Easiest: Easy mode (2 minutes, no settings, no Git)
Works like Letter Desk: login runs in the browser and your data lives in your own cloud storage (or just this browser).
1. Take the `public/` folder (or unzip `visitops-easy-site.zip`).
2. Open app.netlify.com/drop and drag the folder in (any static host works; use https).
3. Open the site: **First time: create the administrator**. Done.
4. To share data with your team: **Connect cloud storage** (Appwrite, Dropbox, Google Drive or OneDrive). See `docs/EASY-MODE.md`.

Easy mode trusts the people who know the workspace password (permissions are enforced in the browser). For server-enforced permissions, webhooks and IP rules use the server mode below.

# Server mode: deploy in 10 minutes

You need: a free GitHub account and a Netlify account. Dropbox backup is optional and can be added later.

## Path A: GitHub + Netlify (recommended)
1. **GitHub** → New repository → name `visitops` → **Private** → Create.
2. Upload everything from this folder (drag the files in; keep the folders `netlify/`, `public/`, `scripts/`). Commit.
3. **Netlify** → Add new site → Import an existing project → GitHub → pick `visitops`.
   Build command: *(empty)*. Publish directory: `public`. Click **Deploy**.
4. **Site configuration → Environment variables** → add (mark Secret):
   - `SESSION_SECRET` = 32+ random characters (generate one at any password manager, or `openssl rand -base64 48`)
   - `SETUP_CODE` = a code you choose (6+ characters)
5. **Deploys → Trigger deploy → Deploy site** (so the variables take effect).
6. Open your site. You will see **Create administrator account**. Enter the setup code, your email, name and password.
7. Back in Netlify, **delete `SETUP_CODE`** and redeploy once.
8. Admin Control → Users & roles → create a **second administrator**.

## Path B: Netlify CLI (no GitHub)
```
npm install
npx netlify login
npx netlify init            # or: npx netlify link
npx netlify env:set SESSION_SECRET "$(openssl rand -base64 48)" --secret
npx netlify env:set SETUP_CODE "choose-a-code" --secret
npm run deploy
```

## Test before you deploy (optional)
```
npm install
npm run selftest
```
Runs 62 checks of setup, sign-in, storage, permissions, sample data and the "Test as" roles on your own computer with an in-memory store.

## Check the deployment
```
npm run check https://YOUR-SITE.netlify.app
```
It tells you in plain words whether the page, the server functions, the security headers and the data protection are working, and what to fix if not.

## Testing with your team
1. Turn on test mode (below) and share the site link with your team.
2. On the **Dashboard**, the **Team test guide** lists what to try next for the current role, ticks steps off as you go, and each step has an **Open** button.
3. Empty site? Click **Load sample data**: 2 departments, 3 teams, members and 9 visits, some already approved, some waiting for review.
4. Use the **Test as** menu at the top to switch role (Administrator, MIS Officer, Team Leader, Team Member, Cross-team Monitor). For leaders and members, pick the person. Each browser tab remembers its own choice, so two people (or two tabs) can test a hand-off: a member completes a visit, the leader approves it.
5. When finished, **Admin Control → Clear all data**, then delete `OPEN_ACCESS` and redeploy.

The menu is now ordered the way you work: Dashboard, Visit Register, Leader Review, MIS Reports; then set-up in order (Departments, then Teams & Members); then Admin Control.

## Test mode (no sign-in)
Add `OPEN_ACCESS` = `true` in Netlify and redeploy: the sign-in screen is skipped and everyone who has the link is an administrator, with a red banner on every page. Delete the variable and redeploy to switch it off. Use only with test data, or pair it with `ALLOWED_IPS` so only your network can open it.

## Optional later
- **Dropbox backup:** README step 1, then add the three `DROPBOX_*` variables.
- **Restrict who signs in:** `ALLOWED_EMAIL_DOMAINS` (for example `emergingrating.com`) and/or `ALLOWED_IPS`.
- **Custom domain:** Netlify → Domain management.

## Common problems
| You see | Do this |
|---|---|
| "The server functions are not available" | You used drag-and-drop. Use Path A or B. |
| "Server is not configured (SESSION_SECRET)" | Add `SESSION_SECRET` (32+ chars), redeploy. |
| No "Create administrator" screen | `SETUP_CODE` missing at deploy time, or an administrator already exists. |
| "Sign-in is not allowed from this network" | `ALLOWED_IPS` does not include you. Clear it and redeploy. |
