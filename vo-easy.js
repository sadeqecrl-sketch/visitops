/* VisitOps "Easy mode" engine (Letter Desk style).
 *
 * Runs the same rules as netlify/functions/api.mjs, but inside the browser:
 *   - Login: users live in the app data (salted PBKDF2 hashes); the first screen creates the administrator.
 *   - Data: kept in this browser and, if configured, synced to YOUR cloud storage (Appwrite, Google Drive,
 *     OneDrive or Dropbox) as ONE file encrypted with the workspace password (AES-GCM, PBKDF2 150k).
 *   - No server code, no environment variables. Deploy by drag-and-drop on any static host.
 *
 * The screens call VOEasy.handle(method, path, body, headers) instead of fetch('/api/...').
 * Security model (same as Letter Desk): sign-in and roles are enforced in the browser, and the cloud file is
 * protected by the workspace password. Anyone who knows the workspace password can read the data. Use the
 * Netlify "server mode" (netlify/functions) if you need server-enforced permissions.
 */
(function (root) {
  'use strict';
  var isBrowser = typeof document !== 'undefined';
  var LS = (function () { try { if (root.localStorage) return root.localStorage; } catch (e) {} var m = {}; return { getItem: function (k) { return k in m ? m[k] : null; }, setItem: function (k, v) { m[k] = String(v); }, removeItem: function (k) { delete m[k]; } }; })();
  var SS = (function () { try { if (root.sessionStorage) return root.sessionStorage; } catch (e) {} var m = {}; return { getItem: function (k) { return k in m ? m[k] : null; }, setItem: function (k, v) { m[k] = String(v); }, removeItem: function (k) { delete m[k]; } }; })();
  var cr = root.crypto || (typeof require !== 'undefined' ? require('node:crypto').webcrypto : null);

  var ROLES = ['admin', 'mis', 'leader', 'member', 'monitor'];
  var MEMBER_ROLES = ['Team Member', 'Team Leader', 'MIS Officer', 'Cross-team Monitor'];
  var STATUSES = ['Planned', 'In Progress', 'Completed', 'Cancelled'];
  var DATE = /^\d{4}-\d{2}-\d{2}$/, USERNAME = /^[a-z0-9._-]{2,40}$/, EMAIL = /^[^\s@]{1,64}@[^\s@]{1,200}\.[^\s@]{2,}$/;
  var MIN_PW = 6, SESSION_MS = 8 * 3600e3, REMEMBER_MS = 30 * 24 * 3600e3;

  /* ------------------------------------------------------------------ state */
  function empty() {
    return { v: 1, db: { seq: { dept: 0, team: 0, member: 0, visit: 0 }, departments: [], teams: [], members: [], visits: [] },
      users: { seq: 0, users: [] }, settings: { testMode: false, allowedDomains: [] } };
  }
  function fix(d) { var e = empty(); for (var k in e) if (!d[k]) d[k] = e[k]; if (!d.settings.allowedDomains) d.settings.allowedDomains = []; return d; }
  var S; try { S = fix(JSON.parse(LS.getItem('vo_data') || 'null') || empty()); } catch (e) { S = empty(); }
  var clone = function (o) { return JSON.parse(JSON.stringify(o)); };
  var pending = [], replaying = false, actAs = null;

  function HttpError(status, msg) { this.status = status; this.message = msg; }
  var bad = function (m, s) { return new HttpError(s || 400, m); };
  var str = function (v, max) { return String(v == null ? '' : v).trim().slice(0, max || 500); };
  var int = function (v) { var n = Number(v); return Number.isInteger(n) && n > 0 ? n : 0; };

  function persist() {
    try { LS.setItem('vo_data', JSON.stringify(S)); } catch (e) { /* storage full or blocked */ }
    if (!replaying && Cloud.on()) { LS.setItem('vo_dirty', '1'); Cloud.changed(); }
  }
  async function read(name) { return { data: S[name] }; }
  // fn edits a copy; if it throws nothing is kept (same contract as the server's mutate()).
  async function mutate(name, fn) {
    var draft = clone(S[name]), out = await fn(draft);
    S[name] = draft; persist(); return out;
  }

  /* ------------------------------------------------------------------ crypto helpers */
  var enc = function (s) { return new TextEncoder().encode(s); };
  function b64(u) { var s = ''; for (var i = 0; i < u.length; i += 8192) s += String.fromCharCode.apply(null, u.subarray(i, i + 8192)); return btoa(s); }
  function unb(s) { var x = atob(s), u = new Uint8Array(x.length); for (var i = 0; i < x.length; i++) u[i] = x.charCodeAt(i); return u; }
  function b64u(u) { return b64(u).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  async function pbkdf2Bits(pw, salt) {
    var k = await cr.subtle.importKey('raw', enc(pw), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await cr.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: 150000, hash: 'SHA-256' }, k, 256));
  }
  async function hashPassword(pw) { var s = cr.getRandomValues(new Uint8Array(16)); return 'pbkdf2$' + b64(s) + '$' + b64(await pbkdf2Bits(pw, s)); }
  async function verifyPassword(pw, stored) {
    var p = String(stored || '').split('$');
    if (p[0] !== 'pbkdf2' || !p[1] || !p[2]) { await pbkdf2Bits(String(pw), new Uint8Array(16)); return false; }
    var a = await pbkdf2Bits(String(pw), unb(p[1])), b = unb(p[2]), d = a.length ^ b.length;
    for (var i = 0; i < a.length; i++) d |= a[i] ^ (b[i] || 0);
    return d === 0;
  }
  function checkPasswordPolicy(pw) {
    if (typeof pw !== 'string' || pw.length < MIN_PW) return 'Use at least ' + MIN_PW + ' characters.';
    if (pw.length > 128) return 'Password is too long.';
    if (/^(.)\1+$/.test(pw) || /^(password|123456|qwerty)/i.test(pw)) return 'That password is too easy to guess.';
    return '';
  }
  function tempPassword() {
    var abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789', b = cr.getRandomValues(new Uint8Array(8)), o = '';
    for (var i = 0; i < 8; i++) o += abc[b[i] % abc.length]; return o;
  }

  /* ------------------------------------------------------------------ rules (same as server) */
  var handleOf = function (u) { return String(u.username || u.email.split('@')[0]).toLowerCase(); };
  var publicUser = function (u) { return { id: u.id, email: u.email, username: handleOf(u), name: u.name, role: u.role, memberId: u.memberId || 0, active: u.active !== false, mustChange: false }; };
  function domainAllowed(email, role) {
    var list = S.settings.allowedDomains || []; if (!list.length) return true;
    if (role === 'admin') return true; // administrators can never be locked out by this rule
    return list.indexOf(String(email || '').toLowerCase().split('@')[1] || '') >= 0;
  }
  var leaderTeamId = function (db, u) { return u.memberId ? (db.teams.find(function (t) { return t.leaderMemberId === u.memberId; }) || {}).id || 0 : 0; };
  var memberTeamId = function (db, u) { return u.memberId ? (db.members.find(function (m) { return m.id === u.memberId; }) || {}).teamId || 0 : 0; };
  function canSeeVisit(db, u, v) {
    if (['admin', 'mis', 'monitor'].indexOf(u.role) >= 0) return true;
    if (u.role === 'leader') { var t = leaderTeamId(db, u); return !!t && v.teamId === t; }
    if (u.role === 'member') return !!u.memberId && v.assigneeId === u.memberId;
    return false;
  }
  function canWriteVisit(db, u, v) {
    if (u.role === 'admin') return true;
    if (u.role === 'leader') { var t = leaderTeamId(db, u); return !!t && v.teamId === t; }
    if (u.role === 'member') return !!u.memberId && v.assigneeId === u.memberId;
    return false;
  }
  var requireAdmin = function (u) { if (u.role !== 'admin') throw bad('Administrator role required', 403); };

  function cleanVisit(b) {
    var v = { date: str(b.date, 10), purpose: str(b.purpose, 60), client: str(b.client, 200), area: str(b.area, 200),
      teamId: int(b.teamId), assigneeId: int(b.assigneeId), status: str(b.status, 20), followup: str(b.followup, 10),
      amount: Math.min(1e12, Math.max(0, Number(b.amount) || 0)), contact: str(b.contact, 200), phone: str(b.phone, 60),
      email: str(b.email, 200), notes: str(b.notes, 4000) };
    if (!DATE.test(v.date)) throw bad('A valid visit date is required');
    if (!v.client) throw bad('Client name is required');
    if (STATUSES.indexOf(v.status) < 0) throw bad('Invalid status');
    if (v.followup && !DATE.test(v.followup)) throw bad('Invalid follow-up date');
    if (!v.teamId || !v.assigneeId) throw bad('Select a team and an assignee');
    return v;
  }
  function checkTeamAssignee(db, v) {
    if (!db.teams.some(function (t) { return t.id === v.teamId; })) throw bad('Team not found');
    var m = db.members.find(function (x) { return x.id === v.assigneeId; });
    if (!m || m.teamId !== v.teamId) throw bad('Assignee must belong to the selected team');
  }
  function resetReview(v) { v.review = 'Pending review'; v.reviewComment = ''; v.reviewer = ''; v.reviewedAt = ''; }
  function cleanDept(b) {
    var d = { name: str(b.name, 120), code: str(b.code, 20).toUpperCase(), head: str(b.head, 120), status: b.status === 'Inactive' ? 'Inactive' : 'Active', purpose: str(b.purpose, 1000) };
    if (!d.name || !d.code) throw bad('Department name and code are required');
    return d;
  }

  /* ------------------------------------------------------------------ session (browser gate, like Letter Desk) */
  function readSession() {
    try {
      var raw = SS.getItem('vo_sess') || LS.getItem('vo_sess'); if (!raw) return null;
      var p = JSON.parse(raw); return p && p.exp > Date.now() ? p : null;
    } catch (e) { return null; }
  }
  function newSession(u, rm) {
    var p = { uid: u.id, pv: u.pv, rm: rm ? 1 : 0, exp: Date.now() + (rm ? REMEMBER_MS : SESSION_MS) };
    (rm ? LS : SS).setItem('vo_sess', JSON.stringify(p)); (rm ? SS : LS).removeItem('vo_sess');
  }
  function clearSession() { SS.removeItem('vo_sess'); LS.removeItem('vo_sess'); }

  var OPEN_USER = { id: 'open', email: 'test-mode@local', username: 'test', name: 'Test administrator', role: 'admin', memberId: 0, active: true, hash: '', pv: 0 };
  function openUser(hdr) {
    var role = String(hdr['x-test-as'] || '');
    if (ROLES.indexOf(role) < 0) return OPEN_USER;
    var memberId = ['leader', 'member'].indexOf(role) >= 0 ? Number(hdr['x-test-member']) || 0 : 0;
    return Object.assign({}, OPEN_USER, { role: role, memberId: memberId, name: role === 'admin' ? OPEN_USER.name : 'Test ' + role });
  }
  function authenticate(hdr) {
    var users = S.users.users;
    if (actAs) { var a = users.find(function (x) { return x.id === actAs; }); return a ? { user: a, rm: false } : null; }
    var p = readSession();
    if (!p) return S.settings.testMode ? { user: openUser(hdr), rm: false } : null;
    var u = users.find(function (x) { return x.id === p.uid; });
    if (!u || u.active === false || u.pv !== p.pv || !domainAllowed(u.email, u.role)) return S.settings.testMode ? { user: openUser(hdr), rm: false } : null;
    return { user: u, rm: !!p.rm };
  }

  /* ------------------------------------------------------------------ login / setup */
  var fails = {};
  async function login(body) {
    var id = str(body.login != null ? body.login : body.email, 200).toLowerCase(), password = String(body.password == null ? '' : body.password), rm = body.remember === true;
    var users = S.users.users, matches = users.filter(function (x) { return x.email === id || handleOf(x) === id; });
    var u = matches.length === 1 ? matches[0] : matches.find(function (x) { return x.email === id; }) || null;
    if (u && !domainAllowed(u.email, u.role)) u = null;
    if (!u) { await verifyPassword(password, null); throw bad('Incorrect username or password', 401); }
    var f = fails[u.id] || (fails[u.id] = { n: 0, until: 0 });
    if (f.until > Date.now()) throw bad('Too many wrong passwords. Try again in ' + Math.ceil((f.until - Date.now()) / 1000) + ' seconds.', 429);
    var ok = await verifyPassword(password, u.hash);
    if (!ok || u.active === false) {
      if (++f.n >= 5) { f.until = Date.now() + 60000; f.n = 0; }
      throw bad(ok ? 'This account is inactive. Ask an administrator.' : 'Incorrect username or password', 401);
    }
    f.n = 0; newSession(u, rm);
    return { s: 200, j: { user: publicUser(u), remember: rm } };
  }
  // First-run: no setup code, like Letter Desk ("First time: create the administrator").
  async function setup(body) {
    if (S.users.users.length) throw bad('Setup is already done. Please sign in.', 403);
    var email = str(body.email, 200).toLowerCase(), name = str(body.name, 120) || 'Administrator', password = String(body.password == null ? '' : body.password);
    if (!EMAIL.test(email)) throw bad('Enter a valid email address');
    var msg = checkPasswordPolicy(password); if (msg) throw bad(msg);
    var hash = await hashPassword(password);
    var u = await mutate('users', function (d) {
      if (d.users.length) throw bad('Setup is already done. Please sign in.', 403);
      d.seq = (d.seq || 0) + 1;
      var x = { id: String(d.seq), email: email, username: email.split('@')[0], name: name, role: 'admin', memberId: 0, hash: hash, active: true, pv: 1, createdAt: new Date().toISOString() };
      d.users.push(x); return clone(x);
    });
    newSession(u, false);
    return { s: 201, j: { user: publicUser(u), remember: false } };
  }

  /* ------------------------------------------------------------------ routes */
  async function route(method, path, body, hdr) {
    var parts = String(path).replace(/^\/?(api\/?)?/, '').split('/').filter(Boolean), a = parts[0], b = parts[1], c = parts[2];
    var ok = function (j, s) { return { s: s || 200, j: j }; };

    if (a === 'logout' && method === 'POST') { clearSession(); return ok({ ok: true }); }
    if (a === 'health' && method === 'GET') return ok({ mode: 'easy', sessionSecret: true, storageRead: 'ok', storageWrite: 'ok', cloud: Cloud.state, openAccess: !!S.settings.testMode });
    if (a === 'policy' && method === 'GET') return ok({ mode: 'easy', domains: S.settings.allowedDomains || [], networkRestricted: false, openAccess: !!S.settings.testMode,
      needsSetup: S.users.users.length === 0, setupEnabled: true, setupNeedsCode: false, webhooks: false, cloud: Cloud.info() });
    if (a === 'setup' && method === 'POST') return setup(body);
    if (a === 'login' && method === 'POST') return login(body);

    var auth = authenticate(hdr); if (!auth) throw bad('Not signed in', 401);
    var user = auth.user;
    if (a === 'me' && method === 'GET') return ok({ user: publicUser(user), remember: auth.rm, openAccess: !!S.settings.testMode && user.id === 'open' });

    if (a === 'password' && method === 'POST') {
      var next = String(body.next == null ? '' : body.next);
      if (!(await verifyPassword(String(body.current == null ? '' : body.current), user.hash))) throw bad('Current password is incorrect', 400);
      var pmsg = checkPasswordPolicy(next); if (pmsg) throw bad(pmsg);
      if (next === body.current) throw bad('Choose a different password');
      var hash = await hashPassword(next);
      var upd = await mutate('users', function (d) { var x = d.users.find(function (i) { return i.id === user.id; }); x.hash = hash; x.pv = (x.pv || 1) + 1; return clone(x); });
      newSession(upd, auth.rm); return ok({ user: publicUser(upd), remember: auth.rm });
    }

    if (a === 'data' && method === 'GET') {
      var db = S.db, out = { departments: db.departments, teams: db.teams, members: db.members, visits: db.visits.filter(function (v) { return canSeeVisit(db, user, v); }), users: [] };
      if (user.role === 'admin') { out.users = S.users.users.map(publicUser); out.webhooks = []; out.webhookEvents = {}; }
      return ok(clone(out));
    }

    if (a === 'settings') { // easy-mode only: workspace-wide switches (administrators)
      requireAdmin(user);
      if (method === 'GET') return ok({ testMode: !!S.settings.testMode, allowedDomains: S.settings.allowedDomains || [] });
      if (method === 'PUT') {
        var doms = Array.isArray(body.allowedDomains) ? body.allowedDomains : String(body.allowedDomains || '').split(/[,\s;]+/);
        doms = doms.map(function (x) { return String(x).trim().toLowerCase().replace(/^@/, ''); }).filter(Boolean).slice(0, 20);
        await mutate('settings', function (s) { if (body.testMode !== undefined) s.testMode = !!body.testMode; if (body.allowedDomains !== undefined) s.allowedDomains = doms; });
        return ok({ ok: true });
      }
    }

    if (a === 'visits') {
      if (method === 'POST' && !b) {
        if (['admin', 'leader', 'member'].indexOf(user.role) < 0) throw bad('This role cannot create visits', 403);
        var v = cleanVisit(body);
        var view = await mutate('db', function (db) {
          checkTeamAssignee(db, v);
          if (!canWriteVisit(db, user, v) || (user.role === 'member' && v.teamId !== memberTeamId(db, user))) throw bad('You cannot create a visit for that team or assignee', 403);
          var row = Object.assign({ id: ++db.seq.visit }, v); resetReview(row); db.visits.push(row); return row;
        });
        return ok({ id: view.id }, 201);
      }
      if (method === 'PUT' && b && !c) {
        var id = int(b), nv = cleanVisit(body);
        await mutate('db', function (db) {
          var old = db.visits.find(function (x) { return x.id === id; });
          if (!old) throw bad('Visit not found', 404);
          if (!canWriteVisit(db, user, old)) throw bad('You cannot edit this visit', 403);
          checkTeamAssignee(db, nv);
          if (user.role === 'member' && (nv.teamId !== old.teamId || nv.assigneeId !== user.memberId)) throw bad('Members can only manage their own assigned visits', 403);
          if (user.role === 'leader' && nv.teamId !== leaderTeamId(db, user)) throw bad('You can only manage your own team', 403);
          var wasDone = old.status === 'Completed'; Object.assign(old, nv);
          if (nv.status === 'Completed' && !wasDone) resetReview(old);
        });
        return ok({ ok: true });
      }
      if (method === 'POST' && b && c === 'review') {
        var rid = int(b), decision = str(body.decision, 20), comment = str(body.comment, 1000);
        if (['Approved', 'Returned'].indexOf(decision) < 0) throw bad('Invalid decision');
        if (decision === 'Returned' && !comment) throw bad('A return reason is required');
        await mutate('db', function (db) {
          var v = db.visits.find(function (x) { return x.id === rid; });
          if (!v) throw bad('Visit not found', 404);
          var allowed = user.role === 'admin' || (user.role === 'leader' && v.teamId === leaderTeamId(db, user));
          if (!allowed) throw bad('Only the team leader or an administrator can review this visit', 403);
          if (v.status !== 'Completed') throw bad('Only completed visits can be reviewed');
          v.review = decision; v.reviewComment = decision === 'Returned' ? comment : ''; v.reviewer = user.role === 'admin' ? 'Administrator' : user.name; v.reviewedAt = new Date().toISOString();
          if (decision === 'Returned') v.status = 'In Progress';
        });
        return ok({ ok: true });
      }
    }

    if (a === 'departments') {
      requireAdmin(user);
      if (method === 'POST' && !b) {
        var d = cleanDept(body);
        await mutate('db', function (db) {
          if (db.departments.some(function (x) { return x.name.toLowerCase() === d.name.toLowerCase(); })) throw bad('Department name already exists');
          if (db.departments.some(function (x) { return x.code === d.code; })) throw bad('Department code already exists');
          db.departments.push(Object.assign({ id: ++db.seq.dept }, d));
        });
        return ok({ ok: true }, 201);
      }
      if (method === 'PUT' && b) {
        var did = int(b), d2 = cleanDept(body);
        await mutate('db', function (db) {
          var x = db.departments.find(function (i) { return i.id === did; }); if (!x) throw bad('Department not found', 404);
          if (db.departments.some(function (o) { return o.id !== did && (o.name.toLowerCase() === d2.name.toLowerCase() || o.code === d2.code); })) throw bad('Department name or code already exists');
          Object.assign(x, d2);
        });
        return ok({ ok: true });
      }
      if (method === 'DELETE' && b) {
        var xid = int(b);
        await mutate('db', function (db) {
          if (db.teams.some(function (t) { return t.departmentId === xid; })) throw bad('Move its teams to another department before deleting');
          db.departments = db.departments.filter(function (x) { return x.id !== xid; });
        });
        return ok({ ok: true });
      }
    }

    if (a === 'teams' && method === 'POST' && !b) {
      requireAdmin(user);
      var tn = str(body.name, 120), tl = str(body.leader, 120), td = str(body.desc, 1000), dep = int(body.departmentId);
      if (!tn || !tl) throw bad('Team name and leader are required');
      await mutate('db', function (db) {
        if (db.teams.some(function (t) { return t.name.toLowerCase() === tn.toLowerCase(); })) throw bad('Team name already exists');
        if (dep && !db.departments.some(function (x) { return x.id === dep; })) throw bad('Department not found');
        var team = { id: ++db.seq.team, name: tn, leader: tl, desc: td, departmentId: dep, leaderMemberId: 0 };
        var m = { id: ++db.seq.member, name: tl, email: '', teamId: team.id, role: 'Team Leader' };
        team.leaderMemberId = m.id; db.teams.push(team); db.members.push(m);
      });
      return ok({ ok: true }, 201);
    }
    if (a === 'members' && method === 'POST' && !b) {
      requireAdmin(user);
      var m0 = { name: str(body.name, 120), email: str(body.email, 200), teamId: int(body.teamId), role: MEMBER_ROLES.indexOf(body.role) >= 0 ? body.role : 'Team Member' };
      if (!m0.name) throw bad('Member name is required');
      await mutate('db', function (db) { if (!db.teams.some(function (t) { return t.id === m0.teamId; })) throw bad('Team not found'); db.members.push(Object.assign({ id: ++db.seq.member }, m0)); });
      return ok({ ok: true }, 201);
    }

    if (a === 'users') {
      requireAdmin(user);
      var dbq = S.db;
      var checkLink = function (role, memberId) {
        if (role === 'leader') { if (!memberId || !dbq.teams.some(function (t) { return t.leaderMemberId === memberId; })) throw bad('A team leader must be linked to the leader entry of a team'); }
        else if (role === 'member') { if (!memberId || !dbq.members.some(function (m) { return m.id === memberId; })) throw bad('A team member must be linked to a member entry'); }
      };
      if (method === 'POST' && !b) {
        var email = str(body.email, 200).toLowerCase(), username = str(body.username, 40).toLowerCase() || email.split('@')[0], name = str(body.name, 120) || email.split('@')[0], role = str(body.role, 20), memberId = int(body.memberId);
        if (!EMAIL.test(email)) throw bad('Enter a valid email address');
        if (!domainAllowed(email, role)) throw bad('That email domain is not allowed. Allowed: ' + (S.settings.allowedDomains || []).map(function (x) { return '@' + x; }).join(', '));
        if (!USERNAME.test(username)) throw bad('Username: 2-40 letters, digits, dot, dash or underscore');
        if (ROLES.indexOf(role) < 0) throw bad('Invalid role');
        checkLink(role, memberId);
        var given = String(body.password == null ? '' : body.password);
        if (given) { var gm = checkPasswordPolicy(given); if (gm) throw bad(gm); }
        var pw = given || tempPassword(), hash2 = await hashPassword(pw);
        var created = await mutate('users', function (d) {
          if (d.users.some(function (u) { return u.email === email || handleOf(u) === username || u.email === username; })) throw bad('That email or username is already in use');
          d.seq = (d.seq || 0) + 1;
          var u = { id: String(d.seq), email: email, username: username, name: name, role: role, memberId: ['leader', 'member'].indexOf(role) >= 0 ? memberId : 0, hash: hash2, active: true, pv: 1, createdAt: new Date().toISOString() };
          d.users.push(u); return publicUser(u);
        });
        return ok({ user: created, tempPassword: pw }, 201);
      }
      if (b && !c && method === 'PUT') {
        await mutate('users', function (d) {
          var u = d.users.find(function (x) { return x.id === b; }); if (!u) throw bad('User not found', 404);
          var role = body.role !== undefined ? str(body.role, 20) : u.role, memberId = body.memberId !== undefined ? int(body.memberId) : u.memberId;
          var active = body.active !== undefined ? !!body.active : u.active !== false;
          if (ROLES.indexOf(role) < 0) throw bad('Invalid role');
          if (u.id === user.id && (role !== u.role || !active)) throw bad('You cannot change your own role or disable yourself');
          checkLink(role, memberId);
          if (u.role === 'admin' && (role !== 'admin' || !active) && !d.users.some(function (x) { return x.id !== u.id && x.role === 'admin' && x.active !== false; })) throw bad('At least one active administrator is required');
          if (body.name !== undefined) u.name = str(body.name, 120) || u.name;
          if (role !== u.role || active !== (u.active !== false)) u.pv = (u.pv || 1) + 1;
          u.role = role; u.memberId = ['leader', 'member'].indexOf(role) >= 0 ? memberId : 0; u.active = active;
        });
        return ok({ ok: true });
      }
      if (b && c === 'reset' && method === 'POST') {
        if (b === user.id) throw bad('Use "Change password" for your own account');
        var pw2 = tempPassword(), hash3 = await hashPassword(pw2);
        await mutate('users', function (d) { var u = d.users.find(function (x) { return x.id === b; }); if (!u) throw bad('User not found', 404); u.hash = hash3; u.pv = (u.pv || 1) + 1; });
        return ok({ tempPassword: pw2 });
      }
      if (b && !c && method === 'DELETE') {
        if (b === user.id) throw bad('You cannot delete your own account');
        await mutate('users', function (d) {
          var u = d.users.find(function (x) { return x.id === b; }); if (!u) throw bad('User not found', 404);
          if (u.role === 'admin' && !d.users.some(function (x) { return x.id !== u.id && x.role === 'admin' && x.active !== false; })) throw bad('At least one active administrator is required');
          d.users = d.users.filter(function (x) { return x.id !== b; });
        });
        return ok({ ok: true });
      }
    }

    if (a === 'clear' && method === 'POST') {
      requireAdmin(user);
      if (body.confirm !== 'DELETE') throw bad('Confirmation required');
      await mutate('db', function (db) { db.departments = []; db.teams = []; db.members = []; db.visits = []; });
      await mutate('users', function (d) { d.users.forEach(function (u) { if (['leader', 'member'].indexOf(u.role) >= 0) u.memberId = 0; }); });
      return ok({ ok: true });
    }

    if (a === 'restore' && method === 'POST') {
      requireAdmin(user);
      var src = body.data;
      if (!src || !Array.isArray(src.teams) || !Array.isArray(src.members) || !Array.isArray(src.visits)) throw bad('Invalid backup format');
      if (src.teams.length + src.members.length + src.visits.length > 100000) throw bad('Backup too large');
      var counts = await mutate('db', function (db) {
        var dm = {}, tm = {}, mm = {}, nd = 0, nt = 0, nm = 0, nv = 0;
        (src.departments || []).forEach(function (d0) {
          var d = cleanDept(d0), ex = db.departments.find(function (x) { return x.name.toLowerCase() === d.name.toLowerCase() || x.code === d.code; });
          if (ex) dm[d0.id] = ex.id; else { var r = Object.assign({ id: ++db.seq.dept }, d); db.departments.push(r); dm[d0.id] = r.id; nd++; }
        });
        src.teams.forEach(function (t) {
          var name = str(t.name, 120); if (!name) return;
          var ex = db.teams.find(function (x) { return x.name.toLowerCase() === name.toLowerCase(); });
          if (ex) tm[t.id] = ex.id; else { var r = { id: ++db.seq.team, name: name, leader: str(t.leader, 120), desc: str(t.desc, 1000), departmentId: dm[t.departmentId] || 0, leaderMemberId: 0 }; db.teams.push(r); tm[t.id] = r.id; nt++; }
        });
        src.members.forEach(function (m) {
          if (!tm[m.teamId]) return;
          var r = { id: ++db.seq.member, name: str(m.name, 120), email: str(m.email, 200), teamId: tm[m.teamId], role: MEMBER_ROLES.indexOf(m.role) >= 0 ? m.role : 'Team Member' };
          db.members.push(r); mm[m.id] = r.id; nm++;
        });
        src.teams.forEach(function (t) {
          var team = db.teams.find(function (x) { return x.id === tm[t.id]; }); if (!team || team.leaderMemberId) return;
          var lm = src.members.find(function (m) { return t.leaderMemberId ? m.id === t.leaderMemberId : (m.teamId === t.id && m.role === 'Team Leader' && m.name === t.leader); });
          if (lm && mm[lm.id]) team.leaderMemberId = mm[lm.id];
        });
        src.visits.forEach(function (v0) {
          if (!tm[v0.teamId] || !mm[v0.assigneeId]) return;
          var v; try { v = cleanVisit(Object.assign({}, v0, { teamId: tm[v0.teamId], assigneeId: mm[v0.assigneeId] })); } catch (e) { return; }
          db.visits.push(Object.assign({ id: ++db.seq.visit }, v, { review: ['Approved', 'Returned'].indexOf(v0.review) >= 0 ? v0.review : 'Pending review', reviewComment: str(v0.reviewComment, 1000), reviewer: str(v0.reviewer, 120), reviewedAt: str(v0.reviewedAt, 40) }));
          nv++;
        });
        return { departments: nd, teams: nt, members: nm, visits: nv };
      });
      return ok({ ok: true, added: counts });
    }
    throw bad(a === 'webhooks' || a === 'backup' ? 'Not available in easy mode (data is synced to your cloud storage instead)' : 'Not found', 404);
  }

  var NOREPLAY = { login: 1, logout: 1, password: 1, setup: 1, health: 1, policy: 1, me: 1 };
  async function handle(method, path, body, headers) {
    var hdr = {}; for (var k in (headers || {})) hdr[String(k).toLowerCase()] = headers[k];
    try {
      var r = await route(method, path, body || {}, hdr);
      var first = String(path).replace(/^\/?(api\/?)?/, '').split('/')[0];
      if (method !== 'GET' && r.s < 400 && !replaying && !NOREPLAY[first] && Cloud.on()) { var au = authenticate(hdr); pending.push({ method: method, path: path, body: body, hdr: hdr, uid: au ? au.user.id : '' }); }
      return r;
    } catch (e) {
      if (e && e.status) return { s: e.status, j: { error: e.message } };
      if (isBrowser) console.error('VisitOps easy-mode error', e);
      return { s: 500, j: { error: 'Unexpected error: ' + ((e && e.message) || e) } };
    }
  }

  /* ------------------------------------------------------------------ cloud storage (ported from Letter Desk) */
  var Cloud = { state: 'off', msg: '', on: function () { return false; }, changed: function () {}, info: function () { return { state: this.state, msg: this.msg }; } };
  // Safe defaults (replaced below when the browser allows encryption).
  Cloud.config = function () { return { provider: '', workspace: '', poll: '30', fields: {}, hasKey: false, key: '', configured: false }; };
  Cloud.providerHelp = function () { return ''; };
  Cloud.saveConfig = function () { throw new Error('Cloud storage needs a secure (https) address'); };
  Cloud.disconnect = Cloud.test = Cloud.syncNow = function () { return Promise.resolve(); };
  var VOEasy = { handle: handle, cloud: Cloud, onRemote: null, _state: function () { return S; }, _reset: function () { S = empty(); pending = []; fails = {}; }, ready: Promise.resolve() };

  if (isBrowser && cr && cr.subtle) (function () {
    var D = { provider: '', workspace: '', poll: '', appwrite: { endpoint: 'https://cloud.appwrite.io/v1', project: '', db: '', col: '' }, gdrive: { clientId: '' }, onedrive: { clientId: '' }, dropbox: { clientId: '' } };
    function mg(a, b) { for (var k in b) { if (b[k] && typeof b[k] === 'object') a[k] = mg(a[k] || {}, b[k]); else if (b[k] !== '' && b[k] != null) a[k] = b[k]; } return a; }
    var saved = {}; try { saved = JSON.parse(LS.getItem('vo_cfg') || '{}'); } catch (e) {}
    var CFG = mg(mg(D, root.VO_CLOUD || {}), saved); ['provider', 'workspace', 'poll'].forEach(function (k) { if (k in saved) CFG[k] = saved[k]; });
    var PN = CFG.provider, cfg = CFG[PN] || {};
    var RU = location.origin + location.pathname;
    var WS = String(CFG.workspace || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20).toLowerCase(), FN = 'visitops' + (WS ? '-' + WS : '') + '.enc', AP = 'vo_' + (WS ? WS + '_' : '');
    var configured = !!(PN && (cfg.project || cfg.clientId));

    function ok(r) { if (r.status === 401) throw 'auth'; if (!r.ok) throw new Error(r.status); return r; }
    var PV = {
      appwrite: {
        api: function (m, p, b) { return fetch(cfg.endpoint + '/databases/' + cfg.db + '/collections/' + cfg.col + '/documents' + p, { method: m, headers: { 'X-Appwrite-Project': cfg.project, 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined }).then(function (r) { return r.json().then(function (j) { if (r.status === 404 && m === 'GET') return null; if (!r.ok) throw new Error(j.message); return j; }); }); },
        put: async function (id, d) { try { await this.api('PATCH', '/' + id, { data: d }); } catch (e) { await this.api('POST', '', { documentId: id, data: d }); } },
        read: async function () { var m = await this.api('GET', '/' + AP + 'meta'); if (!m) return null; var q = []; for (var i = 0; i < m.n; i++) q.push(this.api('GET', '/' + AP + i)); return (await Promise.all(q)).map(function (x) { return x.d; }).join(''); },
        write: async function (s) { var n = Math.ceil(s.length / 40000); for (var i = 0; i < n; i++) await this.put(AP + i, { d: s.slice(i * 40000, (i + 1) * 40000) }); await this.put(AP + 'meta', { n: n }); }
      },
      gdrive: {
        tok: '', exp: 0,
        auth: function (click) { var t = this; return new Promise(function (res, rej) { if (t.tok && Date.now() < t.exp) return res(t.tok); if (!click || !root.google) return rej('auth');
          google.accounts.oauth2.initTokenClient({ client_id: cfg.clientId, scope: 'https://www.googleapis.com/auth/drive.appdata', callback: function (r) { if (r.error) return rej('auth'); t.tok = r.access_token; t.exp = Date.now() + (r.expires_in - 60) * 1000; res(t.tok); } }).requestAccessToken(); }); },
        h: async function () { return { Authorization: 'Bearer ' + await this.auth() }; },
        fid: async function () { var r = ok(await fetch('https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&fields=files(id)&q=' + encodeURIComponent("name='" + FN + "'"), { headers: await this.h() })), f = (await r.json()).files; return f && f[0] && f[0].id; },
        read: async function () { var id = await this.fid(); if (!id) return null; return ok(await fetch('https://www.googleapis.com/drive/v3/files/' + id + '?alt=media', { headers: await this.h() })).text(); },
        write: async function (s) { var id = await this.fid(), h = await this.h();
          if (id) return ok(await fetch('https://www.googleapis.com/upload/drive/v3/files/' + id + '?uploadType=media', { method: 'PATCH', headers: h, body: s }));
          h['Content-Type'] = 'multipart/related; boundary=vob';
          ok(await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', { method: 'POST', headers: h, body: '--vob\r\nContent-Type: application/json\r\n\r\n' + JSON.stringify({ name: FN, parents: ['appDataFolder'] }) + '\r\n--vob\r\nContent-Type: text/plain\r\n\r\n' + s + '\r\n--vob--' })); }
      },
      onedrive: {
        tok: '', exp: 0, SC: 'Files.ReadWrite.AppFolder offline_access', U: 'https://graph.microsoft.com/v1.0/me/drive/special/approot:/' + FN + ':/content',
        tk: async function (p) { var r = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', { method: 'POST', body: new URLSearchParams(Object.assign({ client_id: cfg.clientId, redirect_uri: RU, scope: this.SC }, p)) }), j = await r.json(); if (!j.access_token) throw 'auth'; this.tok = j.access_token; this.exp = Date.now() + (j.expires_in - 60) * 1000; if (j.refresh_token) LS.setItem('vo_rt', j.refresh_token); return this.tok; },
        login: async function (w) { var v = b64u(cr.getRandomValues(new Uint8Array(32))), c = b64u(new Uint8Array(await cr.subtle.digest('SHA-256', enc(v))));
          var got = new Promise(function (res) { addEventListener('message', function f(e) { if (e.origin === location.origin && e.data && e.data.voms) { removeEventListener('message', f); res(new URLSearchParams(e.data.voms).get('code')); } }); });
          w.location = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' + new URLSearchParams({ client_id: cfg.clientId, response_type: 'code', redirect_uri: RU, scope: this.SC, state: 'voms', code_challenge: c, code_challenge_method: 'S256' });
          var code = await got; if (!code) throw 'auth'; return this.tk({ grant_type: 'authorization_code', code: code, code_verifier: v }); },
        auth: async function (click) { if (this.tok && Date.now() < this.exp) return this.tok; if (click) return this.login(open('', 'voms', 'width=500,height=650')); var rt = LS.getItem('vo_rt'); if (rt) try { return await this.tk({ grant_type: 'refresh_token', refresh_token: rt }); } catch (e) {} throw 'auth'; },
        read: async function () { var r = await fetch(this.U, { headers: { Authorization: 'Bearer ' + await this.auth() } }); if (r.status === 404) return null; return ok(r).text(); },
        write: async function (s) { ok(await fetch(this.U, { method: 'PUT', headers: { Authorization: 'Bearer ' + await this.auth(), 'Content-Type': 'text/plain' }, body: s })); }
      },
      dropbox: {
        tok: '', exp: 0,
        tk: async function (p) { var r = await fetch('https://api.dropboxapi.com/oauth2/token', { method: 'POST', body: new URLSearchParams(Object.assign({ client_id: cfg.clientId }, p)) }), j = await r.json(); if (!j.access_token) throw 'auth'; this.tok = j.access_token; this.exp = Date.now() + ((j.expires_in || 14400) - 60) * 1000; if (j.refresh_token) LS.setItem('vo_rt', j.refresh_token); return this.tok; },
        login: async function (w) { var v = b64u(cr.getRandomValues(new Uint8Array(32))), c = b64u(new Uint8Array(await cr.subtle.digest('SHA-256', enc(v))));
          var got = new Promise(function (res) { addEventListener('message', function f(e) { if (e.origin === location.origin && e.data && e.data.voms) { removeEventListener('message', f); res(new URLSearchParams(e.data.voms).get('code')); } }); });
          w.location = 'https://www.dropbox.com/oauth2/authorize?' + new URLSearchParams({ client_id: cfg.clientId, response_type: 'code', redirect_uri: RU, token_access_type: 'offline', state: 'voms', code_challenge: c, code_challenge_method: 'S256' });
          var code = await got; if (!code) throw 'auth'; return this.tk({ grant_type: 'authorization_code', code: code, code_verifier: v, redirect_uri: RU }); },
        auth: async function (click) { if (this.tok && Date.now() < this.exp) return this.tok; var rt = LS.getItem('vo_rt'); if (rt) try { return await this.tk({ grant_type: 'refresh_token', refresh_token: rt }); } catch (e) { LS.removeItem('vo_rt'); } if (click) return this.login(open('', 'voms', 'width=500,height=650')); throw 'auth'; },
        read: async function () { var r = await fetch('https://content.dropboxapi.com/2/files/download', { method: 'POST', headers: { Authorization: 'Bearer ' + await this.auth(), 'Dropbox-API-Arg': JSON.stringify({ path: '/' + FN }) } }); if (r.status === 409) return null; return ok(r).text(); },
        write: async function (s) { ok(await fetch('https://content.dropboxapi.com/2/files/upload', { method: 'POST', headers: { Authorization: 'Bearer ' + await this.auth(), 'Dropbox-API-Arg': JSON.stringify({ path: '/' + FN, mode: 'overwrite', mute: true }), 'Content-Type': 'application/octet-stream' }, body: s })); }
      }
    };
    var Pv = PV[PN];
    if (configured && PN === 'gdrive') { var sc = document.createElement('script'); sc.src = 'https://accounts.google.com/gsi/client'; document.head.appendChild(sc); }

    var pass = LS.getItem('vo_key') || CFG.key || '', cloudOn = !!(configured && Pv);
    var pt = 0, tm = 0, busy = false, again = false, need = false, waitDone, badge = null;
    Cloud.on = function () { return cloudOn && !!pass; };
    function paint(t) { // small status badge, bottom-left (like Letter Desk)
      if (!badge) { badge = document.createElement('div'); badge.style.cssText = 'position:fixed;left:10px;bottom:10px;z-index:100000;font:12px sans-serif;padding:4px 10px;border-radius:12px;background:#000a;color:#fff;cursor:pointer'; badge.onclick = function () { Cloud.syncNow(); }; document.body.appendChild(badge); }
      var good = /^(Synced|Ready|Saving|Loading|Testing|Connection OK)/.test(t);
      badge.innerHTML = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:' + (good ? '#22c55e' : '#ef4444') + '"></span>'; badge.appendChild(document.createTextNode('Cloud: ' + t)); badge.title = good ? 'Connected. Click to sync now.' : 'Not connected. Click for details.';
      Cloud.status = t; var el = document.getElementById('cloudStatus'); if (el) el.textContent = t;
    }
    Cloud.status = '';
    function setState(s, m) { Cloud.state = s; Cloud.msg = m || ''; if (waitDone && s !== 'wait') { var w = waitDone; waitDone = null; w(); } }
    async function K(salt) { var k = await cr.subtle.importKey('raw', enc(pass), 'PBKDF2', false, ['deriveKey']); return cr.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 150000, hash: 'SHA-256' }, k, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }
    async function get() { var s = await Pv.read(); return s ? JSON.parse(s) : null; }
    async function decryptDoc(e) { try { return JSON.parse(new TextDecoder().decode(await cr.subtle.decrypt({ name: 'AES-GCM', iv: unb(e.iv) }, await K(unb(e.salt)), unb(e.d)))); } catch (x) { throw 'key'; } }
    function fail(e) {
      if (Cloud.state === 'wait') setState('fail', e === 'key' ? 'key' : e === 'auth' ? 'auth' : 'net');
      if (e === 'auth') { Pv.tok = ''; need = true; paint('Sign in (click here)'); }
      else if (e === 'key') { LS.removeItem('vo_key'); pass = ''; paint('Wrong workspace password: reload and re-enter'); }
      else paint('Offline (will retry)');
    }
    // Take the cloud version, then re-apply this device's unsynced actions on top of it (so nobody's work is lost).
    async function mergeRemote(e) {
      var mine = pending.slice(); S = fix(await decryptDoc(e)); LS.setItem('vo_data', JSON.stringify(S)); LS.setItem('vo_rev', e.rev); LS.setItem('vo_wid', e.w || '');
      replaying = true; var lost = 0;
      try { for (var i = 0; i < mine.length; i++) { actAs = mine[i].uid || null; try { var r = await route(mine[i].method, mine[i].path, mine[i].body || {}, mine[i].hdr || {}); if (r && r.s >= 400) lost++; } catch (x) { lost++; } } }
      finally { actAs = null; replaying = false; }
      pending = mine; try { LS.setItem('vo_data', JSON.stringify(S)); } catch (x) {}
      if (VOEasy.onRemote) VOEasy.onRemote({ merged: mine.length, lost: lost });
    }
    async function push() {
      if (busy) { again = true; return; } busy = true; paint('Saving...');
      try {
        var e = await get(), rev = e ? e.rev : 0;
        // The cloud copy changed since we last synced: take it, then re-apply our unsynced actions on top.
        if (e && (rev !== (+LS.getItem('vo_rev') || 0) || (e.w || '') !== (LS.getItem('vo_wid') || ''))) { await mergeRemote(e); rev = e.rev; }
        var salt = e && e.salt ? unb(e.salt) : cr.getRandomValues(new Uint8Array(16)), iv = cr.getRandomValues(new Uint8Array(12)), wid = b64u(cr.getRandomValues(new Uint8Array(9)));
        var c = await cr.subtle.encrypt({ name: 'AES-GCM', iv: iv }, await K(salt), enc(JSON.stringify(S)));
        await Pv.write(JSON.stringify({ rev: rev + 1, w: wid, salt: b64(salt), iv: b64(iv), d: b64(new Uint8Array(c)) }));
        var chk = await get();
        if (!chk || chk.w !== wid) { busy = false; again = true; paint('Merging...'); return finishPush(); } // someone wrote at the same moment: re-check
        LS.setItem('vo_rev', rev + 1); LS.setItem('vo_wid', wid); LS.setItem('vo_dirty', '0'); pending = []; paint('Synced'); setState('ready');
      } catch (x) { fail(x); }
      busy = false; finishPush();
    }
    function finishPush() { busy = false; if (again) { again = false; push(); } }
    async function pull(quiet) {
      if (!quiet) paint('Loading...');
      try {
        var e = await get();
        if (!e) { LS.setItem('vo_rev', 0); LS.setItem('vo_wid', ''); paint('Ready'); setState('ready'); if (S.users.users.length) push(); return; }
        var localRev = +LS.getItem('vo_rev') || 0, localW = LS.getItem('vo_wid') || '';
        if (e.rev === localRev && (e.w || '') === localW) { paint('Synced'); setState('ready'); if (LS.getItem('vo_dirty') === '1') push(); return; }
        if (LS.getItem('vo_dirty') === '1' && pending.length) { await push(); return; }
        S = fix(await decryptDoc(e)); LS.setItem('vo_data', JSON.stringify(S)); LS.setItem('vo_rev', e.rev); LS.setItem('vo_wid', e.w || ''); LS.setItem('vo_dirty', '0');
        paint('Synced'); setState('ready'); if (VOEasy.onRemote) VOEasy.onRemote({});
      } catch (x) { fail(x); }
    }
    Cloud.changed = function () { clearTimeout(tm); tm = setTimeout(push, 1500); };
    Cloud.syncNow = function () { if (!pass) return Cloud.openConfig && Cloud.openConfig(); if (need) { need = false; return Pv.auth(true).then(function () { return LS.getItem('vo_dirty') === '1' ? push() : pull(); }).catch(function () { need = true; paint('Sign in (click here)'); }); } return LS.getItem('vo_dirty') === '1' ? push() : pull(); };
    Cloud.test = function () { paint('Testing...'); return (Pv.auth ? Pv.auth(true) : Promise.resolve()).then(function () { return Pv.read(); }).then(function () { paint('Connection OK'); return true; }).catch(function (e) { paint(e === 'auth' ? 'Sign-in failed' : 'Test failed: ' + ((e && e.message) || e)); return false; }); };
    Cloud.config = function () { return { provider: PN, workspace: CFG.workspace || '', poll: CFG.poll === '' || CFG.poll == null ? '30' : String(CFG.poll), fields: cfg, hasKey: !!pass, key: pass, configured: configured }; };
    Cloud.saveConfig = function (o) { // o: {provider, fields:{...}, workspace, poll, key}
      var c = {}; try { c = JSON.parse(LS.getItem('vo_cfg') || '{}'); } catch (e) {}
      var ws0 = c.workspace || CFG.workspace || '', p0 = LS.getItem('vo_pv') || '';
      c.workspace = String(o.workspace || '').trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20).toLowerCase(); c.poll = o.poll; c.provider = o.provider;
      if (o.provider) { c[o.provider] = Object.assign(c[o.provider] || {}, o.fields || {}); if (!o.key) throw new Error('Enter a workspace password'); LS.setItem('vo_key', o.key); }
      if (o.provider !== p0 || c.workspace !== ws0) { LS.removeItem('vo_rev'); LS.removeItem('vo_wid'); LS.removeItem('vo_rt'); }
      LS.setItem('vo_pv', o.provider || ''); LS.setItem('vo_cfg', JSON.stringify(c)); location.reload();
    };
    Cloud.disconnect = function () { ['vo_cfg', 'vo_rev', 'vo_wid', 'vo_rt', 'vo_key', 'vo_pv', 'vo_dirty'].forEach(function (k) { LS.removeItem(k); }); location.reload(); };
    Cloud.providerHelp = function (p) { return p === 'gdrive' ? 'Register as Authorized JavaScript origin: ' + location.origin : p === 'onedrive' ? 'Register as Single-page application Redirect URI: ' + RU : p === 'dropbox' ? 'Register as Redirect URI: ' + RU : p === 'appwrite' ? 'Register as Web platform hostname: ' + location.hostname : ''; };

    if (!cloudOn) { Cloud.state = 'off'; Cloud.msg = configured ? 'incomplete' : ''; }
    else if (!pass) { Cloud.state = 'fail'; Cloud.msg = 'nokey'; }
    else {
      Cloud.state = 'wait'; paint('Loading...');
      VOEasy.ready = new Promise(function (res) { waitDone = res; setTimeout(function () { if (Cloud.state === 'wait') setState('fail', 'net'); }, 15000); });
      pull();
      var v = CFG.poll === '' || CFG.poll == null ? 30 : +CFG.poll;
      if (v > 0) pt = setInterval(function () { var ae = document.activeElement; if (!pass || need || busy || document.hidden || LS.getItem('vo_dirty') === '1') return; if (ae && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName)) return; pull(true); }, (PN === 'appwrite' ? Math.max(v, 60) : Math.max(v, 10)) * 1000);
      document.addEventListener('visibilitychange', function () { if (!document.hidden && pass && !need && !busy && LS.getItem('vo_dirty') !== '1') pull(true); });
      root.addEventListener('online', function () { if (pass && !need) Cloud.syncNow(); });
    }
    if (!cloudOn) { var st = function () { paint(configured ? 'Cloud setup incomplete' : 'Not connected (data stays in this browser)'); }; if (document.body) st(); else document.addEventListener('DOMContentLoaded', st); }
  })();

  if (typeof module !== 'undefined' && module.exports) module.exports = VOEasy; else root.VOEasy = VOEasy;
})(typeof window !== 'undefined' ? window : globalThis);
