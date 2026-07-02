/**
 * Live end-to-end SRP test: drives the real web/js/srp.js against a running server.
 *
 *   DD_URL=http://127.0.0.1:8100 DD_INVITE=DD-XXXX-XXXX-XXXX node test/srp.e2e.mjs
 *
 * Registers a throwaway SRP account, logs in (zero-knowledge), checks mutual auth
 * and the session, verifies wrong-password and legacy-account paths, then deletes
 * the throwaway account. Exits non-zero on any failure.
 */

import { register, ClientLogin } from '../web/js/srp.js';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITE = process.env.DD_INVITE || '';
const USER = 'zz_srp_e2e_' + Math.floor(Math.random() * 1e6);
const PASS = 'a-very-strong-passphrase-42';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

function cookieFrom(res, jar) {
  const sc = res.headers.get('set-cookie');
  if (sc) jar.cookie = sc.split(';')[0];
  return jar;
}
// The whole run exceeds the per-IP auth rate limit (that limit has its own Go
// unit tests). The server trusts X-Forwarded-For from loopback, so each request
// presents a fresh client IP to keep this test about SRP, not throttling.
let ipCounter = 0;
const nextIP = () => `198.51.100.${ipCounter++ % 250}`;
async function post(path, body, jar) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-For': nextIP(),
      ...(jar?.cookie ? { Cookie: jar.cookie } : {}),
    },
    body: JSON.stringify(body),
  });
  let json = null; try { json = await res.json(); } catch {}
  if (jar) cookieFrom(res, jar);
  return { status: res.status, json };
}
async function get(path, jar) {
  const res = await fetch(BASE + path, {
    headers: { 'X-Forwarded-For': nextIP(), ...(jar?.cookie ? { Cookie: jar.cookie } : {}) },
  });
  let json = null; try { json = await res.json(); } catch {}
  return { status: res.status, json };
}

async function srpLogin(username, password, jar) {
  const client = new ClientLogin(username, password);
  const ch = await post('/api/srp/challenge', { username, A: client.start().A }, null);
  if (ch.json?.legacy) return { legacy: true };
  if (ch.status !== 200) return { status: ch.status };
  const { M1 } = await client.finish(ch.json.salt, ch.json.B);
  let M1d = '', clientD = null;
  if (ch.json.salt2 && ch.json.B2) {
    clientD = new ClientLogin(username, password, client.a);
    clientD.start();
    M1d = (await clientD.finish(ch.json.salt2, ch.json.B2)).M1;
  }
  const auth = await post('/api/srp/authenticate', { token: ch.json.token, M1, M1d }, jar);
  // The decoy signal is deliberately opaque: a restricted feature list (no
  // "settings") means the duress proof matched, never a literal duress flag.
  const restricted = auth.status === 200 && !(auth.json?.features || []).includes('settings');
  const verifier = restricted && clientD ? clientD : client;
  return {
    status: auth.status, json: auth.json, restricted,
    serverOK: auth.json?.M2 ? verifier.verifyServer(auth.json.M2) : false,
  };
}

(async () => {
  console.log(`SRP e2e against ${BASE} as ${USER}`);
  if (!INVITE) { console.error('  ✗ set DD_INVITE'); process.exit(1); }

  // 1. Register (zero-knowledge: only salt + verifier leave the browser).
  const reg = await register(USER, PASS);
  ok(!/[^0-9a-f]/.test(reg.verifier) && reg.verifier.length > 400, 'verifier computed client-side');
  const jar = {};
  const r = await post('/api/srp/register', { username: USER, salt: reg.salt, verifier: reg.verifier, invite: INVITE }, jar);
  ok(r.status === 200 && r.json.username === USER, 'SRP registration succeeds with invite');

  // 2. Fresh login.
  const jar2 = {};
  const login = await srpLogin(USER, PASS, jar2);
  ok(login.status === 200, 'SRP login returns 200');
  ok(login.serverOK === true, 'client verifies server proof M2 (mutual auth)');
  const me = await get('/api/me', jar2);
  ok(me.status === 200 && me.json.username === USER, 'session works (/api/me)');

  ok(login.restricted === false, 'real login gets the full feature list');
  ok(!('duress' in (login.json || {})), 'authenticate response never says "duress"');
  ok(!('duress' in (me.json || {})), '/api/me response never says "duress"');

  // 3. Duress password (decoy).
  const DURESS = 'duress-decoy-pass-99';
  const dreg = await register(USER, DURESS);
  const setD = await post('/api/account/duress', { salt: dreg.salt, verifier: dreg.verifier }, jar2);
  ok(setD.status === 200, 'set duress password (computed client-side)');
  const djar = {};
  const dlogin = await srpLogin(USER, DURESS, djar);
  ok(dlogin.status === 200 && dlogin.restricted === true, 'duress password logs into a restricted (decoy) session');
  ok(dlogin.serverOK === true, 'server proof verifies on duress login');
  ok(!('duress' in (dlogin.json || {})), 'decoy response carries no telltale duress field');
  const rlogin = await srpLogin(USER, PASS, {});
  ok(rlogin.status === 200 && rlogin.restricted === false, 'real password still logs in as real');

  // 3b. Decoy-session hardening.
  //  - "Change password" from the decoy must update the DURESS credential only.
  const NEWDURESS = 'coercer-changed-pass-1';
  const nreg = await register(USER, NEWDURESS);
  const chg = await post('/api/account/verifier', { salt: nreg.salt, verifier: nreg.verifier }, djar);
  ok(chg.status === 200, 'password change from decoy session is accepted');
  const rlogin2 = await srpLogin(USER, PASS, {});
  ok(rlogin2.status === 200 && rlogin2.restricted === false, 'real password unaffected by decoy password change');
  const dlogin2 = await srpLogin(USER, NEWDURESS, {});
  ok(dlogin2.status === 200 && dlogin2.restricted === true, 'decoy password change updated the duress credential');
  //  - Setting a duress password from the decoy must fake success (no 403 tell)
  //    without touching anything.
  const xreg = await register(USER, 'probe-from-decoy-1234');
  const probe = await post('/api/account/duress', { salt: xreg.salt, verifier: xreg.verifier }, djar);
  ok(probe.status === 200, 'duress-set from decoy answers 200 (no detectable 403)');
  const dlogin3 = await srpLogin(USER, NEWDURESS, {});
  ok(dlogin3.status === 200 && dlogin3.restricted === true, 'duress-set from decoy was a no-op');

  // 4. A third (neither) password must fail.
  const bad = await srpLogin(USER, 'totally-wrong-password', {});
  ok(bad.status === 401, 'wrong password rejected (401)');

  // 4. Legacy account detection.
  const legacy = await srpLogin('Micu', 'whatever', {});
  ok(legacy.legacy === true, 'legacy bcrypt account flagged for fallback');

  // 5. Cleanup: delete the throwaway account.
  const del = await post('/api/account/delete', {}, jar2);
  ok(del.status === 200, 'account self-delete works');
  const gone = await get('/api/me', jar2);
  ok(gone.status === 401, 'session cleared after delete');

  console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
  process.exit(failures === 0 ? 0 : 1);
})();
