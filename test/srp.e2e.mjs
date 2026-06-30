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
async function post(path, body, jar) {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(jar?.cookie ? { Cookie: jar.cookie } : {}) },
    body: JSON.stringify(body),
  });
  let json = null; try { json = await res.json(); } catch {}
  if (jar) cookieFrom(res, jar);
  return { status: res.status, json };
}
async function get(path, jar) {
  const res = await fetch(BASE + path, { headers: jar?.cookie ? { Cookie: jar.cookie } : {} });
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
  const dur = !!auth.json?.duress;
  const verifier = dur && clientD ? clientD : client;
  return {
    status: auth.status, json: auth.json, duress: dur,
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

  ok(login.duress === false, 'real login is not flagged as duress');

  // 3. Duress password (decoy).
  const DURESS = 'duress-decoy-pass-99';
  const dreg = await register(USER, DURESS);
  const setD = await post('/api/account/duress', { salt: dreg.salt, verifier: dreg.verifier }, jar2);
  ok(setD.status === 200, 'set duress password (computed client-side)');
  const dlogin = await srpLogin(USER, DURESS, {});
  ok(dlogin.status === 200 && dlogin.duress === true, 'duress password logs in, flagged as duress');
  ok(dlogin.serverOK === true, 'server proof verifies on duress login');
  const rlogin = await srpLogin(USER, PASS, {});
  ok(rlogin.status === 200 && rlogin.duress === false, 'real password still logs in as real');

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
