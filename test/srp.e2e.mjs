/**
 * Live end-to-end SRP test: drives the real web/js/srp.js against a running server.
 *
 *   DD_URL=http://127.0.0.1:8100 DD_INVITE=DD-XXXX-XXXX-XXXX node test/srp.e2e.mjs
 *
 * Registers a throwaway SRP account, logs in (zero-knowledge), checks mutual auth
 * and the session, verifies the wrong-password and duress paths, then deletes the
 * throwaway account. Exits non-zero on any failure.
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
  if (ch.status !== 200) return { status: ch.status };
  const { M1 } = await client.finish(ch.json.salt, ch.json.B, ch.json.kdf);
  let M1d = '', clientD = null;
  if (ch.json.salt2 && ch.json.B2) {
    clientD = new ClientLogin(username, password, client.a);
    clientD.start();
    M1d = (await clientD.finish(ch.json.salt2, ch.json.B2, ch.json.kdf2)).M1;
  }
  const auth = await post('/api/srp/authenticate', { token: ch.json.token, M1, M1d }, jar);
  srpLogin.lastChallenge = ch.json;
  // Detect which credential won only by checking the server proof against the
  // two local transcripts. The API response and feature list remain identical.
  const primaryOK = !!auth.json?.M2 && client.verifyServer(auth.json.M2);
  const duressOK = !!auth.json?.M2 && !!clientD && clientD.verifyServer(auth.json.M2);
  const usedDuress = !primaryOK && duressOK;
  return {
    status: auth.status, json: auth.json, usedDuress,
    serverOK: primaryOK || duressOK,
  };
}

(async () => {
  console.log(`SRP e2e against ${BASE} as ${USER}`);
  if (!INVITE) { console.error('  ✗ set DD_INVITE'); process.exit(1); }

  // 1. Register (zero-knowledge: only salt + verifier leave the browser; the
  //    password is PBKDF2-stretched before the SRP x derivation).
  const reg = await register(USER, PASS);
  ok(!/[^0-9a-f]/.test(reg.verifier) && reg.verifier.length > 400, 'verifier computed client-side');
  ok(reg.kdf === 'pbkdf2:600000', 'registration uses the PBKDF2 stretch by default');
  const jar = {};
  const r = await post('/api/srp/register', { username: USER, salt: reg.salt, verifier: reg.verifier, kdf: reg.kdf, invite: INVITE }, jar);
  ok(r.status === 200 && r.json.username === USER, 'SRP registration succeeds with invite');

  // 2. Fresh login.
  const jar2 = {};
  const login = await srpLogin(USER, PASS, jar2);
  ok(login.status === 200, 'SRP login returns 200');
  ok(login.serverOK === true, 'client verifies server proof M2 (mutual auth)');
  ok(srpLogin.lastChallenge?.kdf === reg.kdf, 'challenge advertises the stored kdf');
  const me = await get('/api/me', jar2);
  ok(me.status === 200 && me.json.username === USER, 'session works (/api/me)');

  ok(login.usedDuress === false, 'real login authenticates the primary transcript');
  ok(!('duress' in (login.json || {})), 'authenticate response never says "duress"');
  ok(!('duress' in (me.json || {})), '/api/me response never says "duress"');

  // 3. Duress password (decoy).
  const DURESS = 'duress-decoy-pass-99';
  const dreg = await register(USER, DURESS);
  const setD = await post('/api/account/duress', { salt: dreg.salt, verifier: dreg.verifier, kdf: dreg.kdf }, jar2);
  ok(setD.status === 200, 'set duress password (computed client-side)');
  const djar = {};
  const dlogin = await srpLogin(USER, DURESS, djar);
  ok(dlogin.status === 200 && dlogin.usedDuress === true, 'duress password authenticates the decoy transcript');
  ok(dlogin.serverOK === true, 'server proof verifies on duress login');
  ok(!('duress' in (dlogin.json || {})), 'decoy response carries no telltale duress field');
  ok(JSON.stringify(dlogin.json?.features) === JSON.stringify(login.json?.features),
     'primary and duress responses expose identical feature lists');
  const rlogin = await srpLogin(USER, PASS, {});
  ok(rlogin.status === 200 && rlogin.usedDuress === false, 'real password still logs in as real');

  // 3b. Decoy-session hardening.
  //  - "Change password" from the decoy must update the DURESS credential only.
  const NEWDURESS = 'coercer-changed-pass-1';
  const nreg = await register(USER, NEWDURESS);
  const chg = await post('/api/account/verifier', { salt: nreg.salt, verifier: nreg.verifier, kdf: nreg.kdf }, djar);
  ok(chg.status === 200, 'password change from decoy session is accepted');
  const rlogin2 = await srpLogin(USER, PASS, {});
  ok(rlogin2.status === 200 && rlogin2.usedDuress === false, 'real password unaffected by decoy password change');
  const dlogin2 = await srpLogin(USER, NEWDURESS, {});
  ok(dlogin2.status === 200 && dlogin2.usedDuress === true, 'decoy password change updated the duress credential');
  //  - Setting a duress password from the decoy must fake success (no 403 tell)
  //    without touching anything.
  const xreg = await register(USER, 'probe-from-decoy-1234');
  const probe = await post('/api/account/duress', { salt: xreg.salt, verifier: xreg.verifier, kdf: xreg.kdf }, djar);
  ok(probe.status === 200, 'duress-set from decoy answers 200 (no detectable 403)');
  const dlogin3 = await srpLogin(USER, NEWDURESS, {});
  ok(dlogin3.status === 200 && dlogin3.usedDuress === true, 'duress-set from decoy was a no-op');

  // Deleting from a decoy session must look successful without deleting the
  // primary account. Use a fresh decoy session because delete logs it out.
  const deleteDecoyJar = {};
  const deleteDecoyLogin = await srpLogin(USER, NEWDURESS, deleteDecoyJar);
  const decoyDelete = await post('/api/account/delete', {}, deleteDecoyJar);
  ok(deleteDecoyLogin.usedDuress === true && decoyDelete.status === 200,
     'account delete from decoy reports success');
  const afterDecoyDelete = await srpLogin(USER, PASS, {});
  ok(afterDecoyDelete.status === 200 && afterDecoyDelete.usedDuress === false,
     'decoy deletion leaves the primary account intact');

  // 4. A third (neither) password must fail.
  const bad = await srpLogin(USER, 'totally-wrong-password', {});
  ok(bad.status === 401, 'wrong password rejected (401)');

  // 4. There is no password-carrying endpoint left for a hostile server to
  //    downgrade a client to. Both removed routes must fall through to the static
  //    handler (405/404) rather than reaching any auth code.
  for (const path of ['/api/login', '/api/register']) {
    const res = await fetch(BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: USER, password: PASS }),
    });
    const body = await res.text();
    ok([404, 405].includes(res.status) && !body.includes('"username"'),
      `${path} accepts no password (${res.status})`);
  }

  // 4b. Anti-enumeration: an unknown username gets a challenge that looks exactly
  //     like a fresh account's, including the default kdf.
  const ghost = new ClientLogin('zz_ghost_none', 'x');
  const gch = await post('/api/srp/challenge', { username: 'zz_ghost_none', A: ghost.start().A }, null);
  ok(gch.status === 200 && gch.json.kdf === 'pbkdf2:600000' && gch.json.kdf2 === 'pbkdf2:600000',
     'unknown-user challenge advertises the default kdf');

  // 4c. Authenticated clients cannot persistently downgrade the password KDF.
  // Old kdf-less records remain readable and the browser upgrades them on login,
  // but all newly written credentials must meet the current minimum.
  const weakReg = await register(USER, PASS, 'pbkdf2:10000');
  const down = await post('/api/account/verifier', weakReg, jar2);
  ok(down.status === 400, 'verifier endpoint rejects a weak KDF downgrade');
  const afterDown = await srpLogin(USER, PASS, {});
  ok(afterDown.status === 200 && afterDown.serverOK === true && srpLogin.lastChallenge?.kdf === reg.kdf,
     'rejected downgrade leaves the stretched credential intact');

  // 5. Cleanup: delete the throwaway account.
  const del = await post('/api/account/delete', {}, jar2);
  ok(del.status === 200, 'account self-delete works');
  const gone = await get('/api/me', jar2);
  ok(gone.status === 401, 'session cleared after delete');

  console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
  process.exit(failures === 0 ? 0 : 1);
})();
