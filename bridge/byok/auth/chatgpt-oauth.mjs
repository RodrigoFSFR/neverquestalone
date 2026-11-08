// ChatGPT plan OAuth for the desktop bridge.
// This module is deliberately independent of Electron and the provider registry so it can be
// tested with injected fetch/openExternal/store implementations. Never treat these credentials
// as an API key. OpenAI's OAuth terms and eligibility apply.
import crypto from 'node:crypto';
import http from 'node:http';

const AUTH = 'https://auth.openai.com/api/accounts/authorize';
const TOKEN = 'https://auth.openai.com/api/accounts/oauth/token';
const ISSUER = 'https://auth.openai.com';
const RESOURCE = 'https://api.openai.com/v1';
const SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const HOST_ID = 'urn:uuid:8a42b130-51d1-4f1b-9c0d-1f0cbf9e88a2';

const b64url = b => Buffer.from(b).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(s).digest('base64url');
const form = o => new URLSearchParams(Object.entries(o).filter(([,v]) => v != null).map(([k,v]) => [k,String(v)]));

async function json(res) {
  const body = await res.text();
  let value;
  try { value = JSON.parse(body); } catch { throw new Error('oauth_invalid_response'); }
  if (!res.ok) {
    const e = new Error(value.error_description || value.error || `oauth_http_${res.status}`);
    e.code = value.error || 'oauth_failed';
    throw e;
  }
  return value;
}

// Verify ID-token signature and all OIDC binding claims. Unknown algorithms and key types fail closed.
async function verifyIdToken(token, { clientId, nonce, fetch: fetchFn }) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('oauth_bad_id_token');
  let header, claims;
  try { header = JSON.parse(Buffer.from(parts[0], 'base64url')); claims = JSON.parse(Buffer.from(parts[1], 'base64url')); }
  catch { throw new Error('oauth_bad_id_token'); }
  if (!['RS256','ES256'].includes(header.alg) || !header.kid) throw new Error('oauth_bad_id_token');
  const jwksRes = await fetchFn(`${ISSUER}/.well-known/jwks.json`, { headers: { accept: 'application/json' }, redirect: 'error' });
  const jwks = await json(jwksRes);
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid && k.alg === header.alg);
  if (!jwk) throw new Error('oauth_bad_id_token_key');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');
  const valid = header.alg === 'RS256'
    ? crypto.verify('RSA-SHA256', signed, key, signature)
    : crypto.verify('sha256', signed, { key, dsaEncoding: 'ieee-p1363' }, signature);
  const now = Math.floor(Date.now()/1000);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!valid || claims.iss !== ISSUER || !aud.includes(clientId) || claims.nonce !== nonce ||
      !Number.isFinite(claims.exp) || claims.exp <= now || (claims.nbf && claims.nbf > now + 60)) {
    throw new Error('oauth_id_token_validation_failed');
  }
  return claims;
}

/**
 * Start first-time or returning ChatGPT sign-in.
 * store.get/set/delete use the existing OS-backed keystore; persist one JSON bundle under provider id.
 * openExternal(url) must open the user's system browser. The callback binds only to 127.0.0.1.
 */
export async function signInWithChatGPT({ store, openExternal, fetch: fetchFn = globalThis.fetch, timeoutMs = 180000 } = {}) {
  if (!store || typeof store.get !== 'function' || typeof store.set !== 'function' || typeof openExternal !== 'function') {
    throw new TypeError('store and openExternal are required');
  }
  const priorRaw = await store.getLarge('openai-oauth');
  let prior = null;
  try { prior = priorRaw ? JSON.parse(priorRaw) : null; } catch {}
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = sha256(verifier);
  const state = b64url(crypto.randomBytes(32));
  const nonce = b64url(crypto.randomBytes(32));
  const server = http.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const redirectUri = `http://127.0.0.1:${address.port}/auth/callback`;
  let callbackResolve, callbackReject;
  const callback = new Promise((resolve, reject) => { callbackResolve = resolve; callbackReject = reject; });
  server.on('request', (req, res) => {
    const url = new URL(req.url, redirectUri);
    if (url.pathname !== '/auth/callback') { res.writeHead(404).end(); return; }
    if (url.searchParams.get('state') !== state) {
      res.writeHead(400).end('Sign-in state mismatch. You can close this tab.');
      callbackReject(new Error('oauth_state_mismatch')); return;
    }
    if (url.searchParams.has('error')) {
      res.writeHead(400).end('Sign-in was not completed. You can close this tab.');
      callbackReject(new Error(url.searchParams.get('error'))); return;
    }
    const code = url.searchParams.get('code');
    const issuedClientId = url.searchParams.get('client_id') || prior?.client_id || null;
    if (!code || !issuedClientId) {
      res.writeHead(400).end('Missing sign-in response. You can close this tab.');
      callbackReject(new Error('oauth_missing_code')); return;
    }
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end('NeverQuestAlone sign-in complete. You can close this tab.');
    callbackResolve({ code, issuedClientId });
  });
  const clientId = prior?.client_id || 'dynamic_agent_client';
  const auth = new URL(AUTH);
  Object.entries({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope: SCOPES,
    resource: RESOURCE, code_challenge: challenge, code_challenge_method: 'S256',
    state, nonce, ext_agent_host_id: HOST_ID,
    ...(!prior ? { agent_name_hint: 'NeverQuestAlone' } : {}),
    ...(prior?.id_token ? { id_token_hint: prior.id_token } : {}),
  }).forEach(([k,v]) => auth.searchParams.set(k,v));
  let timer;
  try {
    await openExternal(auth.href);
    const result = await Promise.race([
      callback,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('oauth_timeout')), timeoutMs); }),
    ]);
    const tokens = await json(await fetchFn(TOKEN, {
      method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form({ grant_type: 'authorization_code', client_id: result.issuedClientId, code: result.code,
        code_verifier: verifier, redirect_uri: redirectUri, resource: RESOURCE }),
    }));
    if (!tokens.access_token || !tokens.refresh_token || !tokens.id_token ||
        !String(tokens.scope || '').split(/\s+/).includes('chatgpt.tokens.use.direct')) {
      throw new Error('oauth_required_scope_missing');
    }
    await verifyIdToken(tokens.id_token, { clientId: result.issuedClientId, nonce, fetch: fetchFn });
    const bundle = { client_id: result.issuedClientId, access_token: tokens.access_token,
      refresh_token: tokens.refresh_token, id_token: tokens.id_token,
      expires_at: Date.now() + Number(tokens.expires_in || 0) * 1000 };
    await store.setLarge('openai-oauth', JSON.stringify(bundle));
    return { ok: true, expiresAt: bundle.expires_at };
  } finally {
    clearTimeout(timer);
    await new Promise(resolve => server.close(resolve));
  }
}

/** Refresh and atomically replace rotating credentials before returning an access token. */
export async function chatGPTAccessToken({ store, fetch: fetchFn = globalThis.fetch, now = Date.now } = {}) {
  const raw = await store.getLarge('openai-oauth');
  if (!raw) throw new Error('oauth_not_connected');
  let saved;
  try { saved = JSON.parse(raw); } catch { throw new Error('oauth_credentials_corrupt'); }
  if (saved.expires_at > now() + 60_000) return saved.access_token;
  const tokens = await json(await fetchFn(TOKEN, {
    method: 'POST', redirect: 'error',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: form({ grant_type: 'refresh_token', client_id: saved.client_id, refresh_token: saved.refresh_token, resource: RESOURCE }),
  }));
  if (!tokens.access_token || !tokens.refresh_token) throw new Error('oauth_refresh_invalid_response');
  const next = { ...saved, access_token: tokens.access_token, refresh_token: tokens.refresh_token,
    id_token: tokens.id_token || saved.id_token, expires_at: now() + Number(tokens.expires_in || 0) * 1000 };
  await store.setLarge('openai-oauth', JSON.stringify(next));
  return next.access_token;
}

export async function disconnectChatGPT({ store, fetch: fetchFn = globalThis.fetch } = {}) {
  const raw = await store.getLarge('openai-oauth');
  if (!raw) return { ok: true };
  let saved;
  try { saved = JSON.parse(raw); } catch { saved = null; }
  if (saved?.refresh_token) {
    try {
      await fetchFn(`${ISSUER}/api/accounts/oauth/revoke`, {
        method: 'POST', redirect: 'error',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form({ token: saved.refresh_token, token_type_hint: 'refresh_token', client_id: saved.client_id }),
      });
    } catch { /* local deletion still takes precedence */ }
  }
  await store.deleteLarge('openai-oauth');
  return { ok: true };
}

export const CHATGPT_OAUTH = Object.freeze({ authUrl: AUTH, tokenUrl: TOKEN, resource: RESOURCE, scopes: SCOPES, hostId: HOST_ID });
