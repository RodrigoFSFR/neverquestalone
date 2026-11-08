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
const HOST_ID_STORE = 'openai-oauth-host-id';
const HOST_ID_RE = /^urn:uuid:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

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
async function oidcMetadata(fetchFn) {
  const metadata = await json(await fetchFn(`${ISSUER}/.well-known/openid-configuration`, {
    headers: { accept: 'application/json' }, redirect: 'error',
  }));
  if (metadata.issuer !== ISSUER) throw new Error('oauth_issuer_mismatch');
  return metadata;
}

function trustedIssuerUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.hostname === 'auth.openai.com' && !u.username && !u.password ? u.href : null;
  } catch { return null; }
}

// Verify the ID-token signature and all OIDC binding claims. Unknown algorithms and key types fail closed.
async function verifyIdToken(token, { clientId, nonce, fetch: fetchFn, metadata }) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('oauth_bad_id_token');
  let header, claims;
  try { header = JSON.parse(Buffer.from(parts[0], 'base64url')); claims = JSON.parse(Buffer.from(parts[1], 'base64url')); }
  catch { throw new Error('oauth_bad_id_token'); }
  if (!['RS256','ES256'].includes(header.alg) || !header.kid) throw new Error('oauth_bad_id_token');
  const jwksUrl = trustedIssuerUrl(metadata?.jwks_uri);
  if (!jwksUrl) throw new Error('oauth_bad_jwks_uri');
  const jwks = await json(await fetchFn(jwksUrl, { headers: { accept: 'application/json' }, redirect: 'error' }));
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid &&
    (k.use == null || k.use === 'sig') && (!Array.isArray(k.key_ops) || k.key_ops.includes('verify')) &&
    (header.alg === 'RS256' ? k.kty === 'RSA' : k.kty === 'EC' && k.crv === 'P-256'));
  if (!jwk) throw new Error('oauth_bad_id_token_key');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');
  const valid = header.alg === 'RS256'
    ? crypto.verify('RSA-SHA256', signed, key, signature)
    : crypto.verify('sha256', signed, { key, dsaEncoding: 'ieee-p1363' }, signature);
  const now = Math.floor(Date.now()/1000);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  const authorizedPartyOk = aud.length <= 1 ? (claims.azp == null || claims.azp === clientId) : claims.azp === clientId;
  if (!valid || claims.iss !== ISSUER || !aud.includes(clientId) || !authorizedPartyOk ||
      claims.nonce !== nonce || !Number.isFinite(claims.iat) || claims.iat > now + 60 ||
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
  let hostId = await store.get(HOST_ID_STORE);
  if (!HOST_ID_RE.test(hostId || '')) {
    hostId = `urn:uuid:${crypto.randomUUID()}`;
    await store.set(HOST_ID_STORE, hostId);
  }
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
    state, nonce, ext_agent_host_id: hostId,
    ...(!prior ? { agent_name_hint: 'neverquestalone' } : {}),
    ...(prior?.id_token ? { id_token_hint: prior.id_token } : {}),
  }).forEach(([k,v]) => auth.searchParams.set(k,v));
  let timer;
  try {
    const opened = await openExternal(auth.href);
    if (opened?.ok === false) throw new Error('oauth_browser_open_failed');
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
    const metadata = await oidcMetadata(fetchFn);
    await verifyIdToken(tokens.id_token, { clientId: result.issuedClientId, nonce, fetch: fetchFn, metadata });
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
      const metadata = await oidcMetadata(fetchFn);
      const endpoint = trustedIssuerUrl(metadata.revocation_endpoint);
      if (endpoint) await fetchFn(endpoint, {
        method: 'POST', redirect: 'error',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form({ token: saved.refresh_token, token_type_hint: 'refresh_token', client_id: saved.client_id }),
      });
    } catch { /* local deletion still takes precedence */ }
  }
  await store.deleteLarge('openai-oauth');
  return { ok: true };
}

export const CHATGPT_OAUTH = Object.freeze({ authUrl: AUTH, tokenUrl: TOKEN, resource: RESOURCE, scopes: SCOPES, hostIdStore: HOST_ID_STORE });
