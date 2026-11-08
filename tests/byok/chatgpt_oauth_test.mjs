import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { signInWithChatGPT, chatGPTAccessToken } from '../../bridge/byok/auth/chatgpt-oauth.mjs';

const ISSUER = 'https://auth.openai.com';
const TOKEN = `${ISSUER}/api/accounts/oauth/token`;

function signedIdToken(privateKey, { clientId, nonce, kid = 'nqa-test-key' }) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({
    iss: ISSUER, aud: clientId, nonce, iat: now, exp: now + 3600,
  })).toString('base64url');
  const input = `${header}.${claims}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url');
  return `${input}.${signature}`;
}

function memoryStore() {
  const values = new Map();
  return {
    values,
    async get(k) { return values.get(k) ?? null; },
    async set(k, v) { values.set(k, v); },
    async getLarge(k) { return values.get(`large:${k}`) ?? null; },
    async setLarge(k, v) { values.set(`large:${k}`, v); },
    async deleteLarge(k) { return values.delete(`large:${k}`); },
  };
}

test('ChatGPT OAuth uses PKCE, validates the ID token, and persists refreshable credentials', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'nqa-test-key', use: 'sig', alg: 'RS256' };
  const store = memoryStore();
  let authUrl;
  let nonce;
  let tokenBody;
  const clientId = 'oaiapp_test_client';
  const fetchFn = async (url, options = {}) => {
    if (url === TOKEN) {
      tokenBody = new URLSearchParams(options.body);
      if (tokenBody.get('grant_type') === 'authorization_code') {
        return new Response(JSON.stringify({
          access_token: 'access-token-one',
          refresh_token: 'refresh-token-one',
          id_token: signedIdToken(privateKey, { clientId, nonce }),
          expires_in: 3600,
          scope: 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct',
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      assert.equal(tokenBody.get('grant_type'), 'refresh_token');
      assert.equal(tokenBody.get('refresh_token'), 'refresh-token-one');
      return new Response(JSON.stringify({
        access_token: 'access-token-two',
        refresh_token: 'refresh-token-two',
        expires_in: 3600,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url === `${ISSUER}/.well-known/openid-configuration`) {
      return new Response(JSON.stringify({
        issuer: ISSUER,
        jwks_uri: `${ISSUER}/.well-known/jwks.json`,
        revocation_endpoint: `${ISSUER}/api/accounts/oauth/revoke`,
      }), { status: 200 });
    }
    if (url === `${ISSUER}/.well-known/jwks.json`) {
      return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    }
    throw new Error(`unexpected URL: ${url}`);
  };
  const openExternal = async value => {
    authUrl = new URL(value);
    nonce = authUrl.searchParams.get('nonce');
    const callbackUrl = new URL(authUrl.searchParams.get('redirect_uri'));
    callbackUrl.searchParams.set('code', 'authorization-code');
    callbackUrl.searchParams.set('state', authUrl.searchParams.get('state'));
    callbackUrl.searchParams.set('client_id', clientId);
    const callback = await globalThis.fetch(callbackUrl);
    assert.equal(callback.status, 200);
    return { ok: true };
  };

  const connected = await signInWithChatGPT({ store, openExternal, fetch: fetchFn, timeoutMs: 5000 });
  assert.equal(connected.ok, true);
  assert.equal(authUrl.searchParams.get('client_id'), 'dynamic_agent_client');
  assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authUrl.searchParams.get('scope').split(' ').includes('chatgpt.tokens.use.direct'), true);
  assert.equal(tokenBody.get('client_id'), clientId);
  assert.ok(tokenBody.get('code_verifier'));
  assert.equal(tokenBody.get('redirect_uri'), authUrl.searchParams.get('redirect_uri'));
  assert.match(await store.get('openai-oauth-host-id'), /^urn:uuid:/);

  assert.equal(await chatGPTAccessToken({ store, fetch: fetchFn }), 'access-token-one');
  const saved = JSON.parse(await store.getLarge('openai-oauth'));
  saved.expires_at = Date.now() - 1000;
  await store.setLarge('openai-oauth', JSON.stringify(saved));
  assert.equal(await chatGPTAccessToken({ store, fetch: fetchFn }), 'access-token-two');
  const rotated = JSON.parse(await store.getLarge('openai-oauth'));
  assert.equal(rotated.refresh_token, 'refresh-token-two');
  assert.equal(rotated.access_token, 'access-token-two');
  assert.ok(rotated.expires_at > Date.now());
});

test('ChatGPT OAuth refuses a token without the direct-use scope', async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'nqa-test-key', use: 'sig', alg: 'RS256' };
  const store = memoryStore();
  let nonce;
  const clientId = 'oaiapp_scope_test';
  const fetchFn = async url => {
    if (url === TOKEN) return new Response(JSON.stringify({
      access_token: 'access', refresh_token: 'refresh',
      id_token: signedIdToken(privateKey, { clientId, nonce }), expires_in: 3600,
      scope: 'openid profile email offline_access resource.invoke',
    }), { status: 200 });
    if (url === `${ISSUER}/.well-known/openid-configuration`) return new Response(JSON.stringify({
      issuer: ISSUER, jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    }), { status: 200 });
    if (url === `${ISSUER}/.well-known/jwks.json`) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
    throw new Error('unexpected URL');
  };
  const openExternal = async value => {
    const auth = new URL(value);
    nonce = auth.searchParams.get('nonce');
    const callbackUrl = new URL(auth.searchParams.get('redirect_uri'));
    callbackUrl.searchParams.set('code', 'code');
    callbackUrl.searchParams.set('state', auth.searchParams.get('state'));
    callbackUrl.searchParams.set('client_id', clientId);
    await globalThis.fetch(callbackUrl);
    return { ok: true };
  };
  await assert.rejects(
    signInWithChatGPT({ store, openExternal, fetch: fetchFn, timeoutMs: 5000 }),
    /oauth_required_scope_missing/,
  );
  assert.equal(await store.getLarge('openai-oauth'), null);
});
