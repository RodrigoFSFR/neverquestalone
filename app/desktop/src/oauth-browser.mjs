// Validate the one URL the app may hand to the operating system's default browser.
// Renderer navigation remains locked to nqa://app; this is only the OpenAI OAuth authorize endpoint.
export function isChatGPTAuthorizationUrl(raw) {
  let url;
  try { url = new URL(String(raw)); } catch { return false; }
  if (url.protocol !== 'https:' || url.hostname !== 'auth.openai.com' || url.port ||
      url.username || url.password || url.pathname !== '/api/accounts/authorize' || url.hash) return false;

  const q = url.searchParams;
  if (q.get('response_type') !== 'code' || !q.get('client_id') ||
      q.get('resource') !== 'https://api.openai.com/v1' ||
      q.get('code_challenge_method') !== 'S256' ||
      !/^[A-Za-z0-9_-]{40,128}$/.test(q.get('code_challenge') || '') ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(q.get('state') || '') ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(q.get('nonce') || '') ||
      !String(q.get('scope') || '').split(/\\s+/).includes('chatgpt.tokens.use.direct') ||
      !/^urn:uuid:[0-9a-f-]{36}$/i.test(q.get('ext_agent_host_id') || '')) return false;

  let redirect;
  try { redirect = new URL(q.get('redirect_uri') || ''); } catch { return false; }
  if (redirect.protocol !== 'http:' || redirect.hostname !== '127.0.0.1' ||
      redirect.username || redirect.password || redirect.pathname !== '/auth/callback' ||
      redirect.search || redirect.hash || !/^\\d+$/.test(redirect.port)) return false;
  const port = Number(redirect.port);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}
