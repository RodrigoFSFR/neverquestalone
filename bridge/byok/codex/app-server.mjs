// A tightly-scoped Codex app-server smoke test using the documented ChatGPT-plan token handoff.
// It deliberately starts with a fresh CODEX_HOME and empty workspace: no user MCP servers,
// project instructions, or existing workspace files are exposed to this one-turn check.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const PROVIDER_CONFIG = [
  ['model_provider="openai_chatgpt_plan"'],
  ['model_providers.openai_chatgpt_plan.name="ChatGPT plan"'],
  ['model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"'],
  ['model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN"'],
  ['model_providers.openai_chatgpt_plan.wire_api="responses"'],
  ['model_providers.openai_chatgpt_plan.requires_openai_auth=false'],
  ['model_providers.openai_chatgpt_plan.supports_websockets=false'],
  ['sandbox_mode="read-only"'],
  ['approval_policy="never"'],
].flat();

const isObj = v => !!v && typeof v === 'object' && !Array.isArray(v);
const error = code => Object.assign(new Error(code), { code });

/**
 * Exercise the local Codex app-server once with the current ChatGPT OAuth token.
 * The token is passed only via ACCESS_TOKEN in the child environment, never as an argument,
 * config value, file, IPC return value, or log entry.
 */
export async function testCodexAppServer({
  accessToken,
  spawnProcess = spawn,
  platform = process.platform,
  timeoutMs = 45_000,
  version = '1.4.19',
} = {}) {
  if (typeof accessToken !== 'string' || !accessToken) throw error('oauth_not_connected');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'neverquestalone-codex-'));
  const home = path.join(root, 'codex-home');
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  fs.mkdirSync(workspace, { recursive: true, mode: 0o700 });
  const args = ['app-server', '--listen', 'stdio://', ...PROVIDER_CONFIG.flatMap(v => ['-c', v])];
  const env = {
    ...process.env,
    CODEX_HOME: home,
    ACCESS_TOKEN: accessToken,
  };
  // npm installs a .cmd shim on Windows. shell:true is used only with fixed, literal arguments;
  // the OAuth token is supplied through the environment and never participates in shell parsing.
  const child = spawnProcess('codex', args, {
    cwd: workspace, env, stdio: ['pipe', 'pipe', 'pipe'],
    ...(platform === 'win32' ? { shell: true, windowsHide: true } : {}),
  });

  let stderr = '';
  let sequence = 0;
  const pending = new Map();
  let completed = null;
  let completionResolve;
  let completionReject;
  const turnDone = new Promise((resolve, reject) => { completionResolve = resolve; completionReject = reject; });
  // A process that dies before turn/start must not leave an unhandled turn waiter.
  turnDone.catch(() => {});
  let closed = false;
  const send = value => {
    if (closed || child.stdin.destroyed) throw error('codex_process_closed');
    child.stdin.write(JSON.stringify(value) + '\n');
  };
  const request = (method, params) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject });
    try { send({ id, method, params }); }
    catch (e) { pending.delete(id); reject(e); }
  });
  const notify = method => send({ method });

  const lines = createInterface({ input: child.stdout });
  lines.on('line', line => {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    if (!isObj(msg)) return;
    if (Object.hasOwn(msg, 'id') && pending.has(msg.id)) {
      const p = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) p.reject(error('codex_rpc_error'));
      else p.resolve(msg.result);
      return;
    }
    if (msg.method === 'turn/completed') {
      const status = msg.params?.turn?.status ?? msg.params?.status ?? null;
      completed = status;
      completionResolve(status);
    }
  });
  child.stderr.on('data', chunk => {
    if (stderr.length < 4096) stderr += String(chunk).slice(0, 4096 - stderr.length);
  });
  child.on('error', e => {
    closed = true;
    const code = e?.code === 'ENOENT' ? 'codex_not_installed' : 'codex_start_failed';
    for (const p of pending.values()) p.reject(error(code));
    pending.clear();
    completionReject(error(code));
  });
  child.on('close', code => {
    closed = true;
    for (const p of pending.values()) p.reject(error('codex_process_closed'));
    pending.clear();
    if (completed === null) completionReject(error(stderr.toLowerCase().includes('not recognized') ? 'codex_not_installed' : 'codex_process_closed'));
  });

  let timeout;
  const deadline = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      try { child.kill(); } catch {}
      reject(error('codex_timeout'));
    }, timeoutMs);
    timeout.unref?.();
  });

  try {
    const operation = (async () => {
      await request('initialize', {
        clientInfo: { name: 'neverquestalone', title: 'NeverQuestAlone', version: String(version) },
      });
      notify('initialized');
      const thread = await request('thread/start', {
        modelProvider: 'openai_chatgpt_plan',
        cwd: workspace,
        sandbox: 'read-only',
        approvalPolicy: 'never',
        ephemeral: true,
        developerInstructions: 'This is a connectivity test. Do not use tools, do not inspect files, and do not run commands. Reply with exactly the word OK.',
      });
      const threadId = thread?.thread?.id;
      if (typeof threadId !== 'string' || !threadId) throw error('codex_bad_thread');
      await request('turn/start', {
        threadId,
        input: [{ type: 'text', text: 'Reply with exactly OK.' }],
        cwd: workspace,
        sandboxPolicy: { type: 'readOnly', networkAccess: false },
        approvalPolicy: 'never',
      });
      const status = await turnDone;
      if (status !== 'completed') throw error('codex_turn_failed');
      return { ok: true, status: 'completed' };
    })();
    return await Promise.race([operation, deadline]);
  } catch (e) {
    const code = ['codex_not_installed', 'codex_start_failed', 'codex_process_closed', 'codex_timeout',
      'codex_rpc_error', 'codex_bad_thread', 'codex_turn_failed', 'oauth_not_connected'].includes(e?.code)
      ? e.code : 'codex_failed';
    throw error(code);
  } finally {
    if (timeout) clearTimeout(timeout);
    closed = true;
    try { child.kill(); } catch {}
    try { lines.close(); } catch {}
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  }
}
