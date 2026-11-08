import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import fs from 'node:fs';
import { testCodexAppServer } from '../../bridge/byok/codex/app-server.mjs';

function fakeSpawn({ complete = true, exitAfter = false, stallAt = null } = {}) {
  const calls = [];
  const spawn = (command, args, options) => {
    const child = new EventEmitter();
    child.stdin = {
      destroyed: false,
      write(line) {
        const msg = JSON.parse(line);
        calls.push(msg);
        if (!msg.id || msg.method === stallAt) return true;
        let result = {};
        if (msg.method === 'thread/start') result = { thread: { id: 'thread-test' } };
        if (msg.method === 'turn/start') result = { turn: { id: 'turn-test', status: 'inProgress' } };
        child.stdout.write(JSON.stringify({ id: msg.id, result }) + '\n');
        if (msg.method === 'turn/start' && complete) {
          setImmediate(() => child.stdout.write(JSON.stringify({
            method: 'turn/completed', params: { turn: { id: 'turn-test', status: 'completed' } },
          }) + '\n'));
        } else if (msg.method === 'turn/start' && exitAfter) {
          setImmediate(() => child.emit('close', 1));
        }
        return true;
      },
    };
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => { child.stdin.destroyed = true; return true; };
    spawn.last = { command, args, options, child };
    return child;
  };
  spawn.calls = calls;
  return spawn;
}

test('Codex app-server uses the documented OAuth environment handoff and isolated read-only workspace', async () => {
  const spawn = fakeSpawn();
  const result = await testCodexAppServer({ accessToken: 'test-access-token', spawnProcess: spawn, platform: 'linux', timeoutMs: 1000, version: 'test' });
  assert.deepEqual(result, { ok: true, status: 'completed' });
  assert.equal(spawn.last.command, 'codex');
  assert.ok(spawn.last.args.includes('model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN"'));
  assert.ok(spawn.last.options.env.ACCESS_TOKEN === 'test-access-token');
  assert.ok(spawn.last.options.env.CODEX_HOME);
  assert.ok(fs.existsSync(spawn.last.options.cwd) === false, 'temporary workspace is removed after the test');
  assert.deepEqual(spawn.calls[0].params.clientInfo, { name: 'neverquestalone', title: 'NeverQuestAlone', version: 'test' });
  assert.equal(spawn.calls.find(x => x.method === 'thread/start').params.sandbox, 'read-only');
  assert.equal(spawn.calls.find(x => x.method === 'turn/start').params.sandboxPolicy.networkAccess, false);
});

test('Codex app-server refuses to start without an access token', async () => {
  await assert.rejects(testCodexAppServer({ accessToken: '' }), { code: 'oauth_not_connected' });
});

test('Codex app-server applies its timeout while waiting for initialize', async () => {
  const spawn = fakeSpawn({ stallAt: 'initialize' });
  await assert.rejects(
    testCodexAppServer({ accessToken: 'test-access-token', spawnProcess: spawn, platform: 'linux', timeoutMs: 5 }),
    { code: 'codex_timeout' },
  );
});
