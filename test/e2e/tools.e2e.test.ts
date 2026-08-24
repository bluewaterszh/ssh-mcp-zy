import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { startE2E, e2eAvailable, textOf } from './harness.js';

// §5 of the readiness report: exercise all 16 tools through a real MCP client
// over a real transport against a real SSH server. This is the check that would
// have caught open-session being registered without a handler — the in-process
// harness found it, but only because it too went through the MCP layer.
let e2e: Awaited<ReturnType<typeof startE2E>>;
const available = await e2eAvailable();

beforeAll(async () => {
  if (!available) return;
  e2e = await startE2E();
}, 30000);

afterAll(async () => { await e2e?.cleanup(); });

function sessionNameOf(result: any): string {
  const match = textOf(result).match(/Session \"([^\"]+)\" opened/);
  if (!match) throw new Error(`open-session result did not contain a session name: ${textOf(result)}`);
  return match[1];
}

describe.skipIf(!available)('E2E — tool surface over stdio', () => {
  it('advertises all 16 tools to a real client', async () => {
    const { tools } = await e2e.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'apply-patch', 'close-session', 'edit-file', 'list-connections', 'list-sessions', 'open-session',
      'privileged-command', 'read-batch', 'read-command', 'read-session-output',
      'run-batch', 'run-command', 'sftp-download', 'sftp-upload', 'signal-process',
      'write-session-input',
    ]);
  });

  it('list-connections reports the configured profiles', async () => {
    const res = await e2e.callTool('list-connections');
    expect(textOf(res)).toContain('admin');
    expect(textOf(res)).toContain('viewer');
  });

  it('read-command returns real output from the host', async () => {
    const res = await e2e.callTool('read-command', { command: 'whoami' });
    expect(res.isError).toBeFalsy();
    expect(textOf(res).trim()).toBe('admin');
  });

  it('read-command refuses curl — not read-only despite the allowlist shape', async () => {
    const res = await e2e.callTool('read-command', { command: 'curl http://169.254.169.254/' });
    expect(res.isError).toBe(true);
  });

  it('run-command reports a non-zero exit as an error with the code', async () => {
    const res = await e2e.callTool('run-command', { command: 'sh -c "echo to-stderr >&2; exit 7"' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('to-stderr');
    expect(textOf(res)).toContain('[exit 7]');
  });

  it('privileged-command elevates without the password reaching the output', async () => {
    const res = await e2e.callTool('privileged-command', { command: 'id -u' });
    expect(res.isError).toBeFalsy();
    // uid 0 — the command really ran as root.
    expect(textOf(res)).toContain('0');
    // The sudo password must never appear in what the model sees. (Note: sudo's
    // first-use lecture does arrive on stderr and is surfaced as [stderr],
    // which is the intended behaviour — stderr is not swallowed.)
    expect(textOf(res)).not.toContain('secret');
  });

  it('interactive sessions keep CWD and environment between commands', async () => {
    const opened = await e2e.callTool('open-session', { name: 'e2e-shell', type: 'interactive' });
    expect(opened.isError).toBeFalsy();
    const sessionName = sessionNameOf(opened);

    await e2e.callTool('run-command', { session: sessionName, command: 'cd /tmp' });
    await e2e.callTool('run-command', { session: sessionName, command: 'export E2E_VAR=persisted' });

    const pwd = await e2e.callTool('run-command', { session: sessionName, command: 'pwd' });
    expect(textOf(pwd).trim()).toBe('/tmp');

    const env = await e2e.callTool('run-command', { session: sessionName, command: 'echo $E2E_VAR' });
    expect(textOf(env).trim()).toBe('persisted');

    const listed = await e2e.callTool('list-sessions');
    expect(textOf(listed)).toContain(sessionName);

    const closed = await e2e.callTool('close-session', { name: sessionName });
    expect(closed.isError).toBeFalsy();
  }, 30000);

  it('background sessions stream output that read-session-output can poll', async () => {
    await e2e.callTool('run-command', { command: 'echo first-line > /tmp/e2e-bg.log' });
    const opened = await e2e.callTool('open-session', {
      name: 'e2e-bg', type: 'background', command: 'tail -f /tmp/e2e-bg.log',
    });
    const sessionName = sessionNameOf(opened);

    await new Promise((r) => setTimeout(r, 800));
    const out = await e2e.callTool('read-session-output', { name: sessionName, lines: 10 });
    expect(textOf(out)).toContain('first-line');

    await e2e.callTool('close-session', { name: sessionName });
  }, 30000);

  it('read-batch and run-batch amortize multiple commands in one MCP call', async () => {
    const read = await e2e.callTool('read-batch', { commands: ['pwd', 'whoami'] });
    expect(read.isError).toBeFalsy();
    expect(textOf(read)).toContain('[1/2] pwd');
    expect(textOf(read)).toContain('[2/2] whoami');

    const run = await e2e.callTool('run-batch', {
      commands: ['printf batch-one', 'printf batch-two'], stopOnError: true,
    });
    expect(run.isError).toBeFalsy();
    expect(textOf(run)).toContain('batch-one');
    expect(textOf(run)).toContain('batch-two');
  }, 30000);

  it('edit-file validates exact replacements across multiple files before writing', async () => {
    const a = '/tmp/e2e-edit-a.txt';
    const b = '/tmp/e2e-edit-b.txt';
    await e2e.callTool('run-command', { command: `printf 'alpha old\\n' > ${a}; printf 'beta old\\n' > ${b}` });

    const checked = await e2e.callTool('edit-file', {
      edits: [
        { path: a, oldText: 'alpha old', newText: 'alpha new' },
        { path: b, oldText: 'beta old', newText: 'beta new' },
      ],
      check: true,
    });
    expect(checked.isError).toBeFalsy();

    const before = await e2e.callTool('read-command', { command: `cat ${a} ${b}` });
    expect(textOf(before)).toContain('alpha old');
    expect(textOf(before)).toContain('beta old');

    const applied = await e2e.callTool('edit-file', {
      edits: [
        { path: a, oldText: 'alpha old', newText: 'alpha new' },
        { path: b, oldText: 'beta old', newText: 'beta new' },
      ],
    });
    expect(applied.isError).toBeFalsy();
    const after = await e2e.callTool('read-command', { command: `cat ${a} ${b}` });
    expect(textOf(after)).toContain('alpha new');
    expect(textOf(after)).toContain('beta new');

    await e2e.callTool('run-command', { command: `rm -f ${a} ${b}` });
  }, 30000);

  it('interactive session input can wait briefly and return recent output in the same call', async () => {
    const opened = await e2e.callTool('open-session', { name: 'e2e-input', type: 'interactive' });
    const sessionName = sessionNameOf(opened);
    const res = await e2e.callTool('write-session-input', {
      name: sessionName,
      input: 'echo interactive-ok',
      waitMs: 150,
      readLines: 10,
    });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain('interactive-ok');
    await e2e.callTool('close-session', { name: sessionName });
  }, 30000);

  it('sftp-upload and sftp-download round-trip a file', async () => {
    const remotePath = '/tmp/e2e-transfer.txt';
    const content = 'round-trip through SFTP';

    const up = await e2e.callTool('sftp-upload', { remotePath, content });
    expect(up.isError).toBeFalsy();

    const down = await e2e.callTool('sftp-download', { remotePath });
    expect(textOf(down)).toContain(content);

    await e2e.callTool('run-command', { command: `rm -f ${remotePath}` });
  }, 30000);

  it('signal-process kills a real remote process', async () => {
    // The process reports its own PID before exec'ing sleep, so the test does
    // not have to pattern-match a process list — `pgrep -f "sleep 120"` also
    // matches the shell running the pgrep, which made this flaky and wrong.
    const opened = await e2e.callTool('open-session', {
      name: 'e2e-victim',
      type: 'background',
      command: 'sh -c \'echo PID=$$; exec sleep 120\'',
    });
    const sessionName = sessionNameOf(opened);
    await new Promise((r) => setTimeout(r, 800));

    const out = await e2e.callTool('read-session-output', { name: sessionName, lines: 5 });
    const pid = parseInt(textOf(out).match(/PID=(\d+)/)?.[1] ?? '');
    expect(pid).toBeGreaterThan(0);

    const alive = await e2e.callTool('run-command', { command: `sh -c "kill -0 ${pid} && echo alive"` });
    expect(textOf(alive)).toContain('alive');

    const killed = await e2e.callTool('signal-process', { pid, signal: 'TERM' });
    expect(killed.isError).toBeFalsy();

    await new Promise((r) => setTimeout(r, 500));
    const gone = await e2e.callTool('run-command', { command: `sh -c "kill -0 ${pid} 2>/dev/null || echo gone"` });
    expect(textOf(gone)).toContain('gone');

    await e2e.callTool('close-session', { name: sessionName }).catch(() => {});
  }, 30000);

  it('serves the connection resource', async () => {
    const { resources } = await e2e.client.listResources();
    expect(resources.map((r) => r.uri)).toContain('ssh://connections');

    const read = await e2e.client.readResource({ uri: 'ssh://connections' });
    const body = JSON.parse((read.contents[0] as any).text);
    expect(JSON.stringify(body)).toContain('admin');
  });

  it('enforces the readOnly profile through a real connection', async () => {
    const res = await e2e.callTool('run-command', { profile: 'viewer', command: 'npm install' });
    expect(res.isError).toBe(true);
  }, 30000);
});
