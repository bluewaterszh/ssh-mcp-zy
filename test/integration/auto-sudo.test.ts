import { randomUUID } from 'crypto';
import type { ClientCallback, ExecOptions } from 'ssh2';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SSHConnection } from '../../src/ssh/connection.js';
import { resolveCredentials } from '../../src/config/credential-resolver.js';
import { profiles, setupEnv } from './fixtures.js';
import { isSshServerUp, sshAvailable, SSH_HOST } from './helpers.js';

const available = await sshAvailable();
let env: ReturnType<typeof setupEnv>;
let conn: SSHConnection;
let observer: SSHConnection;

beforeAll(async () => {
  if (!available) return;
  env = setupEnv();
  const credentials = await resolveCredentials(profiles.admin);
  observer = new SSHConnection(profiles.admin, credentials, new Map(), 'insecure');
  conn = new SSHConnection({ ...profiles.admin, sudo: true }, credentials, new Map(), 'insecure');
});

afterAll(async () => {
  await Promise.all([conn?.close(), observer?.close()]);
  env?.restore();
});

describe.skipIf(!available)('Profile automatic sudo', () => {
  it('logs in as an ordinary user and reuses a root command worker', async () => {
    const login = await observer.exec('id -u');
    expect(login.exitCode).toBe(0);
    expect(login.stdout.trim()).not.toBe('0');

    const first = await conn.exec('id -u; printf "%s\\n" "$PPID"');
    const second = await conn.exec('id -u; printf "%s\\n" "$PPID"');
    expect(first.exitCode).toBe(0);
    expect(second.exitCode).toBe(0);
    expect(first.stdout.trim().split('\n')[0]).toBe('0');
    expect(second.stdout.trim()).toBe(first.stdout.trim());
  }, 15000);

  it('keeps application stdin separate from sudo authentication', async () => {
    const result = await conn.exec('id -u; cat', { stdin: 'application input\n' });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('0\napplication input\n');
    expect(result.stdout + result.stderr).not.toContain(conn.getSudoPassword());
  }, 15000);

  it('authenticates correctly when the login shell traces the bootstrap command', async () => {
    const credentials = await resolveCredentials(profiles.admin);
    const traced = new SSHConnection({ ...profiles.admin, sudo: true }, credentials, new Map(), 'insecure');
    try {
      await traced.ensureConnected();
      const client = traced.getClient();
      const exec = client.exec.bind(client);
      client.exec = (command: string, options: ExecOptions | ClientCallback, callback?: ClientCallback) => {
        const withTrace = `set -x; ${command}`;
        return typeof options === 'function'
          ? exec(withTrace, options)
          : exec(withTrace, options, callback!);
      };
      const result = await traced.exec('id -u; cat', { stdin: 'traced payload\n' });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe('0\ntraced payload\n');
      expect(result.stderr).not.toContain(credentials.sudoPassword);
    } finally {
      await traced.close();
    }
  }, 15000);

  it('elevates one-shot PTY commands', async () => {
    const result = await conn.exec('id -u', { tty: true });
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('0');
  }, 15000);

  it('preserves root identity, cwd and environment in an interactive session', async () => {
    const session = await conn.openSession({ name: 'auto-sudo-state', type: 'interactive' });
    try {
      await session.run('cd /tmp && export SSHMCP_TEST_VALUE=retained');
      const result = await session.run('id -u; pwd; printf "%s\\n" "$SSHMCP_TEST_VALUE"');
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe('0\n/tmp\nretained');

      session.writeInput('exit\n');
      await expect.poll(() => session.status, { timeout: 3000 }).toBe('closed');
      await expect(session.run('id -u')).rejects.toThrow(/not active/);
    } finally {
      await session.close();
    }
  }, 15000);

  it('captures immediate output from a root background command', async () => {
    const session = await conn.openSession({
      name: 'auto-sudo-background',
      type: 'background',
      command: 'printf "immediate\\n"; id -u',
    });
    try {
      await expect.poll(() => session.readOutput(10), { timeout: 3000 }).toBe('immediate\n0');
    } finally {
      await session.close();
    }
  }, 15000);

  it('authenticates again after reconnecting', async () => {
    await conn.close();
    const result = await conn.exec('id -u');
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe('0');
  }, 15000);

  it('stops a root background process when its session closes', async () => {
    const session = await conn.openSession({
      name: 'auto-sudo-stop-background',
      type: 'background',
      command: 'printf "%s\\n" "$$"; exec sleep 4932',
    });
    let pid: number | undefined;
    try {
      await expect.poll(() => session.readOutput(10).trim(), { timeout: 3000 }).toMatch(/^\d+$/);
      pid = Number(session.readOutput(10).trim());
      expect((await conn.exec(`kill -0 ${pid}`)).exitCode).toBe(0);
      expect(await conn.closeSession(session.name)).toBe('closed');
      await expect.poll(async () => (await conn.exec(`kill -0 ${pid}`)).exitCode, {
        timeout: 5000,
      }).not.toBe(0);
    } finally {
      await session.close();
      if (pid) await conn.exec(`kill -KILL ${pid} 2>/dev/null || true`);
    }
  }, 15000);

  it('stops a root direct command when its request is aborted', async () => {
    const abort = new AbortController();
    let pid: number | undefined;
    try {
      await expect(conn.exec('printf "%s\\n" "$$"; exec sleep 4933', {
        stdin: '',
        abortSignal: abort.signal,
        timeoutMs: 10000,
        onProgress: (_bytes, output) => {
          if (/^\d+$/.test(output.trim())) {
            pid = Number(output.trim());
            abort.abort();
          }
        },
      })).rejects.toThrow(/aborted/i);
      expect(pid).toBeGreaterThan(0);
      await expect.poll(async () => (await conn.exec(`kill -0 ${pid}`)).exitCode, {
        timeout: 5000,
      }).not.toBe(0);
    } finally {
      if (pid) await conn.exec(`kill -KILL ${pid} 2>/dev/null || true`);
    }
  }, 15000);

  it('rejects a wrong password without running the command as the login user', async () => {
    const marker = `/tmp/sshmcp-sudo-${randomUUID()}`;
    const wrongPassword = 'sshmcp-invalid-password';
    const credentials = await resolveCredentials(profiles.admin);
    const failed = new SSHConnection(
      { ...profiles.admin, sudo: true },
      { ...credentials, sudoPassword: wrongPassword },
      new Map(),
      'insecure',
    );
    try {
      let failure: unknown;
      try {
        await failed.exec(`touch '${marker}'`);
      } catch (error) {
        failure = error;
      }
      expect(failure).toBeInstanceOf(Error);
      expect(String(failure)).not.toContain(wrongPassword);
      const check = await observer.exec(`test -e '${marker}'`);
      expect(check.exitCode).toBe(1);
    } finally {
      await failed.close();
      await observer.exec(`rm -f '${marker}'`);
    }
  }, 15000);

  it('fails explicitly when a password is required but none is configured', async () => {
    const credentials = await resolveCredentials(profiles.admin);
    const missing = new SSHConnection(
      { ...profiles.admin, sudo: true },
      { ...credentials, sudoPassword: undefined },
      new Map(),
      'insecure',
    );
    try {
      await expect(missing.exec('id -u')).rejects.toThrow(/sudo|password/i);
    } finally {
      await missing.close();
    }
  }, 15000);

  it('supports NOPASSWD without feeding a configured password to the application', async (context) => {
    if (!(await isSshServerUp(SSH_HOST, profiles.operator.port))) context.skip();
    const credentials = await resolveCredentials(profiles.operator);
    const plain = new SSHConnection(profiles.operator, credentials, new Map(), 'insecure');
    const elevated = new SSHConnection(
      { ...profiles.operator, sudo: true },
      { ...credentials, sudoPassword: 'must-not-reach-application' },
      new Map(),
      'insecure',
    );
    try {
      const probe = await plain.exec('sudo -k -n true');
      if (probe.exitCode !== 0) context.skip();
      const result = await elevated.exec('id -u; cat', { stdin: 'payload\n' });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe('0\npayload\n');
    } finally {
      await Promise.all([plain.close(), elevated.close()]);
    }
  }, 15000);

  it('supports NOPASSWD with no configured sudo password', async (context) => {
    if (!(await isSshServerUp(SSH_HOST, profiles.operator.port))) context.skip();
    const credentials = await resolveCredentials(profiles.operator);
    const plain = new SSHConnection(profiles.operator, credentials, new Map(), 'insecure');
    const elevated = new SSHConnection(
      { ...profiles.operator, sudo: true },
      { ...credentials, sudoPassword: undefined },
      new Map(),
      'insecure',
    );
    try {
      const probe = await plain.exec('sudo -k -n true');
      if (probe.exitCode !== 0) context.skip();
      const result = await elevated.exec('id -u');
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe('0');
    } finally {
      await Promise.all([plain.close(), elevated.close()]);
    }
  }, 15000);
});
