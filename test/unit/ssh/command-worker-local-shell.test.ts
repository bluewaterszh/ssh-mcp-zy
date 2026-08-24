import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'events';
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';
import { CommandWorker, COMMAND_WORKER_BOOTSTRAP } from '../../../src/ssh/command-worker.js';

class ChildShellChannel extends EventEmitter {
  readonly stderr;
  readonly type = 'session';
  readonly outgoing = { id: 1, state: 'open' };
  writable = true;
  private closed = false;

  constructor(private readonly child: ChildProcessWithoutNullStreams) {
    super();
    this.stderr = child.stderr;
    child.stdout.on('data', (data) => this.emit('data', data));
    child.once('error', (err) => this.emit('error', err));
    child.once('close', () => {
      this.closed = true;
      this.writable = false;
      this.outgoing.state = 'closed';
      this.emit('close');
    });
  }

  get destroyed() { return this.closed; }

  write(text: string) {
    return this.child.stdin.write(text);
  }

  end() {
    this.writable = false;
    this.outgoing.state = 'eof';
    this.child.stdin.end();
  }

  destroy() {
    this.child.kill('SIGKILL');
  }

  signal(name: string) {
    this.child.kill(`SIG${name}` as NodeJS.Signals);
  }

  close() {
    this.child.kill('SIGKILL');
  }
}

const hasPosixShell = process.platform !== 'win32';

describe.skipIf(!hasPosixShell)('CommandWorker against a real POSIX shell', () => {
  it('keeps one worker alive while each command remains stateless and independently framed', async () => {
    const child = spawn('/bin/sh', ['-c', COMMAND_WORKER_BOOTSTRAP], {
      env: { ...process.env, SHELL: '/bin/sh' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const channel = new ChildShellChannel(child);
    let starts = 0;
    let ends = 0;
    let closed = 0;
    const worker = await CommandWorker.create(
      channel as any,
      'local',
      1024 * 1024,
      5000,
      () => { closed++; },
      () => { starts++; return () => { ends++; }; },
    );

    const first = await worker.tryRun("printf 'hello'; printf 'warn' >&2; exit 7")!;
    expect(first.stdout).toBe('hello');
    expect(first.stderr).toBe('warn');
    expect(first.exitCode).toBe(7);

    // Stateful shell operations live only in the per-command child shell.
    expect((await worker.tryRun('cd /tmp')!).exitCode).toBe(0);
    const pwd = await worker.tryRun('pwd')!;
    expect(pwd.stdout.trim()).not.toBe('/tmp');

    expect((await worker.tryRun('export SSHMCP_LOCAL_VAR=secret')!).exitCode).toBe(0);
    const env = await worker.tryRun('printf "${SSHMCP_LOCAL_VAR-unset}"')!;
    expect(env.stdout).toBe('unset');

    // Syntax errors and exit must kill only the child command shell, never the worker.
    const malformed = await worker.tryRun("echo 'unterminated")!;
    expect(malformed.exitCode).not.toBe(0);
    const afterMalformed = await worker.tryRun("printf 'still-alive'")!;
    expect(afterMalformed.stdout).toBe('still-alive');

    const explicitExit = await worker.tryRun('exit 9')!;
    expect(explicitExit.exitCode).toBe(9);
    const afterExit = await worker.tryRun("printf 'after-exit'")!;
    expect(afterExit.stdout).toBe('after-exit');

    expect(starts).toBe(ends);
    expect(starts).toBeGreaterThanOrEqual(8);

    await worker.close();
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) resolve();
      else child.once('close', () => resolve());
    });
    expect(closed).toBe(1);
    expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
  }, 15000);
});
