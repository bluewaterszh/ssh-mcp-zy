import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import type { Profile } from '../../../src/types.js';

class WorkerChannel extends EventEmitter {
  stderr = new EventEmitter();
  writes: string[] = [];

  constructor() {
    super();
    // The real worker bootstrap emits READY immediately after sshd accepts the
    // exec request, before the client writes the first command frame.
    setTimeout(() => this.emit('data', Buffer.from('SSHMCP_WORKER_READY_v1__/bin/bash\n')), 0);
  }

  write(text: string) {
    this.writes.push(text);
    const markers = [...text.matchAll(/SSHMCP_W(?:OB|OE|EB|EE)_[A-Za-z0-9_-]+/g)].map((m) => m[0]);
    if (markers.length === 4) {
      const [outBegin, errBegin, outEnd, errEnd] = markers;
      const delay = text.includes("-c 'slow'") ? 80 : 0;
      setTimeout(() => {
        this.emit('data', Buffer.from(`${outBegin}\nworker\n${outEnd}__0\n`));
        this.stderr.emit('data', Buffer.from(`${errBegin}\n${errEnd}\n`));
      }, delay);
    }
    return true;
  }

  end() { queueMicrotask(() => this.emit('close')); }
}

function execChannel(output: string) {
  const stream = Object.assign(new EventEmitter(), {
    stderr: new EventEmitter(),
    writable: true,
    outgoing: { state: 'open' },
    write: vi.fn(),
    end: vi.fn(),
    signal: vi.fn(),
    close: vi.fn(),
  });
  setTimeout(() => {
    stream.emit('data', Buffer.from(output));
    stream.emit('close', 0, '');
  }, 0);
  return stream;
}

const profile = {
  name: 'p', host: 'h', port: 22, user: 'u', role: 'admin', auth: 'password', group: 'dev',
  tty: false, timeout: 5000, maxChars: 1000, maxOutputBytes: 1000, readOnly: false,
  approvalPolicy: 'auto', cert: false, sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000, commandQuotaPerDay: 0,
} as unknown as Profile;

let workerOpenCalls: number;
let execCalls: string[];

beforeEach(() => {
  workerOpenCalls = 0;
  execCalls = [];
  vi.resetModules();
  vi.doMock('ssh2', () => {
    class FakeClient extends EventEmitter {
      connect() { queueMicrotask(() => this.emit('ready')); return this; }
      // Presence is used only to distinguish a complete ssh2 client from tiny
      // unit fakes that intentionally exercise the legacy direct path.
      shell() { return this; }
      exec(command: string, _opts: unknown, cb: (err: Error | undefined, stream: unknown) => void) {
        if (command.includes('__sshmcp_line')) {
          workerOpenCalls++;
          cb(undefined, new WorkerChannel());
        } else {
          execCalls.push(command);
          cb(undefined, execChannel('direct\n'));
        }
        return this;
      }
      end() { this.emit('close'); }
    }
    return { Client: FakeClient, default: { Client: FakeClient } };
  });
});

afterEach(() => {
  vi.doUnmock('ssh2');
  vi.resetModules();
});

async function connect() {
  const { SSHConnection } = await import('../../../src/ssh/connection.js');
  return new SSHConnection(profile, { password: 'x' } as never, new Map(), 'insecure');
}

describe('SSHConnection persistent command worker', () => {
  it('reuses one non-PTY shell for sequential stateless exec calls', async () => {
    const conn = await connect();
    expect((await conn.exec('one')).stdout).toBe('worker\n');
    expect((await conn.exec('two')).stdout).toBe('worker\n');

    expect(workerOpenCalls).toBe(1);
    expect(execCalls).toEqual([]);
    expect(conn.toInfo().activeChannels).toBe(0);
    await conn.close();
  });

  it('invalidates old release tokens on reconnect so late closes cannot steal new slots', async () => {
    const conn = await connect();
    await conn.ensureConnected();
    const releaseOld = conn.noteChannelOpened();
    expect(conn.toInfo().activeChannels).toBe(1);

    conn.getClient().emit('close');
    expect(conn.toInfo().activeChannels).toBe(0);

    // Simulate work on the next transport generation. A delayed close from the
    // previous generation must not decrement this new slot.
    const releaseNew = conn.noteChannelOpened();
    expect(conn.toInfo().activeChannels).toBe(1);
    releaseOld();
    expect(conn.toInfo().activeChannels).toBe(1);
    releaseNew();
    expect(conn.toInfo().activeChannels).toBe(0);
  });

  it('uses one-shot exec for standalone background operators so they cannot pollute the worker', async () => {
    const conn = await connect();
    const result = await conn.exec('sleep 10 &');
    expect(result.stdout).toBe('direct\n');
    expect(workerOpenCalls).toBe(0);
    expect(execCalls).toEqual(['sleep 10 &']);
    await conn.close();
  });

  it('still allows common non-background ampersand syntax onto the worker', async () => {
    const conn = await connect();
    expect((await conn.exec('true && true')).stdout).toBe('worker\n');
    expect((await conn.exec('echo x 2>&1')).stdout).toBe('worker\n');
    expect(workerOpenCalls).toBe(1);
    expect(execCalls).toEqual([]);
    await conn.close();
  });

  it('falls back to a one-shot exec instead of queueing behind a busy worker', async () => {
    const conn = await connect();
    const slow = conn.exec('slow');
    await new Promise((resolve) => setTimeout(resolve, 10));
    const fast = conn.exec('fast');

    expect((await fast).stdout).toBe('direct\n');
    expect((await slow).stdout).toBe('worker\n');
    expect(workerOpenCalls).toBe(1);
    expect(execCalls).toEqual(['fast']);
    expect(conn.toInfo().activeChannels).toBe(0);
    await conn.close();
  });
});
