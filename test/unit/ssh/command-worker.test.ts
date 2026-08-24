import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'events';
import { CommandWorker } from '../../../src/ssh/command-worker.js';

class FakeChannel extends EventEmitter {
  stderr = new EventEmitter();
  writes: string[] = [];
  ended = false;
  autoComplete = true;

  write(text: string) {
    this.writes.push(text);
    const ready = text.match(/SSHMCP_WORKER_READY_([A-Za-z0-9_-]+)/)?.[0];
    if (ready) {
      queueMicrotask(() => this.emit('data', Buffer.from(`${ready}__/bin/bash\n`)));
      return true;
    }

    const markers = [...text.matchAll(/SSHMCP_W(?:OB|OE|EB|EE)_[A-Za-z0-9_-]+/g)].map((m) => m[0]);
    if (markers.length === 4 && this.autoComplete) {
      const [outBegin, errBegin, outEnd, errEnd] = markers;
      queueMicrotask(() => {
        this.emit('data', Buffer.from(`${outBegin}\nhello\n${outEnd}__7\n`));
        this.stderr.emit('data', Buffer.from(`${errBegin}\nwarn\n${errEnd}\n`));
      });
    }
    return true;
  }

  end() { this.ended = true; }
}

async function worker(channel = new FakeChannel(), maxOutput = 1024) {
  const starts = vi.fn();
  const ends = vi.fn();
  const closed = vi.fn();
  const instance = await CommandWorker.create(
    channel as any,
    'p',
    maxOutput,
    60_000,
    closed,
    starts,
    ends,
  );
  return { instance, channel, starts, ends, closed };
}

describe('CommandWorker', () => {
  it('frames stdout/stderr and preserves the child exit code', async () => {
    const { instance, channel, starts, ends } = await worker();
    const pending = instance.tryRun('printf hello', { workdir: "/repo with space" });
    expect(pending).not.toBeNull();
    const result = await pending!;

    expect(result.stdout).toBe('hello\n');
    expect(result.stderr).toBe('warn\n');
    expect(result.exitCode).toBe(7);
    expect(starts).toHaveBeenCalledTimes(1);
    expect(ends).toHaveBeenCalledTimes(1);

    const wire = channel.writes.at(-1)!;
    expect(wire).toContain("cd '/repo with space' && '/bin/bash' -c 'printf hello' </dev/null");
  });

  it('does not queue a second caller while the worker is busy', async () => {
    const channel = new FakeChannel();
    const { instance } = await worker(channel);
    channel.autoComplete = false;

    const first = instance.tryRun('sleep 1');
    expect(first).not.toBeNull();
    expect(instance.tryRun('echo second')).toBeNull();

    // Finish the first command manually.
    const wire = channel.writes.at(-1)!;
    const markers = [...wire.matchAll(/SSHMCP_W(?:OB|OE|EB|EE)_[A-Za-z0-9_-]+/g)].map((m) => m[0]);
    const [outBegin, errBegin, outEnd, errEnd] = markers;
    channel.emit('data', Buffer.from(`${outBegin}\n${outEnd}__0\n`));
    channel.stderr.emit('data', Buffer.from(`${errBegin}\n${errEnd}\n`));
    await first;
    expect(instance.isAvailable).toBe(true);
  });

  it('keeps protocol detection working after output is capped', async () => {
    const channel = new FakeChannel();
    const { instance } = await worker(channel, 16);
    channel.autoComplete = false;
    const pending = instance.tryRun('chatty')!;
    const wire = channel.writes.at(-1)!;
    const markers = [...wire.matchAll(/SSHMCP_W(?:OB|OE|EB|EE)_[A-Za-z0-9_-]+/g)].map((m) => m[0]);
    const [outBegin, errBegin, outEnd, errEnd] = markers;

    channel.emit('data', Buffer.from(`${outBegin}\n${'x'.repeat(10000)}${outEnd}__0\n`));
    channel.stderr.emit('data', Buffer.from(`${errBegin}\n${errEnd}\n`));
    const result = await pending;
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toHaveLength(16);
  });

  it('a pre-aborted call does not destroy an otherwise healthy worker', async () => {
    const { instance } = await worker();
    const ac = new AbortController();
    ac.abort();
    await expect(instance.tryRun('echo never', { abortSignal: ac.signal }))
      .rejects.toThrow(/aborted before execution/i);
    expect(instance.isAvailable).toBe(true);
  });

  it('keeps the active-command count until an aborted worker channel really closes', async () => {
    const channel = new FakeChannel();
    const { instance, ends } = await worker(channel);
    channel.autoComplete = false;
    const ac = new AbortController();
    const pending = instance.tryRun('slow', { abortSignal: ac.signal })!;

    ac.abort();
    await expect(pending).rejects.toThrow(/aborted/i);
    expect(ends).not.toHaveBeenCalled();

    channel.emit('close');
    expect(ends).toHaveBeenCalledTimes(1);
  });
});
