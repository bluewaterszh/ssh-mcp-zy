import { EventEmitter } from 'events';
import type { Client, ClientChannel, ExecOptions } from 'ssh2';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { openSudoChannel, startSudoChannel, SudoAuthenticationError } from '../../../src/ssh/sudo-channel.js';
import { terminateChannel } from '../../../src/ssh/channel-signal.js';

vi.mock('../../../src/ssh/channel-signal.js', () => ({ terminateChannel: vi.fn() }));

class FakeChannel extends EventEmitter {
  stderr = new EventEmitter();
  writes: string[] = [];
  destroyed = false;
  ended = false;
  write(text: string): boolean { this.writes.push(text); return true; }
  end(): void { this.ended = true; }
}

function fixture(password: string | undefined = 'only-in-stdin', options = {}) {
  const stream = new FakeChannel();
  let wrapped = '';
  let execOptions: ExecOptions | undefined;
  const exec = vi.fn((command: string, opts: ExecOptions, callback: Function) => {
    wrapped = command;
    execOptions = opts;
    callback(undefined, stream);
  });
  const pending = openSudoChannel(
    { exec } as unknown as Pick<Client, 'exec'>,
    'printf application-output',
    {},
    password,
    options,
  );
  const prompt = wrapped.match(/SSHMCP_SUDO_PASSWORD_[a-f0-9]+/)?.[0] ?? '';
  const ready = wrapped.match(/SSHMCP_SUDO_READY_[a-f0-9]+/)![0];
  const go = wrapped.match(/SSHMCP_SUDO_GO_[a-f0-9]+/)![0];
  return { stream, pending, wrapped, prompt, ready, go, exec, execOptions };
}

function stdout(stream: FakeChannel, value: string): void {
  stream.emit('data', Buffer.from(value));
}

function stderr(stream: FakeChannel, value: string): void {
  stream.stderr.emit('data', Buffer.from(value));
}

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe('automatic sudo channel', () => {
  it('sends a password only on the generated prompt and gates application stdin behind GO', async () => {
    const f = fixture();
    expect(f.wrapped).not.toContain('only-in-stdin');
    expect(f.wrapped).toContain('sudo -k -H -u root -S');
    expect(f.wrapped).toContain('id -u');
    expect(f.stream.writes).toEqual([]);
    stderr(f.stream, f.prompt);
    expect(f.stream.writes).toEqual(['only-in-stdin\n']);
    stdout(f.stream, f.ready + '\n');
    const channel = await f.pending;
    expect(channel).toBe(f.stream);
    expect(f.stream.writes).toEqual(['only-in-stdin\n']);
    startSudoChannel(channel);
    expect(f.stream.writes).toEqual(['only-in-stdin\n', f.go + '\n']);
    startSudoChannel(channel);
    expect(f.stream.writes).toHaveLength(2);
  });

  it('handles split prompts and CRLF readiness on a PTY stream', async () => {
    const f = fixture();
    stdout(f.stream, 'password for user: \r\n');
    expect(f.stream.writes).toEqual([]);
    for (const c of f.prompt) stdout(f.stream, c);
    expect(f.stream.writes).toEqual(['only-in-stdin\n']);
    for (const c of f.ready + '\r\n') stdout(f.stream, c);
    startSudoChannel(await f.pending);
    expect(f.stream.writes.at(-1)).toBe(f.go + '\n');
    expect(f.wrapped).toContain('stty -echo');
    expect(f.wrapped).toContain('stty "$__sshmcp_tty"');
  });

  it('does not send a configured password when NOPASSWD authenticates without a prompt', async () => {
    const f = fixture();
    stdout(f.stream, f.ready + '\n');
    startSudoChannel(await f.pending);
    expect(f.stream.writes).toEqual([f.go + '\n']);
  });

  it('uses noninteractive sudo when no password was configured', async () => {
    const stream = new FakeChannel();
    let command = '';
    const exec = (text: string, _opts: ExecOptions, cb: Function) => { command = text; cb(undefined, stream); };
    const pending = openSudoChannel({ exec } as unknown as Pick<Client, 'exec'>, 'id -u', {}, undefined);
    expect(command).toContain('sudo -k -H -u root -n');
    const ready = command.match(/SSHMCP_SUDO_READY_[a-f0-9]+/)![0];
    stdout(stream, ready + '\n');
    startSudoChannel(await pending);
    expect(stream.writes).toHaveLength(1);
  });

  it('attaches application listeners before any application output is released', async () => {
    const f = fixture();
    stdout(f.stream, f.ready + '\n');
    const channel = await f.pending;
    const output: string[] = [];
    channel.on('data', (data: Buffer) => output.push(data.toString()));
    f.stream.write = (text: string) => {
      f.stream.writes.push(text);
      if (text === f.go + '\n') stdout(f.stream, 'immediate output');
      return true;
    };
    expect(output).toEqual([]);
    startSudoChannel(channel);
    expect(output).toEqual(['immediate output']);
  });

  it('rejects a second password prompt without retrying or exposing diagnostics', async () => {
    const f = fixture();
    stderr(f.stream, f.prompt);
    stderr(f.stream, 'secret diagnostic only-in-stdin\n' + f.prompt);
    await expect(f.pending).rejects.toThrow('Sudo authentication failed.');
    expect(f.stream.writes).toEqual(['only-in-stdin\n']);
    expect(f.stream.ended).toBe(true);
    expect(terminateChannel).toHaveBeenCalledWith(f.stream);
  });

  it('rejects two prompts delivered together', async () => {
    const f = fixture();
    stderr(f.stream, f.prompt + '\n' + f.prompt);
    await expect(f.pending).rejects.toThrow('Sudo authentication failed.');
    expect(f.stream.writes).toEqual(['only-in-stdin\n']);
  });

  it('ignores command traces and marker substrings, including across buffer truncation', async () => {
    const f = fixture();
    const resolved = vi.fn();
    f.pending.then(resolved);
    for (const c of '+ ' + f.wrapped + '\n') stderr(f.stream, c);
    for (const c of 'x'.repeat(4000) + f.prompt + '\n') stderr(f.stream, c);
    stdout(f.stream, 'trace: ' + f.ready + '\n');
    await Promise.resolve();
    expect(f.stream.writes).toEqual([]);
    expect(resolved).not.toHaveBeenCalled();
    stderr(f.stream, f.prompt);
    expect(f.stream.writes).toEqual(['only-in-stdin\n']);
    stdout(f.stream, f.ready + '\n');
    startSudoChannel(await f.pending);
    expect(f.stream.writes.at(-1)).toBe(f.go + '\n');
  });

  it('reports denied sudo without copying remote stderr or passwords', async () => {
    const f = fixture();
    stderr(f.stream, 'sudo: denied: only-in-stdin');
    f.stream.emit('close', 1);
    await expect(f.pending).rejects.toThrow('Check the sudo password and permission');
    const error = await f.pending.catch((err: Error) => err);
    expect(error).toBeInstanceOf(SudoAuthenticationError);
    expect(String(error)).not.toContain('only-in-stdin');
    expect(f.stream.writes).toEqual([]);
  });

  it('times out a silent prompt and detaches authentication listeners', async () => {
    vi.useFakeTimers();
    const f = fixture('secret', { timeoutMs: 100 });
    const rejected = expect(f.pending).rejects.toThrow('Sudo authentication timed out.');
    await vi.advanceTimersByTimeAsync(100);
    await rejected;
    expect(f.stream.ended).toBe(true);
    expect(f.stream.listenerCount('data')).toBe(0);
    expect(f.stream.stderr.listenerCount('data')).toBe(0);
  });

  it('aborts authentication and closes the channel', async () => {
    const ac = new AbortController();
    const f = fixture('secret', { abortSignal: ac.signal });
    ac.abort();
    await expect(f.pending).rejects.toThrow('Sudo authentication aborted.');
    expect(f.stream.ended).toBe(true);
  });

  it('does not open a channel for invalid passwords or already aborted requests', async () => {
    const exec = vi.fn();
    const client = { exec } as unknown as Pick<Client, 'exec'>;
    await expect(openSudoChannel(client, 'id', {}, 'two\nlines')).rejects.toThrow('single line');
    const ac = new AbortController();
    ac.abort();
    await expect(openSudoChannel(client, 'id', {}, 'secret', { abortSignal: ac.signal }))
      .rejects.toThrow('aborted before execution');
    expect(exec).not.toHaveBeenCalled();
  });

  it('terminates a channel whose open callback arrives after timeout', async () => {
    vi.useFakeTimers();
    let callback: Function = () => {};
    const exec = (_command: string, _opts: ExecOptions, cb: Function) => { callback = cb; };
    const pending = openSudoChannel({ exec } as unknown as Pick<Client, 'exec'>, 'id', {}, 'secret', { timeoutMs: 10 });
    const rejected = expect(pending).rejects.toThrow('timed out');
    await vi.advanceTimersByTimeAsync(10);
    await rejected;
    const stream = new FakeChannel();
    callback(undefined, stream);
    expect(stream.ended).toBe(true);
    expect(terminateChannel).toHaveBeenCalledWith(stream);
  });

  it('fails if the root channel closes between READY and GO', async () => {
    const f = fixture();
    stdout(f.stream, f.ready + '\n');
    const channel = await f.pending;
    f.stream.emit('close');
    expect(() => startSudoChannel(channel)).toThrow('closed before command execution');
    expect(f.stream.writes).toEqual([]);
  });

  it('leaves ordinary channels alone', () => {
    const stream = new FakeChannel();
    startSudoChannel(stream as unknown as ClientChannel);
    expect(stream.writes).toEqual([]);
  });
});
