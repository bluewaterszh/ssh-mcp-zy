import type { ClientChannel } from 'ssh2';
import { randomBytes } from 'crypto';
import type { CommandResult, ExecOpts } from '../types.js';
import { shellSingleQuote, validateRemotePath } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { terminateChannel, waitForChannelClose } from './channel-signal.js';
import { timingLog } from '../observability/timing.js';

const HANDSHAKE_TIMEOUT_MS = 1_000;
const PROGRESS_INTERVAL_MS = 500;

// sshd already invokes an exec request through the user's configured shell with
// `-c`. Keep that exact process/environment alive instead of using a `shell`
// request (which OpenSSH turns into a login shell and may source different
// profile files). The loop evaluates only ssh-mcp's fixed, quoted protocol
// lines; caller commands remain single-quoted arguments to the user's shell.
export const COMMAND_WORKER_BOOTSTRAP =
  '__sshmcp_shell="${SHELL:-}"; ' +
  'if [ -z "$__sshmcp_shell" ]; then __sshmcp_name="${0#-}"; ' +
  '__sshmcp_shell="$(command -v "$__sshmcp_name" 2>/dev/null || true)"; fi; ' +
  '[ -n "$__sshmcp_shell" ] && [ -x "$__sshmcp_shell" ] || exit 127; ' +
  'while IFS= read -r __sshmcp_line; do eval "$__sshmcp_line"; done';

function marker(): string {
  return randomBytes(12).toString('base64url');
}

class FramedCapture {
  private pending = '';
  private started = false;
  done = false;
  output = '';
  exitCode: number | null = null;

  constructor(
    private readonly begin: string,
    private readonly end: string,
    private readonly maxChars: number,
    private readonly carriesExitCode: boolean,
  ) {}

  feed(chunk: Buffer): void {
    if (this.done) return;
    this.pending += chunk.toString();

    if (!this.started) {
      const at = this.pending.indexOf(this.begin);
      if (at < 0) {
        this.pending = this.pending.slice(-Math.max(this.begin.length - 1, 0));
        return;
      }
      this.pending = this.pending.slice(at + this.begin.length);
      if (this.pending.startsWith('\r\n')) this.pending = this.pending.slice(2);
      else if (this.pending.startsWith('\n')) this.pending = this.pending.slice(1);
      this.started = true;
    }

    if (this.carriesExitCode) {
      const re = new RegExp(`${this.end}__(\\d+)(?:\\r?\\n|$)`);
      const match = re.exec(this.pending);
      if (match) {
        this.append(this.pending.slice(0, match.index));
        this.exitCode = Number(match[1]);
        this.pending = this.pending.slice(match.index + match[0].length);
        this.done = true;
        return;
      }
    } else {
      const line = `${this.end}\n`;
      const crlf = `${this.end}\r\n`;
      let at = this.pending.indexOf(line);
      let width = line.length;
      const crlfAt = this.pending.indexOf(crlf);
      if (crlfAt >= 0 && (at < 0 || crlfAt < at)) {
        at = crlfAt;
        width = crlf.length;
      }
      if (at >= 0) {
        this.append(this.pending.slice(0, at));
        this.pending = this.pending.slice(at + width);
        this.done = true;
        return;
      }
    }

    const overlap = this.end.length + 32;
    if (this.pending.length > overlap) {
      const flush = this.pending.slice(0, -overlap);
      this.pending = this.pending.slice(-overlap);
      this.append(flush);
    }
  }

  private append(text: string): void {
    if (this.output.length >= this.maxChars) return;
    this.output += text.slice(0, this.maxChars - this.output.length);
  }
}

export interface CommandWorkerRunOpts extends ExecOpts {
  workdir?: string;
}

/** Persistent non-PTY shell for stateless commands. Busy workers are never queued. */
export class CommandWorker {
  private busy = false;
  private closed = false;
  private shellPath = '';
  private closing: Promise<void> | null = null;
  private closeNotified = false;

  private constructor(
    private readonly stream: ClientChannel,
    private readonly profileName: string,
    private readonly maxOutputChars: number,
    private readonly defaultTimeoutMs: number,
    private readonly onClosed: () => void,
    private readonly beginRun: () => () => void,
  ) {
    stream.once('close', () => {
      this.closed = true;
      this.notifyClosed();
    });
    // A persistent channel can emit error while no command-specific listener is
    // attached. Keep one permanent listener so an idle worker error cannot become
    // an uncaught EventEmitter 'error' and crash the whole MCP process.
    stream.on('error', () => {
      this.closed = true;
      this.notifyClosed();
    });
  }

  static async create(
    stream: ClientChannel,
    profileName: string,
    maxOutputChars: number,
    defaultTimeoutMs: number,
    onClosed: () => void,
    beginRun: () => () => void,
  ): Promise<CommandWorker> {
    const worker = new CommandWorker(
      stream, profileName, maxOutputChars, defaultTimeoutMs,
      onClosed, beginRun,
    );
    try {
      await worker.handshake();
      return worker;
    } catch (err) {
      // A failed POSIX/worker handshake must not leave the just-opened SSH
      // channel behind merely because the caller will fall back to direct exec.
      await worker.close().catch(() => {});
      throw err;
    }
  }

  get isAvailable(): boolean {
    return !this.closed && !this.busy;
  }

  tryRun(command: string, opts: CommandWorkerRunOpts = {}): Promise<CommandResult> | null {
    if (!this.isAvailable) return null;
    this.busy = true;
    const releaseRun = this.beginRun();
    return this.run(command, opts).finally(() => {
      this.busy = false;
      releaseRun();
    });
  }

  async close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closing = this.closeInternal();
    return this.closing;
  }

  private async closeInternal(): Promise<void> {
    const wasBusy = this.busy;
    this.closed = true;
    this.notifyClosed();

    if (wasBusy) {
      terminateChannel(this.stream);
    } else {
      try { this.stream.end(); } catch { /* already closed */ }
    }

    // Do not leave a persistent worker channel behind if the peer never answers
    // the close/signal ladder. Busy commands get the same bounded escalation
    // budget as background-session shutdown; an idle shell gets a short grace.
    const closed = await waitForChannelClose(this.stream, wasBusy ? 3500 : 1000);
    if (!closed) {
      try { this.stream.destroy(); } catch { /* already gone */ }
    }
  }

  private notifyClosed(): void {
    if (this.closeNotified) return;
    this.closeNotified = true;
    this.onClosed();
  }

  private async handshake(): Promise<void> {
    const token = marker();
    const ready = `SSHMCP_WORKER_READY_${token}`;
    const unsupported = `SSHMCP_WORKER_UNSUPPORTED_${token}`;
    const started = performance.now();

    await new Promise<void>((resolve, reject) => {
      let buffer = '';
      let settled = false;
      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.stream.removeListener('data', onData);
        this.stream.removeListener('close', onClose);
        this.stream.removeListener('error', onError);
        err ? reject(err) : resolve();
      };
      const onData = (data: Buffer) => {
        buffer += data.toString();
        const readyAt = buffer.indexOf(`${ready}__`);
        if (readyAt >= 0) {
          const rest = buffer.slice(readyAt + ready.length + 2);
          const eol = rest.search(/[\r\n]/);
          if (eol < 0) return;
          const reportedShell = rest.slice(0, eol).trim();
          if (!reportedShell) {
            finish(new Error('Persistent command worker could not determine the remote login shell'));
            return;
          }
          try {
            this.shellPath = validateRemotePath(reportedShell, 'Remote login shell');
          } catch (err) {
            finish(err instanceof Error ? err : new Error(String(err)));
            return;
          }
          finish();
          return;
        }
        if (buffer.includes(unsupported)) {
          finish(new Error('Persistent command worker requires a POSIX shell'));
        }
      };
      const onClose = () => finish(new Error('Persistent command worker shell closed during handshake'));
      const onError = (err: Error) => finish(err);
      const timer = setTimeout(
        () => finish(new Error('Persistent command worker POSIX handshake timed out')),
        HANDSHAKE_TIMEOUT_MS,
      );
      timer.unref();

      this.stream.on('data', onData);
      this.stream.once('close', onClose);
      this.stream.once('error', onError);
      this.stream.write(
        `__sshmcp_shell="\${SHELL:-}"; ` +
        `if [ -z "$__sshmcp_shell" ]; then __sshmcp_name="\${0#-}"; ` +
        `__sshmcp_shell="$(command -v "$__sshmcp_name" 2>/dev/null || true)"; fi; ` +
        `if [ -n "$__sshmcp_shell" ] && [ -x "$__sshmcp_shell" ]; then ` +
        `printf '%s__%s\\n' '${ready}' "$__sshmcp_shell"; ` +
        `else printf '%s\\n' '${unsupported}'; fi\n`,
      );
    });

    timingLog('ssh.worker.handshake', {
      profile: this.profileName,
      handshakeMs: Number((performance.now() - started).toFixed(3)),
      shell: this.shellPath,
    });
  }

  private run(command: string, opts: CommandWorkerRunOpts): Promise<CommandResult> {
    const token = marker();
    const outBegin = `SSHMCP_WOB_${token}`;
    const outEnd = `SSHMCP_WOE_${token}`;
    const errBegin = `SSHMCP_WEB_${token}`;
    const errEnd = `SSHMCP_WEE_${token}`;
    const stdout = new FramedCapture(outBegin, outEnd, this.maxOutputChars, true);
    const stderr = new FramedCapture(errBegin, errEnd, this.maxOutputChars, false);
    const timeoutMs = opts.timeoutMs ?? this.defaultTimeoutMs;
    const startedAt = Date.now();
    const timingStarted = performance.now();

    return new Promise<CommandResult>((resolve, reject) => {
      let settled = false;
      let lastProgressSent = 0;
      let detachAbort = () => { /* no signal */ };

      const cleanup = () => {
        clearTimeout(timer);
        detachAbort();
        this.stream.removeListener('data', onStdout);
        this.stream.stderr.removeListener('data', onStderr);
        this.stream.removeListener('close', onClose);
        this.stream.removeListener('error', onError);
      };
      const fail = (err: Error, outcome: string, killWorker = false) => {
        if (settled) return;
        settled = true;
        cleanup();
        const finish = async () => {
          if (killWorker) {
            // Hold the command's active-channel accounting until the worker has
            // actually closed (or has been forcibly destroyed after a bounded
            // wait). Otherwise the idle reaper could tear down the SSH transport
            // before TERM/KILL is delivered, recreating the old orphan-process bug.
            await this.close().catch(() => {});
          }
          timingLog('ssh.worker.run', {
            profile: this.profileName,
            outcome,
            totalMs: Number((performance.now() - timingStarted).toFixed(3)),
          });
          reject(err);
        };
        void finish();
      };
      const maybeDone = () => {
        if (settled || !stdout.done || !stderr.done) return;
        settled = true;
        cleanup();
        const result: CommandResult = {
          stdout: stdout.output,
          stderr: stderr.output,
          exitCode: stdout.exitCode ?? 1,
          durationMs: Date.now() - startedAt,
          profile: this.profileName,
        };
        timingLog('ssh.worker.run', {
          profile: this.profileName,
          outcome: 'closed',
          exitCode: result.exitCode,
          stdoutBytes: Buffer.byteLength(result.stdout),
          stderrBytes: Buffer.byteLength(result.stderr),
          totalMs: Number((performance.now() - timingStarted).toFixed(3)),
        });
        resolve(result);
      };
      const onStdout = (data: Buffer) => {
        stdout.feed(data);
        if (opts.onProgress && Date.now() - lastProgressSent >= PROGRESS_INTERVAL_MS) {
          lastProgressSent = Date.now();
          const lines = stdout.output.split('\n');
          const tail = lines.slice(-3).join('\n').trim();
          opts.onProgress(Buffer.byteLength(stdout.output), redactText(tail, { entropyScan: true }));
        }
        maybeDone();
      };
      const onStderr = (data: Buffer) => { stderr.feed(data); maybeDone(); };
      const onClose = () => fail(
        new Error('Persistent command worker closed before command completion'),
        'worker-closed',
      );
      const onError = (err: Error) => fail(
        new Error(`Persistent command worker failed: ${err.message}`),
        'worker-error',
        true,
      );
      const timer = setTimeout(() => fail(
        new Error(`Command timed out after ${timeoutMs}ms`),
        'timeout',
        true,
      ), timeoutMs);

      if (opts.abortSignal) {
        if (opts.abortSignal.aborted) {
          fail(new Error('Command aborted before execution'), 'aborted-before-execution');
          return;
        }
        const onAbort = () => fail(new Error('Command aborted'), 'aborted', true);
        opts.abortSignal.addEventListener('abort', onAbort, { once: true });
        detachAbort = () => opts.abortSignal!.removeEventListener('abort', onAbort);
      }

      this.stream.on('data', onStdout);
      this.stream.stderr.on('data', onStderr);
      this.stream.once('close', onClose);
      this.stream.once('error', onError);

      const workdir = opts.workdir ? `cd ${shellSingleQuote(opts.workdir)} && ` : '';
      this.stream.write(
        `printf '%s\\n' '${outBegin}'; ` +
        `printf '%s\\n' '${errBegin}' >&2; ` +
        `( ${workdir}${shellSingleQuote(this.shellPath)} -c ${shellSingleQuote(command)} </dev/null ); ` +
        `__sshmcp_rc=$?; ` +
        `printf '%s__%s\\n' '${outEnd}' "$__sshmcp_rc"; ` +
        `printf '%s\\n' '${errEnd}' >&2\n`,
      );
    });
  }
}
