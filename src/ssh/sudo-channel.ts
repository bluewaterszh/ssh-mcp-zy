import { randomUUID } from 'crypto';
import type { Client, ClientChannel, ExecOptions } from 'ssh2';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { terminateChannel } from './channel-signal.js';

interface SudoChannelOptions {
  timeoutMs?: number;
  abortSignal?: AbortSignal;
}

const pendingStarts = new WeakMap<ClientChannel, () => void>();

/** Authentication failures must not be retried as transient channel-open errors. */
export class SudoAuthenticationError extends Error {
  override name = 'SudoAuthenticationError';
}

/** Release the root shell only after the caller has attached its output listeners. */
export function startSudoChannel(stream: ClientChannel): void {
  const start = pendingStarts.get(stream);
  if (!start) return;
  pendingStarts.delete(stream);
  start();
}

/**
 * Authenticate a new root exec channel without sharing sudo timestamps or sending
 * a password to application stdin. READY/GO keeps application output behind the
 * authentication handshake until the command/session consumer is attached.
 */
export function openSudoChannel(
  client: Pick<Client, 'exec'>,
  command: string,
  execOpts: ExecOptions,
  password: string | undefined,
  options: SudoChannelOptions = {},
): Promise<ClientChannel> {
  if (password !== undefined && /[\r\n\0]/.test(password)) {
    return Promise.reject(new SudoAuthenticationError('The configured sudo password must be a single line.'));
  }
  if (options.abortSignal?.aborted) {
    return Promise.reject(new SudoAuthenticationError('Sudo authentication aborted before execution.'));
  }

  const token = randomUUID().replaceAll('-', '');
  const prompt = `SSHMCP_SUDO_PASSWORD_${token}`;
  const ready = `SSHMCP_SUDO_READY_${token}`;
  const go = `SSHMCP_SUDO_GO_${token}`;
  const promptLine = new RegExp(`(?:^|\\r?\\n)${prompt}(?=\\r?\\n|$)`);
  const readyLine = new RegExp(`(?:^|\\r?\\n)${ready}\\r?\\n`);
  const bootstrap =
    '[ "$(id -u)" = 0 ] || exit 126; ' +
    '__sshmcp_tty=""; if [ -t 0 ]; then __sshmcp_tty=$(stty -g) && stty -echo || exit 125; fi; ' +
    `printf '\\n%s\\n' '${ready}'; ` +
    'IFS= read -r __sshmcp_go || exit 125; ' +
    `[ "$__sshmcp_go" = '${go}' ] || exit 125; ` +
    '[ -z "$__sshmcp_tty" ] || stty "$__sshmcp_tty" || exit 125; ' +
    `exec "\${SHELL:-/bin/sh}" -c ${shellSingleQuote(command)}`;
  const authentication = password ? `-S -p ${shellSingleQuote(prompt)}` : '-n';
  const wrapped = `printf '\\n' >&2; exec sudo -k -H -u root ${authentication} -- /bin/sh -c ${shellSingleQuote(bootstrap)}`;

  return new Promise((resolve, reject) => {
    let stream: ClientChannel | undefined;
    let settled = false;
    let passwordSent = false;
    let stdout = '';
    let stderr = '';

    const cleanup = () => {
      clearTimeout(timer);
      options.abortSignal?.removeEventListener('abort', onAbort);
      stream?.removeListener('data', onStdout);
      stream?.stderr.removeListener('data', onStderr);
      stream?.removeListener('close', onClose);
      stream?.removeListener('error', onError);
    };
    const fail = (message: string, channelOpenError = false) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (stream) {
        terminateChannel(stream);
        // Authentication never started the application. Closing stdin releases
        // sudo/read even on servers that do not honor SSH signal requests.
        try { stream.end(); } catch { /* already closed */ }
        stream.on('error', () => {});
      }
      reject(channelOpenError ? new Error(message) : new SudoAuthenticationError(message));
    };
    const authenticated = () => {
      if (settled || !stream) return;
      settled = true;
      cleanup();
      const channel = stream;
      let unavailable = false;
      const onUnavailable = () => { unavailable = true; };
      channel.once('close', onUnavailable);
      channel.on('error', onUnavailable);
      pendingStarts.set(channel, () => {
        channel.removeListener('close', onUnavailable);
        channel.removeListener('error', onUnavailable);
        if (unavailable || channel.destroyed) {
          throw new SudoAuthenticationError('The authenticated sudo channel closed before command execution.');
        }
        try { channel.write(go + '\n'); } catch {
          terminateChannel(channel);
          try { channel.end(); } catch { /* already closed */ }
          throw new SudoAuthenticationError('The sudo channel closed before command execution.');
        }
      });
      resolve(channel);
    };
    const inspect = (buffer: string): string => {
      const promptMatch = promptLine.exec(buffer);
      if (promptMatch) {
        if (!password || passwordSent) {
          fail('Sudo authentication failed. Check the configured sudo password and account permissions.');
          return '';
        }
        passwordSent = true;
        try { stream!.write(password + '\n'); } catch {
          fail('The sudo channel closed while sending authentication.');
          return '';
        }
        buffer = buffer.slice(promptMatch.index + promptMatch[0].length);
        // sudo can emit the next prompt in the same data chunk as the first.
        if (promptLine.test(buffer)) {
          fail('Sudo authentication failed. Check the configured sudo password and account permissions.');
          return '';
        }
      }
      if (readyLine.test(buffer)) {
        authenticated();
      }
      // Keep marker overlap only. Remote diagnostics can contain secrets and
      // must never be included in tool output, traces, or authentication errors.
      const retained = Math.max(prompt.length, ready.length + 2) + 2;
      if (buffer.length <= retained) return buffer;
      const start = buffer.length - retained;
      // A truncated diagnostic line must not become a marker line merely
      // because its prefix was discarded between data chunks.
      const prefix = buffer[start - 1] === '\n' ? '' : '\0';
      return prefix + buffer.slice(start);
    };
    const onStdout = (data: Buffer) => { stdout = inspect(stdout + data.toString()); };
    const onStderr = (data: Buffer) => { stderr = inspect(stderr + data.toString()); };
    const onClose = () => fail(password
      ? 'Sudo authentication failed. Check the sudo password and permission to run commands as root.'
      : 'Passwordless sudo failed. Configure the profile sudo password or permit passwordless sudo.');
    const onError = () => fail('The SSH channel failed during sudo authentication.');
    const onAbort = () => fail('Sudo authentication aborted.');
    const timer = setTimeout(() => fail('Sudo authentication timed out.'), options.timeoutMs ?? 15_000);
    timer.unref();
    options.abortSignal?.addEventListener('abort', onAbort, { once: true });

    try {
      client.exec(wrapped, execOpts, (err, channel) => {
        if (settled) {
          if (channel) {
            terminateChannel(channel);
            try { channel.end(); } catch { /* already closed */ }
            channel.on('error', () => {});
          }
          return;
        }
        if (err) {
          fail('Failed to open an SSH channel for sudo authentication.', true);
          return;
        }
        stream = channel;
        channel.on('data', onStdout);
        channel.stderr.on('data', onStderr);
        channel.once('close', onClose);
        channel.on('error', onError);
      });
    } catch {
      fail('Failed to open an SSH channel for sudo authentication.', true);
    }
  });
}
