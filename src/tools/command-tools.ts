import { z } from 'zod';
import { shellSingleQuote } from '../guard/sanitizer.js';
import { redactText } from '../guard/redactor.js';
import { TOOL_DESCRIPTIONS as D } from './descriptions.js';
import { commandOutput, textResult } from './results.js';
import { PolicyRefusedError, type ToolDeps, type Pipeline } from './pipeline.js';
import type { CommandResult } from '../types.js';

interface BatchBuffer {
  blocks: string[];
  bytes: number;
  truncated: boolean;
}

function appendBatchBlock(state: BatchBuffer, block: string, maxBytes: number): void {
  if (state.truncated) return;
  const separator = state.blocks.length ? '\n\n' : '';
  const separatorBytes = Buffer.byteLength(separator);
  const blockBytes = Buffer.from(block, 'utf8');
  if (state.bytes + separatorBytes + blockBytes.length <= maxBytes) {
    state.blocks.push(block);
    state.bytes += separatorBytes + blockBytes.length;
    return;
  }

  const notice = `\n[batch output truncated at ${maxBytes} bytes]`;
  const available = Math.max(0, maxBytes - state.bytes - separatorBytes - Buffer.byteLength(notice));
  const prefix = blockBytes.subarray(0, available).toString('utf8');
  state.blocks.push(prefix + notice);
  state.bytes = maxBytes;
  state.truncated = true;
}

interface ForegroundGuard {
  signal?: AbortSignal;
  timedOut(): boolean;
  throwIfTimedOut(): void;
}

async function withForegroundGuard<T>(
  upstream: AbortSignal | undefined,
  maxMs: number | undefined,
  run: (guard: ForegroundGuard) => Promise<T>,
): Promise<T> {
  if (!maxMs || maxMs <= 0) {
    return run({ signal: upstream, timedOut: () => false, throwIfTimedOut: () => {} });
  }

  const controller = new AbortController();
  let timedOut = false;
  let detachUpstream = () => {};
  if (upstream) {
    if (upstream.aborted) {
      controller.abort(upstream.reason);
    } else {
      const onAbort = () => controller.abort(upstream.reason);
      upstream.addEventListener('abort', onAbort, { once: true });
      detachUpstream = () => upstream.removeEventListener('abort', onAbort);
    }
  }

  const timeoutError = () => new Error(
    `FOREGROUND_TIMEOUT: synchronous command work exceeded ${Math.round(maxMs / 1000)}s ` +
    'and was cancelled before the HTTP/tunnel response deadline. For long-running work, ' +
    'use open-session(type="background", command="...") and poll read-session-output.',
  );
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort(timeoutError());
  }, maxMs);
  timer.unref();

  const guard: ForegroundGuard = {
    signal: controller.signal,
    timedOut: () => timedOut,
    throwIfTimedOut: () => { if (timedOut) throw timeoutError(); },
  };

  try {
    return await run(guard);
  } catch (err) {
    if (timedOut) throw timeoutError();
    throw err;
  } finally {
    clearTimeout(timer);
    detachUpstream();
  }
}

/** Tools that run a command on the remote host. */
export function registerCommandTools(
  { server, registry, policy, foregroundCommandMaxMs }: ToolDeps,
  pipeline: Pipeline,
) {
  const { runAudited, execAndReport, defaultProfileName } = pipeline;

  // ─── read-command ──────────────────────────────────────────────────────
  server.tool(
    'read-command',
    D["read-command"],
    {
      command: z.string().describe('Read-only shell command (must be in the allowlist)'),
      profile: z.string().optional().describe('Profile name'),
    },
    { readOnlyHint: true },
    async ({ command, profile }, extra) => {
      return withForegroundGuard(extra?.signal, foregroundCommandMaxMs, (guard) => runAudited(
        command,
        {
          toolName: 'read-command', failureClass: 'read-only', enforceClass: 'read-only',
          profile, extra, abortSignal: guard.signal,
        },
        execAndReport(),
      ));
    },
  );

  // ─── read-batch ─────────────────────────────────────────────────────────
  server.tool(
    'read-batch',
    D["read-batch"],
    {
      commands: z.array(z.string()).min(1).max(64).describe('Read-only shell commands to execute sequentially'),
      profile: z.string().optional().describe('Profile name'),
      stopOnError: z.boolean().default(true).describe('Stop after the first rejected or failed command'),
    },
    { readOnlyHint: true },
    async ({ commands, profile, stopOnError }, extra) => {
      return withForegroundGuard(extra?.signal, foregroundCommandMaxMs, async (guard) => {
        const batch: BatchBuffer = { blocks: [], bytes: 0, truncated: false };
        const maxResponseBytes = registry.getProfile(defaultProfileName(profile)).maxOutputBytes;
        let failed = false;

        for (let i = 0; i < commands.length; i++) {
          guard.throwIfTimedOut();
          const command = commands[i];
          try {
            const output = await runAudited(
              command,
              {
                toolName: 'read-batch', failureClass: 'read-only',
                enforceClass: 'read-only', profile, extra, abortSignal: guard.signal,
              },
              execAndReport(),
            );
            const body = output.content.map((c) => c.text).join('\n') || '(no output)';
            appendBatchBlock(
              batch,
              `[${i + 1}/${commands.length}] ${redactText(command, { entropyScan: true })}\n${body}`,
              maxResponseBytes,
            );
            if (output.isError) {
              failed = true;
              if (stopOnError) break;
            }
          } catch (err) {
            if (guard.timedOut()) throw err;
            failed = true;
            const message = err instanceof Error ? err.message : String(err);
            appendBatchBlock(
              batch,
              `[${i + 1}/${commands.length}] ${redactText(command, { entropyScan: true })}\n` +
                `[tool error] ${redactText(message, { entropyScan: true })}`,
              maxResponseBytes,
            );
            if (stopOnError) break;
          }
        }

        return {
          content: [{ type: 'text' as const, text: batch.blocks.join('\n\n') }],
          ...(failed ? { isError: true } : {}),
        };
      });
    },
  );

  // ─── run-command ───────────────────────────────────────────────────────
  server.tool(
    'run-command',
    D["run-command"],
    {
      command: z.string().describe('Shell command to execute'),
      profile: z.string().optional().describe('Profile name'),
      session: z.string().optional().describe('Exact interactive session name returned by open-session (stateful)'),
      tty: z.boolean().optional().describe('Allocate a pseudo-terminal'),
    },
    { destructiveHint: true },
    async ({ command, profile, session, tty }, extra) => {
      return withForegroundGuard(extra?.signal, foregroundCommandMaxMs, (guard) => runAudited(
        command,
        {
          toolName: 'run-command', failureClass: 'safe', profile, session, extra,
          abortSignal: guard.signal,
        },
        async (rt) => {
          // A session run keeps the caller's shell state; a plain exec does not.
          let audited: CommandResult;
          if (session) {
            const sess = rt.conn.getSession(session);
            if (!sess) throw new Error(`Session "${session}" not found`);
            audited = await sess.run(rt.command, undefined, rt.abortSignal);
          } else {
            audited = await rt.conn.exec(rt.command, {
              tty, onProgress: rt.onProgress, abortSignal: rt.abortSignal,
            });
          }
          return { audited, output: commandOutput(audited) };
        },
      ));
    },
  );

  // ─── run-batch ──────────────────────────────────────────────────────────
  server.tool(
    'run-batch',
    D["run-batch"],
    {
      commands: z.array(z.string()).min(1).max(64).describe('Shell commands to execute sequentially'),
      profile: z.string().optional().describe('Profile name'),
      session: z.string().optional().describe('Exact interactive session name returned by open-session; all commands run in that session'),
      tty: z.boolean().optional().describe('Allocate a pseudo-terminal for non-session commands'),
      stopOnError: z.boolean().default(true).describe('Stop after the first rejected or failed command'),
    },
    { destructiveHint: true },
    async ({ commands, profile, session, tty, stopOnError }, extra) => {
      return withForegroundGuard(extra?.signal, foregroundCommandMaxMs, async (guard) => {
        const batch: BatchBuffer = { blocks: [], bytes: 0, truncated: false };
        const maxResponseBytes = registry.getProfile(defaultProfileName(profile)).maxOutputBytes;
        let failed = false;

        for (let i = 0; i < commands.length; i++) {
          guard.throwIfTimedOut();
          const command = commands[i];
          try {
            const output = await runAudited(
              command,
              {
                toolName: 'run-batch', failureClass: 'safe', profile, session, extra,
                abortSignal: guard.signal,
              },
              async (rt) => {
                let audited: CommandResult;
                if (session) {
                  const sess = rt.conn.getSession(session);
                  if (!sess) throw new Error(`Session "${session}" not found`);
                  audited = await sess.run(rt.command, undefined, rt.abortSignal);
                } else {
                  audited = await rt.conn.exec(rt.command, {
                    tty, onProgress: rt.onProgress, abortSignal: rt.abortSignal,
                  });
                }
                return { audited, output: commandOutput(audited) };
              },
            );
            const body = output.content.map((c) => c.text).join('\n') || '(no output)';
            appendBatchBlock(
              batch,
              `[${i + 1}/${commands.length}] ${redactText(command, { entropyScan: true })}\n${body}`,
              maxResponseBytes,
            );
            if (output.isError) {
              failed = true;
              if (stopOnError) break;
            }
          } catch (err) {
            if (guard.timedOut()) throw err;
            failed = true;
            const message = err instanceof Error ? err.message : String(err);
            appendBatchBlock(
              batch,
              `[${i + 1}/${commands.length}] ${redactText(command, { entropyScan: true })}\n` +
                `[tool error] ${redactText(message, { entropyScan: true })}`,
              maxResponseBytes,
            );
            if (stopOnError) break;
          }
        }

        return {
          content: [{ type: 'text' as const, text: batch.blocks.join('\n\n') }],
          ...(failed ? { isError: true } : {}),
        };
      });
    },
  );

  // ─── privileged-command ────────────────────────────────────────────────
  server.tool(
    'privileged-command',
    D["privileged-command"],
    {
      command: z.string().describe('Command to execute with sudo'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ command, profile }, extra) => {
      const profileName = defaultProfileName(profile);
      return withForegroundGuard(extra?.signal, foregroundCommandMaxMs, (guard) => runAudited(
        command,
        {
          toolName: 'privileged-command',
          failureClass: 'privileged',
          profile,
          extra,
          abortSignal: guard.signal,
          // Evaluate the bare command too: the sudo wrapper would otherwise
          // hide a forbidden command inside a quoted `sh -c` argument.
          preCheck: (cleanCmd) => {
            const rawEval = policy.evaluate(cleanCmd, registry.getProfile(profileName), 'privileged-command');
            if (rawEval.decision === 'deny') {
              throw new PolicyRefusedError(
                `POLICY_DENIED: ${rawEval.reason || 'Command not allowed'}`,
                rawEval,
              );
            }
          },
          wrap: (cleanCmd) => `sudo -p "" -S sh -c ${shellSingleQuote(cleanCmd)}`,
        },
        (rt) => {
          const sudoPassword = rt.conn.getSudoPassword();
          return execAndReport({ stdin: sudoPassword ? sudoPassword + '\n' : undefined })(rt);
        },
      ));
    },
  );

  // ─── signal-process ────────────────────────────────────────────────────
  server.tool(
    'signal-process',
    D["signal-process"],
    {
      pid: z.number().int().min(1).describe('Process ID to signal (positive integer)'),
      signal: z.enum(['INT', 'TERM', 'KILL']).default('TERM').describe('Signal to send'),
      profile: z.string().optional().describe('Profile name'),
    },
    { destructiveHint: true },
    async ({ pid, signal, profile }, extra) => {
      return runAudited(
        `kill -${signal} ${pid}`,
        { toolName: 'signal-process', failureClass: 'destructive', profile, extra, synthetic: true },
        async (rt) => {
          const { audited, output } = await execAndReport()(rt);
          // `kill` is silent on success — confirm what was sent rather than
          // returning an empty result.
          const silentSuccess = !output.isError && !audited.stdout.trim() && !audited.stderr.trim();
          return {
            audited,
            output: silentSuccess ? textResult(`Signal ${signal} sent to PID ${pid}`) : output,
          };
        },
      );
    },
  );
}
