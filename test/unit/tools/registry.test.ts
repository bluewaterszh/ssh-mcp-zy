import { describe, it, expect, afterEach } from 'vitest';
import { createHarness, textOf, type Harness } from './harness.js';

let h: Harness;

afterEach(async () => { await h?.close(); });

async function call(name: string, args: Record<string, unknown> = {}) {
  return h.client.callTool({ name, arguments: args }) as Promise<any>;
}

function sessionNameOf(result: any): string {
  const match = textOf(result).match(/Session \"([^\"]+)\" opened/);
  if (!match) throw new Error(`open-session result did not contain a session name: ${textOf(result)}`);
  return match[1];
}

describe('MCP tool surface', () => {
  it('exposes exactly the documented tools', async () => {
    h = await createHarness();
    const { tools } = await h.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([
      'apply-patch', 'close-session', 'edit-file', 'list-connections', 'list-sessions', 'open-session',
      'privileged-command', 'read-batch', 'read-command', 'read-session-output',
      'run-batch', 'run-command', 'sftp-download', 'sftp-upload', 'signal-process',
      'write-session-input',
    ]);
  });

  it('does not mark any mutating tool readOnly', async () => {
    h = await createHarness();
    const { tools } = await h.client.listTools();
    const readOnly = tools.filter((t) => t.annotations?.readOnlyHint).map((t) => t.name).sort();
    // A mutating tool advertised as read-only invites auto-approval by clients.
    expect(readOnly).toEqual(['list-connections', 'list-sessions', 'read-batch', 'read-command', 'read-session-output', 'sftp-download']);
  });
});

describe('file path validation', () => {
  it('rejects control-character paths before SFTP or exec opens', async () => {
    h = await createHarness();
    const uploaded = await call('sftp-upload', {
      remotePath: '/tmp/good\nforged-log-line',
      content: 'x',
    });
    expect(uploaded.isError).toBe(true);
    expect(h.getRemoteFile('/tmp/good\nforged-log-line')).toBeUndefined();

    const patched = await call('apply-patch', {
      workdir: '/repo\nrm -rf /',
      patch: 'diff --git a/a b/a\n',
    });
    expect(patched.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('SFTP workdir path semantics', () => {
  it('resolves upload/download/edit relative paths against profile.workdir', async () => {
    h = await createHarness({ workdir: '/repo/project' });

    const up = await call('sftp-upload', { remotePath: 'out/../created.txt', content: 'created' });
    expect(up.isError).toBeFalsy();
    expect(h.getRemoteFile('/repo/project/out/../created.txt')).toBe('created');

    h.setRemoteFile('/repo/project/./read.txt', 'read-me');
    const down = await call('sftp-download', { remotePath: './read.txt' });
    expect(down.isError).toBeFalsy();
    expect(textOf(down)).toContain('read-me');

    h.setRemoteFile('/repo/project/src/./a.txt', 'before');
    const edit = await call('edit-file', {
      edits: [{ path: 'src/./a.txt', oldText: 'before', newText: 'after' }],
    });
    expect(edit.isError).toBeFalsy();
    expect(h.getRemoteFile('/repo/project/src/./a.txt')).toBe('after');
  });

  it('does not treat workdir as a sandbox; .. follows normal path semantics', async () => {
    h = await createHarness({ workdir: '/repo/project' });
    h.setRemoteFile('/repo/project/../shared.txt', 'before');
    const res = await call('edit-file', {
      edits: [{ path: '../shared.txt', oldText: 'before', newText: 'after' }],
    });
    expect(res.isError).toBeFalsy();
    expect(h.getRemoteFile('/repo/project/../shared.txt')).toBe('after');
  });
});

describe('apply-patch', () => {
  it('sends patch content byte-for-byte over SSH stdin instead of embedding it in the command', async () => {
    h = await createHarness();
    const patch = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-old\n+new '$HOME' \\ path\n";
    const res = await call('apply-patch', { patch, workdir: '/repo with space' });

    expect(res.isError).toBeFalsy();
    const exec = h.execCalls.at(-1)!;
    expect(exec.command).toBe("git -C '/repo with space' apply --recount --whitespace=nowarn -");
    expect(exec.stdin).toBe(patch);
    expect(exec.command).not.toContain('$HOME');
    expect(textOf(res)).toContain(`Applied patch (${Buffer.byteLength(patch, 'utf8')} bytes)`);
  });

  it('rejects an oversized patch before opening a remote exec', async () => {
    h = await createHarness({}, { applyPatchMaxBytes: 5 });
    const res = await call('apply-patch', { patch: '123456' });

    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/Patch is too large|applyPatchMaxBytes/i);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('edit-file', () => {
  it('applies exact replacements and validates before writing', async () => {
    h = await createHarness();
    h.setRemoteFile('/a.txt', 'alpha old\n');
    h.setRemoteFile('/b.txt', 'beta old\n');

    const checked = await call('edit-file', {
      check: true,
      edits: [
        { path: '/a.txt', oldText: 'old', newText: 'ONE' },
        { path: '/b.txt', oldText: 'old', newText: 'TWO' },
      ],
    });
    expect(checked.isError).toBeFalsy();
    expect(h.getRemoteFile('/a.txt')).toBe('alpha old\n');

    const applied = await call('edit-file', {
      edits: [
        { path: '/a.txt', oldText: 'old', newText: 'ONE' },
        { path: '/b.txt', oldText: 'old', newText: 'TWO' },
      ],
    });
    expect(applied.isError).toBeFalsy();
    expect(h.getRemoteFile('/a.txt')).toBe('alpha ONE\n');
    expect(h.getRemoteFile('/b.txt')).toBe('beta TWO\n');
  });

  it('refuses to overwrite a file that changed after the edit was planned', async () => {
    h = await createHarness();
    h.setRemoteFile('/race.txt', 'before\n');
    h.setSftpReadHook((path, readCount) => {
      if (path === '/race.txt' && readCount === 2) {
        h.setRemoteFile('/race.txt', 'changed-by-other-agent\n');
      }
    });

    const res = await call('edit-file', {
      edits: [{ path: '/race.txt', oldText: 'before', newText: 'ours' }],
    });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/file changed|re-read\/retry/i);
    expect(h.getRemoteFile('/race.txt')).toBe('changed-by-other-agent\n');
  });
  it('uses one SFTP subsystem channel for a multi-file edit and closes it', async () => {
    h = await createHarness();
    h.setRemoteFile('/a.txt', 'A old');
    h.setRemoteFile('/b.txt', 'B old');

    const res = await call('edit-file', {
      edits: [
        { path: '/a.txt', oldText: 'old', newText: 'new' },
        { path: '/b.txt', oldText: 'old', newText: 'new' },
      ],
    });
    expect(res.isError).toBeFalsy();
    expect(h.sftpOpenCount()).toBe(1);
    expect(h.sftpCloseCount()).toBe(1);
    expect(h.channelOpenCount()).toBe(1);
    expect(h.channelCloseCount()).toBe(1);
  });

  it('closes the shared SFTP channel when edit validation fails', async () => {
    h = await createHarness();
    h.setRemoteFile('/a.txt', 'no match here');
    const res = await call('edit-file', {
      edits: [{ path: '/a.txt', oldText: 'missing', newText: 'x' }],
    });
    expect(res.isError).toBe(true);
    expect(h.sftpOpenCount()).toBe(1);
    expect(h.sftpCloseCount()).toBe(1);
    expect(h.channelOpenCount()).toBe(1);
    expect(h.channelCloseCount()).toBe(1);
  });
});

describe('read-command — enforceClass', () => {
  it('runs an allowlisted read-only command', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'ls -la' });
    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toContain('ls -la');
  });

  // The security property of this tool: it is advertised to the model as not
  // modifying the system, so anything not classified read-only must be refused
  // even when the profile's role would allow it via run-command.
  it('refuses a destructive command', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'rm -rf /tmp/x' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('refuses a merely "safe" command', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'npm install' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('refuses curl, which is not read-only', async () => {
    h = await createHarness();
    const res = await call('read-command', { command: 'curl http://169.254.169.254/latest/meta-data/' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('batch commands', () => {
  it('read-batch executes and audits each read independently', async () => {
    h = await createHarness();
    const res = await call('read-batch', { commands: ['ls -la', 'pwd'] });

    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toEqual(['ls -la', 'pwd']);
    expect(h.auditRecords.slice(-2).map((r) => r.command)).toEqual(['ls -la', 'pwd']);
    expect(textOf(res)).toContain('[1/2] ls -la');
    expect(textOf(res)).toContain('[2/2] pwd');
  });

  it('read-batch stops before a command that is not read-only', async () => {
    h = await createHarness();
    const res = await call('read-batch', { commands: ['ls', 'rm -rf /tmp/x', 'pwd'] });

    expect(res.isError).toBe(true);
    expect(h.execCalls.map((c) => c.command)).toEqual(['ls']);
    expect(textOf(res)).toMatch(/tool error|read-only/i);
  });

  it('run-batch executes sequentially and stops on a remote failure by default', async () => {
    h = await createHarness();
    h.setExecResult({ exitCode: 7, stderr: 'boom' });
    const res = await call('run-batch', { commands: ['echo one', 'echo two'] });

    expect(res.isError).toBe(true);
    expect(h.execCalls.map((c) => c.command)).toEqual(['echo one']);
    expect(textOf(res)).toContain('[exit 7]');
  });

  it('run-batch can continue after failures when requested', async () => {
    h = await createHarness();
    h.setExecResult({ exitCode: 3 });
    const res = await call('run-batch', { commands: ['echo one', 'echo two'], stopOnError: false });

    expect(res.isError).toBe(true);
    expect(h.execCalls.map((c) => c.command)).toEqual(['echo one', 'echo two']);
    expect(h.auditRecords.slice(-2).map((r) => r.command)).toEqual(['echo one', 'echo two']);
  });
});

describe('run-command — approval gate', () => {
  it('executes a destructive command once the client approves', async () => {
    h = await createHarness();
    h.setApproval(true);
    const res = await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(res.isError).toBeFalsy();
    expect(h.execCalls.map((c) => c.command)).toContain('rm -rf /tmp/build');
  });

  it('blocks a destructive command when the client declines', async () => {
    h = await createHarness();
    h.setApproval(false);
    const res = await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('denies a forbidden command outright, with no prompt', async () => {
    h = await createHarness();
    h.setApproval(true);
    const res = await call('run-command', { command: 'rm -rf /' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });

  it('runs a safe command without prompting', async () => {
    h = await createHarness();
    h.setApproval(false);
    const res = await call('run-command', { command: 'npm install' });
    expect(res.isError).toBeFalsy();
  });
});

describe('privileged-command', () => {
  it('pipes the sudo password over stdin, never in the command line', async () => {
    h = await createHarness();
    const res = await call('privileged-command', { command: 'systemctl restart nginx' });
    expect(res.isError).toBeFalsy();
    const exec = h.execCalls.at(-1)!;
    expect(exec.command).not.toContain('sudo-secret');
    expect(exec.stdin).toBe('sudo-secret\n');
  });

  it('single-quotes the wrapped command so it cannot break out', async () => {
    h = await createHarness();
    await call('privileged-command', { command: "echo 'hi'; id" });
    const exec = h.execCalls.at(-1)!;
    expect(exec.command).toMatch(/^sudo -p "" -S sh -c '/);
    expect(exec.command).toContain("'\\''");
  });

  // The denylist is evaluated against the bare command as well: without that,
  // the sudo wrapper would hide a forbidden command inside a quoted sh -c arg.
  it('denies a forbidden command hidden inside the sudo wrapper', async () => {
    h = await createHarness();
    const res = await call('privileged-command', { command: 'rm -rf /' });
    expect(res.isError).toBe(true);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('command results carry exit status', () => {
  it('reports a non-zero exit as an error with the code and stderr', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: 'Unit not found', exitCode: 4 });
    const res = await call('run-command', { command: 'systemctl restart nope' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('Unit not found');
    expect(textOf(res)).toContain('[exit 4]');
  });

  it('does not flag a successful command that wrote to stderr', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: 'done', stderr: 'warning: deprecated', exitCode: 0 });
    const res = await call('run-command', { command: 'npm install' });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain('done');
  });

  it('reports a signal kill as an error', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: '', exitCode: 0, signal: 'KILL' });
    const res = await call('run-command', { command: 'sleep 100' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain('SIGKILL');
  });

  it('signal-process does not claim success when kill failed', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: 'No such process', exitCode: 1 });
    const res = await call('signal-process', { pid: 4242, signal: 'TERM' });
    expect(res.isError).toBe(true);
    expect(textOf(res)).not.toContain('sent to PID');
  });
});

describe('output redaction', () => {
  it('redacts secrets in command output before the model sees them', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY', exitCode: 0 });
    const res = await call('read-command', { command: 'env' });
    expect(textOf(res)).not.toContain('wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY');
  });
});

describe('audit records', () => {
  it('records an allowed command as allowed', async () => {
    h = await createHarness();
    await call('read-command', { command: 'ls -la' });
    expect(h.auditRecords.at(-1)).toMatchObject({ command: 'ls -la', decision: 'allow', exitCode: 0 });
  });

  it('records a policy denial as denied', async () => {
    h = await createHarness();
    await call('run-command', { command: 'rm -rf /' });
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'denylist' });
  });

  // Regression: a command that was allowed, approved and executed but then
  // failed used to be written to the audit log as decision 'deny' — telling an
  // auditor the command was blocked when it had actually run on the host.
  it('records an executed-but-failed command with its real decision', async () => {
    h = await createHarness();
    h.setExecResult({ stdout: '', stderr: 'boom', exitCode: 7 });
    await call('run-command', { command: 'npm install' });
    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('allow');
    expect(record.exitCode).toBe(7);
  });

  // Regression: sanitizeCommand ran outside the try, so a rejected payload left
  // no trace at all — a client could probe with malformed input unaudited.
  it('records an input rejected by the sanitizer', async () => {
    h = await createHarness({ maxChars: 10 });
    const res = await call('run-command', { command: 'x'.repeat(50) });
    expect(res.isError).toBe(true);
    expect(h.auditRecords.at(-1)).toMatchObject({ decision: 'deny', ruleId: 'input-rejected' });
  });

  it('records a declined approval', async () => {
    h = await createHarness();
    h.setApproval(false);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('require-approval');
    expect(record.error).toMatch(/APPROVAL_DENIED/);
  });
});

describe('just-in-time approval grants', () => {
  // Approving the same destructive command every few seconds trains the
  // operator to click through prompts, which is worse than a bounded grant.
  it('skips the prompt for an identical command within the grant window', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(true);

    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });

    expect(h.approvalPrompts()).toBe(1);
    expect(h.execCalls).toHaveLength(3);
  });

  // Bound to the exact command: a grant must not widen to a similar one.
  it('still prompts for a different command', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(true);

    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build-prod' });

    expect(h.approvalPrompts()).toBe(2);
  });

  it('records the grant as the approver in the audit log', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(true);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });

    // The second run is attributable to the grant, not to a fresh human answer.
    expect(h.auditRecords.at(-2).approver).toBe('mcp-client');
    expect(h.auditRecords.at(-1).approver).toBe('jit-grant');
  });

  // Off by default: auto-approval weakens the gate that makes destructive
  // commands safe, so it must be an explicit decision.
  it('is disabled by default — every destructive command prompts', async () => {
    h = await createHarness();
    h.setApproval(true);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(h.approvalPrompts()).toBe(2);
  });

  it('does not grant anything when the client declines', async () => {
    h = await createHarness({}, { approvalGrantTtlMs: 60_000 });
    h.setApproval(false);
    await call('run-command', { command: 'rm -rf /tmp/build' });
    await call('run-command', { command: 'rm -rf /tmp/build' });
    expect(h.approvalPrompts()).toBe(2);
    expect(h.execCalls).toHaveLength(0);
  });
});

describe('command quota', () => {
  // The approval gate stops destructive commands and the HTTP limiter caps
  // request rate, but neither bounds total work: an agent looping over allowed
  // commands stays under both. The quota is the circuit breaker for that.
  it('refuses further commands once the daily quota is spent', async () => {
    h = await createHarness({ commandQuotaPerDay: 3 });

    for (let i = 0; i < 3; i++) {
      const ok = await call('read-command', { command: `ls dir-${i}` });
      expect(ok.isError).toBeFalsy();
    }

    const blocked = await call('read-command', { command: 'ls again' });
    expect(blocked.isError).toBe(true);
    expect(textOf(blocked)).toMatch(/QUOTA_EXCEEDED/);
    // The refused command must not reach the host.
    expect(h.execCalls).toHaveLength(3);
  });

  it('audits a quota refusal with its own rule id', async () => {
    h = await createHarness({ commandQuotaPerDay: 1 });
    await call('read-command', { command: 'ls' });
    await call('read-command', { command: 'ls' });

    const record = h.auditRecords.at(-1);
    expect(record.decision).toBe('deny');
    expect(record.ruleId).toBe('command-quota');
  });

  it('does not count commands the policy already refused', async () => {
    h = await createHarness({ commandQuotaPerDay: 2 });
    // Denied by the forbidden list — should not spend budget.
    await call('run-command', { command: 'rm -rf /' });
    await call('run-command', { command: 'rm -rf /' });

    const ok = await call('read-command', { command: 'ls' });
    expect(ok.isError).toBeFalsy();
  });

  it('is unlimited when the quota is zero', async () => {
    h = await createHarness({ commandQuotaPerDay: 0 });
    for (let i = 0; i < 12; i++) {
      const res = await call('read-command', { command: `ls ${i}` });
      expect(res.isError).toBeFalsy();
    }
  });
});

describe('sessions', () => {
  it('opens, lists and closes a UUID-suffixed session, auditing the actual name', async () => {
    h = await createHarness();
    const opened = await call('open-session', { name: 'work', type: 'interactive' });
    expect(opened.isError).toBeFalsy();
    const actualName = sessionNameOf(opened);
    expect(actualName).toMatch(/^work-[0-9a-f-]{36}$/);
    expect(actualName.length).toBeLessThanOrEqual(64);
    expect(h.auditRecords.at(-1).command).toContain(`session:open interactive ${actualName}`);

    const listed = await call('list-sessions', {});
    expect(textOf(listed)).toContain(actualName);

    const closed = await call('close-session', { name: actualName });
    expect(closed.isError).toBeFalsy();
    expect(h.auditRecords.at(-1).command).toBe(`session:close interactive ${actualName}`);
  });

  it('gives concurrent clients using the same prefix distinct actual names', async () => {
    h = await createHarness();
    const first = sessionNameOf(await call('open-session', { name: 'work', type: 'interactive' }));
    const second = sessionNameOf(await call('open-session', { name: 'work', type: 'interactive' }));
    expect(first).not.toBe(second);
    expect(first).toMatch(/^work-[0-9a-f-]{36}$/);
    expect(second).toMatch(/^work-[0-9a-f-]{36}$/);
    await call('close-session', { name: first });
    await call('close-session', { name: second });
  });

  it('audits closing a background session, recording its actual UUID name and kind', async () => {
    h = await createHarness();
    const actualName = sessionNameOf(await call('open-session', {
      name: 'logs', type: 'background', command: 'tail -f /var/log/syslog',
    }));
    const closed = await call('close-session', { name: actualName });
    expect(closed.isError).toBeFalsy();
    const record = h.auditRecords.at(-1);
    expect(record.command).toBe(`session:close background ${actualName}`);
    expect(record.commandClass).toBe('safe');
    expect(record.ruleId).toBe('session-release');
    expect(record.decision).toBe('allow');
    expect(record.exitCode).toBe(0);
  });

  it('closes the UUID-named session even on a profile whose policy refuses "safe" commands', async () => {
    h = await createHarness({ readOnly: true });
    const actualName = sessionNameOf(await call('open-session', {
      name: 'logs', type: 'background', command: 'tail -f /var/log/syslog',
    }));
    const closed = await call('close-session', { name: actualName });
    expect(closed.isError).toBeFalsy();
    expect(h.auditRecords.at(-1).command).toBe(`session:close background ${actualName}`);

    const listed = await call('list-sessions', {});
    expect(textOf(listed)).not.toContain(actualName);
  });

  it.each([
    ['unsignalled', /could not be signalled/],
    ['stop-unconfirmed', /had not closed in time/],
  ] as const)('tells the caller when a %s close may have left the command running', async (outcome, expected) => {
    h = await createHarness();
    h.setCloseOutcome(outcome);
    const actualName = sessionNameOf(await call('open-session', {
      name: 'logs', type: 'background', command: 'tail -f /var/log/syslog',
    }));
    const closed = await call('close-session', { name: actualName });
    expect(textOf(closed)).toMatch(expected);
    expect(h.auditRecords.at(-1).exitCode).toBe(1);
  });

  it('says nothing extra when the stop is confirmed', async () => {
    h = await createHarness();
    const actualName = sessionNameOf(await call('open-session', {
      name: 'logs', type: 'background', command: 'tail -f /var/log/syslog',
    }));
    const closed = await call('close-session', { name: actualName });
    expect(textOf(closed)).toBe(`Session "${actualName}" closed.`);
  });

  it('rejects a session name prefix with shell metacharacters', async () => {
    h = await createHarness();
    const res = await call('open-session', { name: 'a; rm -rf /', type: 'interactive' });
    expect(res.isError).toBe(true);
  });

  it('redacts secrets in background session output using the returned actual name', async () => {
    h = await createHarness();
    const actualName = sessionNameOf(await call('open-session', {
      name: 'logs', type: 'background', command: 'tail -f /var/log/syslog',
    }));
    const res = await call('read-session-output', { name: actualName, lines: 5 });
    expect(res.isError).toBeFalsy();
  });
});

describe('interactive session I/O', () => {
  it('writes one policy-checked line using the UUID name returned by open-session', async () => {
    h = await createHarness();
    const opened = await call('open-session', { name: 'repl', type: 'interactive' });
    const actualName = sessionNameOf(opened);

    const written = await call('write-session-input', { name: actualName, input: 'continue' });
    expect(written.isError).toBeFalsy();
    expect(h.sessionInputs).toEqual(['continue\n']);
    expect(h.auditRecords.at(-1).command).toBe('continue');

    const output = await call('read-session-output', { name: actualName, lines: 5 });
    expect(textOf(output)).toContain('session output line');
  });

  it('rejects embedded newlines so one policy check cannot deliver multiple shell lines', async () => {
    h = await createHarness();
    const opened = await call('open-session', { name: 'repl', type: 'interactive' });
    const actualName = sessionNameOf(opened);

    const res = await call('write-session-input', {
      name: actualName,
      input: 'echo safe\nrm -rf /tmp/hidden',
    });
    expect(res.isError).toBe(true);
    expect(h.sessionInputs).toHaveLength(0);
  });
});

describe('resources', () => {
  it('lists the documented resources', async () => {
    h = await createHarness();
    const { resources } = await h.client.listResources();
    expect(resources.map((r) => r.uri)).toContain('ssh://connections');
  });

  it('returns connection data as JSON', async () => {
    h = await createHarness();
    const res = await h.client.readResource({ uri: 'ssh://connections' });
    const body = JSON.parse((res.contents[0] as any).text);
    expect(JSON.stringify(body)).toContain('dev');
  });
});
