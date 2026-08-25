import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { EventEmitter } from 'events';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { registerTools, registerResources } from '../../../src/tools/registry.js';
import { PolicyEngine, DEFAULT_RULES } from '../../../src/policy/engine.js';
import { AuditStore } from '../../../src/audit/store.js';
import type { CommandResult, Profile } from '../../../src/types.js';
import type { CloseOutcome } from '../../../src/ssh/session.js';

/**
 * In-process MCP client + server over InMemoryTransport, with the SSH layer
 * stubbed. The point is the handler layer — enforceClass, the approval gate,
 * output redaction, exit-status reporting and audit records — which is where
 * every per-request security decision lives and which had no tests at all.
 */

export const testProfile: Profile = {
  name: 'dev',
  group: 'dev',
  host: 'stub',
  port: 22,
  user: 'tester',
  auth: 'password',
  tty: false,
  timeout: 5000,
  maxChars: 5000,
  maxOutputBytes: 1_048_576,
  role: 'admin',
  readOnly: false,
  approvalPolicy: 'ask-destructive',
  cert: false,
  sessionMaxPerConnection: 5,
  sessionIdleTimeoutMs: 60_000,
  sessionBackgroundMaxMs: 3_600_000,
  commandQuotaPerDay: 0,
};

export interface ExecCall {
  command: string;
  stdin?: string;
}

export interface Harness {
  client: Client;
  execCalls: ExecCall[];
  auditRecords: any[];
  sessionInputs: string[];
  setRemoteFile(path: string, content: string): void;
  getRemoteFile(path: string): string | undefined;
  setSftpReadHook(hook?: (path: string, readCount: number) => void): void;
  sftpOpenCount(): number;
  sftpCloseCount(): number;
  channelOpenCount(): number;
  channelCloseCount(): number;
  /** What the stubbed exec returns; override per test. */
  setExecResult(result: Partial<CommandResult>): void;
  /** Artificial remote runtime used by timeout/cancellation tests. */
  setExecDelayMs(ms: number): void;
  /** Whether the client approves elicitation prompts. */
  setApproval(approve: boolean): void;
  /** How many times the client was actually prompted. */
  approvalPrompts(): number;
  /**
   * What `closeSession` reports; override per test.
   *
   * Configurable because the stub used to return `void`, so `outcome === 'unsignalled'` was
   * never true and the branch that warns the caller a stop was not dispatched was dead in
   * every unit test — including the ones written to cover it.
   */
  setCloseOutcome(outcome: CloseOutcome): void;
  close(): Promise<void>;
}

export async function createHarness(
  overrides: Partial<Profile> = {},
  toolOpts: {
    approvalGrantTtlMs?: number;
    applyPatchMaxBytes?: number;
    foregroundCommandMaxMs?: number;
  } = {},
): Promise<Harness> {
  const profile: Profile = { ...testProfile, ...overrides };
  const execCalls: ExecCall[] = [];
  const auditRecords: any[] = [];
  const sessionInputs: string[] = [];
  const remoteFiles = new Map<string, Buffer>();
  const sftpReadCounts = new Map<string, number>();
  let sftpReadHook: ((path: string, readCount: number) => void) | undefined;
  let sftpOpens = 0;
  let sftpCloses = 0;
  let channelOpens = 0;
  let channelCloses = 0;
  let approve = true;
  let closeOutcome: CloseOutcome = 'closed';
  let approvalPrompts = 0;
  let execResult: Partial<CommandResult> = {};
  let execDelayMs = 0;

  const makeResult = (command: string): CommandResult => ({
    stdout: `stdout for ${command}`,
    stderr: '',
    exitCode: 0,
    durationMs: 1,
    profile: profile.name,
    ...execResult,
  });

  const sessions = new Map<string, any>();

  const fakeSftp: any = {
    stat(path: string, cb: (err: Error | undefined, stats?: any) => void) {
      const data = remoteFiles.get(path);
      if (!data) {
        const err = Object.assign(new Error(`ENOENT: ${path}`), { code: 'ENOENT' });
        cb(err);
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      cb(undefined, { size: data.length, mode: 0o100644, mtime: now, atime: now });
    },
    createReadStream(path: string) {
      const stream = Object.assign(new EventEmitter(), { destroy: () => {} });
      const count = (sftpReadCounts.get(path) ?? 0) + 1;
      sftpReadCounts.set(path, count);
      sftpReadHook?.(path, count);
      const data = remoteFiles.get(path);
      queueMicrotask(() => {
        if (!data) stream.emit('error', new Error(`ENOENT: ${path}`));
        else {
          stream.emit('data', Buffer.from(data));
          stream.emit('close');
        }
      });
      return stream;
    },
    createWriteStream(path: string) {
      const stream = Object.assign(new EventEmitter(), {
        end(content: string | Buffer) {
          remoteFiles.set(path, Buffer.isBuffer(content) ? Buffer.from(content) : Buffer.from(content));
          queueMicrotask(() => stream.emit('close'));
        },
      });
      return stream;
    },
    end() { sftpCloses++; },
  };

  const conn: any = {
    profile,
    async ensureConnected() {},
    noteActivity() {},
    noteChannelOpened() { channelOpens++; return () => { channelCloses++; }; },
    async exec(command: string, opts: any = {}) {
      execCalls.push({ command, stdin: opts.stdin });
      if (opts.abortSignal?.aborted) throw new Error('Command aborted before execution');
      if (execDelayMs > 0) {
        await new Promise<void>((resolve, reject) => {
          let settled = false;
          const finish = (err?: Error) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            opts.abortSignal?.removeEventListener('abort', onAbort);
            err ? reject(err) : resolve();
          };
          const onAbort = () => finish(new Error('Command aborted'));
          const timer = setTimeout(() => finish(), execDelayMs);
          opts.abortSignal?.addEventListener('abort', onAbort, { once: true });
        });
      }
      return makeResult(command);
    },
    getSudoPassword: () => 'sudo-secret',
    getClient: () => ({
      sftp(cb: (err: Error | undefined, handle?: any) => void) { sftpOpens++; cb(undefined, fakeSftp); },
    }),
    getSession: (name: string) => sessions.get(name),
    // Matches SSHConnection.listSessions(): Session objects, not SessionInfo —
    // the handler calls toInfo() itself.
    listSessions: () => [...sessions.values()],
    async openSession({ name, type }: any) {
      const session = {
        type,
        toInfo: () => ({ id: name, name, profile: profile.name, type, status: 'active', createdAt: new Date(), lastActivity: new Date(), ttlMs: 1000 }),
        run: async (command: string) => { execCalls.push({ command }); return makeResult(command); },
        readOutput: () => 'session output line',
        writeInput: (input: string) => { sessionInputs.push(input); },
      };
      sessions.set(name, session);
      return session;
    },
    async closeSession(name: string): Promise<CloseOutcome> {
      if (!sessions.has(name)) throw new Error(`Session \"${name}\" not found`);
      sessions.delete(name);
      return closeOutcome;
    },
    toInfo: () => ({
      profile: profile.name, host: profile.host, port: profile.port, user: profile.user,
      status: 'connected', sessionCount: sessions.size, activeChannels: 0,
    }),
  };

  const registry: any = {
    getOrCreate: async () => conn,
    get: () => conn,
    getProfile: () => profile,
    listConnections: () => [conn.toInfo()],
    listAllProfiles: () => [profile],
  };

  // Capture audit records instead of writing to disk.
  const audit = { record: async (r: any) => { auditRecords.push(r); } } as unknown as AuditStore;

  const server = new McpServer(
    { name: 'test', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerTools(server, registry, new PolicyEngine(DEFAULT_RULES), audit, toolOpts);
  registerResources(server, registry);

  const client = new Client(
    { name: 'test-client', version: '0.0.0' },
    { capabilities: { elicitation: {} } },
  );
  // Stand in for the human at the approval prompt.
  client.setRequestHandler(ElicitRequestSchema, async () => {
    approvalPrompts++;
    return approve ? { action: 'accept', content: { confirm: true } } : { action: 'decline' };
  });

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    execCalls,
    auditRecords,
    sessionInputs,
    setRemoteFile(path, content) { remoteFiles.set(path, Buffer.from(content)); },
    getRemoteFile(path) { return remoteFiles.get(path)?.toString('utf8'); },
    setSftpReadHook(hook) { sftpReadHook = hook; },
    sftpOpenCount: () => sftpOpens,
    sftpCloseCount: () => sftpCloses,
    channelOpenCount: () => channelOpens,
    channelCloseCount: () => channelCloses,
    setExecResult(result) { execResult = result; },
    setExecDelayMs(ms) { execDelayMs = ms; },
    setApproval(value) { approve = value; },
    setCloseOutcome(outcome) { closeOutcome = outcome; },
    approvalPrompts: () => approvalPrompts,
    async close() { await client.close(); await server.close(); },
  };
}

/** Flatten a CallToolResult's text content. */
export function textOf(result: any): string {
  return (result.content ?? []).map((c: any) => c.text ?? '').join('\n');
}
