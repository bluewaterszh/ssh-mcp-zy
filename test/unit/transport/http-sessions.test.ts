import { afterEach, describe, expect, it, vi } from 'vitest';
import { request, type Server, type IncomingHttpHeaders } from 'http';
import type { AddressInfo } from 'net';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { startHttpServer } from '../../../src/transport/http.js';
import type { ConnectionRegistry } from '../../../src/ssh/connection-registry.js';

const BEARER = 'session-policy-test-token';
const headers = {
  authorization: `Bearer ${BEARER}`,
  host: 'session-test.local',
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
  'mcp-protocol-version': '2025-06-18',
};
const servers: Server[] = [];
const releases: Array<() => void> = [];

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function createServer() {
  const mcp = new McpServer({ name: 'session-policy-test', version: '1' });
  let count = 0;
  mcp.registerTool('count', {}, async () => ({
    content: [{ type: 'text' as const, text: String(++count) }],
  }));
  return mcp;
}

async function fixture(options: {
  maxSessions?: number;
  sessionIdleTimeoutMs?: number;
  factory?: () => McpServer | Promise<McpServer>;
} = {}) {
  const factory = vi.fn(options.factory ?? createServer);
  const server = await startHttpServer(factory, {
    port: 0,
    bearerToken: BEARER,
    allowedHosts: ['session-test.local'],
    maxSessions: options.maxSessions,
    sessionIdleTimeoutMs: options.sessionIdleTimeoutMs,
    registry: { listConnections: () => [], listAllProfiles: () => [] } as unknown as ConnectionRegistry,
  });
  servers.push(server);
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  let nextId = 0;
  async function rpc(method: string, sid?: string, params?: unknown, signal?: AbortSignal, host?: string) {
    const body = JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, ...(params === undefined ? {} : { params }) });
    // Node's request API preserves the explicit Host header used by the DNS-rebinding tests.
    const response = await new Promise<{ status: number; headers: IncomingHttpHeaders; text: string }>((resolve, reject) => {
      const req = request(url, {
        method: 'POST', agent: false, signal,
        headers: { ...headers, ...(sid ? { 'mcp-session-id': sid } : {}), ...(host ? { host } : {}) },
      }, (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => { text += chunk; });
        res.once('error', reject);
        res.once('end', () => resolve({ status: res.statusCode!, headers: res.headers, text }));
      });
      req.once('error', reject);
      req.end(body);
    });
    const json = response.headers['content-type']?.includes('text/event-stream')
      ? JSON.parse(response.text.split('\n').find((line) => line.startsWith('data: '))!.slice(6))
      : JSON.parse(response.text);
    return { status: response.status, sid: response.headers['mcp-session-id'] as string, json };
  }
  const init = (signal?: AbortSignal, host?: string) => rpc('initialize', undefined, {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'session-policy-test', version: '1' },
  }, signal, host);
  const status = async () => {
    const response = await fetch(url + '/status', { headers });
    expect(response.status).toBe(200);
    return (await response.json()).httpSessions as {
      limit: number; established: number; initializing: number; inFlightRequests: number;
      lruEvictions: number; idleExpirations: number;
    };
  };
  return { factory, rpc, init, status, url };
}

afterEach(async () => {
  for (const release of releases.splice(0)) release();
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
  }
  vi.restoreAllMocks();
});

describe('HTTP session capacity and LRU', () => {
  it('defaults to 512 and continues serving clients after more than 512 unclosed sessions', async () => {
    const f = await fixture();
    const ids: string[] = [];
    for (let i = 0; i < 515; i++) {
      const initialized = await f.init();
      expect(initialized.status).toBe(200);
      ids.push(initialized.sid);
    }
    expect(await f.status()).toMatchObject({ limit: 512, established: 512, initializing: 0, lruEvictions: 3 });
    for (const sid of ids.slice(0, 3)) expect((await f.rpc('ping', sid)).status).toBe(404);
    expect((await f.rpc('ping', ids[3])).status).toBe(200);
    expect((await f.rpc('ping', ids[514])).status).toBe(200);
  }, 20000);

  it('reuses one MCP session for multiple tool calls without creating more transports', async () => {
    const f = await fixture();
    const { sid } = await f.init();
    for (let i = 1; i <= 5; i++) {
      const response = await f.rpc('tools/call', sid, { name: 'count', arguments: {} });
      expect(response.status).toBe(200);
      expect(response.json.result.content[0].text).toBe(String(i));
    }
    expect(f.factory).toHaveBeenCalledTimes(1);
    expect(await f.status()).toMatchObject({ established: 1, initializing: 0, inFlightRequests: 0 });
  });

  it('evicts the least recently used idle session, even when timestamps are equal', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_000);
    const f = await fixture({ maxSessions: 3 });
    const a = await f.init();
    const b = await f.init();
    const c = await f.init();
    expect((await f.rpc('ping', a.sid)).status).toBe(200);
    const d = await f.init();
    expect(d.status).toBe(200);
    expect((await f.rpc('ping', b.sid)).status).toBe(404);
    for (const sid of [a.sid, c.sid, d.sid]) expect((await f.rpc('ping', sid)).status).toBe(200);
    expect(await f.status()).toMatchObject({ established: 3, lruEvictions: 1 });
  });

  it('skips an older busy session and evicts an idle one', async () => {
    const entered = deferred<void>();
    const release = deferred<void>();
    releases.push(() => release.resolve());
    const f = await fixture({ maxSessions: 2, factory: () => {
      const mcp = createServer();
      mcp.registerTool('hold', {}, async () => {
        entered.resolve();
        await release.promise;
        return { content: [{ type: 'text' as const, text: 'finished' }] };
      });
      return mcp;
    } });
    const a = await f.init();
    const b = await f.init();
    const running = f.rpc('tools/call', a.sid, { name: 'hold', arguments: {} });
    await entered.promise;
    await f.rpc('ping', b.sid); // A is the older session, but it is still executing.
    const c = await f.init();
    expect(c.status).toBe(200);
    expect((await f.rpc('ping', b.sid)).status).toBe(404);
    expect(await f.status()).toMatchObject({ established: 2, inFlightRequests: 1, lruEvictions: 1 });
    release.resolve();
    expect((await running).json.result.content[0].text).toBe('finished');
    expect((await f.rpc('ping', a.sid)).status).toBe(200);
  });

  it('rejects new sessions when every slot is busy and recovers when a request finishes', async () => {
    const entered = [deferred<void>(), deferred<void>()];
    const gates = [deferred<void>(), deferred<void>()];
    releases.push(...gates.map((gate) => () => gate.resolve()));
    let factoryIndex = 0;
    const f = await fixture({ maxSessions: 2, factory: () => {
      const index = factoryIndex++;
      const mcp = createServer();
      if (index < 2) mcp.registerTool('hold', {}, async () => {
        entered[index].resolve();
        await gates[index].promise;
        return { content: [{ type: 'text' as const, text: 'finished' }] };
      });
      return mcp;
    } });
    const a = await f.init();
    const b = await f.init();
    const first = f.rpc('tools/call', a.sid, { name: 'hold', arguments: {} });
    const second = f.rpc('tools/call', b.sid, { name: 'hold', arguments: {} });
    await Promise.all(entered.map((entry) => entry.promise));
    const rejected = await f.init();
    expect(rejected.status).toBe(503);
    expect(rejected.json.error.message).toMatch(/busy or initializing/);
    expect(await f.status()).toMatchObject({ inFlightRequests: 2, lruEvictions: 0 });
    gates[0].resolve();
    expect((await first).status).toBe(200);
    expect((await f.init()).status).toBe(200);
    expect((await f.rpc('ping', a.sid)).status).toBe(404);
    gates[1].resolve();
    expect((await second).status).toBe(200);
    expect((await f.rpc('ping', b.sid)).status).toBe(200);
  });

  it('counts pending initialization against the cap and releases a failed reservation', async () => {
    const entered = [deferred<void>(), deferred<void>()];
    const gates = [deferred<void>(), deferred<void>()];
    releases.push(...gates.map((gate) => () => gate.resolve()));
    let index = 0;
    const f = await fixture({ maxSessions: 2, factory: async () => {
      const current = index++;
      if (current < 2) {
        entered[current].resolve();
        await gates[current].promise;
      }
      return createServer();
    } });
    const first = f.init();
    const second = f.init();
    await Promise.all(entered.map((entry) => entry.promise));
    expect(await f.status()).toMatchObject({ established: 0, initializing: 2 });
    expect((await f.init()).status).toBe(503);
    expect(f.factory).toHaveBeenCalledTimes(2);
    gates[0].reject(new Error('test factory failure'));
    expect((await first).status).toBe(500);
    expect(await f.status()).toMatchObject({ initializing: 1 });
    expect((await f.init()).status).toBe(200);
    gates[1].resolve();
    expect((await second).status).toBe(200);
    expect(await f.status()).toMatchObject({ established: 2, initializing: 0, inFlightRequests: 0 });
  });

  it('releases reservations rejected by the transport before initialization', async () => {
    const f = await fixture({ maxSessions: 1 });
    expect((await f.init(undefined, 'invalid-host.example')).status).toBe(403);
    expect(await f.status()).toMatchObject({ established: 0, initializing: 0 });
    expect((await f.init()).status).toBe(200);
    expect(await f.status()).toMatchObject({ established: 1, initializing: 0, lruEvictions: 0 });
  });

  it('releases an abandoned initialization without waiting for its factory to finish', async () => {
    const entered = deferred<void>();
    const gate = deferred<void>();
    releases.push(() => gate.resolve());
    let first = true;
    const f = await fixture({ maxSessions: 1, factory: async () => {
      if (first) {
        first = false;
        entered.resolve();
        await gate.promise;
      }
      return createServer();
    } });
    const abort = new AbortController();
    const abandoned = f.init(abort.signal);
    const rejection = expect(abandoned).rejects.toThrow();
    await entered.promise;
    abort.abort();
    await rejection;
    await vi.waitFor(async () => expect(await f.status()).toMatchObject({ initializing: 0 }), { interval: 10 });
    expect((await f.init()).status).toBe(200);
    gate.resolve();
    expect(await f.status()).toMatchObject({ established: 1, initializing: 0 });
  });

  it('preserves TTL cleanup while protecting a long-running request', async () => {
    let now = 1_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const entered = deferred<void>();
    const gate = deferred<void>();
    releases.push(() => gate.resolve());
    const f = await fixture({ sessionIdleTimeoutMs: 1_000, factory: () => {
      const mcp = createServer();
      mcp.registerTool('hold', {}, async () => {
        entered.resolve();
        await gate.promise;
        return { content: [{ type: 'text' as const, text: 'finished' }] };
      });
      return mcp;
    } });
    const a = await f.init();
    const running = f.rpc('tools/call', a.sid, { name: 'hold', arguments: {} });
    await entered.promise;
    now += 2_000;
    expect((await f.rpc('ping', a.sid)).status).toBe(200);
    expect(await f.status()).toMatchObject({ established: 1, idleExpirations: 0 });
    gate.resolve();
    expect((await running).status).toBe(200);
    now += 1_001;
    expect((await f.rpc('ping', a.sid)).status).toBe(404);
    expect(await f.status()).toMatchObject({ established: 0, idleExpirations: 1 });
  });
});
