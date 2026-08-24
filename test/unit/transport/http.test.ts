import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'net';

const HTTP_PORT = 18399;
const HTTP_HOST = '127.0.0.1';
const BEARER = 'test-token-secret';

beforeAll(async () => {
  process.env.SSH_MCP_DISABLE_MAIN = '1';
  await startTestServer();
});

afterAll(async () => {
  // Server cleanup — the mock doesn't expose a close handle,
  // so we rely on process exit to clean up
});

function startTestServer(): Promise<Server> {
  return new Promise(async (resolve, reject) => {
    try {
      const { startHttpServer } = await import('../../../src/transport/http.js');
      const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');

      const mockRegistry = {
        listConnections: () => [],
        listAllProfiles: () => [],
        get: () => undefined,
        getOrCreate: async () => { throw new Error('not in test'); },
      } as any;

      const mcpServer = new McpServer(
        { name: 'test', version: '0.0.0' },
        { capabilities: { tools: {}, resources: {} } },
      );

      await startHttpServer(() => mcpServer, {
        port: HTTP_PORT,
        host: HTTP_HOST,
        bearerToken: BEARER,
        rateLimit: 5,
        maxBodyBytes: 1_048_576,
        sessionIdleTimeoutMs: 100,
        registry: mockRegistry,
      });

      setTimeout(() => resolve({ close: () => {} } as any), 100);
    } catch (err) {
      reject(err);
    }
  });
}

function httpRequest(method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HTTP_HOST,
      port: HTTP_PORT,
      path,
      method,
      headers,
      // Fresh socket per request: keep-alive pooling makes these tests
      // order-coupled, since a socket the server destroys stays in the pool.
      agent: false as const,
    };
    const http = require('http');
    const req2 = http.request(options, (res: any) => {
      let data = '';
      res.on('data', (chunk: any) => (data += chunk));
      res.on('end', () => {
        resolve({ status: res.statusCode, body: data, headers: res.headers });
      });
    });
    req2.on('error', reject);
    if (body) req2.write(body);
    req2.end();
  });
}

describe('HTTP transport — auth', () => {
  it('rejects request without bearer token', async () => {
    const res = await httpRequest('GET', '/status');
    expect(res.status).toBe(401);
    // RFC 7235: a 401 has to tell the client how to authenticate.
    expect(res.headers['www-authenticate']).toMatch(/Bearer/);
    // Same JSON-RPC dialect as the 413/429 on this server.
    expect(JSON.parse(res.body).error.message).toBe('Unauthorized');
  });

  it('rejects request with wrong token', async () => {
    const res = await httpRequest('GET', '/status', { authorization: 'Bearer wrong-token' });
    expect(res.status).toBe(401);
  });

  it('accepts request with correct token', async () => {
    const res = await httpRequest('GET', '/status', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
  });

  it('rejects malformed authorization header', async () => {
    const res = await httpRequest('GET', '/status', { authorization: 'Basic xyz' });
    expect(res.status).toBe(401);
  });

  // Load balancers probe /health unauthenticated, and it reveals nothing
  // beyond "the process is up".
  it('serves /health without authentication', async () => {
    const res = await httpRequest('GET', '/health');
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body).healthy).toBe(true);
  });
});

describe('HTTP transport — /health endpoint', () => {
  it('returns healthy status', async () => {
    const res = await httpRequest('GET', '/health', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.healthy).toBe(true);
  });
});

describe('HTTP transport — /status endpoint', () => {
  it('returns server status', async () => {
    const res = await httpRequest('GET', '/status', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe('running');
    // Version comes from package.json — no hardcoded literal to drift.
    const { SERVER_VERSION } = await import('../../../src/version.js');
    expect(body.version).toBe(SERVER_VERSION);
  });
});

describe('HTTP transport — 404', () => {
  it('returns 404 for unknown path', async () => {
    const res = await httpRequest('GET', '/unknown', { authorization: `Bearer ${BEARER}` });
    expect(res.status).toBe(404);
  });
});

describe('HTTP transport — body size limit', () => {
  // The 413 must actually arrive before the socket dies, and must announce
  // Connection: close so a keep-alive client discards the socket instead of
  // pooling one the server is about to destroy (that poisoned the next test).
  it('enforces the configured body cap by UTF-8 bytes and closes the connection', async () => {
    // 270k emoji are ~1.08 MB in UTF-8 but only 540k JS UTF-16 code units. This
    // catches implementations that accidentally compare string length instead of bytes.
    const largeBody = '🙂'.repeat(270_000);
    const res = await httpRequest(
      'POST',
      '/',
      { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json' },
      largeBody,
    );
    expect(res.status).toBe(413);
    expect(res.headers.connection).toBe('close');
    expect(JSON.parse(res.body).error.message).toMatch(/too large/i);
  });
});

describe('HTTP transport — sessions', () => {
  const headers = { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };

  it('reaps an idle MCP session when the client disappears without DELETE', async () => {
    const init = await httpRequest('POST', '/', headers, JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'initialize',
      params: {
        protocolVersion: '2025-06-18', capabilities: {},
        clientInfo: { name: 'idle-reaper-test', version: '0.0.0' },
      },
    }));
    expect(init.status).toBe(200);
    const sessionId = init.headers['mcp-session-id'];
    expect(typeof sessionId).toBe('string');

    // No DELETE: this is the crash/network-loss path that used to retain the
    // transport forever. The server in this file uses a 100ms test-only TTL.
    await new Promise((r) => setTimeout(r, 180));

    const stale = await httpRequest(
      'POST', '/', { ...headers, 'mcp-session-id': sessionId as string },
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'ping' }),
    );
    expect(stale.status).toBe(404);
    expect(JSON.parse(stale.body).error.message).toMatch(/expired|not found/i);
  });

  it('rejects a non-initialize POST that carries no session id', async () => {
    const res = await httpRequest('POST', '/', headers, JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.body).error.message).toMatch(/mcp-session-id/i);
  });

  it('rejects an unknown session id instead of silently starting a new one', async () => {
    const res = await httpRequest(
      'POST',
      '/',
      { ...headers, 'mcp-session-id': 'does-not-exist' },
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
    );
    expect(res.status).toBe(404);
    expect(JSON.parse(res.body).error.message).toMatch(/session not found/i);
  });
});

describe('HTTP transport — rate limiting', () => {
  it('returns 429 after exceeding rate limit on MCP route', async () => {
    const headers = { authorization: `Bearer ${BEARER}`, 'content-type': 'application/json' };
    const results: number[] = [];
    for (let i = 0; i < 10; i++) {
      const res = await httpRequest('POST', '/', headers, JSON.stringify({ jsonrpc: '2.0', id: i, method: 'ping' }));
      results.push(res.status);
    }
    // Rate limit is 3/min and the bucket is shared with earlier tests in this
    // file, so assert the shape rather than an exact split: throttling kicks in
    // and, once it does, it stays on for the rest of the burst.
    const firstThrottled = results.indexOf(429);
    expect(firstThrottled).toBeGreaterThanOrEqual(0);
    expect(results.slice(firstThrottled).every((s) => s === 429)).toBe(true);
    expect(results.filter((s) => s === 429).length).toBeGreaterThanOrEqual(7);
  });
});
