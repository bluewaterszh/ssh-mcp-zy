import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { randomUUID, timingSafeEqual } from 'crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { ConnectionRegistry } from '../ssh/connection-registry.js';
import { SERVER_VERSION } from '../version.js';
import { OperatorError } from '../errors.js';

const DEFAULT_MAX_BODY_SIZE = 16_777_216; // 16MB; configurable via HttpTransportOpts
/** Cap on concurrent MCP sessions, so unauthenticated-adjacent churn can't grow the map without bound. */
const MAX_SESSIONS = 64;
/** Reclaim MCP clients that disappear without sending the protocol DELETE. */
const DEFAULT_SESSION_IDLE_TIMEOUT_MS = 600_000; // 10 minutes

interface ManagedTransport {
  transport: StreamableHTTPServerTransport;
  lastActivity: number;
  activeRequests: number;
}

class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private maxTokens: number;
  private refillIntervalMs: number;

  constructor(maxRequestsPerMinute: number) {
    this.maxTokens = maxRequestsPerMinute;
    this.tokens = maxRequestsPerMinute;
    this.lastRefill = Date.now();
    this.refillIntervalMs = 60_000;
  }

  tryConsume(): { allowed: boolean; retryAfterMs: number } {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const refilled = Math.floor((elapsed / this.refillIntervalMs) * this.maxTokens);
    if (refilled > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + refilled);
      this.lastRefill += Math.round((refilled / this.maxTokens) * this.refillIntervalMs);
    }

    if (this.tokens > 0) {
      this.tokens--;
      return { allowed: true, retryAfterMs: 0 };
    }

    const retryAfterMs = Math.ceil(this.refillIntervalMs / this.maxTokens);
    return { allowed: false, retryAfterMs };
  }
}

export interface HttpTransportOpts {
  port: number;
  host?: string;
  bearerToken?: string;
  registry: ConnectionRegistry;
  rateLimit?: number;
  /** Maximum JSON request body size for the MCP route. */
  maxBodyBytes?: number;
  /** Idle lifetime for an MCP HTTP session. Active requests are never reaped. */
  sessionIdleTimeoutMs?: number;
  /**
   * Host headers accepted by the DNS-rebinding guard. Defaults to the bind
   * address and localhost; set this when running behind a reverse proxy that
   * presents a different hostname.
   */
  allowedHosts?: string[];
}

function jsonRpcError(res: ServerResponse, status: number, code: number, message: string): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null }));
}

/**
 * @param createMcpServer Builds a fresh McpServer per MCP session. An McpServer
 *   binds to exactly one transport, so a shared instance would let only the
 *   first client initialize — and would stay unusable after that client left.
 */
export async function startHttpServer(
  createMcpServer: () => McpServer | Promise<McpServer>,
  opts: HttpTransportOpts,
): Promise<void> {
  const { port, host = '127.0.0.1', bearerToken, registry } = opts;

  if (!bearerToken) {
    throw new OperatorError(
      'HTTP transport requires --bearerToken. Example: --transport=http --bearerToken=secret\n' +
      'Without authentication, any network client can execute SSH commands on your hosts.',
    );
  }

  const rateLimiter = opts.rateLimit && opts.rateLimit > 0
    ? new RateLimiter(opts.rateLimit)
    : null;

  // DNS rebinding: a page the user visits can make their browser POST to a
  // localhost server, and the bearer token does not help if the browser is
  // tricked into attaching it. Validating the Host header is what stops it.
  // GHSA-w48q-cv73-mx4w is exactly this, and the SDK leaves it to the caller.
  const allowedHosts = opts.allowedHosts?.length
    ? opts.allowedHosts
    : [`${host}:${port}`, `localhost:${port}`, `127.0.0.1:${port}`, `[::1]:${port}`];

  const maxBodyBytes = opts.maxBodyBytes && opts.maxBodyBytes > 0
    ? opts.maxBodyBytes
    : DEFAULT_MAX_BODY_SIZE;
  const sessionIdleTimeoutMs = opts.sessionIdleTimeoutMs && opts.sessionIdleTimeoutMs > 0
    ? opts.sessionIdleTimeoutMs
    : DEFAULT_SESSION_IDLE_TIMEOUT_MS;
  const transports = new Map<string, ManagedTransport>();

  /**
   * HTTP connections are request-scoped, so a socket/request close is not evidence that
   * the MCP session ended. Clients that crash or lose the network may never send DELETE;
   * without this reaper their entries lived forever and eventually exhausted all 64 slots.
   */
  function reapIdleTransports(now = Date.now()): void {
    const cutoff = now - sessionIdleTimeoutMs;
    for (const [id, managed] of transports) {
      if (managed.activeRequests > 0 || managed.lastActivity > cutoff) continue;
      if (transports.get(id) !== managed) continue;
      transports.delete(id);
      void managed.transport.close().catch(() => { /* already disconnected */ });
    }
  }

  // The timer handles normal cleanup; opportunistic reaping below makes capacity recovery
  // immediate between timer ticks. unref() keeps housekeeping from extending process life.
  const reapIntervalMs = Math.min(Math.max(Math.floor(sessionIdleTimeoutMs / 2), 25), 30_000);
  const sessionReaper = setInterval(reapIdleTransports, reapIntervalMs);
  sessionReaper.unref();

  function trackRequest(managed: ManagedTransport, res: ServerResponse): () => void {
    managed.activeRequests++;
    managed.lastActivity = Date.now();
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      managed.activeRequests = Math.max(0, managed.activeRequests - 1);
      managed.lastActivity = Date.now();
      res.removeListener('finish', finish);
      res.removeListener('close', finish);
    };
    res.once('finish', finish);
    res.once('close', finish);
    return finish;
  }

  /** Route to the session's transport, or start a new session on `initialize`. */
  async function resolveTransport(
    req: IncomingMessage,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<ManagedTransport | null> {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;

    reapIdleTransports();

    if (sessionId) {
      const existing = transports.get(sessionId);
      if (existing) {
        existing.lastActivity = Date.now();
        return existing;
      }
      jsonRpcError(res, 404, -32001, 'Session not found or expired. Re-initialize to obtain a new session.');
      return null;
    }

    const body = Array.isArray(parsedBody) ? parsedBody : [parsedBody];
    if (!body.some((m) => isInitializeRequest(m))) {
      jsonRpcError(res, 400, -32000, 'Missing mcp-session-id header. Send an initialize request first.');
      return null;
    }

    if (transports.size >= MAX_SESSIONS) {
      jsonRpcError(res, 503, -32000, `Server is at its session limit (${MAX_SESSIONS}). Close an existing session and retry.`);
      return null;
    }

    let managed: ManagedTransport;
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableDnsRebindingProtection: true,
      allowedHosts,
      onsessioninitialized: (id) => {
        managed.lastActivity = Date.now();
        transports.set(id, managed);
      },
      onsessionclosed: (id) => { transports.delete(id); },
    });
    managed = { transport, lastActivity: Date.now(), activeRequests: 0 };
    // Explicit transport teardown is immediate. A vanished client is handled by the idle
    // reaper above rather than treating an HTTP request close as an MCP session close.
    transport.onclose = () => {
      const id = transport.sessionId;
      if (id && transports.get(id) === managed) transports.delete(id);
    };

    const mcp = await createMcpServer();
    await mcp.connect(transport);
    return managed;
  }

  const httpServer = createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);

    // Liveness probes are conventionally unauthenticated, and the README lists
    // /health without an auth caveat. It exposes nothing beyond "process is up".
    const isHealthProbe = req.method === 'GET' && url.pathname === '/health';

    if (!isHealthProbe) {
      const auth = req.headers.authorization || '';
      const expected = `Bearer ${bearerToken}`;
      const authBuf = Buffer.from(auth);
      const expectedBuf = Buffer.from(expected);
      const match = authBuf.length === expectedBuf.length &&
        timingSafeEqual(authBuf, expectedBuf);
      if (!match) {
        // RFC 7235: a 401 must say how to authenticate. MCP clients also parse
        // JSON-RPC envelopes on this route, so 401 speaks the same dialect as
        // the 429 and 413 responses rather than a bare {error}.
        res.writeHead(401, {
          'Content-Type': 'application/json',
          'WWW-Authenticate': 'Bearer realm="ssh-mcp"',
        });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32001, message: 'Unauthorized' },
          id: null,
        }));
        return;
      }
    }

    if (rateLimiter && url.pathname === '/' && (req.method === 'POST' || req.method === 'GET' || req.method === 'DELETE')) {
      const { allowed, retryAfterMs } = rateLimiter.tryConsume();
      if (!allowed) {
        const retryAfterSec = Math.ceil(retryAfterMs / 1000);
        res.writeHead(429, {
          'Content-Type': 'application/json',
          'Retry-After': String(retryAfterSec),
        });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          error: {
            code: -32604,
            message: `Rate limit exceeded. Retry after ${retryAfterSec}s.`,
          },
        }));
        return;
      }
    }

    if (req.method === 'POST' && url.pathname === '/') {
      let body = '';
      let bodyBytes = 0;
      let bodyTooLarge = false;
      req.on('data', (chunk: Buffer) => {
        bodyBytes += chunk.length;
        if (!bodyTooLarge) body += chunk.toString();
        if (bodyBytes > maxBodyBytes) {
          if (!bodyTooLarge) {
            bodyTooLarge = true;
            // Connection: close is load-bearing, not cosmetic. Without it a
            // keep-alive client (Node's default agent since v19) returns this
            // socket to its pool, and the destroy below then kills the pooled
            // socket — so the client's *next* request fails with EPIPE.
            res.writeHead(413, {
              'Content-Type': 'application/json',
              'Connection': 'close',
            });
            // Destroy only once the 413 has flushed; destroying immediately
            // races the response and the client sees a bare connection reset
            // instead of the status telling it what went wrong.
            res.end(
              JSON.stringify({
                jsonrpc: '2.0',
                error: { code: -32600, message: `Request body too large (max ${maxBodyBytes} bytes)` },
                id: null,
              }),
              () => req.destroy(),
            );
          }
        }
      });
      req.on('end', async () => {
        if (bodyTooLarge) return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(body);
        } catch {
          jsonRpcError(res, 400, -32700, 'Parse error: invalid JSON');
          return;
        }
        const managed = await resolveTransport(req, res, parsed);
        if (!managed) return;
        const finishActivity = trackRequest(managed, res);
        try {
          await managed.transport.handleRequest(req, res, parsed);
        } catch (err) {
          finishActivity();
          throw err;
        }
      });
      return;
    }

    if ((req.method === 'GET' || req.method === 'DELETE') && url.pathname === '/') {
      const managed = await resolveTransport(req, res);
      if (!managed) return;
      const finishActivity = trackRequest(managed, res);
      try {
        await managed.transport.handleRequest(req, res);
      } catch (err) {
        finishActivity();
        throw err;
      }
      return;
    }

    if (req.method === 'GET' && url.pathname === '/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'running',
        version: SERVER_VERSION,
        connections: registry.listConnections(),
        profiles: registry.listAllProfiles().map((p) => ({
          name: p.name,
          host: p.host,
          user: p.user,
          role: p.role,
          readOnly: p.readOnly,
        })),
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ healthy: true }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  httpServer.once('close', () => clearInterval(sessionReaper));

  // Previously listen() had no error handler, so EADDRINUSE surfaced as an
  // unhandled 'error' event and a raw stack — and startHttpServer resolved
  // immediately regardless, so the caller carried on as if the server was up.
  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', (err: NodeJS.ErrnoException) => {
      // OperatorError, not Error: every listen failure at this point is about how the
      // server was invoked — a port already taken, a privileged port, a mistyped
      // --httpHost. Leaving them on the defect path printed a stack and exited 1, which
      // under this codebase's rule invites the operator to report their own port choice
      // as a bug.
      reject(new OperatorError(
        err.code === 'EADDRINUSE'
          ? `Cannot bind ${host}:${port} — address already in use.`
          : `Cannot bind ${host}:${port}: ${err.message}`,
      ));
    });
    httpServer.listen(port, host, () => {
      console.error(`SSH MCP Server v2 (HTTP) listening on http://${host}:${port}`);
      console.error('Endpoints: POST / (MCP), GET /status, GET /health');
      if (rateLimiter) {
        console.error(`Rate limit: ${opts.rateLimit} req/min`);
      }
      resolve();
    });
  });
}
