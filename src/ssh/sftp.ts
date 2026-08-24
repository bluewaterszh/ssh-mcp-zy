import type { SFTPWrapper } from 'ssh2';
import type { SftpUploadOpts, SftpDownloadOpts, SftpStat } from '../types.js';
import type { SSHConnection } from './connection.js';
import { openWithRetry } from './channel-retry.js';
import { validateRemotePath } from '../guard/sanitizer.js';
import { timingLog } from '../observability/timing.js';

/** Operations over one already-open SFTP subsystem channel. */
export class SftpSession {
  constructor(
    private readonly sftp: SFTPWrapper,
    private readonly defaultMaxBytes: number,
  ) {}

  async upload(opts: SftpUploadOpts): Promise<void> {
    const remotePath = validateRemotePath(opts.remotePath, 'remotePath');
    return new Promise<void>((resolve, reject) => {
      const stream = this.sftp.createWriteStream(remotePath, { mode: opts.mode ?? 0o644 });
      stream.on('error', reject);
      stream.on('close', resolve);
      stream.end(Buffer.isBuffer(opts.content) ? opts.content : Buffer.from(opts.content));
    });
  }

  async download(opts: SftpDownloadOpts): Promise<Buffer> {
    const remotePath = validateRemotePath(opts.remotePath, 'remotePath');
    const maxBytes = opts.maxBytes ?? this.defaultMaxBytes;

    const size = await new Promise<number | undefined>((resolve) => {
      this.sftp.stat(remotePath, (err, stats) => resolve(err ? undefined : stats?.size));
    });
    if (size !== undefined && size > maxBytes) {
      throw new Error(
        `Refusing to download ${remotePath}: ${size} bytes exceeds the ${maxBytes} byte limit ` +
        `(commandMaxOutputBytes). Narrow the file or raise the limit for this profile.`,
      );
    }

    return new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let received = 0;
      let settled = false;
      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        reject(err);
      };
      const stream = this.sftp.createReadStream(remotePath);
      stream.on('data', (chunk: Buffer) => {
        if (settled) return;
        received += chunk.length;
        if (received > maxBytes) {
          fail(new Error(
            `Refusing to download ${remotePath}: exceeded the ${maxBytes} byte limit while transferring.`,
          ));
          stream.destroy();
          return;
        }
        chunks.push(chunk);
      });
      stream.on('error', fail);
      stream.on('close', () => {
        if (settled) return;
        settled = true;
        resolve(Buffer.concat(chunks));
      });
    });
  }

  async list(remotePath: string): Promise<SftpStat[]> {
    remotePath = validateRemotePath(remotePath, 'remotePath');
    return new Promise<SftpStat[]>((resolve, reject) => {
      this.sftp.readdir(remotePath, (err: Error | undefined, list: any[]) => {
        if (err) {
          reject(new Error(`SFTP list error: ${err.message}`));
          return;
        }
        resolve(
          list.map((entry) => ({
            path: `${remotePath}/${entry.filename}`,
            size: entry.attrs.size,
            mode: entry.attrs.mode,
            isDirectory: (entry.attrs.mode & 0o170000) === 0o040000,
            isFile: (entry.attrs.mode & 0o170000) === 0o100000,
            mtime: new Date(entry.attrs.mtime * 1000),
            atime: new Date(entry.attrs.atime * 1000),
          })),
        );
      });
    });
  }

  async stat(remotePath: string): Promise<SftpStat> {
    remotePath = validateRemotePath(remotePath, 'remotePath');
    return new Promise<SftpStat>((resolve, reject) => {
      this.sftp.stat(remotePath, (err: Error | undefined, stats: any) => {
        if (err) {
          reject(new Error(`SFTP stat error: ${err.message}`));
          return;
        }
        resolve({
          path: remotePath,
          size: stats.size,
          mode: stats.mode,
          isDirectory: (stats.mode & 0o170000) === 0o040000,
          isFile: (stats.mode & 0o170000) === 0o100000,
          mtime: new Date(stats.mtime * 1000),
          atime: new Date(stats.atime * 1000),
        });
      });
    });
  }
}

export class SftpClient {
  constructor(private conn: SSHConnection) {}

  /**
   * Run several file operations over one SFTP subsystem channel.
   *
   * A subsystem request is an SSH channel open. On high-latency servers that can
   * dominate the actual file work, so edit-file uses one session for all of its
   * stat/read/recheck/write operations instead of opening a new channel for each.
   */
  async withSession<T>(fn: (session: SftpSession) => Promise<T>): Promise<T> {
    const totalStarted = performance.now();
    const openStarted = performance.now();
    // Mark the request active before opening the subsystem so the connection
    // idle reaper cannot race a new SFTP operation.
    this.conn.noteActivity();
    // ensureConnected lives inside the retry: Dropbear drops the whole
    // connection under SFTP channel churn, so an attempt can fail because the
    // link died rather than because the channel was refused. Re-establishing
    // before each attempt covers both.
    let sftp: SFTPWrapper;
    try {
      sftp = await openWithRetry(async () => {
        await this.conn.ensureConnected();
        const client = this.conn.getClient();
        return new Promise<SFTPWrapper>((resolve, reject) => {
          client.sftp((err, handle) => {
            if (err) {
              reject(new Error(`SFTP error: ${err.message}`));
              return;
            }
            resolve(handle);
          });
        });
      });
    } catch (err) {
      timingLog('ssh.sftp', {
        profile: this.conn.profile.name,
        outcome: 'open-error',
        openMs: Number((performance.now() - openStarted).toFixed(3)),
        totalMs: Number((performance.now() - totalStarted).toFixed(3)),
      });
      throw err;
    }

    const openedAt = performance.now();
    const releaseChannel = this.conn.noteChannelOpened();
    let outcome = 'success';
    try {
      return await fn(new SftpSession(sftp, this.conn.profile.maxOutputBytes));
    } catch (err) {
      outcome = 'operation-error';
      throw err;
    } finally {
      // Every client.sftp() opens a new subsystem channel. Without end() they
      // accumulate for the life of the connection until the server's MaxSessions
      // limit is hit, after which no channel — SFTP, exec or shell — can open.
      try { sftp.end(); } catch { /* already torn down */ }
      releaseChannel();
      const endedAt = performance.now();
      timingLog('ssh.sftp', {
        profile: this.conn.profile.name,
        outcome,
        openMs: Number((openedAt - openStarted).toFixed(3)),
        operationMs: Number((endedAt - openedAt).toFixed(3)),
        totalMs: Number((endedAt - totalStarted).toFixed(3)),
      });
    }
  }

  async upload(opts: SftpUploadOpts): Promise<void> {
    return this.withSession((session) => session.upload(opts));
  }

  async download(opts: SftpDownloadOpts): Promise<Buffer> {
    return this.withSession((session) => session.download(opts));
  }

  async list(remotePath: string): Promise<SftpStat[]> {
    return this.withSession((session) => session.list(remotePath));
  }

  async stat(remotePath: string): Promise<SftpStat> {
    return this.withSession((session) => session.stat(remotePath));
  }
}
